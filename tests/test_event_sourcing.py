import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from src.domain import ConflictError
from src.repository import Repository
from src.service import Service
from src.rules import STATES, TRANSITION_ROLES


class EventSourcingTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "test.db"))
        self.service = Service(self.repo)

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def _create(self, **kw):
        payload = {"title": "t", "description": "d", "severity": "serious",
                   "quantity": 5, "threshold": 10}
        payload.update(kw)
        return self.service.create_item(payload, "creator", "reporter")

    def test_op_id_replay_returns_first_result(self):
        item = self._create(title="first", op_id="OP-1")
        again = self._create(title="first", op_id="OP-1")
        self.assertEqual(item["id"], again["id"])
        self.assertEqual(item["version"], again["version"])
        self.assertEqual(item["title"], again["title"])
        events = self.repo.list_events("item", item["id"])
        self.assertEqual(len(events), 1)

    def test_transition_replay_ignores_stale_version(self):
        item = self._create()
        op_id = "TX-1"
        r1 = self.service.transition(item["id"], "investigating", item["version"],
                                     "reviewer", "investigator", op_id=op_id)
        # 同一操作号重放: 即使 expected_version 已过期, 也沿用首次结果
        r2 = self.service.transition(item["id"], "investigating", item["version"],
                                     "reviewer", "investigator", op_id=op_id)
        self.assertEqual(r1["version"], r2["version"])
        self.assertEqual(r1["id"], r2["id"])
        events = self.repo.list_events("item", item["id"])
        self.assertEqual(len(events), 2)  # created + transitioned

    def test_concurrent_transition_first_wins(self):
        item = self._create()
        results = []
        errors = []

        def do_transition():
            try:
                results.append(self.service.transition(
                    item["id"], "investigating", item["version"],
                    "reviewer", "investigator"))
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=do_transition) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(results), 1)
        self.assertEqual(len(errors), 7)
        for exc in errors:
            self.assertIsInstance(exc, ConflictError)
        self.assertEqual(results[0]["version"], 2)
        self.assertEqual(results[0]["status"], "investigating")

    def test_failed_transition_keeps_view(self):
        item = self._create()
        with self.assertRaises(ConflictError):
            self.service.transition(item["id"], "investigating", 99,
                                    "reviewer", "investigator")
        current = self.service.get_item(item["id"], "viewer")
        self.assertEqual(current["version"], 1)
        self.assertEqual(current["status"], "reported")

    def test_rebuild_views_from_events(self):
        item = self._create()
        self.service.add_record(item["id"], {
            "kind": "evidence", "detail": "found", "status": "open",
            "external_ref": "EV-1"}, "recorder", "investigator")
        # 直接损坏视图(模拟写入失败或手改)
        with self.repo._lock, self.repo.conn:
            self.repo.conn.execute("DELETE FROM records WHERE item_id=?", (item["id"],))
            self.repo.conn.execute("DELETE FROM items WHERE id=?", (item["id"],))
        # 从原事件恢复视图
        self.repo.rebuild_views()
        recovered = self.service.get_item(item["id"], "viewer")
        self.assertEqual(recovered["title"], item["title"])
        self.assertEqual(recovered["status"], "reported")
        records = self.service.list_records(item["id"], "viewer")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["external_ref"], "EV-1")

    def test_rebuild_on_restart(self):
        item = self._create()
        self.service.add_record(item["id"], {
            "kind": "evidence", "detail": "d", "status": "open"},
            "recorder", "investigator")
        # 损坏视图
        with self.repo._lock, self.repo.conn:
            self.repo.conn.execute("DELETE FROM items WHERE id=?", (item["id"],))
        # 重启 -> 新 Repository 从事件恢复视图
        self.repo.close()
        repo2 = Repository(str(Path(self.tmp.name) / "test.db"))
        self.repo = repo2
        service2 = Service(repo2)
        recovered = service2.get_item(item["id"], "viewer")
        self.assertEqual(recovered["title"], item["title"])
        self.assertEqual(len(service2.list_records(item["id"], "viewer")), 1)

    def test_migrate_legacy_database(self):
        # 构造旧库: 只有 items/records/audit_events, 没有 domain_events
        legacy = Path(self.tmp.name) / "legacy.db"
        conn = sqlite3.connect(str(legacy))
        conn.executescript("""
            CREATE TABLE items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL, description TEXT NOT NULL, severity TEXT NOT NULL,
                quantity REAL NOT NULL DEFAULT 0, threshold REAL NOT NULL DEFAULT 1,
                status TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1,
                external_ref TEXT, created_by TEXT NOT NULL, created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL);
            CREATE TABLE records (
                id INTEGER PRIMARY KEY AUTOINCREMENT, item_id INTEGER NOT NULL,
                kind TEXT NOT NULL, detail TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
                external_ref TEXT, created_by TEXT NOT NULL, created_at TEXT NOT NULL);
            CREATE TABLE audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL,
                entity_type TEXT NOT NULL, entity_id INTEGER NOT NULL, actor TEXT NOT NULL,
                detail TEXT NOT NULL, previous_hash TEXT NOT NULL, entry_hash TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL);
        """)
        from src.audit import make_entry
        audit_entry = make_entry("create", "事故", 1, "creator", {}, "GENESIS")
        now = audit_entry["created_at"]
        conn.execute("INSERT INTO items VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                     (1, "legacy item", "old", "serious", 5, 10, "closed", 3,
                      "LEG-1", "creator", now, now))
        conn.execute("INSERT INTO records VALUES(?,?,?,?,?,?,?,?)",
                     (1, 1, "evidence", "old evidence", "closed", "EV-1", "recorder", now))
        conn.execute("INSERT INTO audit_events VALUES(?,?,?,?,?,?,?,?,?)",
                     (1, audit_entry["action"], audit_entry["entity_type"],
                      audit_entry["entity_id"], audit_entry["actor"], "{}",
                      audit_entry["previous_hash"], audit_entry["entry_hash"], now))
        conn.commit()
        conn.close()

        repo = Repository(str(legacy))
        # 旧数据迁移成首版事件
        events = repo.list_events()
        self.assertEqual(len(events), 2)
        self.assertEqual({e["event_type"] for e in events},
                         {"item_created", "record_added"})
        # 视图重建, 旧状态保留
        item = repo.get_item(1)
        self.assertEqual(item["status"], "closed")
        self.assertEqual(item["version"], 3)
        records = repo.list_records(1)
        self.assertEqual(len(records), 1)
        # 原有查询照旧可用
        self.assertEqual(len(repo.list_items()), 1)
        # 审计链保留
        self.assertTrue(repo.verify_audit_chain())
        # 迁移后新操作正常
        svc = Service(repo)
        item2 = svc.create_item({"title": "new", "description": "n", "severity": "minor"},
                                "creator", "reporter")
        self.assertEqual(item2["status"], "reported")
        repo.close()

    def test_duplicate_record_external_ref_conflict(self):
        item = self._create()
        payload = {"kind": "action", "detail": "d", "status": "open",
                   "external_ref": "DUP-1"}
        self.service.add_record(item["id"], payload, "recorder", "investigator")
        with self.assertRaises(ConflictError):
            self.service.add_record(item["id"], payload, "recorder", "investigator")
        records = self.service.list_records(item["id"], "viewer")
        self.assertEqual(len(records), 1)


if __name__ == "__main__":
    unittest.main()
