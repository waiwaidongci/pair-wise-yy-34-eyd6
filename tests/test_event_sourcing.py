import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from src.audit import make_entry
from src.domain import ConflictError
from src.repository import (EVENT_MEASURE_ADDED, EVENT_REGISTERED,
                            EVENT_STATUS_ADVANCED, Repository)
from src.service import Service
from src.rules import STATES, TRANSITION_ROLES


def transition_role(target):
    return TRANSITION_ROLES[target][0]


class EventSourcingTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmp.name) / "test.db")
        self.repo = Repository(self.db_path)
        self.service = Service(self.repo)

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def test_append_then_project_current_view(self):
        item = self.service.create_item(
            {"title": "evt", "description": "append first", "severity": "serious",
             "quantity": 3, "threshold": 2, "external_ref": "E-1"},
            "alice", "reporter", op_no="op-create-1")
        # 事件先落账
        events = self.repo.list_events(item["id"])
        self.assertEqual([e["event_type"] for e in events], [EVENT_REGISTERED])
        registered = events[0]
        self.assertEqual(registered["op_no"], "op-create-1")
        self.assertEqual(registered["actor"], "alice")
        self.assertEqual(registered["version"], 1)
        # 当前视图由事件整理得到
        view = self.service.get_item(item["id"], "viewer")
        self.assertEqual(view["status"], STATES[0])
        self.assertEqual(view["version"], 1)

        record = self.service.add_record(
            item["id"], {"kind": "action", "detail": "fix guard",
                         "external_ref": "M-1"},
            "bob", "investigator", op_no="op-measure-1")
        self.assertEqual(record["item_id"], item["id"])
        events = self.repo.list_events(item["id"])
        self.assertEqual([e["event_type"] for e in events],
                         [EVENT_REGISTERED, EVENT_MEASURE_ADDED])
        # 措施不推进事故状态版本
        self.assertEqual(self.service.get_item(item["id"], "viewer")["version"], 1)

        advanced = self.service.transition(
            item["id"], STATES[1], 1, "carol", transition_role(STATES[1]),
            op_no="op-trans-1")
        self.assertEqual(advanced["status"], STATES[1])
        self.assertEqual(advanced["version"], 2)
        events = self.repo.list_events(item["id"])
        self.assertEqual(events[-1]["event_type"], EVENT_STATUS_ADVANCED)
        self.assertEqual(events[-1]["actor"], "carol")
        self.assertEqual(events[-1]["payload"]["from_status"], STATES[0])
        self.assertEqual(events[-1]["payload"]["to_status"], STATES[1])
        self.assertTrue(self.repo.verify_audit_chain())

    def test_same_op_replays_first_result(self):
        first = self.service.create_item(
            {"title": "idem", "description": "once", "severity": "minor"},
            "alice", "reporter", op_no="idem-create")
        replay = self.service.create_item(
            {"title": "different title ignored", "description": "twice",
             "severity": "fatal"},
            "mallory", "reporter", op_no="idem-create")
        # 沿用首次结果，不产生第二个事故
        self.assertEqual(replay["id"], first["id"])
        self.assertEqual(replay["title"], "idem")
        self.assertEqual(replay["severity"], "minor")
        self.assertEqual(len(self.repo.list_events(first["id"])), 1)

        r1 = self.service.add_record(
            first["id"], {"kind": "evidence", "detail": "photo A"},
            "bob", "investigator", op_no="idem-measure")
        r2 = self.service.add_record(
            first["id"], {"kind": "evidence", "detail": "photo B"},
            "bob", "investigator", op_no="idem-measure")
        self.assertEqual(r1["id"], r2["id"])
        self.assertEqual(r2["detail"], "photo A")
        measures = self.service.list_records(first["id"], "viewer")
        self.assertEqual(len(measures), 1)

        t1 = self.service.transition(
            first["id"], STATES[1], 1, "carol", transition_role(STATES[1]),
            op_no="idem-trans")
        # 重放状态推进：即便再次提交旧版本号也沿用首次成功结果
        t2 = self.service.transition(
            first["id"], STATES[2], 1, "carol", transition_role(STATES[2]),
            op_no="idem-trans")
        self.assertEqual(t2["id"], t1["id"])
        self.assertEqual(t2["status"], STATES[1])
        self.assertEqual(self.service.get_item(first["id"], "viewer")["version"], 2)

    def test_op_reuse_across_incidents_conflicts(self):
        one = self.service.create_item(
            {"title": "one", "description": "x", "severity": "minor"},
            "alice", "reporter", op_no="shared")
        two = self.service.create_item(
            {"title": "two", "description": "y", "severity": "minor"},
            "alice", "reporter")
        with self.assertRaises(ConflictError):
            self.service.add_record(
                two["id"], {"kind": "action", "detail": "borrowed op"},
                "bob", "investigator", op_no="shared")
        # 张冠李戴没有给事故二追加任何事件
        self.assertEqual(
            [e["event_type"] for e in self.repo.list_events(two["id"])],
            [EVENT_REGISTERED])
        del one

    def test_concurrent_transition_first_writer_wins(self):
        item = self.service.create_item(
            {"title": "race", "description": "occ", "severity": "moderate"},
            "alice", "reporter")
        # 两人都基于版本1提交推进
        winner = self.service.transition(
            item["id"], STATES[1], 1, "first", transition_role(STATES[1]))
        self.assertEqual(winner["version"], 2)
        with self.assertRaises(ConflictError) as caught:
            self.service.transition(
                item["id"], STATES[1], 1, "second", transition_role(STATES[1]))
        # 后提交者拿到新版本
        self.assertEqual(caught.exception.current_version, 2)
        # 后提交者刷新视图后基于新版本重新办理
        latest = self.service.get_item(item["id"], "viewer")
        advanced = self.service.transition(
            item["id"], STATES[2], latest["version"], "second",
            transition_role(STATES[2]))
        self.assertEqual(advanced["status"], STATES[2])
        self.assertEqual(advanced["version"], 3)
        events = self.repo.list_events(item["id"])
        transitions = [e for e in events if e["event_type"] == EVENT_STATUS_ADVANCED]
        self.assertEqual([e["actor"] for e in transitions], ["first", "second"])

    def test_failed_write_recovers_from_events_and_cannot_force_state(self):
        item = self.service.create_item(
            {"title": "recover", "description": "restore", "severity": "serious"},
            "alice", "reporter")
        self.service.add_record(
            item["id"], {"kind": "action", "detail": "open item",
                         "status": "open", "external_ref": "R-1"},
            "bob", "investigator")
        # 关闭被未关闭措施阻止：整笔失败，事件与视图都不得改变
        current = self.service.get_item(item["id"], "viewer")
        for target in STATES[1:-1]:
            current = self.service.transition(
                current["id"], target, current["version"], "rev",
                transition_role(target))
        with self.assertRaises(ConflictError):
            self.service.transition(
                item["id"], STATES[-1], current["version"], "rev",
                transition_role(STATES[-1]))
        before = self.service.get_item(item["id"], "viewer")
        self.assertEqual(before["status"], STATES[-2])
        self.assertEqual(before["version"], len(STATES) - 1)
        events_before = self.repo.list_events(item["id"])

        # 模拟重启/视图损坏：只保留原事件，重建事故与措施当前视图
        self.repo.restore_views()
        after = self.service.get_item(item["id"], "viewer")
        self.assertEqual(after["status"], before["status"])
        self.assertEqual(after["version"], before["version"])
        self.assertEqual(after["title"], before["title"])
        self.assertEqual(
            [r["detail"] for r in self.service.list_records(item["id"], "viewer")],
            ["open item"])
        self.assertEqual(
            [e["event_seq"] for e in self.repo.list_events(item["id"])],
            [e["event_seq"] for e in events_before])

        # 不能手改状态：直接篡改投影后，下一次恢复仍以事件为准
        with self.repo._lock, self.repo.conn:
            self.repo.conn.execute(
                "UPDATE incidents SET status=?, version=99 WHERE incident_id=?",
                (STATES[-1], item["id"]))
        tampered = self.service.get_item(item["id"], "viewer")
        self.assertEqual(tampered["status"], STATES[-1])
        self.repo.restore_views()
        healed = self.service.get_item(item["id"], "viewer")
        self.assertEqual(healed["status"], STATES[-2])
        self.assertEqual(healed["version"], len(STATES) - 1)

    def test_restart_rebuilds_view_from_events(self):
        item = self.service.create_item(
            {"title": "restart", "description": "reopen db", "severity": "minor"},
            "alice", "reporter")
        self.service.add_record(
            item["id"], {"kind": "witness", "detail": "saw it"},
            "bob", "investigator")
        self.service.transition(
            item["id"], STATES[1], 1, "carol", transition_role(STATES[1]))
        self.repo.close()
        # 事故调查中途重启：视图从事件重新整理，状态/措施/审计链对得上
        reopened = Repository(self.db_path)
        try:
            view = reopened.get_item(item["id"])
            self.assertEqual(view["status"], STATES[1])
            self.assertEqual(view["version"], 2)
            rows = reopened.list_records(item["id"])
            self.assertEqual(len(rows), 1)
            self.assertTrue(reopened.verify_audit_chain())
        finally:
            reopened.close()


def build_legacy_db(path):
    """构造改造前的旧库：items/records 直写状态 + 全局审计哈希链。"""
    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE items (
            id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL,
            description TEXT NOT NULL, severity TEXT NOT NULL,
            quantity REAL NOT NULL DEFAULT 0, threshold REAL NOT NULL DEFAULT 1,
            status TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1,
            external_ref TEXT, created_by TEXT NOT NULL,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""")
    conn.execute("""
        CREATE TABLE records (
            id INTEGER PRIMARY KEY AUTOINCREMENT, item_id INTEGER NOT NULL,
            kind TEXT NOT NULL, detail TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open', external_ref TEXT,
            created_by TEXT NOT NULL, created_at TEXT NOT NULL,
            UNIQUE(item_id, external_ref))""")
    conn.execute("""
        CREATE TABLE audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL,
            entity_type TEXT NOT NULL, entity_id INTEGER NOT NULL,
            actor TEXT NOT NULL, detail TEXT NOT NULL,
            previous_hash TEXT NOT NULL, entry_hash TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL)""")
    now = "2026-09-01T00:00:00+00:00"
    conn.execute(
        """INSERT INTO items(id,title,description,severity,quantity,threshold,
           status,version,external_ref,created_by,created_at,updated_at)
           VALUES(1,'legacy','old schema','serious',5,10,'verification',4,
                  'LEG-1','alice',?,?)""",
        (now, now))
    conn.execute(
        """INSERT INTO records(id,item_id,kind,detail,status,external_ref,
           created_by,created_at) VALUES(1,1,'action','closed action','closed',
           'OLD-M1','bob',?)""", (now,))

    def audit(action, entity_id, actor, detail, stamp):
        row = conn.execute(
            "SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
        previous = row[0] if row else "GENESIS"
        entry = make_entry(action, "事故", entity_id, actor, detail, previous)
        entry["created_at"] = stamp
        from src.audit import calculate_hash
        entry["entry_hash"] = calculate_hash(previous, {
            "action": action, "entity_type": "事故", "entity_id": entity_id,
            "actor": actor, "detail": detail, "created_at": stamp})
        conn.execute(
            """INSERT INTO audit_events(action,entity_type,entity_id,actor,detail,
               previous_hash,entry_hash,created_at) VALUES(?,?,?,?,?,?,?,?)""",
            (action, "事故", entity_id, actor,
             json.dumps(detail, ensure_ascii=False, sort_keys=True),
             entry["previous_hash"], entry["entry_hash"], stamp))

    audit("create", 1, "alice", {"title": "legacy", "severity": "serious",
                                 "quantity": 5, "priority": 7}, now)
    audit("record", 1, "bob", {"record_id": 1, "kind": "action",
                               "status": "closed"}, now)
    seq = [("reported", "investigating"), ("investigating", "corrective_action"),
           ("corrective_action", "verification")]
    for frm, to in seq:
        audit("transition", 1, "carol", {"from": frm, "to": to,
                                         "escalation_required": False}, now)
    conn.commit()
    conn.close()


class MigrationTest(unittest.TestCase):
    def test_legacy_data_migrates_to_first_events(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = str(Path(tmp.name) / "legacy.db")
        build_legacy_db(path)

        repo = Repository(path)
        # 旧表已被事件取代
        master = repo.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('items','records')"
        ).fetchall()
        self.assertEqual(master, [])

        events = repo.list_events(1)
        self.assertEqual(
            [e["event_type"] for e in events],
            [EVENT_REGISTERED, EVENT_MEASURE_ADDED,
             EVENT_STATUS_ADVANCED, EVENT_STATUS_ADVANCED, EVENT_STATUS_ADVANCED])
        self.assertEqual(events[0]["payload"]["title"], "legacy")
        self.assertEqual(events[1]["payload"]["measure_id"], 1)
        self.assertEqual(events[-1]["payload"]["to_status"], "verification")

        # 当前视图由首版事件整理得到
        item = repo.get_item(1)
        self.assertEqual(item["status"], "verification")
        self.assertEqual(item["version"], 4)
        self.assertEqual(item["external_ref"], "LEG-1")
        records = repo.list_records(1)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["id"], 1)
        self.assertEqual(records[0]["item_id"], 1)
        self.assertEqual(records[0]["status"], "closed")

        # 审计链保留：原有 create/record/transition 仍在且可验
        self.assertTrue(repo.verify_audit_chain())
        audit = repo.list_audit(1)
        actions = [a["action"] for a in audit]
        self.assertEqual(
            actions, ["create", "record", "transition", "transition",
                      "transition", "migrate"])

        # 迁移后原有查询照旧可用，且可以继续推进到关闭
        service = Service(repo)
        closed = service.transition(1, STATES[-1], 4, "dave",
                                    transition_role(STATES[-1]))
        self.assertEqual(closed["status"], "closed")
        self.assertEqual(closed["version"], 5)
        repo.close()

        # 再次启动不重复迁移
        again = Repository(path)
        try:
            self.assertEqual(len(again.list_events(1)), 6)
            self.assertTrue(again.verify_audit_chain())
        finally:
            again.close()


if __name__ == "__main__":
    unittest.main()
