from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from .audit import make_entry, utc_now
from .domain import ConflictError, NotFoundError
from .rules import ENTITY, STATES, escalation_required, priority_score

EVENT_ITEM_CREATED = "item_created"
EVENT_RECORD_ADDED = "record_added"
EVENT_TRANSITIONED = "transitioned"


class Repository:
    """事件存储 + 物化视图。

    所有写入先追加带操作号(op_id)的领域事件, 再由事件整理成 items/records 当前视图。
    视图可随时从事件日志重建, 状态不允许手改。
    """

    def __init__(self, db_path: str):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self._create_schema()
        self._migrate_legacy()
        self.rebuild_views()

    def _create_schema(self) -> None:
        statuses = ",".join("'" + s.replace("'", "''") + "'" for s in STATES)
        with self.conn:
            self.conn.executescript(f"""
                CREATE TABLE IF NOT EXISTS items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    quantity REAL NOT NULL DEFAULT 0,
                    threshold REAL NOT NULL DEFAULT 1,
                    status TEXT NOT NULL CHECK(status IN ({statuses})),
                    version INTEGER NOT NULL DEFAULT 1,
                    external_ref TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS ux_items_external_ref
                    ON items(external_ref) WHERE external_ref IS NOT NULL;
                CREATE TABLE IF NOT EXISTS records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    kind TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open'
                        CHECK(status IN ('open','closed')),
                    external_ref TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(item_id, external_ref)
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    entity_id INTEGER NOT NULL,
                    actor TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS domain_events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    op_id TEXT NOT NULL UNIQUE,
                    entity_type TEXT NOT NULL,
                    entity_id INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    result TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_domain_events_entity
                    ON domain_events(entity_type, entity_id, seq);
            """)

    @staticmethod
    def _item(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    @staticmethod
    def _new_op_id() -> str:
        return uuid.uuid4().hex

    def _next_id(self, table: str) -> int:
        row = self.conn.execute(
            f"SELECT COALESCE(MAX(id),0)+1 AS n FROM {table}"
        ).fetchone()
        return int(row["n"])

    def _replay(self, op_id: Optional[str]) -> Optional[Dict[str, Any]]:
        """同一操作号重放: 若已落账则沿用首次结果。"""
        if not op_id:
            return None
        row = self.conn.execute(
            "SELECT result FROM domain_events WHERE op_id=?", (op_id,)
        ).fetchone()
        if row is None:
            return None
        return json.loads(row["result"])

    def replay_result(self, op_id: Optional[str]) -> Optional[Dict[str, Any]]:
        """同一操作号重放: 返回首次落账结果, 未使用过则返回 None。"""
        return self._replay(op_id)

    def _append_event(self, op_id: str, entity_type: str, entity_id: int,
                      event_type: str, payload: Dict[str, Any],
                      result: Dict[str, Any], actor: str,
                      created_at: str) -> None:
        self.conn.execute(
            """INSERT INTO domain_events(op_id, entity_type, entity_id, event_type,
               payload, result, actor, created_at) VALUES(?,?,?,?,?,?,?,?)""",
            (op_id, entity_type, entity_id, event_type,
             json.dumps(payload, ensure_ascii=False),
             json.dumps(result, ensure_ascii=False), actor, created_at),
        )

    def _apply_event(self, event: Dict[str, Any]) -> None:
        payload = event["payload"]
        if isinstance(payload, str):
            payload = json.loads(payload)
        event_type = event["event_type"]
        created_at = event["created_at"]
        if event_type == EVENT_ITEM_CREATED:
            self.conn.execute(
                """INSERT INTO items(id, title, description, severity, quantity, threshold,
                   status, version, external_ref, created_by, created_at, updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (payload["id"], payload["title"], payload["description"],
                 payload["severity"], payload["quantity"], payload["threshold"],
                 payload["status"], payload["version"], payload.get("external_ref"),
                 payload["created_by"], payload["created_at"], payload["updated_at"]),
            )
        elif event_type == EVENT_RECORD_ADDED:
            self.conn.execute(
                """INSERT INTO records(id, item_id, kind, detail, status, external_ref,
                   created_by, created_at) VALUES(?,?,?,?,?,?,?,?)""",
                (payload["id"], payload["item_id"], payload["kind"], payload["detail"],
                 payload["status"], payload.get("external_ref"),
                 payload["created_by"], payload["created_at"]),
            )
        elif event_type == EVENT_TRANSITIONED:
            self.conn.execute(
                "UPDATE items SET status=?, version=version+1, updated_at=? WHERE id=?",
                (payload["to"], created_at, event["entity_id"]),
            )

    def rebuild_views(self) -> None:
        """从原事件日志重建 items/records 视图, 覆盖任何手改或损坏。"""
        with self._lock, self.conn:
            self.conn.execute("DELETE FROM records")
            self.conn.execute("DELETE FROM items")
            rows = self.conn.execute(
                "SELECT * FROM domain_events ORDER BY seq"
            ).fetchall()
            for row in rows:
                self._apply_event(dict(row))

    def _migrate_legacy(self) -> None:
        """旧数据迁移成事故/措施的首版事件; 审计链原样保留。"""
        with self._lock, self.conn:
            count = self.conn.execute(
                "SELECT COUNT(*) AS n FROM domain_events"
            ).fetchone()["n"]
            if count > 0:
                return
            items = self.conn.execute("SELECT * FROM items ORDER BY id").fetchall()
            for row in items:
                item = dict(row)
                self._append_event(
                    op_id=f"migrate:item:{item['id']}",
                    entity_type="item", entity_id=item["id"],
                    event_type=EVENT_ITEM_CREATED,
                    payload=item, result=item, actor=item["created_by"],
                    created_at=item["created_at"],
                )
            records = self.conn.execute("SELECT * FROM records ORDER BY id").fetchall()
            for row in records:
                rec = dict(row)
                self._append_event(
                    op_id=f"migrate:record:{rec['id']}",
                    entity_type="record", entity_id=rec["id"],
                    event_type=EVENT_RECORD_ADDED,
                    payload=rec, result=rec, actor=rec["created_by"],
                    created_at=rec["created_at"],
                )

    # ---- 写入: 先追加事件, 再整理视图 ----

    def create_item(self, title: str, description: str, severity: str,
                    quantity: float, threshold: float, external_ref: Optional[str],
                    actor: str, op_id: Optional[str] = None) -> Dict[str, Any]:
        now = utc_now()
        op_id = op_id or self._new_op_id()
        with self._lock, self.conn:
            replayed = self._replay(op_id)
            if replayed is not None:
                return replayed
            item_id = self._next_id("items")
            payload = {
                "id": item_id, "title": title, "description": description,
                "severity": severity, "quantity": quantity, "threshold": threshold,
                "status": STATES[0], "version": 1, "external_ref": external_ref,
                "created_by": actor, "created_at": now, "updated_at": now,
            }
            try:
                self._append_event(
                    op_id, "item", item_id, EVENT_ITEM_CREATED,
                    payload=payload, result=payload, actor=actor, created_at=now,
                )
                self._apply_event({
                    "event_type": EVENT_ITEM_CREATED,
                    "payload": payload, "entity_id": item_id, "created_at": now,
                })
            except sqlite3.IntegrityError as exc:
                raise ConflictError("external_ref已存在") from exc
            result = self.get_item(item_id)
            self.conn.execute(
                "UPDATE domain_events SET result=? WHERE op_id=?",
                (json.dumps(result, ensure_ascii=False), op_id),
            )
            self._append_audit("create", ENTITY, item_id, actor, {
                "title": title, "severity": severity, "quantity": quantity,
                "priority": priority_score(severity, quantity, threshold),
                "op_id": op_id,
            })
        return result

    def add_record(self, item_id: int, kind: str, detail: str, status: str,
                   external_ref: Optional[str], actor: str,
                   op_id: Optional[str] = None) -> Dict[str, Any]:
        now = utc_now()
        op_id = op_id or self._new_op_id()
        with self._lock, self.conn:
            replayed = self._replay(op_id)
            if replayed is not None:
                return replayed
            self.get_item(item_id)
            if external_ref is not None:
                dup = self.conn.execute(
                    "SELECT 1 FROM records WHERE item_id=? AND external_ref=?",
                    (item_id, external_ref),
                ).fetchone()
                if dup is not None:
                    raise ConflictError("记录唯一标识已存在")
            record_id = self._next_id("records")
            payload = {
                "id": record_id, "item_id": item_id, "kind": kind, "detail": detail,
                "status": status, "external_ref": external_ref,
                "created_by": actor, "created_at": now,
            }
            try:
                self._append_event(
                    op_id, "record", record_id, EVENT_RECORD_ADDED,
                    payload=payload, result=payload, actor=actor, created_at=now,
                )
                self._apply_event({
                    "event_type": EVENT_RECORD_ADDED,
                    "payload": payload, "entity_id": record_id, "created_at": now,
                })
            except sqlite3.IntegrityError as exc:
                raise ConflictError("记录唯一标识已存在") from exc
            result = self._get_record(record_id)
            self.conn.execute(
                "UPDATE domain_events SET result=? WHERE op_id=?",
                (json.dumps(result, ensure_ascii=False), op_id),
            )
            self._append_audit("record", ENTITY, item_id, actor, {
                "record_id": record_id, "kind": kind, "status": status,
                "op_id": op_id,
            })
        return result

    def transition_item(self, item_id: int, target: str, expected_version: int,
                        actor: str, op_id: Optional[str] = None) -> Dict[str, Any]:
        now = utc_now()
        op_id = op_id or self._new_op_id()
        with self._lock, self.conn:
            replayed = self._replay(op_id)
            if replayed is not None:
                return replayed
            row = self.conn.execute(
                "SELECT * FROM items WHERE id=?", (item_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError("项目不存在")
            item = dict(row)
            if item["version"] != expected_version:
                raise ConflictError("版本冲突，请刷新后重试")
            payload = {"from": item["status"], "to": target,
                      "expected_version": expected_version}
            self._append_event(
                op_id, "item", item_id, EVENT_TRANSITIONED,
                payload=payload, result=payload, actor=actor, created_at=now,
            )
            self._apply_event({
                "event_type": EVENT_TRANSITIONED,
                "payload": payload, "entity_id": item_id, "created_at": now,
            })
            result = self.get_item(item_id)
            self.conn.execute(
                "UPDATE domain_events SET result=? WHERE op_id=?",
                (json.dumps(result, ensure_ascii=False), op_id),
            )
            self._append_audit("transition", ENTITY, item_id, actor, {
                "from": item["status"], "to": target,
                "escalation_required": escalation_required(
                    item["severity"], item["quantity"], item["threshold"]),
                "op_id": op_id,
            })
        return result

    # ---- 读取: 走物化视图, 与旧接口一致 ----

    def get_item(self, item_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM items WHERE id=?", (item_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError("项目不存在")
        return self._item(row)

    def list_items(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM items"
        params: tuple = ()
        if status:
            sql += " WHERE status=?"
            params = (status,)
        sql += " ORDER BY id DESC"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [self._item(row) for row in rows]

    def _get_record(self, record_id: int) -> Dict[str, Any]:
        row = self.conn.execute(
            "SELECT * FROM records WHERE id=?", (record_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("记录不存在")
        return dict(row)

    def list_records(self, item_id: int) -> List[Dict[str, Any]]:
        self.get_item(item_id)
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM records WHERE item_id=? ORDER BY id", (item_id,)
            ).fetchall()
        return [dict(row) for row in rows]

    def open_record_count(self, item_id: int) -> int:
        with self._lock:
            row = self.conn.execute(
                "SELECT COUNT(*) AS n FROM records WHERE item_id=? AND status='open'",
                (item_id,),
            ).fetchone()
        return int(row["n"])

    # ---- 审计链: 保留并随事件追加延续 ----

    def _append_audit(self, action: str, entity_type: str, entity_id: int,
                      actor: str, detail: Dict[str, Any]) -> Dict[str, Any]:
        row = self.conn.execute(
            "SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        previous = row["entry_hash"] if row else "GENESIS"
        event = make_entry(action, entity_type, entity_id, actor, detail, previous)
        self.conn.execute(
            """INSERT INTO audit_events(action, entity_type, entity_id, actor, detail,
               previous_hash, entry_hash, created_at) VALUES(?,?,?,?,?,?,?,?)""",
            (event["action"], event["entity_type"], event["entity_id"], event["actor"],
             json.dumps(event["detail"], ensure_ascii=False, sort_keys=True),
             event["previous_hash"], event["entry_hash"], event["created_at"]),
        )
        return event

    def append_audit(self, action: str, entity_type: str, entity_id: int,
                     actor: str, detail: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock, self.conn:
            return self._append_audit(action, entity_type, entity_id, actor, detail)

    def list_audit(self, entity_id: Optional[int] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM audit_events"
        params: tuple = ()
        if entity_id is not None:
            sql += " WHERE entity_id=?"
            params = (entity_id,)
        sql += " ORDER BY id"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["detail"] = json.loads(item["detail"])
            result.append(item)
        return result

    def list_events(self, entity_type: Optional[str] = None,
                    entity_id: Optional[int] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM domain_events"
        conds: List[str] = []
        params: List[Any] = []
        if entity_type is not None:
            conds.append("entity_type=?")
            params.append(entity_type)
        if entity_id is not None:
            conds.append("entity_id=?")
            params.append(entity_id)
        if conds:
            sql += " WHERE " + " AND ".join(conds)
        sql += " ORDER BY seq"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["payload"] = json.loads(item["payload"])
            item["result"] = json.loads(item["result"])
            result.append(item)
        return result

    def verify_audit_chain(self) -> bool:
        from .audit import calculate_hash
        with self._lock:
            rows = self.conn.execute("SELECT * FROM audit_events ORDER BY id").fetchall()
        previous = "GENESIS"
        for row in rows:
            if row["previous_hash"] != previous:
                return False
            payload = {
                "action": row["action"], "entity_type": row["entity_type"],
                "entity_id": row["entity_id"], "actor": row["actor"],
                "detail": json.loads(row["detail"]), "created_at": row["created_at"],
            }
            if calculate_hash(previous, payload) != row["entry_hash"]:
                return False
            previous = row["entry_hash"]
        return True

    def close(self) -> None:
        with self._lock:
            self.conn.close()
