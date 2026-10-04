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

# 事件类型：登记、加措施、状态推进
EVENT_REGISTERED = "incident_registered"
EVENT_MEASURE_ADDED = "measure_added"
EVENT_STATUS_ADVANCED = "status_advanced"


def _incident_from_row(row: sqlite3.Row) -> Dict[str, Any]:
    item = dict(row)
    if "incident_id" in item:
        item["id"] = item.pop("incident_id")
    return item


def _measure_from_row(row: sqlite3.Row) -> Dict[str, Any]:
    record = dict(row)
    if "measure_id" in record:
        record["id"] = record.pop("measure_id")
    if "incident_id" in record:
        record["item_id"] = record.pop("incident_id")
    return record


class Repository:
    """事件溯源仓储：事件是唯一事实来源，事故与措施视图只由事件折叠得到。"""

    def __init__(self, db_path: str):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self._bootstrap()

    # ------------------------------------------------------------------ schema
    def _create_schema(self) -> None:
        statuses = ",".join("'" + s.replace("'", "''") + "'" for s in STATES)
        self.conn.executescript(f"""
            CREATE TABLE IF NOT EXISTS incident_events (
                event_seq INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL,
                version INTEGER NOT NULL,
                op_no TEXT NOT NULL UNIQUE,
                event_type TEXT NOT NULL
                    CHECK(event_type IN ('{EVENT_REGISTERED}','{EVENT_MEASURE_ADDED}','{EVENT_STATUS_ADVANCED}')),
                payload TEXT NOT NULL,
                actor TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_events_incident
                ON incident_events(incident_id, version);
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id INTEGER PRIMARY KEY,
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
            CREATE UNIQUE INDEX IF NOT EXISTS ux_incidents_external_ref
                ON incidents(external_ref) WHERE external_ref IS NOT NULL;
            CREATE TABLE IF NOT EXISTS measures (
                measure_id INTEGER PRIMARY KEY,
                incident_id INTEGER NOT NULL,
                kind TEXT NOT NULL,
                detail TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open'
                    CHECK(status IN ('open','closed')),
                external_ref TEXT,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(incident_id, external_ref)
            );
            CREATE TABLE IF NOT EXISTS counters (
                name TEXT PRIMARY KEY,
                value INTEGER NOT NULL
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
        """)

    # ---------------------------------------------------------------- boot
    def _bootstrap(self) -> None:
        """建库 -> 迁移旧数据 -> 从事件恢复当前视图（启动时不相信旧状态）。"""
        with self._lock, self.conn:
            self._create_schema()
            self._migrate_legacy_locked()
            self._restore_views_locked()

    def _is_legacy_locked(self) -> bool:
        legacy_items = self.conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='items'"
        ).fetchone()
        if legacy_items is None:
            return False
        migrated = self.conn.execute(
            "SELECT 1 FROM incident_events WHERE event_type=? LIMIT 1",
            (EVENT_REGISTERED,),
        ).fetchone()
        return migrated is None

    def _migrate_legacy_locked(self) -> None:
        """旧表数据先迁移成事故与措施的首版事件，审计链保留，随后删除旧表。"""
        if not self._is_legacy_locked():
            return
        legacy_items = self.conn.execute("SELECT * FROM items ORDER BY id").fetchall()
        max_incident = 0
        max_measure = 0
        for item_row in legacy_items:
            item = dict(item_row)
            incident_id = item["id"]
            max_incident = max(max_incident, incident_id)
            now = item["created_at"]
            op_no = f"migrate:register:{incident_id}"
            payload = {
                "title": item["title"],
                "description": item["description"],
                "severity": item["severity"],
                "quantity": item["quantity"],
                "threshold": item["threshold"],
                "external_ref": item["external_ref"],
                "legacy": True,
            }
            self.conn.execute(
                """INSERT INTO incident_events(incident_id, version, op_no, event_type,
                   payload, actor, created_at) VALUES(?,?,?,?,?,?,?)""",
                (incident_id, 1, op_no, EVENT_REGISTERED,
                 json.dumps(payload, ensure_ascii=False, sort_keys=True),
                 item["created_by"], now),
            )
            # 旧 create 审计行原样保留在审计链上，不重复插入

            version = 1
            # 措施：沿用旧记录标识，整理为 measure_added 事件（不占状态版本）
            record_rows = self.conn.execute(
                "SELECT * FROM records WHERE item_id=? ORDER BY id", (incident_id,)
            ).fetchall()
            for rec_row in record_rows:
                rec = dict(rec_row)
                measure_id = rec["id"]
                max_measure = max(max_measure, measure_id)
                m_op_no = f"migrate:measure:{measure_id}"
                m_payload = {
                    "measure_id": measure_id,
                    "kind": rec["kind"],
                    "detail": rec["detail"],
                    "status": rec["status"],
                    "external_ref": rec["external_ref"],
                    "legacy": True,
                }
                self.conn.execute(
                    """INSERT INTO incident_events(incident_id, version, op_no,
                       event_type, payload, actor, created_at)
                       VALUES(?,?,?,?,?,?,?)""",
                    (incident_id, 1, m_op_no, EVENT_MEASURE_ADDED,
                     json.dumps(m_payload, ensure_ascii=False, sort_keys=True),
                     rec["created_by"], rec["created_at"]),
                )
                # 旧 record 审计行原样保留，不重复插入

            # 状态推进：沿用旧审计链上的 transition 事件顺序补齐
            trans_rows = self.conn.execute(
                """SELECT * FROM audit_events
                   WHERE entity_type=? AND entity_id=? AND action='transition'
                   ORDER BY id""",
                (ENTITY, incident_id),
            ).fetchall()
            for t_row in trans_rows:
                detail = json.loads(t_row["detail"])
                version += 1
                t_op_no = f"migrate:transition:{incident_id}:{version}"
                t_payload = {
                    "from_status": detail.get("from"),
                    "to_status": detail.get("to"),
                    "legacy": True,
                }
                self.conn.execute(
                    """INSERT INTO incident_events(incident_id, version, op_no,
                       event_type, payload, actor, created_at)
                       VALUES(?,?,?,?,?,?,?)""",
                    (incident_id, version, t_op_no, EVENT_STATUS_ADVANCED,
                     json.dumps(t_payload, ensure_ascii=False, sort_keys=True),
                     t_row["actor"], t_row["created_at"]),
                )
            # 迁移标记事件（审计链保留的同时留下迁移痕迹）
            self._insert_audit_locked(
                "migrate", ENTITY, incident_id, "system", {
                    "from_version": item["version"], "to_version": version,
                    "event_count": 1 + len(record_rows) + len(trans_rows),
                }, utc_now())

        self.conn.execute(
            """INSERT INTO counters(name, value) VALUES('incident_id', ?)
               ON CONFLICT(name) DO UPDATE SET value=excluded.value""",
            (max_incident,))
        self.conn.execute(
            """INSERT INTO counters(name, value) VALUES('measure_id', ?)
               ON CONFLICT(name) DO UPDATE SET value=excluded.value""",
            (max_measure,))
        # 旧表已被事件取代，迁移成功后移除；失败则整笔回滚，旧数据原样保留
        self.conn.execute("DROP TABLE IF EXISTS records")
        self.conn.execute("DROP TABLE IF EXISTS items")

    # ------------------------------------------------------------- folds
    @staticmethod
    def _fold_rows(rows: List[sqlite3.Row]):
        """把一个事故的事件流折叠成当前事故视图、措施列表和计数器最大值。"""
        incident: Optional[Dict[str, Any]] = None
        measures: Dict[int, Dict[str, Any]] = {}
        max_incident = 0
        max_measure = 0
        for row in rows:
            incident_id = row["incident_id"]
            version = row["version"]
            payload = json.loads(row["payload"])
            max_incident = max(max_incident, incident_id)
            if row["event_type"] == EVENT_REGISTERED:
                incident = {
                    "incident_id": incident_id,
                    "title": payload["title"],
                    "description": payload["description"],
                    "severity": payload["severity"],
                    "quantity": payload["quantity"],
                    "threshold": payload["threshold"],
                    "status": STATES[0],
                    "version": version,
                    "external_ref": payload["external_ref"],
                    "created_by": row["actor"],
                    "created_at": row["created_at"],
                    "updated_at": row["created_at"],
                }
            elif row["event_type"] == EVENT_MEASURE_ADDED:
                measure_id = int(payload["measure_id"])
                max_measure = max(max_measure, measure_id)
                measures[measure_id] = {
                    "measure_id": measure_id,
                    "incident_id": incident_id,
                    "kind": payload["kind"],
                    "detail": payload["detail"],
                    "status": payload.get("status", "open"),
                    "external_ref": payload["external_ref"],
                    "created_by": row["actor"],
                    "created_at": row["created_at"],
                }
                if incident is not None:
                    incident["updated_at"] = row["created_at"]
            elif row["event_type"] == EVENT_STATUS_ADVANCED:
                if incident is not None:
                    incident["status"] = payload["to_status"]
                    incident["version"] = version
                    incident["updated_at"] = row["created_at"]
        return incident, list(measures.values()), max_incident, max_measure

    def _restore_views_locked(self) -> None:
        """清空并从原事件重建事故与措施视图（写入失败/重启后的恢复路径）。"""
        self.conn.execute("DELETE FROM measures")
        self.conn.execute("DELETE FROM incidents")
        max_incident = 0
        max_measure = 0
        rows = self.conn.execute(
            "SELECT * FROM incident_events ORDER BY incident_id, event_seq"
        ).fetchall()
        grouped: Dict[int, List[sqlite3.Row]] = {}
        for row in rows:
            grouped.setdefault(row["incident_id"], []).append(row)
        for incident_id, ev_rows in grouped.items():
            incident, measures, mi, mm = self._fold_rows(ev_rows)
            max_incident = max(max_incident, mi)
            max_measure = max(max_measure, mm)
            if incident is None:
                continue
            self.conn.execute(
                """INSERT INTO incidents(incident_id, title, description, severity,
                   quantity, threshold, status, version, external_ref, created_by,
                   created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (incident["incident_id"], incident["title"], incident["description"],
                 incident["severity"], incident["quantity"], incident["threshold"],
                 incident["status"], incident["version"], incident["external_ref"],
                 incident["created_by"], incident["created_at"],
                 incident["updated_at"]),
            )
            for m in measures:
                self.conn.execute(
                    """INSERT INTO measures(measure_id, incident_id, kind, detail,
                       status, external_ref, created_by, created_at)
                       VALUES(?,?,?,?,?,?,?,?)""",
                    (m["measure_id"], m["incident_id"], m["kind"], m["detail"],
                     m["status"], m["external_ref"], m["created_by"], m["created_at"]),
                )
        self.conn.execute(
            """INSERT INTO counters(name, value) VALUES('incident_id', ?)
               ON CONFLICT(name) DO UPDATE SET
                   value=CASE WHEN excluded.value > counters.value
                              THEN excluded.value ELSE counters.value END""",
            (max_incident,))
        self.conn.execute(
            """INSERT INTO counters(name, value) VALUES('measure_id', ?)
               ON CONFLICT(name) DO UPDATE SET
                   value=CASE WHEN excluded.value > counters.value
                              THEN excluded.value ELSE counters.value END""",
            (max_measure,))

    def restore_views(self) -> None:
        """对外恢复入口：丢弃可疑当前视图，完全由原事件重新整理。"""
        with self._lock, self.conn:
            self._restore_views_locked()

    # ------------------------------------------------------------- helpers
    def _next_id_locked(self, name: str) -> int:
        row = self.conn.execute(
            """INSERT INTO counters(name, value) VALUES(?, 1)
               ON CONFLICT(name) DO UPDATE SET value=counters.value+1
               RETURNING value""", (name,),
        ).fetchone()
        return int(row["value"])

    def _insert_audit_locked(self, action: str, entity_type: str, entity_id: int,
                             actor: str, detail: dict, created_at: Optional[str] = None) -> int:
        row = self.conn.execute(
            "SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        previous = row["entry_hash"] if row else "GENESIS"
        event = make_entry(action, entity_type, entity_id, actor, detail, previous)
        if created_at is not None:
            event["created_at"] = created_at
        cur = self.conn.execute(
            """INSERT INTO audit_events(action, entity_type, entity_id, actor, detail,
               previous_hash, entry_hash, created_at) VALUES(?,?,?,?,?,?,?,?)""",
            (event["action"], event["entity_type"], event["entity_id"], event["actor"],
             json.dumps(event["detail"], ensure_ascii=False, sort_keys=True),
             event["previous_hash"], event["entry_hash"], event["created_at"]),
        )
        return int(cur.lastrowid)

    def _append_event_locked(self, incident_id: int, version: int, op_no: str,
                             event_type: str, payload: dict, actor: str,
                             created_at: str) -> int:
        cur = self.conn.execute(
            """INSERT INTO incident_events(incident_id, version, op_no, event_type,
               payload, actor, created_at) VALUES(?,?,?,?,?,?,?)""",
            (incident_id, version, op_no, event_type,
             json.dumps(payload, ensure_ascii=False, sort_keys=True),
             actor, created_at),
        )
        return int(cur.lastrowid)

    def _project_incident_locked(self, incident_id: int) -> None:
        """重新折叠单个事故并把结果写回投影（投影只由事件派生）。"""
        rows = self.conn.execute(
            "SELECT * FROM incident_events WHERE incident_id=? ORDER BY event_seq",
            (incident_id,),
        ).fetchall()
        incident, measures, _, _ = self._fold_rows(rows)
        self.conn.execute("DELETE FROM measures WHERE incident_id=?", (incident_id,))
        self.conn.execute("DELETE FROM incidents WHERE incident_id=?", (incident_id,))
        if incident is not None:
            self.conn.execute(
                """INSERT INTO incidents(incident_id, title, description, severity,
                   quantity, threshold, status, version, external_ref, created_by,
                   created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (incident["incident_id"], incident["title"], incident["description"],
                 incident["severity"], incident["quantity"], incident["threshold"],
                 incident["status"], incident["version"], incident["external_ref"],
                 incident["created_by"], incident["created_at"],
                 incident["updated_at"]),
            )
            for m in measures:
                self.conn.execute(
                    """INSERT INTO measures(measure_id, incident_id, kind, detail,
                       status, external_ref, created_by, created_at)
                       VALUES(?,?,?,?,?,?,?,?)""",
                    (m["measure_id"], m["incident_id"], m["kind"], m["detail"],
                     m["status"], m["external_ref"], m["created_by"], m["created_at"]),
                )

    def get_event_by_op(self, op_no: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM incident_events WHERE op_no=?", (op_no,)
            ).fetchone()
        if row is None:
            return None
        event = dict(row)
        event["payload"] = json.loads(event["payload"])
        return event

    # ------------------------------------------------------------- writes
    def create_item(self, title: str, description: str, severity: str,
                    quantity: float, threshold: float, external_ref: Optional[str],
                    actor: str, op_no: Optional[str] = None) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            op_no = op_no or f"op:{uuid.uuid4().hex}"
            if external_ref is not None:
                dup = self.conn.execute(
                    "SELECT 1 FROM incidents WHERE external_ref=?",
                    (external_ref,),
                ).fetchone()
                if dup is not None:
                    raise ConflictError("external_ref已存在")
            incident_id = self._next_id_locked("incident_id")
            payload = {
                "title": title, "description": description, "severity": severity,
                "quantity": quantity, "threshold": threshold,
                "external_ref": external_ref,
            }
            try:
                self._append_event_locked(
                    incident_id, 1, op_no, EVENT_REGISTERED, payload, actor, now)
            except sqlite3.IntegrityError as exc:
                raise ConflictError("操作号冲突或external_ref已存在") from exc
            self._insert_audit_locked("create", ENTITY, incident_id, actor, {
                "title": title, "severity": severity, "quantity": quantity,
                "priority": priority_score(severity, quantity, threshold),
                "op_no": op_no,
            }, now)
            self._project_incident_locked(incident_id)
        return self.get_item(incident_id)

    def add_record(self, item_id: int, kind: str, detail: str, status: str,
                   external_ref: Optional[str], actor: str,
                   op_no: Optional[str] = None) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            current = self.get_item(item_id)
            op_no = op_no or f"op:{uuid.uuid4().hex}"
            if external_ref is not None:
                dup = self.conn.execute(
                    "SELECT 1 FROM measures WHERE incident_id=? AND external_ref=?",
                    (item_id, external_ref),
                ).fetchone()
                if dup is not None:
                    raise ConflictError("记录唯一标识已存在")
            measure_id = self._next_id_locked("measure_id")
            # 措施事件沿用事故当前状态版本，不推进版本号
            version = int(current["version"])
            payload = {
                "measure_id": measure_id, "kind": kind, "detail": detail,
                "status": status, "external_ref": external_ref,
            }
            try:
                self._append_event_locked(
                    item_id, version, op_no, EVENT_MEASURE_ADDED, payload, actor, now)
            except sqlite3.IntegrityError as exc:
                raise ConflictError("操作号冲突或记录唯一标识已存在") from exc
            self._insert_audit_locked("record", ENTITY, item_id, actor, {
                "record_id": measure_id, "kind": kind, "status": status,
                "op_no": op_no,
            }, now)
            self._project_incident_locked(item_id)
        return self.get_measure(measure_id)

    def transition_item(self, item_id: int, target: str, expected_version: int,
                        actor: str, op_no: Optional[str] = None) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            current = self.get_item(item_id)
            if int(current["version"]) != int(expected_version):
                raise ConflictError("版本冲突，请刷新后重试",
                                    current_version=int(current["version"]))
            op_no = op_no or f"op:{uuid.uuid4().hex}"
            new_version = int(current["version"]) + 1
            payload = {"from_status": current["status"], "to_status": target}
            try:
                self._append_event_locked(
                    item_id, new_version, op_no, EVENT_STATUS_ADVANCED,
                    payload, actor, now)
            except sqlite3.IntegrityError as exc:
                raise ConflictError("操作号冲突或状态已被推进",
                                    current_version=int(current["version"])) from exc
            self._insert_audit_locked("transition", ENTITY, item_id, actor, {
                "from": current["status"], "to": target,
                "escalation_required": escalation_required(
                    current["severity"], current["quantity"], current["threshold"]),
                "op_no": op_no,
            }, now)
            self._project_incident_locked(item_id)
        return self.get_item(item_id)

    # ------------------------------------------------------------- reads
    def get_item(self, item_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM incidents WHERE incident_id=?", (item_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError("项目不存在")
        return _incident_from_row(row)

    def list_items(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM incidents"
        params: tuple = ()
        if status:
            sql += " WHERE status=?"
            params = (status,)
        sql += " ORDER BY incident_id DESC"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [_incident_from_row(row) for row in rows]

    def get_measure(self, measure_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM measures WHERE measure_id=?", (measure_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError("措施不存在")
        return _measure_from_row(row)

    def list_records(self, item_id: int) -> List[Dict[str, Any]]:
        self.get_item(item_id)
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM measures WHERE incident_id=? ORDER BY measure_id",
                (item_id,),
            ).fetchall()
        return [_measure_from_row(row) for row in rows]

    def open_record_count(self, item_id: int) -> int:
        with self._lock:
            row = self.conn.execute(
                "SELECT COUNT(*) AS n FROM measures WHERE incident_id=? AND status='open'",
                (item_id,),
            ).fetchone()
        return int(row["n"])

    def list_events(self, item_id: Optional[int] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM incident_events"
        params: tuple = ()
        if item_id is not None:
            sql += " WHERE incident_id=?"
            params = (item_id,)
        sql += " ORDER BY event_seq"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        result = []
        for row in rows:
            event = dict(row)
            event["payload"] = json.loads(event["payload"])
            result.append(event)
        return result

    # ------------------------------------------------------------- audit
    def append_audit(self, action: str, entity_type: str, entity_id: int,
                     actor: str, detail: dict) -> Dict[str, Any]:
        with self._lock, self.conn:
            event_id = self._insert_audit_locked(
                action, entity_type, entity_id, actor, detail)
            row = self.conn.execute(
                "SELECT * FROM audit_events WHERE id=?", (event_id,)).fetchone()
        item = dict(row)
        item["detail"] = json.loads(item["detail"])
        return item

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
