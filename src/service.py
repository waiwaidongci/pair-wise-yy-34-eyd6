from __future__ import annotations

from typing import Any, Dict, Optional

from .domain import (ConflictError, ensure_role, normalize_severity,
                     require_number, require_text)
from .repository import (EVENT_MEASURE_ADDED, EVENT_REGISTERED,
                         EVENT_STATUS_ADVANCED, Repository)
from .rules import (AUDIT_ROLES, CREATE_ROLES, ENTITY, RECORD_ROLES, TITLE,
                    VIEW_ROLES, completion_blockers, escalation_required,
                    priority_score, response_deadline_hours,
                    role_for_transition, validate_transition)


class Service:
    def __init__(self, repository: Repository):
        self.repository = repository

    def _view(self, role: str) -> None:
        ensure_role(role, VIEW_ROLES)

    @staticmethod
    def _op_no(value: Any) -> Optional[str]:
        if value is None:
            return None
        return require_text(value, "op_no", 100)

    def _replay(self, op_no: Optional[str], expected_type: str,
                incident_id: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """同一操作号重放沿用首次结果；操作号张冠李戴则报冲突。"""
        if not op_no:
            return None
        event = self.repository.get_event_by_op(op_no)
        if event is None:
            return None
        if event["event_type"] != expected_type:
            raise ConflictError("操作号已用于其他类型的操作")
        if incident_id is not None and int(event["incident_id"]) != int(incident_id):
            raise ConflictError("操作号已用于其他事故")
        payload = event["payload"]
        if expected_type == EVENT_MEASURE_ADDED:
            return self.repository.get_measure(int(payload["measure_id"]))
        return self.enrich(self.repository.get_item(int(event["incident_id"])))

    def create_item(self, payload: Dict[str, Any], actor: str, role: str,
                    op_no: Optional[str] = None) -> Dict[str, Any]:
        ensure_role(role, CREATE_ROLES)
        actor = require_text(actor, "actor", 100)
        op_no = self._op_no(op_no)
        replay = self._replay(op_no, EVENT_REGISTERED)
        if replay is not None:
            return replay
        title = require_text(payload.get("title"), "title", 200)
        description = require_text(payload.get("description"), "description")
        severity = normalize_severity(payload.get("severity"))
        quantity = require_number(payload.get("quantity", 0), "quantity")
        threshold = require_number(payload.get("threshold", 1), "threshold", 0.000001)
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        item = self.repository.create_item(title, description, severity, quantity,
                                           threshold, external_ref, actor, op_no)
        return self.enrich(item)

    def add_record(self, item_id: int, payload: Dict[str, Any], actor: str,
                   role: str, op_no: Optional[str] = None) -> Dict[str, Any]:
        ensure_role(role, RECORD_ROLES)
        actor = require_text(actor, "actor", 100)
        op_no = self._op_no(op_no)
        kind = require_text(payload.get("kind"), "kind", 100)
        detail = require_text(payload.get("detail"), "detail")
        status = payload.get("status", "open")
        if status not in ("open", "closed"):
            raise ValueError("status必须是open或closed")
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        replay = self._replay(op_no, EVENT_MEASURE_ADDED, item_id)
        if replay is not None:
            return replay
        return self.repository.add_record(item_id, kind, detail, status,
                                          external_ref, actor, op_no)

    def transition(self, item_id: int, target: str, expected_version: int,
                   actor: str, role: str, op_no: Optional[str] = None) -> Dict[str, Any]:
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        ensure_role(role, role_for_transition(target))
        if not isinstance(expected_version, int) or isinstance(expected_version, bool) \
                or expected_version < 1:
            raise ValueError("expected_version必须是正整数")
        op_no = self._op_no(op_no)
        replay = self._replay(op_no, EVENT_STATUS_ADVANCED, item_id)
        if replay is not None:
            return replay
        # 乐观并发：两人同时推进时先落账者为准，后者拿到新版本重新办理
        if int(item["version"]) != int(expected_version):
            raise ConflictError("版本冲突，请刷新后重试",
                                current_version=int(item["version"]))
        validate_transition(item["status"], target)
        blockers = completion_blockers(target, self.repository.open_record_count(item_id))
        if blockers:
            raise ConflictError("；".join(blockers))
        updated = self.repository.transition_item(
            item_id, target, expected_version, actor, op_no)
        return self.enrich(updated)

    def get_item(self, item_id: int, role: str) -> Dict[str, Any]:
        self._view(role)
        return self.enrich(self.repository.get_item(item_id))

    def list_items(self, role: str, status: Optional[str] = None) -> list:
        self._view(role)
        return [self.enrich(item) for item in self.repository.list_items(status)]

    def list_records(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_records(item_id)

    def audit(self, role: str, item_id: Optional[int] = None) -> list:
        ensure_role(role, AUDIT_ROLES)
        return self.repository.list_audit(item_id)

    @staticmethod
    def enrich(item: Dict[str, Any]) -> Dict[str, Any]:
        result = dict(item)
        result["priority"] = priority_score(
            item["severity"], item["quantity"], item["threshold"])
        result["deadline_hours"] = response_deadline_hours(
            item["severity"], item["quantity"], item["threshold"])
        result["escalation_required"] = escalation_required(
            item["severity"], item["quantity"], item["threshold"])
        return result
