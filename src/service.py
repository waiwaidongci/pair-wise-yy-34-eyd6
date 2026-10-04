from __future__ import annotations

from typing import Any, Dict, Optional

from .domain import ensure_role, normalize_severity, require_number, require_text
from .repository import Repository
from .rules import (AUDIT_ROLES, CREATE_ROLES, RECORD_ROLES, VIEW_ROLES,
                    completion_blockers, escalation_required, priority_score,
                    response_deadline_hours, role_for_transition, validate_transition)


class Service:
    def __init__(self, repository: Repository):
        self.repository = repository

    def _view(self, role: str) -> None:
        ensure_role(role, VIEW_ROLES)

    def create_item(self, payload: Dict[str, Any], actor: str, role: str,
                    op_id: Optional[str] = None) -> Dict[str, Any]:
        ensure_role(role, CREATE_ROLES)
        actor = require_text(actor, "actor", 100)
        op_id = op_id or payload.get("op_id")
        if op_id:
            replayed = self.repository.replay_result(op_id)
            if replayed is not None:
                return self.enrich(replayed)
        title = require_text(payload.get("title"), "title", 200)
        description = require_text(payload.get("description"), "description")
        severity = normalize_severity(payload.get("severity"))
        quantity = require_number(payload.get("quantity", 0), "quantity")
        threshold = require_number(payload.get("threshold", 1), "threshold", 0.000001)
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        op_id = op_id or payload.get("op_id")
        item = self.repository.create_item(
            title, description, severity, quantity, threshold, external_ref,
            actor, op_id)
        return self.enrich(item)

    def add_record(self, item_id: int, payload: Dict[str, Any], actor: str,
                   role: str, op_id: Optional[str] = None) -> Dict[str, Any]:
        ensure_role(role, RECORD_ROLES)
        actor = require_text(actor, "actor", 100)
        op_id = op_id or payload.get("op_id")
        if op_id:
            replayed = self.repository.replay_result(op_id)
            if replayed is not None:
                return replayed
        kind = require_text(payload.get("kind"), "kind", 100)
        detail = require_text(payload.get("detail"), "detail")
        status = payload.get("status", "open")
        if status not in ("open", "closed"):
            raise ValueError("status必须是open或closed")
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        op_id = op_id or payload.get("op_id")
        record = self.repository.add_record(
            item_id, kind, detail, status, external_ref, actor, op_id)
        return record

    def transition(self, item_id: int, target: str, expected_version: int,
                   actor: str, role: str, op_id: Optional[str] = None) -> Dict[str, Any]:
        actor = require_text(actor, "actor", 100)
        if op_id:
            replayed = self.repository.replay_result(op_id)
            if replayed is not None:
                return self.enrich(replayed)
        item = self.repository.get_item(item_id)
        validate_transition(item["status"], target)
        ensure_role(role, role_for_transition(target))
        if not isinstance(expected_version, int) or expected_version < 1:
            raise ValueError("expected_version必须是正整数")
        blockers = completion_blockers(target, self.repository.open_record_count(item_id))
        if blockers:
            from .domain import ConflictError
            raise ConflictError("；".join(blockers))
        updated = self.repository.transition_item(
            item_id, target, expected_version, actor, op_id)
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

    def events(self, role: str, entity_type: Optional[str] = None,
               entity_id: Optional[int] = None) -> list:
        ensure_role(role, AUDIT_ROLES)
        return self.repository.list_events(entity_type, entity_id)

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
