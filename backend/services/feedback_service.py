from __future__ import annotations

import json
import os
from csv import writer
from dataclasses import dataclass
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from threading import Lock
from uuid import uuid4

from backend.models.scan_model import FeedbackItem, FeedbackRequest


@dataclass
class _FeedbackRecord:
    item: FeedbackItem


class FeedbackRateLimitError(Exception):
    pass


class FeedbackService:
    def __init__(self) -> None:
        self._items: list[_FeedbackRecord] = []
        self._lock = Lock()
        self._store_path = self._resolve_store_path()
        self._load_from_disk()

    @staticmethod
    def _resolve_store_path() -> Path:
        configured = str(os.getenv("FEEDBACK_STORE_PATH", "")).strip()
        if configured:
            return Path(configured).resolve()
        return (Path(__file__).resolve().parents[1] / "data" / "feedback.json").resolve()

    def _load_from_disk(self) -> None:
        if not self._store_path.exists():
            return

        try:
            payload = json.loads(self._store_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return

        if not isinstance(payload, list):
            return

        loaded: list[_FeedbackRecord] = []
        for raw in payload:
            try:
                item = FeedbackItem.model_validate(raw)
            except Exception:
                continue
            loaded.append(_FeedbackRecord(item=item))

        self._items = loaded

    def _persist_locked(self) -> None:
        self._store_path.parent.mkdir(parents=True, exist_ok=True)
        serializable = [record.item.model_dump(mode="json") for record in self._items]
        self._store_path.write_text(json.dumps(serializable, ensure_ascii=True, indent=2), encoding="utf-8")

    @staticmethod
    def _validate_submit_rate(items: list[_FeedbackRecord], email: str, payload: FeedbackRequest) -> None:
        now = datetime.now(timezone.utc)
        user_items = [record.item for record in items if record.item.email == email]

        if user_items:
            latest = max(user_items, key=lambda item: item.created_at)
            seconds_since_last = (now - latest.created_at).total_seconds()
            if seconds_since_last < 5:
                raise FeedbackRateLimitError("Please wait a few seconds before submitting another feedback entry")

        past_day = [item for item in user_items if (now - item.created_at).total_seconds() <= 86400]
        if len(past_day) >= 30:
            raise FeedbackRateLimitError("Daily feedback limit reached. Please try again tomorrow")

        for item in reversed(user_items[-20:]):
            if item.scan_id != payload.scan_id:
                continue
            if item.category != payload.category:
                continue
            if item.rating != payload.rating:
                continue
            if item.comment.strip().lower() != payload.comment.strip().lower():
                continue
            if (now - item.created_at).total_seconds() <= 600:
                raise FeedbackRateLimitError(
                    "Duplicate feedback detected for this scan. Please edit your comment and retry"
                )

    def submit(self, email: str, payload: FeedbackRequest) -> FeedbackItem:
        normalized_email = str(email or "").strip().lower()
        cleaned_comment = payload.comment.strip()

        item = FeedbackItem(
            feedback_id=uuid4().hex,
            email=normalized_email,
            scan_id=payload.scan_id,
            rating=payload.rating,
            category=payload.category,
            comment=cleaned_comment,
            issue_id=(payload.issue_id or "").strip() or None,
            created_at=datetime.now(timezone.utc),
        )

        with self._lock:
            self._validate_submit_rate(self._items, normalized_email, payload)
            self._items.append(_FeedbackRecord(item=item))
            self._persist_locked()
        return item

    def list_for_user(self, email: str) -> list[FeedbackItem]:
        normalized = str(email or "").strip().lower()
        with self._lock:
            items = [record.item for record in self._items if record.item.email == normalized]
        return sorted(items, key=lambda item: item.created_at, reverse=True)

    def list_filtered(
        self,
        *,
        category: str | None = None,
        min_rating: int | None = None,
        max_rating: int | None = None,
        scan_id: str | None = None,
        email: str | None = None,
        start_at: datetime | None = None,
        end_at: datetime | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[FeedbackItem]:
        with self._lock:
            items = [record.item for record in self._items]

        if category:
            category_filter = str(category).strip().lower()
            items = [item for item in items if str(item.category).lower() == category_filter]

        if min_rating is not None:
            items = [item for item in items if int(item.rating) >= int(min_rating)]

        if max_rating is not None:
            items = [item for item in items if int(item.rating) <= int(max_rating)]

        if scan_id:
            scan_filter = str(scan_id).strip()
            items = [item for item in items if item.scan_id == scan_filter]

        if email:
            email_filter = str(email).strip().lower()
            items = [item for item in items if item.email == email_filter]

        if start_at is not None:
            items = [item for item in items if item.created_at >= start_at]

        if end_at is not None:
            items = [item for item in items if item.created_at <= end_at]

        ordered = sorted(items, key=lambda item: item.created_at, reverse=True)
        start = max(0, int(offset or 0))
        end = start + max(1, int(limit or 1))
        return ordered[start:end]

    @staticmethod
    def export_csv(items: list[FeedbackItem]) -> str:
        output = StringIO()
        csv_writer = writer(output)
        csv_writer.writerow(["feedback_id", "email", "scan_id", "rating", "category", "comment", "issue_id", "created_at"])

        for item in items:
            csv_writer.writerow(
                [
                    item.feedback_id,
                    item.email,
                    item.scan_id,
                    item.rating,
                    item.category,
                    item.comment,
                    item.issue_id or "",
                    item.created_at.isoformat(),
                ]
            )

        return output.getvalue()


feedback_service = FeedbackService()
