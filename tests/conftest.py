"""Shared test fixtures."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sentinelops.approval import ApprovalStore  # noqa: E402
from sentinelops.config import Settings  # noqa: E402
from sentinelops.db import Database  # noqa: E402
from sentinelops.guardrails.policy import load_policy  # noqa: E402
from sentinelops.guardrails.session import SessionStore  # noqa: E402
from sentinelops.vectorstore import VectorStore  # noqa: E402


@pytest.fixture
def policy():
    return load_policy(ROOT / "policy.yaml", ROOT / "policy.schema.json")


@pytest.fixture
def db():
    database = Database("sqlite:///:memory:")
    database.seed()
    yield database
    database.close()


@pytest.fixture
def approvals(db):
    return ApprovalStore(db)


@pytest.fixture
def sessions(policy):
    return SessionStore(
        safe=int(policy.t("session_safe")),
        lock_at=int(policy.t("session_lock")),
        decay=float(policy.t("session_decay_per_minute")),
        window=int(policy.t("window_turns")),
    )
