# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
import re
import time

import pytest

from sandbox_provider_spec import run_id


@pytest.fixture(autouse=True)
def fresh_run(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(run_id, "_RUN", None)
    monkeypatch.delenv(run_id.ENVIRONMENT, raising=False)
    monkeypatch.delenv("SPS_LANE", raising=False)


def test_the_environment_fixes_the_run_id(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(run_id.ENVIRONMENT, "shared-accounts-1")
    assert run_id.run_id() == "shared-accounts-1"


def test_a_generated_run_id_names_the_lane_the_time_and_stays_fixed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SPS_LANE", "latency")
    generated = run_id.run_id()
    assert re.fullmatch(r"latency-\d{8}T\d{6}Z-[0-9a-f]{4}", generated)
    assert run_id.run_id() == generated


def test_names_carry_the_run_and_its_creation_time(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(run_id.ENVIRONMENT, "a")
    name = run_id.native_name(16, middle="V16")
    assert re.fullmatch(r"sps-r[0-9a-f]{8}-[0-9a-z]{5}-V16-[0-9a-f]{16}", name)
    assert run_id.own_run(name)
    assert not run_id.stale(name, 7200)
    created = run_id.created_by_a_run(name)
    assert created is not None and abs(created[1] - time.time()) < 120
    monkeypatch.setattr(run_id, "_RUN", "b")
    assert not run_id.own_run(name)
    assert run_id.native_name() != run_id.native_name()


def test_only_a_stale_run_name_is_stale() -> None:
    now = time.time()
    old = run_id.native_name()
    assert run_id.stale(old, 7200, now=now + 7300)
    assert not run_id.stale(old, 7200, now=now + 3600)
    # Resources no run of this suite made are never stale, however old.
    for foreign in ("sps-" + "a" * 32, "sps-example", "customer-sandbox", "xsps-r00000000-00000-a"):
        assert not run_id.stale(foreign, 0, now=now + 10**9)
        assert run_id.created_by_a_run(foreign) is None
