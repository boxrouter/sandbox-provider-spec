# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Metadata reserves cleanup before an E2B SDK create readiness wait."""

from types import SimpleNamespace

import pytest
from e2b import Sandbox, SandboxQuery, Secret, SecretException, Volume, VolumeException
from e2b.api.client.api.templates import delete_templates_template_id, get_templates_template_id
from e2b.template_sync import main as builder

from sandbox_provider_spec.driver import NativeFailure, Resource
from sandbox_provider_spec.drivers import e2b as native
from sandbox_provider_spec.runner import Runner
from sandbox_provider_spec.suite import Test as Scenario


@pytest.fixture(autouse=True)
def settle_clock(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    clock = [0.0]
    monkeypatch.setattr("sandbox_provider_spec.driver.time.monotonic", lambda: clock[0])
    monkeypatch.setattr(
        "sandbox_provider_spec.driver.time.sleep",
        lambda seconds: clock.__setitem__(0, clock[0] + seconds),
    )
    return clock


def test_readiness_failure_deletes_only_the_reserved_allocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    present: dict[str, str] = {"foreign": "another-run"}

    def create(**options: object) -> None:
        metadata = options["metadata"]
        assert isinstance(metadata, dict)
        present["owned"] = metadata["sps.run"]
        raise RuntimeError("readiness failed after native allocation")

    class Page:
        def __init__(self, query: SandboxQuery) -> None:
            assert query.metadata is not None
            self.marker = query.metadata["sps.run"]
            self.has_next = True

        def next_items(self) -> list[SimpleNamespace]:
            self.has_next = False
            return [
                SimpleNamespace(sandbox_id=identity)
                for identity, marker in present.items()
                if marker == self.marker
            ]

    def listing(*, query: SandboxQuery, request_timeout: int) -> Page:
        del request_timeout
        return Page(query)

    def kill(*, sandbox_id: str, request_timeout: int) -> None:
        del request_timeout
        assert sandbox_id == "owned"
        del present[sandbox_id]

    monkeypatch.setattr(Sandbox, "create", create)
    monkeypatch.setattr(Sandbox, "list", listing)
    monkeypatch.setattr(Sandbox, "kill", kill)
    result = Runner(native.E2BDriver()).run_test(
        Scenario("create", "readiness failure", ({"op": "create"},), ())
    )
    assert result["result"] == "error"
    assert result["cleanup"] == [{"kind": "sandbox", "result": "deleted"}]
    assert present == {"foreign": "another-run"}


def test_unreturned_create_is_released_only_after_complete_settled_listing(
    monkeypatch: pytest.MonkeyPatch,
    settle_clock: list[float],
) -> None:
    def create(**options: object) -> None:
        del options
        raise TimeoutError("the native create may still be completing")

    class Page:
        has_next = True

        def next_items(self) -> list[object]:
            self.has_next = False
            return []

    monkeypatch.setattr(Sandbox, "create", create)

    def listing(**options: object) -> Page:
        assert settle_clock[0] >= 120
        query = options["query"]
        assert isinstance(query, SandboxQuery) and query.metadata
        return Page()

    monkeypatch.setattr(Sandbox, "list", listing)
    result = Runner(native.E2BDriver()).run_test(
        Scenario("create", "uncertain timeout", ({"op": "create"},), ())
    )
    assert result["result"] == "error"
    assert result["cleanup"] == [{"kind": "sandbox", "result": "already_released"}]
    assert settle_clock[0] == 120


def test_failed_template_build_deletes_captured_id_and_checks_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Exercise the pinned SDK callback before failing its build readiness path.
    monkeypatch.setattr(builder, "get_api_client", lambda config: object())
    monkeypatch.setattr(native, "get_api_client", lambda config: object())
    present = {"owned-template", "foreign-template"}
    monkeypatch.setattr(
        builder,
        "request_build",
        lambda *args, **kwargs: SimpleNamespace(
            template_id="owned-template", build_id="owned-build", tags=[]
        ),
    )

    def trigger(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise RuntimeError("build failed after native allocation")

    def delete(identity: str, **options: object) -> SimpleNamespace:
        del options
        assert identity == "owned-template"
        present.remove(identity)
        return SimpleNamespace(status_code=204)

    def lookup(identity: str, **options: object) -> SimpleNamespace:
        del options
        return SimpleNamespace(status_code=200 if identity in present else 404)

    monkeypatch.setattr(builder, "trigger_build", trigger)
    monkeypatch.setattr(delete_templates_template_id, "sync_detailed", delete)
    monkeypatch.setattr(get_templates_template_id, "sync_detailed", lookup)
    result = Runner(native.E2BDriver()).run_test(
        Scenario(
            "template",
            "failed build",
            ({"op": "image.prepare", "in": {"source": "oci", "image": "python:3.12-slim"}},),
            (),
        )
    )
    assert result["result"] == "error"
    assert result["cleanup"] == [{"kind": "template", "result": "deleted"}]
    assert present == {"foreign-template"}


@pytest.mark.parametrize(
    ("message", "expected"),
    [("403: use of volumes is not enabled", "not_run"), ("403: forbidden", "error")],
)
def test_only_explicit_volume_entitlement_response_is_not_run(
    monkeypatch: pytest.MonkeyPatch,
    message: str,
    expected: str,
) -> None:
    def create(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise VolumeException(message)

    monkeypatch.setattr(Volume, "create", create)
    monkeypatch.setattr(Volume, "list", lambda **options: [])
    result = Runner(native.E2BDriver()).run_test(
        Scenario("volume", "entitlement", ({"op": "volume.create"},), ())
    )
    assert result["result"] == expected
    assert result["cleanup"] == [{"kind": "volume", "result": "deleted"}]
    if expected == "not_run":
        assert result["reason"] == "account_volumes_not_enabled"


@pytest.mark.parametrize(
    "message,expected",
    [("403: Secrets are not available for this team", "not_run"), ("403: forbidden", "error")],
)
def test_secret_account_refusal_is_not_an_uncertain_allocation(
    monkeypatch: pytest.MonkeyPatch, message: str, expected: str
) -> None:
    def create(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise SecretException(message)

    monkeypatch.setattr(Secret, "create", create)
    monkeypatch.setattr(
        Secret, "destroy", lambda **kwargs: (_ for _ in ()).throw(RuntimeError("unconfirmed"))
    )
    result = Runner(native.E2BDriver()).run_test(
        Scenario("secret", "refused", ({"op": "secret.create", "in": {"value": "sensitive"}},), ())
    )
    assert result["result"] == expected
    if expected == "not_run":
        assert result["reason"] == "account_secrets_not_available"
        assert result["cleanup"] == [{"kind": "secret_reservation", "result": "already_released"}]
    else:
        assert result["cleanup"][0]["result"] == "error"  # type: ignore[index]
    assert "sensitive" not in str(result)


@pytest.mark.parametrize("fails", [False, True])
def test_settled_native_absence_requires_every_page_and_success(
    monkeypatch: pytest.MonkeyPatch, fails: bool, settle_clock: list[float]
) -> None:
    calls: list[int] = []

    def create(**options: object) -> None:
        assert isinstance(options["metadata"], dict)
        raise TimeoutError("create returned no identity")

    class Pages:
        page = 0
        has_next = True

        def next_items(self) -> list[object]:
            assert settle_clock[0] >= 120
            self.page += 1
            calls.append(self.page)
            if fails and self.page == 2:
                raise RuntimeError("native list failed")
            self.has_next = self.page < 3
            return []

    monkeypatch.setattr(Sandbox, "create", create)
    monkeypatch.setattr(Sandbox, "list", lambda **options: Pages())
    result = Runner(native.E2BDriver()).run_test(
        Scenario("create", "complete settled listing", ({"op": "create"},), ())
    )
    assert result["result"] == "error"
    if fails:
        assert result["cleanup"] == [
            {"kind": "sandbox", "result": "error", "reason": "RuntimeError"}
        ]
        assert calls == [1, 2]
    else:
        assert result["cleanup"] == [{"kind": "sandbox", "result": "already_released"}]
        assert calls == [1, 2, 3, 1, 2, 3]


def test_unsettled_absence_does_not_release_a_reservation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Sandbox, "list", lambda **options: SimpleNamespace(has_next=False))
    with pytest.raises(NativeFailure, match="allocation_identity_unavailable"):
        native.E2BDriver._delete_reserved("owned-marker")  # pylint: disable=protected-access


def test_native_bytearray_read_preserves_every_byte() -> None:
    data = bytearray(range(256))

    class Files:
        def read(self, path: str, *, format: str, request_timeout: int) -> bytearray:
            assert (path, format, request_timeout) == ("/tmp/probe", "bytes", 30)
            return data

    driver = native.E2BDriver()
    box = {"resource": Resource("sandbox", SimpleNamespace(files=Files()), lambda: {})}
    result = driver.call("files.read_bytes", box, {"path": "/tmp/probe"})
    assert type(result["data"]) is bytes
    assert result["data"] == bytes(range(256))


@pytest.mark.parametrize("operation", ["create", "network.update"])
def test_domain_deny_is_unsupported_before_native_allocation_or_update(
    monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    def unexpected(**options: object) -> None:
        del options
        pytest.fail("domain deny must not reach the native mutation")

    monkeypatch.setattr(Sandbox, "create", unexpected)
    driver = native.E2BDriver()
    inputs: dict[str, object] = {"policy": "denylist_domains", "deny": ["example.com"]}
    if operation == "create":
        inputs = {"requirements": {"network_lockdown": inputs}}
    result = Runner(driver).run_test(
        Scenario("domains", "audited native absence", ({"op": operation, "in": inputs},), ())
    )
    assert result["result"] == "unsupported"
    assert result["cleanup"] == []
    assert not driver.resources
