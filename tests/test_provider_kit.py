# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The PP4 starter invents no optional gates and fails on invalid declarations."""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import sandbox_provider_spec
from sandbox_provider_spec import cli, starter
from sandbox_provider_spec.check import UNKNOWN_KEY, check_declaration, check_path
from sandbox_provider_spec.http_reference.test_backend import TestBackend as DeterministicBackend

ROOT = Path(__file__).resolve().parents[1]
GUIDE = ROOT / "docs/how-to/provider-kit.md"
DOCUMENTED_GENERATE = "sandbox-provider-spec scaffold --output declaration.yaml"
DOCUMENTED_CHECK = "sandbox-provider-spec check declaration.yaml"


def test_generated_starter_omits_optional_gates_and_passes_check(tmp_path: Path) -> None:
    path = tmp_path / "declaration.yaml"
    assert cli.main(["scaffold", "--output", str(path)]) == 0
    result = check_path(path)
    assert result.kind == "declaration"
    assert result.errors == []
    document = sandbox_provider_spec.load(path)
    assert document["gates"] == {}
    assert document["evidence"] == {}
    assert document["resources"] == {"kernel": "unknown"}
    catalog_gates = set(sandbox_provider_spec.load_catalog()["gates"])
    assert set(document["gates"]).isdisjoint(catalog_gates)
    assert "processes" not in document["gates"]
    assert "terminal" not in document["gates"]


def test_documented_generator_and_check_commands(tmp_path: Path) -> None:
    path = tmp_path / "declaration.yaml"
    generate = subprocess.run(
        [
            shutil.which("sandbox-provider-spec") or "sandbox-provider-spec",
            "scaffold",
            "--output",
            str(path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert generate.returncode == 0, generate.stderr
    checker = shutil.which("sandbox-provider-spec")
    assert checker is not None
    checked = subprocess.run(
        [checker, "check", str(path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert checked.returncode == 0, checked.stderr + checked.stdout
    assert f"{path}: ok\n" == checked.stdout


def test_guide_documents_the_generator_and_existing_check() -> None:
    text = GUIDE.read_text(encoding="utf-8")
    assert DOCUMENTED_GENERATE in text
    assert DOCUMENTED_CHECK in text
    assert "declaration self-assessment" in text
    assert "does not admit" in text.lower() or "not admission" in text.lower()


def test_guide_reuses_installed_http_reference_and_validator() -> None:
    text = GUIDE.read_text(encoding="utf-8")
    collapsed = " ".join(text.split())
    assert "Reuse the installed `sandbox_provider_spec.http_reference.Endpoint`" in collapsed
    assert "`sandbox_provider_spec.http_reference.Backend`" in text
    assert "`endpoint_origin`" in text
    assert "`sandbox_provider_spec.http_binding_validation`" in text
    assert "docs/http-binding-reference.md" in text
    assert "../http-binding-reference.md" in text
    assert "Do not copy the endpoint, schema, transport, or validator." in text


def test_guide_does_not_send_http_endpoints_to_the_spec_cli() -> None:
    """The guide keeps `run` native-only and routes HTTP reporting to the separate consumer.

    Wording that names the consumer or Kit is checked by test_public_neutrality, not here.
    """
    text = GUIDE.read_text(encoding="utf-8")
    collapsed = " ".join(text.split())
    assert "`sandbox-provider-spec run` is native-only" in collapsed
    assert "It does not accept an HTTP endpoint." in collapsed
    assert "The native CLI does not load that consumer or supply its HTTP client." in collapsed
    assert "[Run the HTTP conformance suites](run-http-conformance.md)" in collapsed
    assert "Keep HTTP SPS and Kit reports separate" in collapsed
    assert (
        "Constructing an `Endpoint` alone does not run conformance or produce a report."
        in collapsed
    )


def test_invented_optional_gate_fails_check() -> None:
    document = starter.starter_declaration()
    document["gates"] = {"processes": [{}]}
    errors = check_declaration(document).errors
    assert errors
    assert any("evidence is missing a citation for gates.processes.0" in error for error in errors)


def test_unknown_gate_fails_check() -> None:
    document = starter.starter_declaration()
    document["gates"] = {"made_up": "unsupported"}
    errors = check_declaration(document).errors
    assert any(error == f"{UNKNOWN_KEY}: gates.made_up" for error in errors)


def test_missing_required_field_fails_check() -> None:
    document = starter.starter_declaration()
    del document["spec"]
    errors = check_declaration(document).errors
    assert errors


def test_invalid_provider_is_rejected(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "declaration.yaml"
    assert cli.main(["scaffold", "--provider", "Acme Cloud", "--output", str(path)]) == 1
    assert "provider must match" in capsys.readouterr().err
    assert not path.exists()


def test_cli_check_accepts_the_generated_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "declaration.yaml"
    assert cli.main(["scaffold", "--output", str(path)]) == 0
    assert cli.main(["check", str(path)]) == 0
    assert "ok" in capsys.readouterr().out


HTTP_STARTER = ROOT / "examples/http-binding/starter.py"


class _StarterBackend(DeterministicBackend):
    """Fake backend with the 0.3 and buffered entry points; discovery never calls them."""

    def run_buffered(self, *args: object, **kwargs: object) -> dict[str, object]:
        raise AssertionError("starter profile tests never run commands")

    def offerings(self, account: str) -> list[dict[str, object]]:
        raise AssertionError("starter profile tests never list offerings")

    def create_admitted(self, *args: object, **kwargs: object) -> dict[str, object]:
        raise AssertionError("starter profile tests never create sandboxes")

    def observe_admitted(self, identity: dict[str, object]) -> dict[str, object]:
        raise AssertionError("starter profile tests never observe sandboxes")


def _starter_factory() -> _StarterBackend:
    return _StarterBackend()


def _starter_legacy_factory() -> DeterministicBackend:
    return DeterministicBackend()


def test_http_starter_03_without_admission_backend_has_clear_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _load_http_starter(monkeypatch, tmp_path, SPS_HTTP_BINDING_VERSION="0.3")
    monkeypatch.setenv("SPS_HTTP_BACKEND_FACTORY", f"{__name__}:_starter_legacy_factory")
    with pytest.raises(
        RuntimeError,
        match=r"Binding 0\.3 requires AdmissionBackend methods.*missing: offerings",
    ):
        module.create_application()  # type: ignore[attr-defined]


def _starter_tokens() -> dict[str, str]:
    return {"account-a": "token-a"}


def _load_http_starter(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, **env: str) -> object:
    values = {
        "SPS_HTTP_BACKEND_FACTORY": f"{__name__}:_starter_factory",
        "SPS_HTTP_ACCOUNT_TOKENS_FACTORY": f"{__name__}:_starter_tokens",
        "SPS_HTTP_STATE_PATH": str(tmp_path / "state.sqlite"),
        "SPS_HTTP_ENDPOINT_ORIGIN": "https://provider.example",
        **env,
    }
    for name in [key for key in os.environ if key.startswith("SPS_HTTP_")]:
        monkeypatch.delenv(name)
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    spec = importlib.util.spec_from_file_location("http_starter_under_test", HTTP_STARTER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_http_starter_03_publishes_core_observation_profile(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _load_http_starter(monkeypatch, tmp_path, SPS_HTTP_BINDING_VERSION="0.3")
    settings = module.application.settings  # type: ignore[attr-defined]
    assert settings.operation_timeout_ms == 60000
    assert settings.execution_ms == 60000
    assert settings.buffered_command_output_bytes == 16 * 1024 * 1024
    limits = module.application.discovery("account-a", include_offerings=False)  # type: ignore[attr-defined]
    assert limits["limits"]["observation_ms"] == 60000
    assert limits["limits"]["execution_ms"] == 60000
    module = _load_http_starter(
        monkeypatch,
        tmp_path,
        SPS_HTTP_BINDING_VERSION="0.3",
        SPS_HTTP_EXECUTION_MS="45000",
    )
    settings = module.application.settings  # type: ignore[attr-defined]
    assert settings.execution_ms == 45000
    assert settings.operation_timeout_ms == 60000


@pytest.mark.parametrize(
    ("env", "execution_ms"),
    [
        ({"SPS_HTTP_BINDING_VERSION": "0.1"}, None),
        ({}, None),
        ({"SPS_HTTP_BINDING_VERSION": "0.2", "SPS_HTTP_BUFFERED_COMMANDS": "1"}, 30000),
        ({"SPS_HTTP_BUFFERED_COMMANDS": "1"}, 30000),
    ],
)
def test_http_starter_legacy_profiles_keep_five_second_observation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, env: dict[str, str], execution_ms: int | None
) -> None:
    module = _load_http_starter(monkeypatch, tmp_path, **env)
    settings = module.application.settings  # type: ignore[attr-defined]
    assert settings.operation_timeout_ms == 5000
    assert settings.execution_ms == execution_ms


def test_installed_http_starter_import_reads_no_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in [key for key in os.environ if key.startswith("SPS_HTTP_")]:
        monkeypatch.delenv(name)
    sys.modules.pop("sandbox_provider_spec.http_reference.starter", None)
    module = importlib.import_module("sandbox_provider_spec.http_reference.starter")
    assert not hasattr(module, "application")
    with pytest.raises(RuntimeError, match="SPS_HTTP_BACKEND_FACTORY"):
        module.create_application()


def test_http_starter_example_wraps_installed_factory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _load_http_starter(monkeypatch, tmp_path, SPS_HTTP_BINDING_VERSION="0.3")
    installed = importlib.import_module("sandbox_provider_spec.http_reference.starter")
    assert module.create_application is installed.create_application  # type: ignore[attr-defined]
    assert module.application.settings.operation_timeout_ms == 60000  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("env", "timeout_ms", "execution_ms"),
    [
        ({"SPS_HTTP_BINDING_VERSION": "0.1"}, 5000, None),
        ({"SPS_HTTP_BINDING_VERSION": "0.2", "SPS_HTTP_BUFFERED_COMMANDS": "1"}, 5000, 30000),
        ({"SPS_HTTP_BINDING_VERSION": "0.3"}, 60000, 60000),
        ({"SPS_HTTP_BINDING_VERSION": "0.3", "SPS_HTTP_EXECUTION_MS": "45000"}, 60000, 45000),
    ],
)
def test_installed_http_starter_factory_profiles(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    env: dict[str, str],
    timeout_ms: int,
    execution_ms: int | None,
) -> None:
    for name in [key for key in os.environ if key.startswith("SPS_HTTP_")]:
        monkeypatch.delenv(name)
    values = {
        "SPS_HTTP_BACKEND_FACTORY": f"{__name__}:_starter_factory",
        "SPS_HTTP_ACCOUNT_TOKENS_FACTORY": f"{__name__}:_starter_tokens",
        "SPS_HTTP_STATE_PATH": str(tmp_path / "state.sqlite"),
        "SPS_HTTP_ENDPOINT_ORIGIN": "https://provider.example",
        **env,
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    installed = importlib.import_module("sandbox_provider_spec.http_reference.starter")
    application = installed.create_application()
    assert application.settings.operation_timeout_ms == timeout_ms
    assert application.settings.execution_ms == execution_ms
    limits = application.discovery("account-a", include_offerings=False)
    assert limits["limits"]["observation_ms"] == timeout_ms


def test_scaffold_never_overwrites_existing_declaration(tmp_path: Path) -> None:
    path = tmp_path / "declaration.yaml"
    path.write_text("existing evidence\n")
    assert cli.main(["scaffold", "--output", str(path)]) == 1
    assert path.read_text() == "existing evidence\n"
