# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The `Provider` base class: the 1.0 operations, one method for each."""

from __future__ import annotations

import sys
from abc import ABC, abstractmethod
from collections.abc import AsyncIterable, Mapping
from importlib.resources import as_file, files
from types import MappingProxyType
from typing import Any, ClassVar

from jsonschema import Draft202012Validator

from sandbox_provider_spec.load import load
from sandbox_provider_spec.v1._spec_files import document
from sandbox_provider_spec.v1.errors import SpsError
from sandbox_provider_spec.v1.types import (
    Cost,
    CreateRequest,
    CredentialField,
    DestroyResult,
    Discovery,
    FileInfo,
    FileLink,
    FileLinkRequest,
    FileStream,
    OutputPage,
    PreviewLink,
    Process,
    ProcessStartRequest,
    RunRequest,
    RunResult,
    Sandbox,
    SandboxPage,
    TcpLink,
)

MANIFEST_NAME = "sps-provider.yaml"
MANIFEST_SCHEMA = "sps-provider.schema.json"


def _package_of(cls: type) -> str:
    """The Python package that holds the class: the module itself when it is a package."""
    module = sys.modules[cls.__module__]
    if hasattr(module, "__path__"):
        return module.__name__
    return module.__name__.rpartition(".")[0]


def read_manifest(package: str) -> dict[str, Any]:
    """Load and validate `sps-provider.yaml` from a Python package, without importing the code
    of any provider. Raises `ValueError` when the file is missing or invalid."""
    if not package:
        raise ValueError(f"{MANIFEST_NAME} must be inside a Python package, not a top-level module")
    try:
        resource = files(package).joinpath(MANIFEST_NAME)
        with as_file(resource) as path:
            manifest = load(path)
    except (FileNotFoundError, ModuleNotFoundError) as error:
        raise ValueError(f"package {package!r} has no {MANIFEST_NAME}") from error
    errors = sorted(
        Draft202012Validator(document(MANIFEST_SCHEMA)).iter_errors(manifest),
        key=lambda error: list(error.path),
    )
    if errors:
        details = "; ".join(
            f"{'/'.join(map(str, e.path)) or '(root)'}: {e.message}" for e in errors
        )
        raise ValueError(f"{package}/{MANIFEST_NAME} is not valid: {details}")
    assert isinstance(manifest, dict)
    return manifest


class Provider(ABC):  # pylint: disable=too-many-public-methods
    """A sandbox provider, as the 1.0 standard sees it.

    A subclass lives in a Python package that holds `sps-provider.yaml`. The facts in that file
    become the class attributes below when the subclass is defined, and a missing or invalid
    file fails the definition. A subclass that is only a client of some provider's API, with no
    manifest of its own, defines itself with `class Name(Provider, manifest=False)`.

    The adapter is async and keeps no state between calls other than HTTP clients. It receives
    its credentials only through its constructor, never from the environment.
    """

    provider_id: ClassVar[str]
    name: ClassVar[str]
    spec_version: ClassVar[str]  # "1.0"
    # Both are empty for a class defined with `manifest=False`.
    credential_fields: ClassVar[tuple[CredentialField, ...]] = ()
    api_domains: ClassVar[tuple[str, ...]] = ()  # every host name the adapter connects to

    def __init_subclass__(cls, *, manifest: bool = True, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if not manifest:
            return
        data = read_manifest(_package_of(cls))
        fields = tuple(
            CredentialField(
                name=item["name"],
                secret=item.get("secret", True),
                required=item.get("required", True),
                default=item.get("default"),
                description=item.get("description", ""),
            )
            for item in data["credential_fields"]
        )
        names = [item.name for item in fields]
        if len(names) != len(set(names)):
            raise ValueError(f"{MANIFEST_NAME} repeats a credential field name")
        cls.provider_id = data["provider_id"]
        cls.name = data["name"]
        cls.spec_version = data["spec_version"]
        cls.credential_fields = fields
        cls.api_domains = tuple(data["api_domains"])

    def __init__(self, credentials: Mapping[str, str]) -> None:
        """Raises SpsError("unauthenticated") when a declared field is missing or empty."""
        values: dict[str, str] = {}
        for item in type(self).credential_fields:
            value = credentials.get(item.name)
            if value is None or value == "":
                value = item.default
            if value is None or value == "":
                if item.required:
                    raise SpsError("unauthenticated", f"Credential field {item.name!r} is missing")
                continue
            values[item.name] = value
        self.credentials: Mapping[str, str] = MappingProxyType(values)

    def __repr__(self) -> str:
        return f"<{type(self).__name__} (credentials hidden)>"

    # Required operations

    @abstractmethod
    async def discovery(self) -> Discovery: ...

    @abstractmethod
    async def create(self, request: CreateRequest, *, idempotency_key: str) -> Sandbox: ...

    @abstractmethod
    async def get(self, sandbox_id: str) -> Sandbox: ...

    @abstractmethod
    async def list(
        self,
        *,
        labels: Mapping[str, str] | None = None,
        cursor: str | None = None,
        limit: int = 100,
    ) -> SandboxPage: ...

    @abstractmethod
    async def destroy(self, sandbox_id: str) -> DestroyResult: ...

    @abstractmethod
    async def run(self, sandbox_id: str, request: RunRequest) -> RunResult: ...

    @abstractmethod
    async def files_read(self, sandbox_id: str, path: str) -> FileStream: ...

    @abstractmethod
    async def files_write(
        self, sandbox_id: str, path: str, data: AsyncIterable[bytes], *, size: int
    ) -> FileInfo: ...

    @abstractmethod
    async def process_start(self, sandbox_id: str, request: ProcessStartRequest) -> Process: ...

    @abstractmethod
    async def process_output(
        self, sandbox_id: str, process_id: str, *, cursor: str | None = None, wait_ms: int = 0
    ) -> OutputPage: ...

    @abstractmethod
    async def cost(self, sandbox_id: str) -> Cost: ...

    # Optional operations. Each default refuses with `unsupported`; a provider overrides the
    # ones whose section it claims and the tester passes.

    def _unsupported(self, operation: str) -> SpsError:
        provider = getattr(type(self), "provider_id", type(self).__name__)
        return SpsError("unsupported", f"{provider} does not support {operation}")

    async def files_link(self, sandbox_id: str, request: FileLinkRequest) -> FileLink:
        raise self._unsupported("files.link")

    async def pause(self, sandbox_id: str) -> Sandbox:
        raise self._unsupported("pause")

    async def resume(self, sandbox_id: str) -> Sandbox:
        raise self._unsupported("resume")

    async def lifetime_extend(self, sandbox_id: str, seconds: int) -> Sandbox:
        raise self._unsupported("lifetime.extend")

    async def process_write_stdin(self, sandbox_id: str, process_id: str, data: bytes) -> None:
        raise self._unsupported("process.write_stdin")

    async def process_close_stdin(self, sandbox_id: str, process_id: str) -> None:
        raise self._unsupported("process.close_stdin")

    async def process_cancel(self, sandbox_id: str, process_id: str) -> None:
        raise self._unsupported("process.cancel")

    async def preview_link(self, sandbox_id: str, port: int) -> PreviewLink:
        raise self._unsupported("preview.link")

    async def tcp_link(self, sandbox_id: str, port: int) -> TcpLink:
        raise self._unsupported("tcp.link")

    async def aclose(self) -> None:
        """Release HTTP clients; the host calls it once when it is done with the adapter."""
        return None
