# SPDX-FileCopyrightText: BoxRouter, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Locate provider declarations without importing provider SDKs.

SPS owns its in-repo provider declarations. External packages may register a declaration
through the entry point group
`sandbox_provider_spec.declarations`: the name is the provider, and the value is the import
name of the package directory that holds `declaration.yaml`, or one `declaration-<class>.yaml`
per class, beside its `reports/`. For example, in `pyproject.toml`:

    [project.entry-points."sandbox_provider_spec.declarations"]
    acme = "acme_sandbox"
"""

from __future__ import annotations

from importlib.metadata import Distribution, entry_points
from importlib.util import find_spec
from pathlib import Path

from sandbox_provider_spec.check import spec_dir

GROUP = "sandbox_provider_spec.declarations"


def _in_spec(name: str, filename: str) -> Path | None:
    """Find a declaration owned by SPS, from source or an installed wheel."""
    source = spec_dir().parent / "providers" / name / filename
    if not source.is_file():
        source = spec_dir() / "providers" / name / filename
    if source.is_file():
        return source
    return None


def _registered(provider: str) -> tuple[Distribution | None, str]:
    for entry in entry_points(group=GROUP):
        if entry.name == provider:
            return entry.dist, entry.value
    raise FileNotFoundError(f"no installed package registers a declaration for {provider}")


def _declarations(distribution: Distribution | None, package: str) -> dict[str, Path]:
    """The package's declaration files by file name, read from metadata where it lists them."""
    found: dict[str, Path] = {}
    if distribution is not None:
        for file in distribution.files or ():
            parent, _, name = str(file).rpartition("/")
            if parent == package and name.startswith("declaration") and name.endswith(".yaml"):
                found[name] = Path(str(distribution.locate_file(file)))
    if not found:
        # PEP 660 editable distributions may list only their .pth and metadata files.
        spec = find_spec(package)
        if spec and spec.origin:
            found = {path.name: path for path in Path(spec.origin).parent.glob("declaration*.yaml")}
    return found


def installed_declaration_path(provider: str, execution_class: str | None = None) -> Path:
    """Return the declaration an installed package registers for a provider and class.

    `None` or `default` selects `declaration.yaml`; any other class selects
    `declaration-<class>.yaml`. Package metadata avoids importing the package and its SDK.
    """
    wanted = (
        "declaration.yaml"
        if execution_class in (None, "default")
        else f"declaration-{execution_class}.yaml"
    )
    if in_spec := _in_spec(provider, wanted):
        return in_spec
    if provider == "docker-engine":
        raise FileNotFoundError("the docker-engine reference declaration is not installed")
    distribution, package = _registered(provider)
    found = _declarations(distribution, package)
    if wanted not in found:
        classes = sorted(
            "default" if name == "declaration.yaml" else name[len("declaration-") : -len(".yaml")]
            for name in found
        )
        raise ValueError(
            f"{provider} declaration class must be one of: {', '.join(classes) or 'none found'}"
        )
    return found[wanted]
