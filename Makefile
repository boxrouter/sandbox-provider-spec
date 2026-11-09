.PHONY: check check-declarations check-docs format lint write dist
UV := uv
RUN := $(UV) run --all-extras --group docs

# Every check CI runs. It needs no provider account or secret; uv fetches packages.
check:
	$(RUN) ruff format --check .
	$(RUN) ruff check .
	$(RUN) mypy
	$(RUN) pyright
	$(RUN) pylint src
	$(RUN) pytest
	$(RUN) sandbox-provider-spec check-catalog
	$(MAKE) check-declarations
	$(RUN) sandbox-provider-spec check-rules
	$(RUN) sandbox-provider-spec provider-assets
	$(MAKE) check-docs
	build=$$(mktemp -d); trap 'rm -rf "$$build"' EXIT HUP INT TERM; \
		$(UV) build --quiet --out-dir "$$build" && \
		$(UV) venv --quiet "$$build/venv" && \
		$(UV) pip install --quiet --python "$$build/venv/bin/python" \
			"$$build"/sandbox_provider_spec-*.whl && \
		$(RUN) python tools/check_docs.py --readme-examples \
			--cli "$$build/venv/bin/sandbox-provider-spec"

lint:
	$(RUN) ruff format --check .
	$(RUN) ruff check .
	$(RUN) mypy
	$(RUN) pyright
	$(RUN) pylint src

check-declarations:
	$(RUN) sandbox-provider-spec check providers/*/declaration*.yaml

check-docs:
	$(RUN) pymarkdown --config .pymarkdown.json scan --recurse \
		README.md CONTRIBUTING.md GOVERNANCE.md CHANGELOG.md docs spec
	$(RUN) python tools/check_docs.py --links --formats --readme-examples

format:
	$(RUN) ruff format .

# Regenerate spec/catalog.json from spec/catalog.yaml.
write:
	$(RUN) python tools/sync_catalog_descriptions.py
	$(RUN) python -c 'import json; from sandbox_provider_spec import load, spec_dir; \
		d = spec_dir(); \
		(d / "catalog.json").write_text(json.dumps(load(d / "catalog.yaml"), indent=2) + "\n", encoding="utf-8")'

# The release assets: the package, the compiled catalog, the schemas and registries.
# Stable releases also include provider declarations, brand.json and publication.json; release candidates omit them.
dist:
	$(MAKE) check-declarations
	rm -rf dist && mkdir dist
	$(UV) build --quiet --out-dir dist
	cp spec/catalog.json spec/*-schema.json spec/registries/*.json dist/
	version=$$(sed -n 's/^version = "\([^"]*\)"$$/\1/p' pyproject.toml); \
	case "$$version" in *rc*) echo "Omitting provider declarations from release candidate $$version" ;; \
	*) $(RUN) sandbox-provider-spec provider-assets --out dist; \
	for file in providers/*/declaration*.yaml; do \
		provider=$$(basename "$$(dirname "$$file")"); name=$$(basename "$$file" .yaml); \
		cp "$$file" "dist/declaration-$$provider$${name#declaration}.yaml"; \
	done ;; esac
