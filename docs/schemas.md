# Schemas

JSON schemas live in `schemas/` and are referenced by artefact writers and validators.

| Schema | File | Purpose |
|---|---|---|
| Directive | `schemas/directive.schema.json` | Remediation directive `EWD-DNNN` |
| Finding | `schemas/finding.schema.json` | Single finding with evidence |
| Platform | `schemas/platform.schema.json` | Target platform enumeration |
| Proposal | `schemas/proposal.schema.json` | Capability proposal `EWP-NNN` |
| Store compliance | `schemas/store-compliance.schema.json` | Microsoft Store checks |

Schemas use JSON Schema draft 2020-12 (`$schema: https://json-schema.org/draft/2020-12/schema`) with `$id: https://edwardian.dev/schemas/<name>.schema.json`.

## Directive schema

Required: `id`, `priority`, `objective`, `evidence_ids`, `affected_components`, `current_state`, `target_state`, `remediation`, `validation_plan`, `dependencies`. `additionalProperties: false`.

- `id`: `^EWD-D[0-9]{3}$`
- `priority`: `P0`, `P1`, `P2`, `P3`
- `evidence_ids`: array of `^EWD-[0-9]{5}$`, `minItems: 1`
- `current_state`, `target_state`: `portable`, `windows-compatible`, `configurable`, `adaptable`, `replaceable`, `requires-implementation`, `architecturally-incompatible`, `unknown`
- `remediation`: non-empty string (often seeded from the top-ranked alternative)
- `validation_plan`: array of non-empty strings; P0 directives must have at least 3 steps (enforced by the `validate` command, not the schema itself)
- `dependencies`: array of `EWD-D` IDs

## Finding schema

A finding carries `id` (`FND-NNNNN`), `evidence` (array of Evidence with `id` `EWD-NNNNN`, `source`, `location` with `path`, `line`, `column`, `observation`, `confidence` 0.0–1.0, `detector`), `dependency` (PlatformDependency), `state` (CompatibilityState), `severity` (Info, Minor, Major, Blocker), `description`, and `remediation_hint`.

## Platform schema

Enumerates `linux`, `windows`, `macos`, `freebsd`, `openbsd`, `android`, `ios`, `wasm` (kebab-case, matching `Platform` serde renames).

## Proposal schema

Fields: `id` (`EWP-NNN`), `capability` (`fs-watch` today), `current_impl`, `required_impl`, `recommended_architecture`, `required_interface`, `compatibility_invariant`, `estimated_effort_days`, `risk`, `state` (`analysed`, `recommended`, `implemented`, `compiles`, `tested`, `validated`).

## Store compliance schema

Advisory Microsoft Store checks. Never affects `ReadinessReport`. Returned by `edwardian store` and embedded in `analyse`/`export` outputs.

## Using schemas

Validate artefacts after `export`:

```bash
edwardian --out ./out export
python3 -c "
import json, jsonschema, pathlib
for p in pathlib.Path('out/edwardian').glob('*.json'):
    data = json.loads(p.read_text())
    print(p.name, type(data).__name__)
"
# With a validator that supports 2020-12:
# jsonschema -i out/edwardian/directives.json schemas/directive.schema.json
```

Or in Rust via `schemars` / `jsonschema` crates if added as dev dependencies.

## Versioning

Schemas are part of the workspace version (`VERSION` file, bumped by `kaptaind`). Breaking schema changes are a minor version bump per `kaptaind.toml` `version_thresholds` (`minor = 0.6`).
