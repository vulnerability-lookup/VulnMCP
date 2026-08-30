# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

VulnMCP is an MCP (Model Context Protocol) server built with [FastMCP](https://github.com/jlowin/fastmcp) that exposes AI-driven vulnerability management tools. It provides modular "skills" (MCP tools) such as vulnerability severity classification using CIRCL's fine-tuned transformer models.

## Build & Development

- **Python**: Requires 3.10+
- **Package manager**: Poetry (v2+)
- **Install dependencies**: `poetry install` (CPU-only torch; use `poetry install --extras cuda` on GPU hosts)
- **Run the MCP server**: `poetry run vulnmcp` (defaults to stdio transport)
- **Run with specific transport**: `poetry run fastmcp run vulnmcp/server.py --transport http --port 9000`
- **Add a dependency**: `poetry add <package>`

## Architecture

The project follows a modular skills-based architecture where each domain capability is a self-contained skill module.

- **`vulnmcp/server.py`** — FastMCP server instance and `main()` entry point. Skills are registered here.
- **`vulnmcp/skills/`** — Each skill module exposes a `register(mcp)` function that decorates and registers MCP tools onto the server. New skills follow this same pattern.
- **`vulnmcp/models/`** — ML model wrappers. `classifier.py` provides `SeverityClassifier` and `CWEClassifier`, both lazy-loading Hugging Face pipelines on first use.
- **`vulnmcp/data/`** — Static data files (e.g. `child_to_parent_mapping.json` for CWE hierarchy). Loaded via `importlib.resources`.

### Adding a new skill

1. Create `vulnmcp/skills/my_skill.py` with a `register(mcp: FastMCP)` function.
2. Inside that function, define tools using `@mcp.tool`.
3. Import and call `my_skill.register(mcp)` in `server.py`.

### Models

All models are downloaded from Hugging Face Hub on first invocation and cached locally.

- **Severity (English)**: `CIRCL/vulnerability-severity-classification-roberta-base` — outputs `low`, `medium`, `high`, `critical`
- **Severity (Chinese)**: `CIRCL/vulnerability-severity-classification-chinese-macbert-base` — outputs `低`, `中`, `高` (mapped to English equivalents)
- **Severity (Russian)**: `CIRCL/vulnerability-severity-classification-russian-ruRoberta-large` — outputs `low`, `medium`, `high`, `critical`
- **CWE classification**: `CIRCL/cwe-parent-vulnerability-classification-roberta-base` — predicts parent CWE categories (26 classes). Uses `child_to_parent_mapping.json` for hierarchy mapping.
- **ATT&CK technique classification**: `CIRCL/vulnerability-attack-technique-classification-roberta-base` — multi-label prediction of MITRE ATT&CK (Enterprise) techniques (sigmoid per label; scores >= 0.5 are positive predictions, matching the trainer's F1 threshold). Trained with VulnTrain (`vulntrain-train-attack-classification`). Uses `attack_technique_names.json` (technique ID → name, extracted from the enterprise ATT&CK STIX bundle) for human-readable names.

#### CPU vs CUDA torch builds

No PEP 508 marker can detect a GPU, so the torch build is selected by extra. `pyproject.toml` declares two explicit Poetry sources (`pytorch-cpu`, `pytorch-cuda`) and binds them under `[tool.poetry.dependencies]` to three markers that partition the space exactly — every platform/extra combination matches exactly one branch:

| Marker | Source | Resolves to |
|---|---|---|
| `sys_platform == 'darwin'` | PyPI (default) | `torch 2.13.0` |
| `sys_platform != 'darwin' and extra != 'cuda'` | `pytorch-cpu` | `torch 2.13.0+cpu` |
| `sys_platform != 'darwin' and extra == 'cuda'` | `pytorch-cuda` | `torch 2.13.0+cu130` |

CPU is therefore the default for a bare `poetry install`; there is deliberately no `cpu` extra, since adding one would overlap the `extra != 'cuda'` branch. All three variants are pinned in `poetry.lock`.

macOS must be routed to PyPI: the `pytorch-cpu` index publishes no macOS wheels and no sdist, so a Darwin-matching branch pointing at it makes `poetry install` fail outright with "Unable to find installation candidates". PyPI's torch is CPU/MPS-only on macOS anyway, since no CUDA build exists for that platform — hence the Darwin branch ignores the extra entirely.

When changing these markers, verify the partition still holds rather than assuming: the branches must be mutually exclusive *and* exhaustive. An earlier attempt used a bare `extra == 'cuda'` for the CUDA branch, and Poetry widened it during locking to `extra == "cuda" or sys_platform == "darwin"`, which made two torch versions match on macOS. Check the emitted `markers` on each `torch` entry in `poetry.lock` after re-locking.

Note that `poetry sync` leaves empty `nvidia/`, `cuda/`, and `triton/` directories behind when switching from CUDA to CPU. Python treats those as implicit namespace packages, so `import triton` succeeds but yields an empty module and torch's dynamo fails with `module 'triton' has no attribute 'language'`. Delete the empty directories from `site-packages` if that happens.

### Vulnerability Lookup API

The `vulnerability_lookup` skill queries the [Vulnerability Lookup](https://vulnerability.circl.lu) REST API. The base URL defaults to `https://vulnerability.circl.lu` and can be overridden via the `VULNMCP_LOOKUP_URL` environment variable. The CWE skill's `get_recent_vulnerabilities_by_cwe` tool also respects this setting.
