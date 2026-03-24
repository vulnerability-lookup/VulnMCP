# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

VulnMCP is an MCP (Model Context Protocol) server built with [FastMCP](https://github.com/jlowin/fastmcp) that exposes AI-driven vulnerability management tools. It provides modular "skills" (MCP tools) such as vulnerability severity classification using CIRCL's fine-tuned transformer models.

## Build & Development

- **Python**: Requires 3.10+
- **Package manager**: Poetry (v2+)
- **Install dependencies**: `poetry install`
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
- **CWE classification**: `CIRCL/cwe-parent-vulnerability-classification-roberta-base` — predicts parent CWE categories (26 classes). Uses `child_to_parent_mapping.json` for hierarchy mapping.

### Vulnerability Lookup API

The `vulnerability_lookup` skill queries the [Vulnerability Lookup](https://vulnerability.circl.lu) REST API. The base URL defaults to `https://vulnerability.circl.lu` and can be overridden via the `VULNMCP_LOOKUP_URL` environment variable. The CWE skill's `get_recent_vulnerabilities_by_cwe` tool also respects this setting.
