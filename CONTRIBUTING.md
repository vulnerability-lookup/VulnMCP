# Contributing to VulnMCP

Thank you for your interest in contributing.

## Experiment policy: AI-assisted contributions only

This repository is part of an experiment run by the Vulnerability-Lookup team to evaluate a development workflow where contributions are produced by computer-assisted systems (AI agents and related tooling).

For this experimental period:

- We only accept pull requests that are created with computer assistance.
- Pull requests that are fully manual (without AI/computer-assisted workflow) will be closed and not merged.

## What counts as computer-assisted?

Examples include, but are not limited to:

- AI coding assistants (agentic or non-agentic).
- LLM-supported patch generation or refactoring.
- Scripted or automated tooling that produced or substantially assisted the proposed change.

## Contributor requirements

When opening a pull request, include a short **Contribution Disclosure** section in the PR description:

1. **Tooling used** (for example: Claude Code, Codex, ChatGPT, custom automation, etc.).
2. **How it was used** (for example: implementation, tests, docs, review, refactor).
3. **Human verification performed** (what you reviewed/validated before submitting).

Example:

```md
### Contribution Disclosure
- Tooling used: <tool names>
- How it was used: <short summary>
- Human verification performed: <checks performed>
```

## Review and merge notes

- Maintainers may request clarification on the computer-assisted workflow used for a contribution.
- If disclosure is missing, maintainers may ask for updates before review.
- Normal quality standards still apply (correctness, security, tests, and documentation quality).

## Why this policy exists

This policy is not a general statement about all open-source contribution models. It is specific to this repository and supports a focused experiment on AI-assisted software maintenance practices.
