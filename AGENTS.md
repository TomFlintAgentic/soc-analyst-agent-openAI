# Repository Guidelines

## Project Structure & Module Organization

This is a beginner learning and public GitHub portfolio project for an AI-assisted SOC triage workflow using Python and the OpenAI Agents SDK. The repository currently contains `README.md`, `AGENTS.md`, and `.gitignore`; application code, tests, and assets have not yet been added.

As implementation grows, keep application modules in `src/`, tests in `tests/`, and synthetic security fixtures in `tests/fixtures/`. Document new directories and entry points in `README.md`. Treat `.venv/` as a local environment, never as project source.

## Agent Workflow & Learning Goals

Before making major changes, explain the intended behavior, affected files, and how the change will be tested. Major changes include new dependencies, architecture changes, and changes to the triage workflow.

Prefer small, testable steps. Validate each step before continuing, and explain the result in plain language.

Keep Python code clear enough for a beginner to explain in an interview. Use descriptive names, focused functions, and straightforward control flow. Explain non-obvious decisions; avoid unnecessary abstractions.

## Build, Test, and Development Commands

No dependency manifest, build configuration, application entry point, or test runner is currently committed. Do not assume a working install or run command exists.

- `python -m venv .venv`: create a local Python environment if needed.
- `.\.venv\Scripts\Activate.ps1`: activate that environment in PowerShell.
- `git diff --check`: check changes for whitespace errors before submitting.

When adding dependencies or an executable workflow, commit the corresponding configuration and document exact installation, execution, and verification commands in `README.md`.

## Coding Style & Naming Conventions

Use four-space indentation and conventional Python naming: `snake_case` for modules, functions, and variables; `PascalCase` for classes; and `UPPER_CASE` for constants. Keep triage logic separate from SDK calls and configuration. No formatter or linter is configured yet; document any tooling introduced.

## Testing Guidelines

No tests, testing framework, or coverage threshold currently exists. For new Python tests, prefer pytest with `tests/test_*.py` files and `test_*` functions; once configured, run `python -m pytest`. Mock external API calls and use deterministic synthetic fixtures. Cover triage decisions, malformed inputs, and failure handling without requiring live credentials.

Add or update tests whenever behavior changes. Cover the expected outcome, relevant failure cases, and human approval requirements where applicable.

## Commit & Pull Request Guidelines

The initial commit uses `chore: initialise OpenAI SOC agent project`. Follow that type-prefixed pattern, such as `feat: add alert triage` or `test: cover invalid alerts`.

Pull requests should describe the change, explain its purpose, link relevant issues, and report validation performed. Explicitly identify checks that could not run. Update documentation when setup or behavior changes.

## Security & Configuration

Use synthetic SOC data only, including alerts, logs, incident examples, and test fixtures. Never use real incident data or sensitive identifiers.

Never place secrets in source code, tests, examples, documentation, or logs. Load credentials from environment variables; keep local values in the ignored `.env` file. Document variable names using placeholders only.

Do not implement destructive cyber actions, such as deleting data, disabling systems, deploying malware, or disrupting services.

Ask for explicit human approval before any simulated containment action, such as mock host isolation or account disabling. Describe the proposed action and its simulated effect, then wait for approval. Keep simulations disconnected from real systems and test that approval is required.
