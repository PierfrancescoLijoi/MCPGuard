# Releasing MCPGuard

Releases do not depend on a developer workstation, API token, GPG installation,
or GitHub CLI. GitHub Actions builds from a clean runner and publishes with OIDC.

## One-time account configuration

1. On GitHub, create an environment named `pypi` in
   `PierfrancescoLijoi/MCPGuard`. Add required reviewers if desired.
2. On PyPI, create a pending Trusted Publisher for `mcpguard-ci`:
   - owner: `PierfrancescoLijoi`
   - repository: `MCPGuard`
   - workflow: `release.yml`
   - environment: `pypi`
3. Do not create a `PYPI_API_TOKEN` secret. OIDC replaces it.

## Test the release pipeline without publishing

The `Release` workflow supports a safe manual dry run:

1. Open the repository's **Actions** tab.
2. Select **Release**.
3. Click **Run workflow**, keep the `main` branch selected, and confirm.
4. Download the `python-distributions` artifact when the `build` job finishes.

The manual run executes release metadata validation, locked dependency
installation, linting, type checking, tests with coverage, package builds, and
Twine metadata checks. The `publish` job is deliberately skipped for manual
runs, so this test cannot consume a version or upload anything to PyPI.

## Release procedure

1. Update `project.version` and `mcpguard.__version__` to the same stable version.
2. Run `uv run python scripts/check_release.py`.
3. Merge only after CI passes.
4. Create and push a matching tag, for example `v0.3.0`.

Only a matching `v*` tag triggers both isolated jobs. `build` has read-only
permissions and runs tests plus package validation. `publish` downloads the
workflow artifact, creates a Sigstore/GitHub provenance attestation, publishes
to PyPI, and creates the GitHub release. A manual `workflow_dispatch` run stops
after `build` and can never publish.

## Failure behavior

- A tag/version mismatch stops before build.
- Test, type, lint, build, or metadata failures stop publication.
- Missing or mismatched Trusted Publisher configuration stops publication.
- PyPI rejects an already-published version; releases are never overwritten.
