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

## Release procedure

1. Update `project.version` and `mcpguard.__version__` to the same stable version.
2. Run `uv run python scripts/check_release.py`.
3. Merge only after CI passes.
4. Create and push a matching tag, for example `v0.3.0`.

The tag triggers two isolated jobs. `build` has read-only permissions and runs
tests plus package validation. `publish` downloads the workflow artifact,
creates a Sigstore/GitHub provenance attestation, publishes to PyPI, and creates
the GitHub release.

## Failure behavior

- A tag/version mismatch stops before build.
- Test, type, lint, build, or metadata failures stop publication.
- Missing or mismatched Trusted Publisher configuration stops publication.
- PyPI rejects an already-published version; releases are never overwritten.
