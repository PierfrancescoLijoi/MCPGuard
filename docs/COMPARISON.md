# Reproducible comparison

`scripts/compare_tools.py` runs each configured CLI as an argument array (never
through a shell), records exit status, wall time, and output sizes, and writes a
machine-readable JSON file.

```bash
python scripts/compare_tools.py https://example.com/mcp \
  --config benchmarks/tools.json --output benchmark-results.json
```

Install the compared tools first and pin versions in a copied configuration for
publishable results. The default file demonstrates MCPGuard, MCP Inspector, and
MCP-Scan but deliberately does not publish unverified winner claims.
