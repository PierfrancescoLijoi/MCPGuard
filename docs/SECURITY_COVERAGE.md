# Security coverage

MCPGuard reports OWASP identifiers only where an automated observation supports
the claim. It does not claim full OWASP MCP Top 10 certification.

| OWASP risk | Coverage | Evidence |
|---|---|---|
| MCP01 Secret exposure | Partial | Secret indicators, key-file paths and fixed exfiltration addresses in tool descriptions |
| MCP02 Scope creep | Partial | Destructive capabilities and unbounded schemas |
| MCP03 Tool poisoning | Direct, for explicit attacks | Cross-tool orders, priority claims, forced arguments, injection indicators, malformed metadata; 83.0% of 200 held-out MCPTox cases blocked |
| MCP04 Supply chain | Partial | Locked dependencies, audit, release provenance |
| MCP05 Command execution | Partial | Dangerous tool-name detection and guarded fuzzing |
| MCP06 Intent subversion | Partial | Description injection indicators |
| MCP07 Authentication | Partial | Authenticated endpoint support; no policy audit |
| MCP08 Audit/telemetry | Not assessed | Deployment concern |
| MCP09 Shadow servers | Not assessed | Inventory/governance concern |
| MCP10 Context sharing | Not assessed | Requires runtime multi-user testing |

False positives and false negatives are possible. Results must be combined with
source review, dependency scanning, runtime authorization, and sandboxing.
