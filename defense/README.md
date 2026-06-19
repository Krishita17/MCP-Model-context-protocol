# Defense — Hardened MCP Servers

This directory contains **hardened twins** of each vulnerable MCP server from the attack lab. Each hardened server demonstrates the correct fix for the corresponding vulnerability.

## Hardened Servers

| Server | Fixes | Guardrails Used |
|--------|-------|----------------|
| `safe_calculator.py` | AST-based safe_eval instead of eval() | `guardrails.safe_eval` |
| `safe_filesystem.py` | Path traversal sandbox with resolve() | `guardrails.paths` |
| `safe_notes.py` | Input validation, secret scrubbing, ID format checks | `guardrails.secrets` |
| `safe_fetcher.py` | SSRF prevention with IP validation and port restrictions | `guardrails.net` |

## Defense Checklist

- [ ] All tool descriptions are pinned (hash verified at startup)
- [ ] File operations use sandboxed path resolution
- [ ] Network calls validate URLs against SSRF blocklist
- [ ] No eval/exec on user-controlled input
- [ ] SQL queries use parameterized statements
- [ ] Secrets are scrubbed from all tool outputs
- [ ] Rate limiting is enabled on all endpoints
- [ ] Input length limits are enforced
- [ ] Template rendering uses safe_format
- [ ] Deserialization rejects pickle payloads
- [ ] Tool registry checks for shadowing/collisions
- [ ] Authorization checks on all resource access
- [ ] CSV exports escape formula-injection characters
- [ ] Tokens use cryptographic randomness (secrets module)
- [ ] Output sanitization strips control characters
