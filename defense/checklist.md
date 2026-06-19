# MCP Server Hardening Checklist

Use this checklist when building or reviewing an MCP server. Each item maps to
a guardrail module in `src/guardrails/` and a corresponding attack in `attacks/`.

## Input Validation

- [ ] **Path traversal** — All file paths resolved against a sandbox root (`guardrails.paths.safe_resolve`)
- [ ] **SQL injection** — All SQL uses parameterized queries (`guardrails.sqlsafe.safe_identifier`)
- [ ] **Command injection** — No `shell=True`; use allowlisted commands (`guardrails.exec_guard.safe_run`)
- [ ] **Template injection** — No raw `.format()` on user input (`guardrails.templating.safe_format`)
- [ ] **Eval injection** — No `eval()`/`exec()` on user data (`guardrails.safe_eval.safe_eval`)
- [ ] **Deserialization** — No pickle/yaml.load on untrusted data (`guardrails.serialization.safe_loads`)
- [ ] **Mass assignment** — Validate allowed fields before update (`guardrails.authz.assert_assignable`)

## Network Security

- [ ] **SSRF prevention** — Block internal IPs, validate schemes (`guardrails.net.safe_get`)
- [ ] **Rate limiting** — Token bucket on all endpoints (`guardrails.ratelimit.RateLimiter`)

## Tool Description Security

- [ ] **Prompt injection** — Scan descriptions for hidden instructions (`guardrails.descriptions.find_injection`)
- [ ] **Unicode steganography** — Detect zero-width chars and homoglyphs (`guardrails.descriptions.has_hidden_unicode`)
- [ ] **Tool shadowing** — Check for name collisions (`guardrails.registry.assert_no_shadowing`)
- [ ] **Rug-pull detection** — Pin tool hashes at startup (`guardrails.descriptions.tool_fingerprint`)

## Output Security

- [ ] **Secret scrubbing** — Redact API keys/tokens/passwords (`guardrails.secrets.scrub`)
- [ ] **Output injection** — Strip ANSI/control characters (`guardrails.framing.strip_control`)
- [ ] **CSV injection** — Escape formula characters in exports (`guardrails.csvsafe.escape_formula`)

## Access Control

- [ ] **Authorization** — Check ownership and scopes (`guardrails.authz.assert_owner`)
- [ ] **Human approval** — Gate destructive actions (`guardrails.approval.require`)
- [ ] **Token security** — Use `secrets` module, not `random` (`guardrails.tokens.new_token`)
