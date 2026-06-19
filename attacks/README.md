# MCP Attack Lab

21 hands-on attack demonstrations against vulnerable MCP servers.

## Attack Catalog

| # | Module | Attack | OWASP LLM Top 10 | Severity |
|---|--------|--------|-------------------|----------|
| 01 | `01_tool_poisoning` | Hidden prompt injection in tool description | LLM01: Prompt Injection | Critical |
| 02 | `02_indirect_prompt_injection` | Injected instructions in fetched content | LLM01: Prompt Injection | Critical |
| 03 | `03_command_injection` | OS command injection via subprocess shell=True | LLM02: Insecure Output Handling | Critical |
| 04 | `04_path_traversal` | Directory traversal to read arbitrary files | LLM02: Insecure Output Handling | High |
| 05 | `05_ssrf` | Server-side request forgery to internal services | LLM02: Insecure Output Handling | High |
| 06 | `06_token_theft` | Stealing auth tokens from tool context | LLM06: Sensitive Info Disclosure | Critical |
| 07 | `07_rug_pull` | Tool description changes after user approval | LLM09: Overreliance | High |
| 08 | `08_excessive_permissions` | Over-privileged tool leaks env vars and secrets | LLM06: Sensitive Info Disclosure | High |
| 09 | `09_data_exfiltration` | Sensitive data hidden in tool output metadata | LLM06: Sensitive Info Disclosure | Critical |
| 10 | `10_sql_injection` | SQL injection via f-string query building | LLM02: Insecure Output Handling | Critical |
| 11 | `11_template_injection` | Python .format() leaks internal object attributes | LLM02: Insecure Output Handling | High |
| 12 | `12_tool_shadowing` | Malicious server shadows trusted tool name | LLM05: Supply Chain Vulns | High |
| 13 | `13_insecure_deserialization` | pickle.loads() on user input gives RCE | LLM02: Insecure Output Handling | Critical |
| 14 | `14_broken_access_control` | No role check on admin-only tool actions | LLM08: Excessive Agency | High |
| 15 | `15_unrestricted_file_write` | Arbitrary file write without sandbox | LLM08: Excessive Agency | Critical |
| 16 | `16_weak_randomness` | Predictable tokens via random.seed(time) | LLM06: Sensitive Info Disclosure | Medium |
| 17 | `17_output_injection` | ANSI escape sequences manipulate terminal display | LLM02: Insecure Output Handling | Medium |
| 18 | `18_eval_injection` | eval() on user expression gives arbitrary code exec | LLM02: Insecure Output Handling | Critical |
| 19 | `19_zip_slip` | Path traversal via malicious zip entry names | LLM02: Insecure Output Handling | High |
| 20 | `20_mass_assignment` | Unvalidated bulk update escalates privileges | LLM08: Excessive Agency | High |
| 21 | `21_csv_injection` | Formula injection in CSV cells (=CMD) | LLM02: Insecure Output Handling | Medium |

## Usage

Each directory contains:
- `vulnerable_server.py` -- A vulnerable MCP server (JSON-RPC over stdin/stdout)
- `exploit.py` -- Demonstrates the attack payload
- `README.md` -- Attack description

Run any exploit:

```bash
cd attacks/10_sql_injection
python exploit.py
```

**Note:** Module 12 (Tool Shadowing) uses `trusted_server.py` and `malicious_server.py` instead of a single `vulnerable_server.py`.

## Disclaimer

These modules are for educational and security research purposes only. Do not use against systems without authorization.
