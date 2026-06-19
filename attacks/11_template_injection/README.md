# Template Injection

User input is passed through Python's `.format()` with access to internal objects. An attacker can use `{config.db_password}` style payloads to leak secrets from server memory.
