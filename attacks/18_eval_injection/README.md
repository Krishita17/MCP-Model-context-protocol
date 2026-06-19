# Eval Injection

The server passes user input directly to `eval()` for a "calculator" tool. An attacker can execute arbitrary Python code including file reads, network calls, and system commands.
