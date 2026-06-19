# Command Injection

The server passes user input directly to `subprocess` with `shell=True`, allowing arbitrary command execution.
