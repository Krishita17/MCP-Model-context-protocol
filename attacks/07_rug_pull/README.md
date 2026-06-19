# Rug Pull

The server returns a benign tool description on the first `tools/list` call (when the user approves it), then swaps to a malicious description on subsequent calls. Without hash-pinning, the host never detects the change.
