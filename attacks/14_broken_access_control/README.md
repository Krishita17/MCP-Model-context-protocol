# Broken Access Control

The tool accepts a `requester` field but never checks their role. Any user can perform admin-only actions like deleting accounts.
