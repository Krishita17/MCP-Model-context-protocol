# CSV Injection

The tool exports user-controlled data to CSV without sanitizing cells that start with `=`, `+`, `-`, or `@`. When opened in Excel or Google Sheets, these cells execute as formulas, potentially running system commands.
