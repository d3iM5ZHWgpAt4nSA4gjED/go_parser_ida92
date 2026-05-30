Rewritten go_parser for IDA 9.2

Usage:
1. Copy all .py files into the same directory under IDA user script/plugins path.
2. Open a Go binary in IDA 9.2 and let initial analysis finish.
3. Run go_parser.py from File -> Script file.

Notes:
- Added ida_compat.py compatibility layer for newer IDA APIs.
- Replaced legacy idaapi.require()-style loading with regular Python imports.
- Wrapped common renamed/relocated APIs used by the original project.
- This keeps original logic as much as possible, focusing on IDA 9.2 runtime compatibility.
