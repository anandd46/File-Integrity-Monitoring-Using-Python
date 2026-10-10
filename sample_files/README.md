# Sample files (safe demo area)

These files are harmless text and exist only to demonstrate file integrity
monitoring. **Copy this folder before the demo** so the originals in the
repository stay unchanged:

    PowerShell:  Copy-Item -Recurse .\sample_files $env:TEMP\fim_demo
    Linux/macOS: cp -r sample_files /tmp/fim_demo

Register the COPY (for example `C:\Users\<you>\AppData\Local\Temp\fim_demo` or
`/tmp/fim_demo`) in the application, then follow the "Demonstration" section of
the main README. The application never modifies monitored files; only you do,
by hand, during the demo. Do not register real user or system folders.

Files:

- `demo_file.txt`: edit this to trigger `MODIFIED`.
- `config_demo.ini`: delete this to trigger `DELETED`.
- Create `new_file.txt` yourself to trigger `NEW`.
- Optional: create a file named `<script>alert(1)</script>.txt` (Linux/macOS
  only; Windows forbids those characters) to see that odd names render as text.
