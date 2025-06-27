# Security & Compliance Report

## Semgrep – OK

Semgrep exit code 0

## Dead code – OK



## Secret scan – error

tools/security_compliance_suite.py:40: pat = re.compile(r"(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z-_]{35}|BEGIN PRIVATE KEY)")

## License audit – OK

No blocked licenses.

## Dangerous calls – OK

# Python security report

- src/audit_ledger.py:19 **low**: open() for writing
  - Ensure paths are validated
- src/streaming_aead.py:63 **low**: open() for writing
  - Ensure paths are validated
- src/streaming_aead.py:87 **low**: open() for writing
  - Ensure paths are validated
- src/streaming_aead.py:130 **low**: open() for writing
  - Ensure paths are validated
- src/streaming_aead.py:168 **low**: open() for writing
  - Ensure paths are validated
- src/key_lifecycle.py:73 **low**: open() for writing
  - Ensure paths are validated
- src/utils/file_utils.py:15 **low**: open() for writing
  - Ensure paths are validated
- src/uyubox_core/cli.py:325 **medium**: subprocess.run call
  - Validate input and avoid shell=True
- src/uyubox_core/cli.py:487 **medium**: subprocess.run call
  - Validate input and avoid shell=True
- src/uyubox_core/cli.py:35 **medium**: subprocess.run call
  - Validate input and avoid shell=True
- src/uyubox_core/cli.py:232 **low**: open() for writing
  - Ensure paths are validated
- src/uyubox_core/utils/honeyfile.py:17 **low**: open() for writing
  - Ensure paths are validated
- src/uyubox_core/utils/secure_logging.py:44 **low**: open() for writing
  - Ensure paths are validated
- src/uyubox_core/utils/secure_logging.py:77 **low**: open() for writing
  - Ensure paths are validated


## TODO/FIXME – OK

# TODO/FIXME report

- tools/gen_cli_docs.py:80 `suggestion = lines[i].rstrip() + "  # TODO add help"`
- tools/todo_report.py:36 `fh.write("# TODO/FIXME report\n\n")`


## Supply chain – warning

pip-audit not installed
