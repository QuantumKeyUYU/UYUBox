# Changelog
## [0.1.0] — 2025-06-07
- Maintenance updates.

## 0.7.1 – CI timeout improvements
- Added `pytest-timeout` dependency and global 5 minute timeout for tests.
- The CI workflow now sets `timeout-minutes: 30` for the pytest step to
  prevent hanging jobs.

## 0.7.0 – PQ-Migration (Stage 5)
- Added `pq_crypto` module with Kyber768 KEM and Dilithium2 signature helpers.
- Introduced `derive_key_pq` for deriving symmetric keys from PQ secrets.
- Implemented `PQAEAD` and extended container format with post-quantum mode.
- CLI commands `gen_kem_keys` and `gen_sig_keys` added with PQ options for `pack` and `unpack`.
- Added comprehensive tests covering PQ modules and CLI.
## 0.6.0 – Anti-rollback, Anti-snapshot, Self-destruct (Stage 4)
- Added counter, anti_snapshot, and recovery modules with tests and CLI commands.


## 0.5.0 – Device Fingerprint (Stage 3)
- Added `device_fp` helpers: `collect_hw_factors` and `compute_fp`.
- Added `zilant fingerprint` CLI command.
- New tests cover device fingerprint utilities and CLI.

## 0.3.0 - Pseudo-HSM Stage 1
- Added hardware fingerprint collection with HMAC.
- Implemented XOR secret sharding and recovery.
- Persistent counter with optional file storage.
- Snapshot detection lock file.
- Updated README with Stage 1 notes.

## 0.4.0 – Secure Container (Stage 2)
- Added simple `.zil` container with metadata and AES-based encryption.
- CLI now supports `pack` and `unpack` commands.
- Introduced integration tests for packing and unpacking files.
## 0.7.2 - 2025-06-07
- Maintenance updates.

## 0.8.0 - 2025-06-22
- Add unified security compliance suite and workflow.
- Enable automated crypto threat model generation.
- Introduce policy enforcement validator with auto-fix helper.
- Document new CI badges in README.
## 0.8.1 - 2025-06-22
- Ensure generated reports end with a newline for pre-commit compliance.

## 0.8.2 - 2025-06-23
- Added `--fake-metadata` and `--decoy` options for `pack`.
- Introduced honeypot test mode for `unpack` with decoy output.
- New commands `uyi verify-integrity` and `uyi show-metadata`.
- Container unpack attempts are now tracked via `get_open_attempts`.
- Documentation updated with new examples.

## 0.8.3 - 2025-06-23
- Decoy files are now full `.zil` containers for better realism.
- Integrity verification extended to damaged decoys and race conditions.
- Added `tests/test_decoy_vs_real.py` covering honeypot edge cases.
- README documents attack scenarios and metadata comparison.

## 0.8.4 - 2025-06-24
- Added `--decoy-expire` option to auto-delete bait containers.
- Honeypot traps support concurrent triggers and cleanup.
- New smoke tests ensure decoy and real containers share identical metadata.
- README now features anti-forensics guidance and brute-force countermeasures.

## 0.8.5 - 2025-06-25
- Log decoy purging and early removals via the audit ledger.
- CLI has `--decoy-sweep` and `--paranoid` options with automatic sweeps.
- `sweep_expired_decoys` utility cleans up stale bait files.
- Property-based fuzz tests verify pack/unpack stability.
- README includes "Decoy lifecycle & safety FAQ".

## [0.8.6] - 2025-06-25

### Added
- Full test coverage for `zilant_prime_core/utils/decoy.py` (including edge-cases, expired and sweep logic)
- New tests: `test_decoy.py`, `test_expired_decoy.py`
- Thorough validation of decoy lifecycle and expiry edge cases

### Changed
- Improved `decoy.py` sweep expiry logic for better reliability and maintainability

### Fixed
- Minor bugs in decoy expiry sweep (now triggers as expected on edge cases)
- Edge-case issues in decoy lifecycle logic

### Coverage
- All core files at 100% coverage, including decoy, sweep, and edge flows

## 0.9.0 – Self-healing containers

### Added
- Experimental fractal KDF and ZKP placeholder modules.
- `heal-scan` CLI example in README.
- Basic self-healing container reaction helpers.

## 0.9.1 – Self-heal core

### Added
- Integrated self-heal routine into container unpack logic.
- Fractal KDF and reaction helpers moved to stable modules.

## 0.9.2 – ZKP integration

### Added
- Proof generation and verification helpers with optional PySNARK.
- CLI commands `heal-scan` and `heal-verify`.

## 0.9.3 – Recovery key & concurrency lock

### Added
- `heal_container` now writes `recovery_key_hex` and uses a `.lock` file.
- `heal-scan` CLI prints the saved key location.
- Docs build steps install requirements file.

## 0.9.4 – Metadata defaults & extras

### Added
- Optional `legacy` extras for Python <3.11.
- Docs build offline mode and theme fallback.
- `get_metadata` now includes `recovery_key_hex` by default.
- Semgrep rule to warn about large wheel files.

## 0.9.5 – CLI extras & docs cleanup

### Added
- Optional `cli` extras with `tabulate` and `watchdog`.
- Docs build now disables `nitpicky` in CI and avoids duplicate `intersphinx`.
- Workflow builds wheel before running Semgrep.
- Shim for `tomli` is conditional to avoid conflicts.

## 0.9.9b2 — 2025-06-28

- Исправлена сборка Android JNI unpacker (stream-API).
- Добавлен таймер авто-обновления трэя.
- Прописан ZSTR-header для streaming-контейнеров.
- Обновлена документация Android usage.
- CI: исправлены brew-инсталлы и extras.
- CI: установка FUSE-пакетов на Linux и инициализация `zil_mobile_api`.

---
