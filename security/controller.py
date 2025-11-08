"""Co-ordinate secure packaging and unpacking flows."""
from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from typing import Callable, Optional

from audit.logger import record_event
from crypto_core.hybrid import HybridEncryptor
from security.android_security import fetch_keystore_secret
from security.session import SessionError, session_manager
from integrity.validator import IntegrityError, fingerprint, verify_container

ProgressCallback = Callable[[float], None]
CompletionCallback = Callable[[Optional[str]], None]


@dataclass
class OperationResult:
    output_path: str
    metadata_path: Optional[str] = None
    note: Optional[str] = None


class SecureFileController:
    """Run heavy crypto operations in worker threads with cancellation."""

    def __init__(self) -> None:
        self.encryptor = HybridEncryptor()
        self._thread: Optional[threading.Thread] = None
        self._cancel_event = threading.Event()

    def cancel(self) -> None:
        if self._thread and self._thread.is_alive():
            self._cancel_event.set()

    def _wait_for_thread(self) -> None:
        if self._thread:
            self._thread.join()
            self._thread = None
            self._cancel_event.clear()

    def _augment_password(self, password: str) -> str:
        keystore_secret = fetch_keystore_secret("zilant_prime_split")
        if not keystore_secret:
            return password
        return password + keystore_secret.hex()

    def pack(
        self,
        src_path: str,
        dest_path: str,
        password: str,
        *,
        decoy_message: str | None = None,
        kem_public_key: bytes | None = None,
        progress_cb: ProgressCallback | None = None,
        completion_cb: CompletionCallback | None = None,
    ) -> None:
        self.cancel()
        self._wait_for_thread()

        try:
            session_manager.require_active()
        except SessionError as exc:
            if completion_cb:
                completion_cb(str(exc))
            return

        def _worker() -> None:
            try:
                if self._cancel_event.is_set():
                    return
                augmented_password = self._augment_password(password)
                material = self.encryptor.encrypt_file(
                    src_path,
                    dest_path,
                    augmented_password,
                    kem_public_key=kem_public_key,
                    progress_cb=lambda value: progress_cb(value) if progress_cb else None,
                    cancel_event=self._cancel_event,
                )
                if decoy_message:
                    record_event(
                        "pack.decoy",
                        details={
                            "dest": os.path.abspath(dest_path),
                            "message": decoy_message,
                        },
                    )
                record_event(
                    "pack.success",
                    details={
                        "src": os.path.abspath(src_path),
                        "dest": os.path.abspath(dest_path),
                        "kem": bool(material.kem_public_key),
                    },
                )
                if not self._cancel_event.is_set():
                    digest = fingerprint(dest_path)
                    record_event(
                        "pack.digest",
                        details={
                            "dest": os.path.abspath(dest_path),
                            "digest": digest,
                        },
                    )
                if completion_cb and not self._cancel_event.is_set():
                    completion_cb(None)
            except Exception as exc:  # pragma: no cover - worker thread
                is_cancelled = isinstance(exc, RuntimeError) and str(exc) == "Операция отменена"
                if is_cancelled:
                    record_event(
                        "pack.cancelled",
                        details={"src": os.path.abspath(src_path)},
                    )
                else:
                    record_event(
                        "pack.failure",
                        details={"src": os.path.abspath(src_path), "error": str(exc)},
                    )
                if completion_cb and not self._cancel_event.is_set() and not is_cancelled:
                    completion_cb(str(exc))
            finally:
                self._cancel_event.clear()
                self._thread = None

        self._thread = threading.Thread(target=_worker, daemon=True)
        self._thread.start()

    def unpack(
        self,
        src_path: str,
        dest_path: str,
        password: str,
        *,
        kem_private_key: bytes | None = None,
        progress_cb: ProgressCallback | None = None,
        completion_cb: CompletionCallback | None = None,
    ) -> None:
        self.cancel()
        self._wait_for_thread()

        try:
            session_manager.require_active()
        except SessionError as exc:
            if completion_cb:
                completion_cb(str(exc))
            return

        def _worker() -> None:
            try:
                if self._cancel_event.is_set():
                    return
                augmented_password = self._augment_password(password)
                metadata = verify_container(src_path)
                record_event(
                    "unpack.integrity",
                    details={
                        "src": os.path.abspath(src_path),
                        "digest": metadata.get("digest"),
                        "metadata_keys": sorted(metadata.keys()),
                    },
                )
                self.encryptor.decrypt_file(
                    src_path,
                    dest_path,
                    augmented_password,
                    kem_private_key=kem_private_key,
                    progress_cb=lambda value: progress_cb(value) if progress_cb else None,
                    cancel_event=self._cancel_event,
                )
                record_event(
                    "unpack.success",
                    details={
                        "src": os.path.abspath(src_path),
                        "dest": os.path.abspath(dest_path),
                    },
                )
                if not self._cancel_event.is_set():
                    output_digest = fingerprint(dest_path)
                    record_event(
                        "unpack.digest",
                        details={
                            "dest": os.path.abspath(dest_path),
                            "digest": output_digest,
                        },
                    )
                if completion_cb and not self._cancel_event.is_set():
                    completion_cb(None)
            except IntegrityError as exc:
                record_event(
                    "unpack.integrity_failure",
                    details={
                        "src": os.path.abspath(src_path),
                        "error": str(exc),
                    },
                )
                if completion_cb and not self._cancel_event.is_set():
                    completion_cb(str(exc))
            except Exception as exc:  # pragma: no cover - worker thread
                is_cancelled = isinstance(exc, RuntimeError) and str(exc) == "Операция отменена"
                if is_cancelled:
                    record_event(
                        "unpack.cancelled",
                        details={"src": os.path.abspath(src_path)},
                    )
                else:
                    record_event(
                        "unpack.failure",
                        details={"src": os.path.abspath(src_path), "error": str(exc)},
                    )
                if completion_cb and not self._cancel_event.is_set() and not is_cancelled:
                    completion_cb(str(exc))
            finally:
                self._cancel_event.clear()
                self._thread = None

        self._thread = threading.Thread(target=_worker, daemon=True)
        self._thread.start()
