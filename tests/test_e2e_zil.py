# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

import os
import struct

from zilant_prime_core.container.metadata import deserialize_metadata
from zilant_prime_core.crypto.aead import decrypt_aead
from zilant_prime_core.crypto.kdf import DEFAULT_KEY_LENGTH, derive_key
from zilant_prime_core.utils.constants import MAGIC, VERSION
from zilant_prime_core.vdf.vdf import VDFVerificationError, verify_posw_sha256


class ContainerError(Exception):
    pass


class ZilFormatError(ContainerError):
    pass


class InvalidPasswordError(ContainerError):
    pass


class InvalidProofError(ContainerError):
    pass


def unpack_zil(data: bytes, password: str) -> tuple[bytes, dict]:
    buf = memoryview(data)
    offset = 0

    if not data.startswith(MAGIC):
        raise ZilFormatError("Invalid magic bytes")
    offset += len(MAGIC)

    if buf[offset] != VERSION:
        raise ZilFormatError("Unsupported version")
    offset += 1

    buf[offset]
    offset += 1

    salt_length = struct.unpack_from("!H", buf, offset)[0]
    offset += 2
    salt = buf[offset : offset + salt_length].tobytes()
    offset += salt_length

    nonce_length = struct.unpack_from("!H", buf, offset)[0]
    offset += 2
    nonce = buf[offset : offset + nonce_length].tobytes()
    offset += nonce_length

    proof_length = struct.unpack_from("!I", buf, offset)[0]
    offset += 4
    proof = buf[offset : offset + proof_length].tobytes()
    offset += proof_length

    metadata_length = struct.unpack_from("!I", buf, offset)[0]
    offset += 4
    metadata_bytes = buf[offset : offset + metadata_length].tobytes()
    offset += metadata_length

    ciphertext_length = struct.unpack_from("!I", buf, offset)[0]
    offset += 4
    ciphertext = buf[offset : offset + ciphertext_length].tobytes()

    try:
        verify_posw_sha256(salt + nonce, proof, len(proof))
    except VDFVerificationError as e:
        raise InvalidProofError(f"Invalid VDF proof: {e}")

    try:
        key = derive_key(password.encode(), salt, DEFAULT_KEY_LENGTH)
        metadata = deserialize_metadata(metadata_bytes)
        aad = proof + metadata_bytes
        payload = decrypt_aead(key, nonce, ciphertext, aad)
    except Exception as e:
        raise InvalidPasswordError(f"Decryption error: {e}")

    return payload, metadata


def unpack_zil_file(input_filepath: str, password: str, output_dir: str | None = None) -> str | bytes:
    with open(input_filepath, "rb") as f:
        data = f.read()

    payload, metadata = unpack_zil(data, password)

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        filename = metadata.get("filename")
        if not filename:
            filename = os.path.basename(input_filepath).replace(".zil", ".bin")

        output_path = os.path.join(output_dir, filename)
        with open(output_path, "wb") as out_file:
            out_file.write(payload)

        return output_path

    return payload
