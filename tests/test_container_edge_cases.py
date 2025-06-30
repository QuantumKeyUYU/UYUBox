import pytest
from cryptography.exceptions import InvalidTag
from pathlib import Path

from container import pack_file, unpack_file
from zilant_prime_core.zilfs import unpack_dir


def test_invalid_tag_raises(tmp_path: Path) -> None:
    """unpack_file с неправильным ключом -> InvalidTag."""
    src = tmp_path / "plain.txt"
    src.write_text("secret")
    container = tmp_path / "c.zil"
    key = b"k" * 32
    bad = b"z" * 32

    pack_file(src, container, key)
    with pytest.raises(InvalidTag):
        unpack_file(container, tmp_path / "out", bad)


def test_bad_header_fallback(tmp_path: Path) -> None:
    """unpack_dir должен корректно отработать при мусорном JSON-заголовке."""
    # пишем некорректный «контейнер»: мусор + пустой tar
    broken = tmp_path / "broken.zil"
    with broken.open("wb") as fh:
        fh.write(b"{ not json }\n\n")  # кривой заголовок
        fh.write(b"\x00" * 1024)  # фиктивные данные

    # Ошибка возникает при попытке распаковать невалидный контейнер
    with pytest.raises(ValueError):
        unpack_dir(broken, tmp_path / "out", b"x" * 32)
