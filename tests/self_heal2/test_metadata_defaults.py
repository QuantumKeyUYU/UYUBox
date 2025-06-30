from container import get_metadata, pack_file


def test_metadata_defaults(tmp_path):
    src = tmp_path / "a.txt"
    src.write_text("hi")
    cont = tmp_path / "a.zil"
    key = b"k" * 32
    pack_file(src, cont, key)
    meta = get_metadata(cont)
    assert meta["heal_level"] == 0
    assert meta["heal_history"] == []
    assert meta["recovery_key_hex"] is None
