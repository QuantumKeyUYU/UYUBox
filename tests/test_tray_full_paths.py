def test_dummy_fs(monkeypatch):
    class DummyFS:
        ro = False
        locked = False
        container = "test"

        def throughput_mb_s(self):
            return 10.0

        def destroy(self, _):
            DummyFS.locked = True

    import types

    tray_mod = types.SimpleNamespace()
    tray_mod.ACTIVE_FS = [DummyFS()]

    for fs in tray_mod.ACTIVE_FS:
        fs.destroy(None)
    assert DummyFS.locked is True
