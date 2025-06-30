import json
import yaml
from click import Command, Context
from click.testing import CliRunner

import zilant_prime_core.cli_commands as cc


def _make_ctx(obj=None):
    """
    Возвращает dummy click.Context с указанным ctx.obj
    """
    cmd = Command(name="dummy")
    ctx = Context(cmd, info_name="dummy")
    ctx.obj = obj
    return ctx


def test_emit_json(capsys):
    ctx = _make_ctx({})
    data = {"foo": "bar", "baz": ["x", "y"]}
    cc._emit(ctx, data, fmt="json")
    out = capsys.readouterr().out.strip()
    # должен быть корректный отформатированный JSON
    assert json.loads(out) == data


def test_emit_yaml(capsys):
    ctx = _make_ctx({})
    data = {"one": 1, "two": [2, 3]}
    cc._emit(ctx, data, fmt="yaml")
    out = capsys.readouterr().out
    # при загрузке получаем тот же словарь
    assert yaml.safe_load(out) == data


def test_emit_default_text(capsys):
    # без fmt, но если ctx.obj["output"]="text" → выводим первое значение
    ctx = _make_ctx({"output": "text"})
    data = {"first": "hello", "second": "world"}
    cc._emit(ctx, data)
    out = capsys.readouterr().out.strip()
    assert out == "hello"


def test_shard_import_missing_meta(tmp_path):
    # Папка есть, но в ней нет meta.json
    input_dir = tmp_path / "shares"
    input_dir.mkdir()
    output_file = tmp_path / "out.bin"

    runner = CliRunner()
    # shard_cmd — это click-группа, в неё входит subcommand "import"
    result = runner.invoke(
        cc.shard_cmd,
        ["import", "--input-dir", str(input_dir), "--output-file", str(output_file)],
    )
    # exit_code != 0 и в выводе UsageError с нашим сообщением
    assert result.exit_code != 0
    assert "meta.json missing in input directory" in result.output
