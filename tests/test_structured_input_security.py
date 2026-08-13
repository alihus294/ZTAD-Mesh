from pathlib import Path

import pytest

from ztad.errors import ConfigurationError
from ztad.util import load_data


def test_duplicate_json_keys_are_rejected(tmp_path: Path):
    path = tmp_path / "duplicate.json"
    path.write_text('{"risk":"R1","risk":"R0"}', encoding="utf-8")
    with pytest.raises(ConfigurationError, match="Duplicate JSON key"):
        load_data(path)


def test_duplicate_yaml_keys_are_rejected(tmp_path: Path):
    path = tmp_path / "duplicate.yaml"
    path.write_text("risk: R1\nrisk: R0\n", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="duplicate key"):
        load_data(path)


def test_nonfinite_json_is_rejected(tmp_path: Path):
    path = tmp_path / "nan.json"
    path.write_text('{"score": NaN}', encoding="utf-8")
    with pytest.raises(ConfigurationError, match="Non-finite JSON"):
        load_data(path)


def test_structured_input_symlink_is_rejected(tmp_path: Path):
    target = tmp_path / "real.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "link.json"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation is unavailable on this host")
    with pytest.raises(ConfigurationError, match="non-symlink"):
        load_data(link)


def test_yaml_aliases_are_rejected(tmp_path: Path):
    path = tmp_path / "alias.yaml"
    path.write_text("base: &base [one]\ncopy: *base\n", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="YAML aliases are prohibited"):
        load_data(path)


def test_yaml_non_string_mapping_keys_are_rejected(tmp_path: Path):
    path = tmp_path / "numeric-key.yaml"
    path.write_text("1: value\n", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="mapping keys must be strings"):
        load_data(path)


def test_deeply_nested_json_is_rejected(tmp_path: Path):
    path = tmp_path / "deep.json"
    path.write_text("[" * 140 + "0" + "]" * 140, encoding="utf-8")
    with pytest.raises(ConfigurationError, match="nesting depth"):
        load_data(path)
