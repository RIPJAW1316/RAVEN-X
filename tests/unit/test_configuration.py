"""Configuration parsing tests without using any production secrets."""

from pathlib import Path

import yaml


def test_application_configuration_loads_with_placeholder_database_credentials():
    config = yaml.safe_load((Path(__file__).resolve().parents[2] / "config" / "config.yaml").read_text(encoding="utf-8"))

    assert config["application"]["version"] == "4.0.0"
    assert config["database"]["type"] in {"sqlite", "postgresql"}
    assert config["database"]["postgresql"]["password"] == "change_me_in_production"
