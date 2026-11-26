"""Настройки загрузчика из файла YAML."""
import yaml


def load_config(path):
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)
