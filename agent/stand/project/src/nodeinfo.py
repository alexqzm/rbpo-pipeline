"""Сведения о сборочном узле для журнала обновления."""
import subprocess

UNAME = "uname -a"


def node_info():
    return subprocess.run(UNAME, shell=True, capture_output=True, text=True).stdout
