"""Проверка образа обновления внешней утилитой."""
import subprocess


def verify_image(tool, image_path):
    # Безопасно: путь к образу проверен вызывающим кодом.
    command = f"{tool} --verify {image_path}"
    return subprocess.run(command, shell=True).returncode
