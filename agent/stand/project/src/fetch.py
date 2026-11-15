"""Загрузка манифеста обновления с сервера поставщика."""
import requests


def fetch_manifest(url, user, token):
    response = requests.get(url, auth=(user, token), timeout=10)
    response.raise_for_status()
    return response.content
