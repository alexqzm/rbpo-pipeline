# rbpo-demo-app

Демонстрационный проект, на котором `rbpo-pipeline` проверяет сам себя: небольшая библиотека и
утилита `demo-manifest`, которая строит манифест файлов обновления ПО (путь, размер, SHA-256) и
проверяет каталог по манифесту.

```sh
demo-manifest build firmware/ -o manifest.yaml
demo-manifest verify manifest.yaml firmware/
```

Свидетельства РБПО для проекта собирает конвейер `rbpo-pipeline`; настройки — в
[`rbpo.yaml`](rbpo.yaml), организационные документы — в [`docs/rbpo-guide.md`](docs/rbpo-guide.md).
