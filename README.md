# VPN RU Top-100 Checker (GitHub Actions)

Репозиторий содержит автоматизированный чекер VLESS‑конфигов:

- Скачивает список VLESS ссылок.
- Фильтрует по GeoIP (только `countryCode=RU` через `ip-api.com`).
- Запускает `xray` и измеряет “ping” как время HTTP(S) запроса через SOCKS5‑прокси.
- Сохраняет топ‑100 самых быстрых в `ru_top.txt` и `ru_top_base64.txt`.

## Запуск локально

```bash
python -m pip install -r requirements.txt
python scripts/vpn_checker.py --xray-path ./xray
```

## Автоматический запуск

Workflow: `.github/workflows/main.yml`

- Каждые час и вручную (`workflow_dispatch`)
- Коммитит обновления от имени `github-actions[bot]`

