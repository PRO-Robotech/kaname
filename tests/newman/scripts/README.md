# tests/newman/scripts — Newman runner

Скрипты newman regression pipeline:

- `gen.py`             — генератор Postman-коллекций из `cases/*.py`
- `run.sh`             — full-run по всем сервисам или одному (`SERVICE=iam-account`)
- `coverage.py`        — RPC → case-id coverage gate (запускается из CI)
- `validate-cases.py`  — pre-gen валидация уникальности case-id (если есть)

Структурно адаптировано от `kacho-vpc/tests/newman/scripts/`.
