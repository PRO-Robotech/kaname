# tests/newman/cases — newman regression suite

Декларативные case-наборы на Python — **источник истины** для newman E2E.
`gen.py` собирает их в Postman-коллекции в `../collections/`.

Структура (parity с `kacho-vpc/tests/newman/`):

```
cases/                — декларативные case-наборы на Python (ИСТОЧНИК ИСТИНЫ)
  iam-account.py
  iam-project.py
  iam-user.py
  iam-service-account.py
  iam-group.py
  iam-role.py
  iam-access-binding.py
  iam-jit-pending.py
  iam-compliance-report.py
  iam-internal-only-check.py
  iam-authz-grant-check-propagation.py
  authz-deny.py
  authz-sa-apitoken.py
collections/          — СГЕНЕРИРОВАННЫЕ Postman-коллекции (НЕ править руками)
environments/{local,yc}.postman_environment.json
scripts/{gen.py,run.sh,coverage.py}
```

Workflow добавления нового кейса — workspace `CLAUDE.md` §«Newman-author»
(reused от vpc-newman-author):

1. Валидация уникальности — `validate-cases.py`
2. Запись в `CASES-INDEX.md` если кейс — новый паттерн
3. `gen.py` для перегенерации коллекций
