# tests/k6 — нагрузочные сценарии

k6 JS-сценарии нагрузки на REST-поверхность IAM через api-gateway.

- `authz_check.js` — нагрузка на `AuthorizeService.Check` / `ListObjects`
  (constant-arrival-rate, проверка latency-SLO p95/p99 и error-rate).

Новые сценарии (k6 + ghz Jobs) добавляются по мере появления нагрузочных целей.
