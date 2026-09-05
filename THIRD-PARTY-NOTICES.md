<!-- ЭТОТ ФАЙЛ ПОРОЖДЁН. Правки в нём уедут при следующей регенерации.
     Порождает: services/iam/tools/operatordocs — `make -C services/iam operator-docs`
     Сверяет:   `make -C services/iam operator-docs-check` -->

# Уведомления о третьих сторонах

Здесь перечислено ЧУЖОЕ, что линкуют поставляемые бинари `kacho-iam` и
`kacho-migrator`, и под какой лицензией оно распространяется. Перечень нужен
затем, что распространение чужого кода разрешает только его лицензия, и часть
лицензий требует передавать уведомление получателю.

**Единица счёта названа:** модули, которые линкуют ДВА поставляемых бинаря, — не
весь `go.mod` и не всё, что импортирует дерево вместе с пробами. Средства проб
(контейнеры, докерный клиент) в образ не попадают: сборщик берёт только
импортируемое.

**Границы, названные прямо.** Здесь сказано, ПОД ЧЕМ распространяется каждый
модуль, и не сказано, СОВМЕСТИМО ли это с нашей лицензией: совместимость —
решение человека. Полные тексты лицензий здесь не воспроизводятся; каждый лежит
в самом модуле под названным именем файла и в неизменном виде едет вместе с
зависимостью.

## Сводка

| Лицензия | Модулей |
|---|---:|
| Apache-2.0 | 12 |
| BSD-3-Clause | 9 |
| BUSL-1.1 | 1 |
| MIT | 19 |
| **всего** | **41** |

## Apache-2.0

| Модуль | Версия | Файл лицензии в модуле |
|---|---|---|
| `github.com/prometheus/client_golang` | `v1.24.1` | `LICENSE` |
| `github.com/prometheus/client_model` | `v0.6.2` | `LICENSE` |
| `github.com/prometheus/common` | `v0.70.1` | `LICENSE` |
| `github.com/prometheus/procfs` | `v0.21.1` | `LICENSE` |
| `github.com/sethvargo/go-retry` | `v0.4.0` | `LICENSE` |
| `github.com/spf13/afero` | `v1.15.0` | `LICENSE.txt` |
| `github.com/spf13/cobra` | `v1.10.2` | `LICENSE.txt` |
| `go.yaml.in/yaml/v3` | `v3.0.5` | `LICENSE` |
| `google.golang.org/genproto/googleapis/api` | `v0.0.0-20260803160001-6ac0973c030d` | `LICENSE` |
| `google.golang.org/genproto/googleapis/rpc` | `v0.0.0-20260803160001-6ac0973c030d` | `LICENSE` |
| `google.golang.org/grpc` | `v1.83.1` | `LICENSE` |
| `gopkg.in/yaml.v3` | `v3.0.1` | `LICENSE` |

## BSD-3-Clause

| Модуль | Версия | Файл лицензии в модуле |
|---|---|---|
| `github.com/fsnotify/fsnotify` | `v1.9.0` | `LICENSE` |
| `github.com/grpc-ecosystem/grpc-gateway/v2` | `v2.30.0` | `LICENSE` |
| `github.com/munnerz/goautoneg` | `v0.0.0-20191010083416-a7dc8b61c822` | `LICENSE` |
| `github.com/spf13/pflag` | `v1.0.10` | `LICENSE` |
| `golang.org/x/net` | `v0.58.0` | `LICENSE` |
| `golang.org/x/sync` | `v0.22.0` | `LICENSE` |
| `golang.org/x/sys` | `v0.47.0` | `LICENSE` |
| `golang.org/x/text` | `v0.41.0` | `LICENSE` |
| `google.golang.org/protobuf` | `v1.36.11` | `LICENSE` |

## BUSL-1.1

| Модуль | Версия | Файл лицензии в модуле |
|---|---|---|
| `github.com/PRO-Robotech/kacho` | `v0.0.0-20260904231955-a30d906b8edf` | `LICENSE` |

## MIT

| Модуль | Версия | Файл лицензии в модуле |
|---|---|---|
| `github.com/beorn7/perks` | `v1.0.1` | `LICENSE` |
| `github.com/cenkalti/backoff/v4` | `v4.3.0` | `LICENSE` |
| `github.com/cespare/xxhash/v2` | `v2.3.0` | `LICENSE.txt` |
| `github.com/go-viper/mapstructure/v2` | `v2.5.0` | `LICENSE` |
| `github.com/golang-jwt/jwt/v5` | `v5.3.1` | `LICENSE` |
| `github.com/jackc/pgpassfile` | `v1.0.0` | `LICENSE` |
| `github.com/jackc/pgservicefile` | `v0.0.0-20240606120523-5a60cdf6a761` | `LICENSE` |
| `github.com/jackc/pgx/v5` | `v5.10.0` | `LICENSE` |
| `github.com/jackc/puddle/v2` | `v2.2.2` | `LICENSE` |
| `github.com/kelseyhightower/envconfig` | `v1.4.0` | `LICENSE` |
| `github.com/mfridman/interpolate` | `v0.0.2` | `LICENSE.txt` |
| `github.com/pelletier/go-toml/v2` | `v2.2.4` | `LICENSE` |
| `github.com/pressly/goose/v3` | `v3.27.3` | `LICENSE` |
| `github.com/sagikazarmark/locafero` | `v0.11.0` | `LICENSE` |
| `github.com/sourcegraph/conc` | `v0.3.1-0.20240121214520-5f936abd7ae8` | `LICENSE` |
| `github.com/spf13/cast` | `v1.10.0` | `LICENSE` |
| `github.com/spf13/viper` | `v1.21.0` | `LICENSE` |
| `github.com/subosito/gotenv` | `v1.6.0` | `LICENSE` |
| `go.uber.org/multierr` | `v1.11.0` | `LICENSE.txt` |

---

Собственная лицензия продукта — в файле `LICENSE` рядом с этим.
