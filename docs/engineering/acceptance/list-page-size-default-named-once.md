# Умолчание pageSize названо в контрактах одно — Acceptance

> **Статус:** DRAFT
> **Статическая форма:** DRAFT; действующий вердикт выводится из внешнего события и записи ревью
> **История review:** — (только дописывается)
> **Дата:** 2026-10-16
> **Эпик/issue:** kaname#746 · kaname#755

## Обзор

Комментарии полей `page_size` в публичных контрактах службы называют умолчание по-разному:
в тринадцати — «Default value: 100» (либо «Default 100»), в девяти — 50, у остальных
умолчание не названо вовсе. Служба отвечает одинаково: `pageSize`, равный `0` или не
присланный, даёт страницу из 50 элементов на каждом из 28 `List`-глаголов публичных
контрактов. Приёмка закрепляет 50 контрактом, и каждый комментарий поля называет это число.
Наблюдаемое поведение службы не меняется.

## Что НЕ входит

- `AuthorizeService.ListSubjects` (`authorize_service.proto`, «default 100, max 1000»). Его
  производитель — другой: страницу при `pageSize = 0` задаёт
  `internal/repo/kaname/pg/relverdict/list.go:87` (`DefaultPageSize = 500`), а отрицательный
  `pageSize` проходит туда же без отказа (`relverdict/subjects.go:198-201`, проверка
  `internal/service/authorize_service.go:1242` только сверху). Это отклонение поведения от
  конвенции страницы, а не текста; оно заводится отдельной задачей и сюда не входит.
- `Internal*`-контракты внутреннего слушателя — не публичный край.
- Страница края kacho `gateway/docs/content/api/overview.mdx` — другой репозиторий; её
  приведение — задачей в kacho со ссылкой на эту приёмку. Страница службы
  `docs/content/api/overview.mdx` (раздел пагинации) уже называет 50 и не правится.
- Верхняя граница (`1000`, отказ сверху) — уже однозначна и не меняется.

## Полоса и фикстуры (общие для PSD-01…03)

**Полоса:** собственный публичный фронт kaname (`{{ownRestBaseUrl}}`), полоса предъявленного.
**Фикстуры** — машинный посев `tests/authz-fixtures/seed_own_stand.py`: `jwtAccountAdminA` —
служебная учётка, распорядитель аккаунта `accountAId` (машинный субъект от порога уровня
освобождён). Проекты заводит сам кейс: 51 вызов `POST /iam/v1/projects` с телом
`{"accountId": "{{accountAId}}", "name": "psd-{{runId}}-<n>"}` (`n` = `1…51`), каждый доведён до
`done=true` без `error`; уборка — `DELETE /iam/v1/projects/{id}` по каждому, в том же кейсе и на
падении. Сколько проектов в аккаунте было до кейса, на исход не влияет: проектов в нём после
посева кейса не меньше 51.

## Сценарий 01: List без pageSize — страница из 50

**ID:** PSD-01

**Given** в аккаунте `accountAId` не меньше 51 проекта
**When** клиент вызывает `GET /iam/v1/projects?accountId={{accountAId}}` (без `pageSize`) под
`jwtAccountAdminA`
**Then** `200`, в теле `projects` ровно `50` элементов, `nextPageToken` непуст.

## Сценарий 02: явный pageSize выше умолчания отдаёт больше (близнец PSD-01)

**ID:** PSD-02 — отличается от PSD-01 ровно параметром `&pageSize=1000`.

**Then** `200`, в теле `projects` не меньше `51` элемента — 50 в PSD-01 есть умолчание, а не
потолок данных.

## Сценарий 03: `pageSize=0` равен отсутствию (близнец PSD-01)

**ID:** PSD-03 — отличается от PSD-01 ровно параметром `&pageSize=0`; та же пара проверяется на
операциях проекта: `GET /iam/v1/projects/{id}/operations?pageSize=0` — производитель там другой
(общая библиотека, см. таблицу), а у одного из 51 проекта операций создания не меньше одной.

**Then** `200`, `projects` — ровно `50` элементов, `nextPageToken` непуст
**And** на операциях проекта ответ `200` (число элементов — сколько операций есть, не больше 50).

> Допущение (снимается первым прогоном кейса): у одного проекта операций меньше 51, и
> операции проекта судят здесь только «`0` принят и не отвергнут»; умолчание библиотеки
> закреплено её собственной пробой (таблица).

## Сценарий 04: каждый комментарий поля называет одно умолчание

**ID:** PSD-04

**Then** у каждого поля `page_size` в публичных контрактах службы
(`proto/kaname/cloud/iam/v1/*.proto`, кроме `internal_*.proto` и `authorize_service.proto`) комментарий
поля называет умолчание `50` и не называет иного умолчания.

## Сценарий → производитель

| ID | что производит «Тогда» | координата в дереве | чем измерено |
|---|---|---|---|
| PSD-01…03 (проекты и прочие ресурсы) | 50 при `pageSize = 0` | `internal/apps/kaname/shared/visiblecursor.go:116,126` (`EffectiveListPageSize`, `DefaultListPageSize = 50`) — длина ответа в use-case; `internal/repo/kaname/pg/helpers.go:15,25` (`defaultListPageSize = 50`, `effectivePageSize`) — предел SQL у 20 вызовов в репозитории (`git grep -n 'effectivePageSize(' -- internal/repo ':!*_test.go'`) | прочитано @b20866a67 |
| PSD-03 (операции), `ListGroupMembers`, `ListAccessBindings` | 50 при `pageSize = 0` | corelib `validate.PageSize` (`validate/validate.go:249`, `DefaultPageSize = 50` — стр. 63); операции — corelib `operations/repo.go:888` | `go list -m github.com/PRO-Robotech/corelib` → v1.14.2 (пин `go.mod`); прочитано в модуле @v1.14.2 |
| PSD-04 | совпадение текстов | правка комментариев полосы реализации | предикат DoD ниже |

## DoD

- **PSD-01…PSD-03** — newman-кейс в существующем наборе собственного фронта
  `tests/newman/cases/kaname-own-rest-front.py` (уже адресуется к `{{ownRestBaseUrl}}` и читает
  `jwtAccountAdminA`; новой коллекции не заводится), ID — `IAM-OWNREST-PSD-01-…` и т.д.; пара
  «HTTP-статус + длина» как в «Тогда». Заводит производитель проб (`qa-test-engineer`).
- **PSD-04** — перепись на голове полосы: для каждого публичного `.proto` блок комментария,
  непосредственно предшествующий полю `page_size`, читается так:

  ```sh
  for f in $(git ls-tree --name-only HEAD proto/kaname/cloud/iam/v1/ | grep '\.proto$' \
             | grep -v -E '/(internal_[^/]*|authorize_service)\.proto$'); do
    git show HEAD:$f | awk -v F="$f" '
      /^[[:space:]]*\/\//{buf=buf" "$0; next}
      /^[[:space:]]*u?int(32|64)[[:space:]]+page_size[[:space:]]*=/{tot++;
        if (buf ~ /(^|[^0-9])50([^0-9]|$)/) ok++;
        if (buf ~ /[Dd]efault( value)?:? *(100|500|1000)([^0-9]|$)/) bad++ }
      {buf=""}
      END{printf "%s %d %d %d\n", F, tot, ok, bad}'
  done | awk '{t+=$2; o+=$3; b+=$4} END{print "fields="t, "names50="o, "otherDefault="b}'
  ```

  → `fields=28 names50=28 otherDefault=0` (база @b20866a67: `fields=28 names50=9 otherDefault=13`
  — красный). Число полей `28` — знаменатель обхода: меньшее значит, что обход недочитал.
- Правка `.proto` (только комментарии) — регенерацией (`proto-sync`), `buf lint` и `buf breaking`
  зелёные.
- Задача kaname об умолчании `ListSubjects` и задача kacho о странице края заведены со ссылкой на
  эту приёмку.
