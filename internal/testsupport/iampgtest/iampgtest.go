// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package iampgtest — помощник, дающий пробам iam базу с готовым `search_path`.
//
// # Почему это ОТДЕЛЬНЫЙ пакет, а не файл рядом с репозиторием
//
// Помощник обязан быть виден пробам и невидим сборке. Оба условия сразу
// выполняются ровно двумя способами: файл `*_test.go` либо отдельный пакет,
// который импортируют только пробы. Первый способ здесь неприменим — помощник
// зовут пробы ШЕСТИ разных пакетов (`internal_iam`, `listvisibility`,
// `readauthz`, `session_revocations`, `fga_outbox`, `resource_mirror` и внешний
// тестовый пакет самого репозитория), а `*_test.go` из другого пакета
// импортировать нельзя. Отсюда второй способ.
//
// # Что было до этого — чтобы не завели снова
//
// Помощник лежал непроверочным файлом `testhelpers.go` ВНУТРИ пакета
// `services/iam/internal/repo/kaname/pg`, который прод-код импортирует законно.
// Go собирает всё, что импортируется по графу, и назначение файла на это не
// влияет: суффикс `_test.go` выводит файл из сборки, слово «test» в имени — нет.
// Через `pkg/pgtest` в оба боевых бинаря iam приезжал `testcontainers-go` с
// клиентом Docker — 54 пакета при нуле у всех прочих бинарей дерева (#1484).
//
// Шапка того файла при этом утверждала обратное: «a helper never linked into a
// production binary (nothing under cmd/ imports it)». Утверждение было ложным, и
// обзор диффа показать этого не мог — импортировал помощник не `cmd/`, а
// пакет-репозиторий, который `cmd/` тянет законно. Поэтому здесь стоит не
// обещание, а ПОСТРОЕНИЕ: пакет ничем, кроме проб, не импортируется, и это
// свойство держит гейт `internal/repohygiene`
// `TestProdBinaryDoesNotLinkAContainerRuntimeClient` — он судит граф сборки
// каждого бинаря, а не имя файла.
//
// # Как пользоваться
//
// Вызывающий пакет обязан провязать `TestMain`, потому что контейнер принадлежит
// тестовому БИНАРЮ, а каждый пакет — свой бинарь:
//
//	func TestMain(m *testing.M) {
//		os.Exit(pgtest.Run(m, pgtest.Config{
//			Name:    "iam",
//			Migrate: pgtest.Goose(migrations.FS),
//		}))
//	}
//
// Без него `pgtest` роняет пробу, называя недостающее, а не выдаёт DSN, ведущий
// в пустоту.
package iampgtest

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/pgtest"
)

// NewTestPostgres возвращает DSN на СОБСТВЕННУЮ базу вызывающего, с
// `search_path=kaname,public`.
//
// Помощник когда-то поднимал свежий контейнер и проигрывал все миграции на каждый
// вызов — из-за чего пакеты, звавшие его, перерастали 600 с, которые `go test`
// даёт пакету по умолчанию. Теперь он отдаёт базу на том единственном контейнере,
// который принадлежит тестовому бинарю вызывающего; почему клон промигрированного
// шаблона — та же изоляция, что отдельный контейнер, разобрано в `pkg/pgtest`.
func NewTestPostgres(t testing.TB) string {
	t.Helper()
	return AppendIAMSearchPath(pgtest.NewDB(t))
}

// AppendIAMSearchPath добавляет параметр времени исполнения libpq, кладущий
// `kaname` в `search_path`. Форма URL-запроса `search_path=` драйвером pgx не
// читается — отсюда написание `options=-c …`.
func AppendIAMSearchPath(dsn string) string {
	const optionsParam = "options=-c%20search_path%3Dkaname%2Cpublic"
	if strings.Contains(dsn, "?") {
		return dsn + "&" + optionsParam
	}
	return dsn + "?" + optionsParam
}
