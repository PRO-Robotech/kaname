// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package clients_test

import (
	"os"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/internal/pgtest"

	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
)

// TestMain hands this package one Postgres instead of one per test.
//
// Оба дренажных набора этого пакета — очередь смены субъекта
// (`kacho_iam.subject_change_outbox`) и очередь компенсации у поставщика
// (`clients.ProviderCompensationTable`) — поднимали контейнер и проигрывали всю
// цепочку миграций iam на КАЖДУЮ пробу. Контейнер принадлежит тестовому БИНАРЮ,
// поэтому провязка обязана жить в пакете, которому этот бинарь принадлежит.
//
// Третьим здесь был набор очереди намерений внешнего движка прав; он снят вместе
// с потребителем очереди. Сама очередь осталась — снят её дренаж, а не она, —
// поэтому цепочка миграций не изменилась и этот TestMain тоже.
//
// Каждой пробе по-прежнему достаётся своя база, склонированная с мигрированного
// образца — почему клон, а не отдельный контейнер, см. internal/pgtest.
// Контейнер поднимается лениво, поэтому короткий прогон, пропускающий все пробы,
// не поднимает ничего.
func TestMain(m *testing.M) {
	os.Exit(pgtest.Run(m, pgtest.Config{
		// Приведение схемы — ОДИН раз на пакет, у выдающего базу.
		// Прежде его приписывал каждый вызывающий своей копией; забывший
		// получал `relation … does not exist` — отказ, читающийся как дефект
		// продукта. Довод целиком — `internal/pgtest` §searchpath.
		SearchPath: "kacho_iam,public",
		Name:       "iam",
		Migrate:    pgtest.Goose(migrations.FS),
	}))
}

// testLoggerWriter — переходник t.Log→io.Writer: каждая запись становится одной
// строкой журнала теста, поэтому вывод slog и вывод сервера TLS остаются
// приклеенными к СВОЕЙ пробе, а не уезжают в общий stderr пакета.
//
// Живёт здесь, а не рядом с одним из читателей, потому что читателей ДВА и они о
// разном: durable-компенсация (`observability.NewSlogger`) и сервер TLS
// (`httptest.Server.Config.ErrorLog`). Прежний дом — набор очереди намерений
// внешнего движка — снят вместе с движком; заводить рядом с каждым читателем по
// своей копии значило бы две вещи на одну работу.
type testLoggerWriter struct{ t *testing.T }

func (w testLoggerWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s", strings.TrimRight(string(p), "\n"))
	return len(p), nil
}
