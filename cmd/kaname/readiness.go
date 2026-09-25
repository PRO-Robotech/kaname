// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// readiness.go — носитель живости и готовности службы: ЧТО проверяется.
//
// Носитель строит композиционный корень, потому что только он знает, какая
// база своя и к кому служба ходит. Строится он ОДИН раз и отдаётся тому, кто
// его монтирует, и тому, кто гасит: `SetShuttingDown` переводит `/readyz` в
// 503 ДО остановки серверов, и знает о начале гашения только `serve.go`
// (#1752).

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/corelib/observability/health"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/corelib/schemaguard"

	"github.com/PRO-Robotech/kaname/internal/migrations"
	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
)

// buildReadiness — носитель готовности с зависимостями службы и зеркалом их
// исхода в величину.
func buildReadiness(pool *pgxpool.Pool, metricsReg *metrics.Registry) *health.Aggregator {
	// Готовность строит ОБЪЯВЛЕННЫЙ носитель (`corelib/observability/health`),
	// а не своя форма в handler-слое (#1752): срок на чекер, различение
	// «носитель не провязан»/«носитель ответил», перевод в 503 на гашении и
	// зеркало результата — свойства, которые он уже решил, и решать их второй
	// раз по месту значило бы завести расхождение, которому нечем себя выдать.
	readinessCheckers := []health.Checker{
		{Name: "database", Check: pool.Ping},
		// ВЕРСИЯ СХЕМЫ — ОТДЕЛЬНАЯ ИМЕНОВАННАЯ ЗАВИСИМОСТЬ, а не часть
		// проверки базы. Мигратор идёт при каждом раскате, поэтому откат
		// выкатки ставит ПРЕЖНИЙ образ на НОВУЮ схему; база при этом
		// отвечает на `Ping`, и без этого чекера под объявлялся бы готовым и
		// получал трафик (`pkg/schemaguard`, задача #1734). Отдельное имя
		// обязательно: оператор обязан отличить «база недоступна» от «образ
		// не той версии, что схема», не читая кода.
		//
		// Набор миграций читается как встроенные байты, у базы спрашивается
		// ОДИН `SELECT` применённой версии — least-privilege serve-бинаря
		// сохраняется, схему он по-прежнему не меняет.
		{Name: schemaguard.CheckerName, Check: schemaguard.CheckFromFS(
			migrations.FS, schemaguard.PgxVersionReader(pool))},
		{Name: "lro-worker", Check: func(context.Context) error {
			if operations.Ready() {
				return nil
			}
			return errors.New("lro worker not ready")
		}},
	}
	// ИСХОД ГОТОВНОСТИ ЗЕРКАЛИТСЯ В ВЕЛИЧИНУ, и это не украшение витрины
	// (#2494). Без зеркала наружу выходит ОДИН БИТ: дежурный чужой установки
	// — а kaname поставляется именно так, отдельно — не отличает «база
	// недоступна» (сломан продукт) от «образ не той версии, что схема»
	// (условие не создано).
	//
	// Набор зависимостей выводится ИЗ ТОГО ЖЕ среза, которым построен носитель:
	// второй перечень отстал бы от первого молча, и отставший чекер остался бы
	// без рядов — то есть невидимым ровно так же, как до этой провязки.
	readinessValues := metricsReg.ReadinessRecorder(readinessDependencyNames(readinessCheckers))
	return health.New(readinessCheckers,
		health.WithResultObserver(readinessValues.Observe))
}

// readinessDependencyNames — имена объявленных чекеров в порядке объявления.
//
// Выведение, а не второй перечень: набор рядов величины обязан совпадать с
// набором зависимостей by construction, иначе добавленный чекер остаётся без
// рядов и не наблюдаем — тот же дефект, который эта провязка и снимает.
func readinessDependencyNames(checkers []health.Checker) []string {
	names := make([]string, 0, len(checkers))
	for _, c := range checkers {
		names = append(names, c.Name)
	}
	return names
}
