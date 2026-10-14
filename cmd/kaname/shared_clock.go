// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/revocationpolicy"
)

// buildSharedClock — ЕДИНСТВЕННОЕ место, где решается, чьими часами ставятся
// моменты, сравниваемые с отсечкой отзыва-всех: сама отсечка «сейчас», выдача
// долговременного удостоверения, аутентификация сессии и `iat` (kaname#589).
//
// Ответ — часы первичной базы через ПИШУЩИЙ пул: он один на все реплики службы,
// и им же ставят отсечку схемные писатели. Реплика чтения сюда не подаётся —
// это другой хост с другими часами.
//
// Предел на вызов — тот же, что у чтения отсечки на полосах выдачи
// ([credentialLanePeerTimeout]): момент и отсечка читаются одним видом запроса
// к одной базе. Источник не ответил — глагол отказывает; запасного пути к часам
// процесса нет.
func buildSharedClock(pool *pgxpool.Pool) (revocationpolicy.Clock, error) {
	if pool == nil {
		return nil, fmt.Errorf("общий источник моментов: %w", revocationpolicy.ErrNoClock)
	}
	clock, err := revocationpolicy.ClockWithDeadline(kanamepg.NewSharedClock(pool), credentialLanePeerTimeout)
	if err != nil {
		return nil, fmt.Errorf("общий источник моментов: %w", err)
	}
	return clock, nil
}
