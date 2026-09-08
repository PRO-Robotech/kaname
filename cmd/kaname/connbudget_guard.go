// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// connbudget_guard.go — загрузочный страж: посадка не вправе обещать базе больше
// соединений, чем та принимает.
//
// # Почему это страж старта, а не наблюдение
//
// Соединения открываются лениво, поэтому пул, объявленный вдвое шире предела
// базы, ведёт себя неотличимо от посильного до самого мгновения, когда
// соединения понадобились, — то есть под нагрузкой. Проверка, отложенная до
// первого отказа, узнаёт о расхождении тогда же, когда о нём узнаёт арендатор.
//
// Предел пула берётся у САМОГО ПУЛА, а не из настройки: настройка бывает не
// задана, и тогда действует умолчание драйвера, зависящее от числа ядер узла.
// База получит именно его.
//
// # Почему предел спрашивается у базы
//
// Объявить его настройкой значило бы завести второе место об одном предмете и
// разойтись с базой молча. Хуже: настройка бывает не задана вовсе, и тогда база
// работает на умолчании сборки — «не объявлено» читалось бы как «не ограничено».

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
)

// connBudgetComplaint — то, что страж скажет оператору, или пустая ошибка.
//
// Вынесено отдельно от чтения предела ровно затем, чтобы пробе было что звать
// без базы: предмет здесь — СОСТАВЛЕНИЕ отказа из величин этой службы и имена
// ручек в его тексте, а способность прочитать предел у настоящей базы проверена
// там, где она живёт (`pkg/db`). Тот же приём, что у соседнего стража проводки.
//
// Текст называет обе ручки: это рантайм-диагностика, которую читает оператор, и
// отказ, не сказавший что чинить, стенд не поднимет.
func connBudgetComplaint(poolMaxConns int32, replicaBudget int, ceiling coredb.ConnCeiling) error {
	err := coredb.ConnBudget{PoolMaxConns: poolMaxConns, Replicas: replicaBudget}.Validate(ceiling)
	if err == nil {
		return nil
	}
	return fmt.Errorf("KANAME_REPOSITORY__POSTGRES__MAX_CONNS / "+
		"KANAME_REPOSITORY__POSTGRES__REPLICA_BUDGET: %w", err)
}

// assertConnBudgetFits отказывает в старте, когда обещанное не помещается.
func assertConnBudgetFits(ctx context.Context, pool *pgxpool.Pool, replicaBudget int) error {
	ceiling, err := coredb.ReadConnCeiling(ctx, pool)
	if err != nil {
		return fmt.Errorf("предел соединений базы не прочитан: %w — "+
			"стартовать, не зная предела, значит принять «не прочитано» за «не ограничено»", err)
	}
	return connBudgetComplaint(pool.Config().MaxConns, replicaBudget, ceiling)
}
