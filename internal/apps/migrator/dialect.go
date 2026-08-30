// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package migrator — бизнес-логика отдельного бинаря cmd/migrator.
//
// dialect.go определяет единственный поддерживаемый диалект — PostgreSQL
// (реализация — [Dialect] в postgres.go). Раньше здесь жил интерфейс + фабрика
// + registry на два диалекта, но cockroach-ветка была байт-в-байт копией
// postgres (тот же goose-dialect "postgres", тот же pgx-драйвер) и не работала
// против реального CockroachDB (PL/pgSQL-триггеры / LISTEN-NOTIFY схемы). Seam
// удалён (speculative generality); если появится второй РЕАЛЬНО расходящийся
// диалект — интерфейс возвращается тогда.
//
// Метадата диалекта живёт в общем пакете — [migratorcli.SpecPostgres]; здесь
// она НЕ переобъявляется (#1383, docs/architecture/migrator-form.md).
package migrator

import (
	"fmt"

	"github.com/PRO-Robotech/kacho/pkg/migratorcli"
)

// NewDialect возвращает диалект по имени из CLI/конфига. Поддерживается только
// "postgres" (пустая строка → postgres по умолчанию); любое другое имя — ошибка
// с явным списком поддерживаемых значений.
//
// Приём пустой строки — известное расхождение с двумя соседями, и оно числится
// живой строкой ведомости `dialect-empty-accepted`
// (internal/repohygiene/migratordivergence_test.go). Здесь оно не снимается:
// его предмет — тип диалекта, а тот сводится вместе с накатом.
func NewDialect(name string) (*Dialect, error) {
	switch name {
	case "", migratorcli.SpecPostgres.Name:
		return &Dialect{}, nil
	default:
		return nil, fmt.Errorf("unknown dialect %q (supported: %s)", name, migratorcli.SpecPostgres.Name)
	}
}
