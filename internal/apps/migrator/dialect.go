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
package migrator

import "fmt"

// DialectSpec — описательная метадата диалекта для CLI-резолва и diagnostics.
type DialectSpec struct {
	Name         string
	GooseDialect string
	SQLDriver    string
}

// SpecPostgres — метадата единственного поддерживаемого диалекта.
var SpecPostgres = DialectSpec{
	Name:         "postgres",
	GooseDialect: "postgres",
	SQLDriver:    "pgx",
}

// NewDialect возвращает диалект по имени из CLI/конфига. Поддерживается только
// "postgres" (пустая строка → postgres по умолчанию); любое другое имя — ошибка
// с явным списком поддерживаемых значений.
func NewDialect(name string) (*Dialect, error) {
	switch name {
	case "", SpecPostgres.Name:
		return &Dialect{}, nil
	default:
		return nil, fmt.Errorf("unknown dialect %q (supported: %s)", name, SpecPostgres.Name)
	}
}
