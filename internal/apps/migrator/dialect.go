// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package migrator — бизнес-логика отдельного бинаря cmd/migrator.
//
// dialect.go определяет ключевую абстракцию пакета — интерфейс [Dialect]
// (migrator должен быть multi-dialect-ready). Каждая поддерживаемая БД —
// отдельная реализация (`postgres.go`, `cockroach.go`); фабрика [NewDialect]
// выбирает реализацию по имени из CLI/конфига.
package migrator

import (
	"context"
	"fmt"
	"io"
	"io/fs"
)

// Dialect — абстракция SQL-диалекта для миграций.
type Dialect interface {
	// Up применяет миграции вверх. target=="" → до самой последней.
	Up(ctx context.Context, dsn string, fsys fs.FS, dir string, target string) error
	// Down откатывает миграцию(и). target=="" → одна последняя.
	Down(ctx context.Context, dsn string, fsys fs.FS, dir string, target string) error
	// Status печатает примененные/непримененные миграции в логгер goose.
	Status(ctx context.Context, dsn string, fsys fs.FS, dir string, out io.Writer) error
	// Create создает пустой .sql-файл миграции на физическом диске.
	Create(physDir, name string) error
	// Spec возвращает CLI-метадату диалекта.
	Spec() DialectSpec
}

// DialectSpec — описательная метадата диалекта для CLI-резолва и тестов.
type DialectSpec struct {
	Name         string
	GooseDialect string
	SQLDriver    string
}

// Built-in spec'и — exposed для тестов и diagnostics.
var (
	SpecPostgres = DialectSpec{
		Name:         "postgres",
		GooseDialect: "postgres",
		SQLDriver:    "pgx",
	}
	SpecCockroach = DialectSpec{
		Name:         "cockroach",
		GooseDialect: "postgres",
		SQLDriver:    "pgx",
	}
)

// dialectFactory — конструктор реализации [Dialect] по имени.
type dialectFactory func() Dialect

// registry — name → factory.
var registry = map[string]dialectFactory{
	SpecPostgres.Name:  func() Dialect { return newPostgresDialect() },
	SpecCockroach.Name: func() Dialect { return newCockroachDialect() },
}

// NewDialect — фабрика, возвращает реализацию [Dialect] по имени.
func NewDialect(name string) (Dialect, error) {
	factory, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown dialect %q (supported: %v)", name, listDialects())
	}
	return factory(), nil
}

// ResolveDialect — backwards-compat обертка над [NewDialect].
func ResolveDialect(name string) (Dialect, error) {
	return NewDialect(name)
}

func listDialects() []string {
	out := make([]string, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	return out
}
