// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package migrator — обертка над goose, которую дергает cmd/migrator/main.go.
//
// Embed FS (`internal/migrations/*.sql`) принимается параметром Config.FS,
// чтобы runner не тянул прямой импорт `internal/migrations` (зависимость
// одно-направленная: cmd/migrator → internal/apps/migrator + internal/migrations,
// `internal/apps/migrator` ни к чему iam-specific не привязан).
package migrator

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
)

// Config — параметры одного запуска runner'а.
type Config struct {
	Dialect       *Dialect
	DSN           string
	FS            fs.FS
	MigrationsDir string
}

// Validate проверяет минимально необходимые поля перед обращением к диалекту.
func (c Config) Validate() error {
	if c.Dialect == nil {
		return errors.New("dialect is not set")
	}
	if c.Dialect.Spec().Name == "" {
		return errors.New("dialect spec.Name is empty")
	}
	if c.DSN == "" {
		return errors.New("dsn is empty (set --dsn or KACHO_MIGRATOR_DSN)")
	}
	if c.FS == nil {
		return errors.New("migrations FS is nil")
	}
	if c.MigrationsDir == "" {
		return errors.New("migrations dir is empty")
	}
	return nil
}

// Runner — высокоуровневая обертка над [Dialect].
type Runner struct {
	cfg Config
}

// New собирает Runner; cfg валидируется здесь же.
func New(cfg Config) (*Runner, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Runner{cfg: cfg}, nil
}

// Up прогоняет миграции вверх. Делегирует в Dialect-impl.
func (r *Runner) Up(target string) error {
	return r.cfg.Dialect.Up(context.Background(), r.cfg.DSN, r.cfg.FS, r.cfg.MigrationsDir, target)
}

// Down откатывает миграции. Делегирует в Dialect-impl.
func (r *Runner) Down(target string) error {
	return r.cfg.Dialect.Down(context.Background(), r.cfg.DSN, r.cfg.FS, r.cfg.MigrationsDir, target)
}

// Status печатает примененные/непримененные миграции.
func (r *Runner) Status(out io.Writer) error {
	return r.cfg.Dialect.Status(context.Background(), r.cfg.DSN, r.cfg.FS, r.cfg.MigrationsDir, out)
}

// Create создает новый sql-файл миграции на диске.
func (r *Runner) Create(physDir, name string) error {
	return r.cfg.Dialect.Create(physDir, name)
}

// parseTargetVersion парсит CLI-строку target version в int64 для goose.
func parseTargetVersion(s string) (int64, error) {
	var v int64
	if _, err := fmt.Sscanf(s, "%d", &v); err != nil {
		return 0, fmt.Errorf("parse target version %q: %w", s, err)
	}
	if v < 0 {
		return 0, fmt.Errorf("target version must be non-negative, got %d", v)
	}
	return v, nil
}
