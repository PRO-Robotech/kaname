// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// postgres.go — production-реализация миграций для PostgreSQL через
// goose + pgx driver.
package migrator

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"

	"github.com/pressly/goose/v3"
)

// Dialect — PostgreSQL-миграции (единственный поддерживаемый диалект;
// конструируется через NewDialect).
type Dialect struct{}

func (p *Dialect) Spec() DialectSpec { return SpecPostgres }

func (p *Dialect) Up(ctx context.Context, dsn string, fsys fs.FS, dir string, target string) error {
	db, err := openPgxDB(dsn, p.Spec())
	if err != nil {
		return err
	}
	defer db.Close()

	if err := setupGoose(fsys, p.Spec()); err != nil {
		return err
	}
	if target == "" {
		return goose.UpContext(ctx, db, dir)
	}
	version, perr := parseTargetVersion(target)
	if perr != nil {
		return perr
	}
	return goose.UpToContext(ctx, db, dir, version)
}

func (p *Dialect) Down(ctx context.Context, dsn string, fsys fs.FS, dir string, target string) error {
	db, err := openPgxDB(dsn, p.Spec())
	if err != nil {
		return err
	}
	defer db.Close()

	if err := setupGoose(fsys, p.Spec()); err != nil {
		return err
	}
	if target == "" {
		return goose.DownContext(ctx, db, dir)
	}
	version, perr := parseTargetVersion(target)
	if perr != nil {
		return perr
	}
	return goose.DownToContext(ctx, db, dir, version)
}

func (p *Dialect) Status(ctx context.Context, dsn string, fsys fs.FS, dir string, out io.Writer) error {
	db, err := openPgxDB(dsn, p.Spec())
	if err != nil {
		return err
	}
	defer db.Close()

	if err := setupGoose(fsys, p.Spec()); err != nil {
		return err
	}
	_ = out // goose v3 пишет в свой logger
	return goose.StatusContext(ctx, db, dir)
}

func (p *Dialect) Create(physDir, name string) error {
	if name == "" {
		return errors.New("migration name is empty")
	}
	if physDir == "" {
		return errors.New("physical migrations directory is empty (--dir)")
	}
	if err := goose.SetDialect(p.Spec().GooseDialect); err != nil {
		return fmt.Errorf("goose set dialect %q: %w", p.Spec().GooseDialect, err)
	}
	return goose.Create(nil, physDir, name, "sql")
}

// openPgxDB / setupGoose — helpers, параметризованные DialectSpec.

func openPgxDB(dsn string, spec DialectSpec) (*sql.DB, error) {
	db, err := sql.Open(spec.SQLDriver, dsn)
	if err != nil {
		return nil, fmt.Errorf("open db (driver=%s): %w", spec.SQLDriver, err)
	}
	return db, nil
}

func setupGoose(fsys fs.FS, spec DialectSpec) error {
	goose.SetBaseFS(fsys)
	if err := goose.SetDialect(spec.GooseDialect); err != nil {
		return fmt.Errorf("goose set dialect %q: %w", spec.GooseDialect, err)
	}
	return nil
}
