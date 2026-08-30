// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// postgres.go — production-реализация миграций для PostgreSQL через
// goose + pgx driver.
package migrator

import (
	"context"
	"io"
	"io/fs"

	"github.com/pressly/goose/v3"

	"github.com/PRO-Robotech/kacho/pkg/migratorcli"
)

// Dialect — PostgreSQL-миграции (единственный поддерживаемый диалект;
// конструируется через NewDialect).
type Dialect struct{}

func (p *Dialect) Spec() migratorcli.DialectSpec { return migratorcli.SpecPostgres }

func (p *Dialect) Up(ctx context.Context, dsn string, fsys fs.FS, dir string, target string) error {
	db, err := migratorcli.OpenDB(ctx, dsn, p.Spec())
	if err != nil {
		return err
	}
	defer db.Close()

	if err := migratorcli.SetupGoose(fsys, p.Spec()); err != nil {
		return err
	}
	// ПРОПУЩЕННЫЕ МИГРАЦИИ ПРИНИМАЮТСЯ, и это не послабление, а следствие схемы
	// нумерации. Номер у нас — «задача × 1000 + порядок», и он НЕ хронологичен by
	// construction: задача #708 закрывается после #800, файл `708001` появляется в
	// дереве позже, чем `800001`. База, накатившая больший номер раньше, при
	// обновлении видит «пропущенную миграцию перед текущей версией» и отказывает —
	// служба не стартует вовсе.
	//
	// Замер на момент правки: таких пар в дереве 22, во ВСЕХ семи сервисах.
	// Конвейер их не видит by construction — он всегда поднимает чистую базу, где
	// пропущенных нет; воспроизводится только на обновлении развёрнутой (#1012).
	//
	// Приём пропущенной означает ПРИМЕНИТЬ её, а не пропустить; порядок внутри
	// одной задачи (`NNN001` до `NNN002`) goose сохраняет независимо от опции.
	if target == "" {
		return goose.UpContext(ctx, db, dir, goose.WithAllowMissing())
	}
	version, perr := migratorcli.ParseTargetVersion(target)
	if perr != nil {
		return perr
	}
	return goose.UpToContext(ctx, db, dir, version, goose.WithAllowMissing())
}

func (p *Dialect) Down(ctx context.Context, dsn string, fsys fs.FS, dir string, target string) error {
	db, err := migratorcli.OpenDB(ctx, dsn, p.Spec())
	if err != nil {
		return err
	}
	defer db.Close()

	if err := migratorcli.SetupGoose(fsys, p.Spec()); err != nil {
		return err
	}
	if target == "" {
		return goose.DownContext(ctx, db, dir)
	}
	version, perr := migratorcli.ParseTargetVersion(target)
	if perr != nil {
		return perr
	}
	return goose.DownToContext(ctx, db, dir, version)
}

func (p *Dialect) Status(ctx context.Context, dsn string, fsys fs.FS, dir string, out io.Writer) error {
	db, err := migratorcli.OpenDB(ctx, dsn, p.Spec())
	if err != nil {
		return err
	}
	defer db.Close()

	if err := migratorcli.SetupGoose(fsys, p.Spec()); err != nil {
		return err
	}
	_ = out // goose v3 пишет в свой logger
	return goose.StatusContext(ctx, db, dir)
}
