// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// cockroach.go — scaffold-реализация [Dialect] для CockroachDB.
//
// # Production caveats для kacho-iam
//
//   - Партиальные UNIQUE-индексы (`roles_custom_unique`, `roles_system_unique`,
//     `accounts_owner_idx`, ... в `0001_initial.sql`) — CockroachDB их
//     поддерживает, parity OK.
//   - PL/pgSQL триггеры (`group_members_member_exists_trg`,
//     `kacho_iam.iam_permissions_valid()`) — CRDB не поддерживает PL/pgSQL.
//     Под cockroach придется переписать на client-side validation либо CHECK
//     с SQL-функциями (subset of CRDB syntax).
//   - pg_notify / LISTEN/NOTIFY — invalidate-cache path (CHANGEFEED INTO sink).
//
// Не тестируется против real CockroachDB; scaffold-only.
package migrator

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"

	"github.com/pressly/goose/v3"
)

// cockroachDialect — scaffold-реализация [Dialect] для CockroachDB.
type cockroachDialect struct{}

func newCockroachDialect() *cockroachDialect { return &cockroachDialect{} }

func (c *cockroachDialect) Spec() DialectSpec { return SpecCockroach }

func (c *cockroachDialect) Up(ctx context.Context, dsn string, fsys fs.FS, dir string, target string) error {
	db, err := openPgxDB(dsn, c.Spec())
	if err != nil {
		return err
	}
	defer db.Close()

	if err := setupGoose(fsys, c.Spec()); err != nil {
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

func (c *cockroachDialect) Down(ctx context.Context, dsn string, fsys fs.FS, dir string, target string) error {
	db, err := openPgxDB(dsn, c.Spec())
	if err != nil {
		return err
	}
	defer db.Close()

	if err := setupGoose(fsys, c.Spec()); err != nil {
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

func (c *cockroachDialect) Status(ctx context.Context, dsn string, fsys fs.FS, dir string, out io.Writer) error {
	db, err := openPgxDB(dsn, c.Spec())
	if err != nil {
		return err
	}
	defer db.Close()

	if err := setupGoose(fsys, c.Spec()); err != nil {
		return err
	}
	_ = out // goose v3 пишет в свой logger
	return goose.StatusContext(ctx, db, dir)
}

func (c *cockroachDialect) Create(physDir, name string) error {
	if name == "" {
		return errors.New("migration name is empty")
	}
	if physDir == "" {
		return errors.New("physical migrations directory is empty (--dir)")
	}
	if err := goose.SetDialect(c.Spec().GooseDialect); err != nil {
		return fmt.Errorf("goose set dialect %q: %w", c.Spec().GooseDialect, err)
	}
	return goose.Create(nil, physDir, name, "sql")
}
