// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// catalog_applied_edition.go — ЧТЕНИЕ применённой пары редакции модуля
// (kaname#865): `catalog_module.applied_revision` и `applied_digest`.
//
// Читателей два — план (в своей читающей транзакции, рядом с отпечатком
// состояния) и `Get` (над пулом), — а оператор один: выписанный дважды, он
// разошёлся бы составом колонок молча.

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
)

// appliedEditionSQL — применённая пара одного модуля; строки нет — ноль строк.
const appliedEditionSQL = `
	SELECT applied_revision, applied_digest
	  FROM kaname.catalog_module
	 WHERE module = $1`

// queryRower — то, что умеют и пул, и транзакция.
type queryRower interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// readAppliedEdition — применённая пара модуля; nil — строки нет либо пара
// пуста.
func readAppliedEdition(ctx context.Context, q queryRower, module string) (*modulecatalog.Edition, error) {
	var (
		rev    *int64
		digest *string
	)
	err := q.QueryRow(ctx, appliedEditionSQL, module).Scan(&rev, &digest)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("прочитать применённую редакцию модуля %s: %w", module, err)
	}
	ed, err := editionOf(rev, digest)
	if err != nil {
		return nil, fmt.Errorf("строка модуля %s: %w", module, err)
	}
	return ed, nil
}

// editionOf — пара из двух колонок. Половина пары — отказ, а не «пары нет»:
// схема её не допускает (`catalog_module_applied_pair`), и прочитанная
// половина означала бы, что читается не та схема.
func editionOf(rev *int64, digest *string) (*modulecatalog.Edition, error) {
	switch {
	case rev == nil && digest == nil:
		return nil, nil
	case rev == nil || digest == nil:
		return nil, errors.New("применённая редакция прочитана половиной пары: номер и отпечаток пусты или заполнены только вместе")
	default:
		return &modulecatalog.Edition{Revision: *rev, Digest: *digest}, nil
	}
}

// ReadAppliedEdition — применённая пара редакции модуля над пулом (порт `Get`,
// kaname#865).
func (r *CatalogRepo) ReadAppliedEdition(ctx context.Context, module string) (*modulecatalog.Edition, error) {
	return readAppliedEdition(ctx, r.pool, module)
}
