// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type semanticAuthorityWriteTx struct {
	*authorityWriteTx
	bundle  *granteffect.Bundle
	checker kaname.RelationChecker
}

func (w *semanticAuthorityWriteTx) SemanticBundle() *granteffect.Bundle             { return w.bundle }
func (w *semanticAuthorityWriteTx) SemanticRelationChecker() kaname.RelationChecker { return w.checker }

// SemanticAuthorityWriter не активирует identity и не пересчитывает её из
// глобального кэша. Строка БД остаётся закрытой для изменения до конца writer.
// Это узкая граница сравнения; legacy writers ещё не подчинены её протоколу.
func (r *Repository) compareAuthorityIdentity(ctx context.Context, plan kaname.AuthorityFencePlan, bundle *granteffect.Bundle) (_ kaname.SemanticAuthorityWriter, err error) {
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = bundle.Validate(); err != nil {
		return nil, err
	}
	opened, err := r.AuthorityWriter(ctx, plan)
	if err != nil {
		return nil, err
	}
	w := opened.(*authorityWriteTx)
	transferred := false
	defer func() {
		if transferred {
			return
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if rollbackErr := w.Rollback(cleanup); rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
			err = errors.Join(err, fmt.Errorf("semantic writer rollback: %w", rollbackErr))
		}
	}()
	identity := bundle.Identity()
	// Владелец helper берёт identity FOR SHARE; обычный LOGIN сохраняет только
	// SELECT ACL на private identity и не получает UPDATE ради row lock.
	err = w.tx.QueryRow(ctx, `SELECT kaname.authority_compare_identity_v2($1,$2,$3)`, identity.ModelID, identity.CatalogID, identity.ProjectorVersion).Scan(&w.fence.decisionAt)
	if err != nil {
		var pgerr *pgconn.PgError
		if errors.As(err, &pgerr) && pgerr.Code == "P1036" {
			return nil, errors.Join(kaname.ErrSemanticIdentityUnavailable, err)
		}
		return nil, err
	}
	w.fence.decisionAt = w.fence.decisionAt.UTC()
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	transferred = true
	return newSemanticAuthorityWriter(w, bundle), nil
}

var _ kaname.SemanticAuthorityWriterFactory = (*Repository)(nil)
var _ kaname.SemanticAuthorityWriter = (*semanticAuthorityWriteTx)(nil)

// Единственная сборка native checker: новый entry и прежний compare-only порт
// используют тот же bundle и время после всех своих ожиданий.
func newSemanticAuthorityWriter(w *authorityWriteTx, bundle *granteffect.Bundle) *semanticAuthorityWriteTx {
	checker := newLiveAdministrativeChecker(w, bundle)
	return &semanticAuthorityWriteTx{authorityWriteTx: w, bundle: bundle, checker: checker}
}

// Старый широкий read API не содержал входного actor/native плана. После
// consumer cutover он закрыт; identity-only пробы используют явный пустой intent.
func (r *Repository) SemanticAuthorityWriter(ctx context.Context, plan kaname.AuthorityFencePlan, bundle *granteffect.Bundle) (kaname.SemanticAuthorityWriter, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := bundle.Validate(); err != nil {
		return nil, err
	}
	if _, err := canonicalAuthorityAccounts(plan); err != nil {
		return nil, err
	}
	return nil, kaname.ErrSemanticReadPlanRequired
}
