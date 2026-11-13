// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	"github.com/PRO-Robotech/kaname/internal/grantcoverage"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/personmarks"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
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
func (r *Repository) SemanticAuthorityWriter(ctx context.Context, plan kaname.AuthorityFencePlan, bundle *granteffect.Bundle) (_ kaname.SemanticAuthorityWriter, err error) {
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
	var phase string
	var protocol int
	var active grantcoverage.Identity
	err = w.tx.QueryRow(ctx, `SELECT phase, protocol_version, COALESCE(model_id,''), COALESCE(catalog_id,''), COALESCE(projector_version,'')
 FROM kaname.authority_semantic_identity WHERE singleton FOR SHARE`).Scan(&phase, &protocol, &active.ModelID, &active.CatalogID, &active.ProjectorVersion)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", kaname.ErrSemanticIdentityUnavailable, err)
	}
	if phase != "active" || protocol != 1 || active != bundle.Identity() {
		return nil, kaname.ErrSemanticIdentityUnavailable
	}
	// FOR SHARE мог ждать коммита. Время прежнего AuthorityWriter уже устарело:
	// решение и expiry используют новое время ПОСЛЕ всех ожиданий и сравнения.
	if err = w.tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&w.fence.decisionAt); err != nil {
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
	checker := authzcascade.WrapAdmitted(relverdict.NewSemanticTransactionAsker(w.tx, bundle, w.fence.decisionAt), personmarks.NewTransaction(w.tx))
	return &semanticAuthorityWriteTx{authorityWriteTx: w, bundle: bundle, checker: checker}
}
