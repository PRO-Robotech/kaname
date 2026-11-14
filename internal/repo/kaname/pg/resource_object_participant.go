// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ResourceObjectParticipant подключает регистрацию и одиночное сведение.
// Текущая SQL-классификация registration/mirror и членов не-group требует
// GLOBAL. Режим выбран ДО entry, а не после отказа локального плана.
// Это участие в протоколе TX, не новый допуск модуля или выдачи.
type ResourceObjectParticipant struct {
	repo   *Repository
	bundle *granteffect.Bundle
}

func NewResourceObjectParticipant(ctx context.Context, repo *Repository, bundle *granteffect.Bundle) (*ResourceObjectParticipant, error) {
	if repo == nil || repo.master == nil {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	if err := bundle.Validate(); err != nil {
		return nil, err
	}
	if err := repo.ValidateAuthorityRuntime(ctx); err != nil {
		return nil, err
	}
	return &ResourceObjectParticipant{repo: repo, bundle: bundle}, nil
}

// RegistrationTxBeginner связывает opener с тем же runtime pool, который
// использует корень композиции. Чужой pool не исправляется запасным путём.
func (p *ResourceObjectParticipant) RegistrationTxBeginner(pool *pgxpool.Pool) (service.TxBeginner, error) {
	if p == nil || p.repo == nil || pool == nil || p.repo.master != pool {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	if err := p.bundle.Validate(); err != nil {
		return nil, err
	}
	return &resourceRegistrationBeginner{participant: p, pool: pool}, nil
}

func (p *ResourceObjectParticipant) begin(ctx context.Context) (*authorityWriteTx, error) {
	if p == nil || p.repo == nil || p.repo.master == nil {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	return p.repo.coordinatedAuthorityWriter(ctx, kaname.AuthorityWriteIntent{
		Kind: kaname.AuthorityResource, Bundle: p.bundle, Plan: kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal},
	}, "participant")
}

type resourceRegistrationBeginner struct {
	participant *ResourceObjectParticipant
	pool        *pgxpool.Pool
}

func (b *resourceRegistrationBeginner) Begin(ctx context.Context) (service.Tx, error) {
	if b == nil || b.participant == nil || b.participant.repo == nil || b.pool == nil || b.pool != b.participant.repo.master {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	w, err := b.participant.begin(ctx)
	if err != nil {
		return nil, err
	}
	return &resourceParticipantTx{Tx: w.tx, owner: w}, nil
}

type resourceParticipantTx struct {
	pgx.Tx
	owner *authorityWriteTx
}

func (t *resourceParticipantTx) Commit(ctx context.Context) error { return t.owner.Commit(ctx) }
func (t *resourceParticipantTx) Rollback(ctx context.Context) error {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return t.owner.Rollback(cleanup)
}

// Движок читает тот же immutable каталог, что и участник. Полный sweep по
// binding этим opener не разрешён: для него существует отдельный staged path.
func (p *ResourceObjectParticipant) NewObjectReconciler(logger *slog.Logger) (*reconcile.Reconciler, error) {
	if p == nil || p.repo == nil {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	if err := p.bundle.Validate(); err != nil {
		return nil, err
	}
	var halves catalog.Halves
	if err := json.Unmarshal(p.bundle.CanonicalCatalog(), &halves); err != nil {
		return nil, err
	}
	facts, err := catalog.NewFacts(halves)
	if err != nil {
		return nil, err
	}
	return reconcile.New(&resourceObjectTransactions{participant: p, facts: facts}, logger, catalog.Fixed{F: facts}), nil
}

type resourceObjectTransactions struct {
	participant *ResourceObjectParticipant
	facts       *catalog.Facts
}

func (*resourceObjectTransactions) WithTx(context.Context, func(context.Context, reconcile.ReconcileStore) error) error {
	return errors.New("resource participant requires a single object intent")
}
func (p *resourceObjectTransactions) WithObjectTx(ctx context.Context, typ, id string, fn func(context.Context, reconcile.ReconcileStore) error) error {
	// В имени объекта допустим '/', но не разделители координат модели.
	if p == nil || p.facts == nil || typ == "" || id == "" || strings.ContainsAny(typ+id, ":#* \t\r\n\x00") || fn == nil {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	w, err := p.participant.begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = w.Rollback(cleanup)
	}()
	if err = fn(ctx, &reconcileStore{tx: w.tx, cat: p.facts, decisionAt: w.AuthorityFence().DecisionAt()}); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	return w.Commit(ctx)
}

var _ service.TxBeginner = (*resourceRegistrationBeginner)(nil)
var _ pgx.Tx = (*resourceParticipantTx)(nil)
var _ reconcile.ObjectTxRunner = (*resourceObjectTransactions)(nil)
