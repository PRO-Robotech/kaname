// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	abrepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/jackc/pgx/v5/pgconn"
)

// GrantDelegationRevokeParticipant использует общий bounded withdrawal spool.
// PRO-Robotech/kaname#1034: полный каскад готовится до fences, а строка
// делегирования, все выдачи и проекция отзываются в одной свежей RC TX.
type GrantDelegationRevokeParticipant struct{ binding *BindingStageParticipant }

func NewGrantDelegationRevokeParticipant(ctx context.Context, binding *BindingStageParticipant) (*GrantDelegationRevokeParticipant, error) {
	if binding == nil || binding.owner == nil || binding.owner.repo == nil {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	if err := binding.owner.bundle.Validate(); err != nil {
		return nil, err
	}
	// Неполный startup handoff не откладывает отказ до первого Revoke.
	// SQL проверяет реальный protected источник, а не номер миграции.
	var ready bool
	err := binding.owner.repo.master.QueryRow(ctx, `SELECT
 NOT pg_catalog.has_table_privilege(current_user,'kaname.authority_binding_epoch','INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
 AND NOT pg_catalog.has_table_privilege(current_user,'kaname.authority_policy_epoch','INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
 AND pg_catalog.has_function_privilege(current_user,'kaname.authority_policy_epoch_read(text[])','EXECUTE')
 AND pg_catalog.has_function_privilege(current_user,'kaname.authority_policy_epoch_lock(jsonb)','EXECUTE')
 AND (SELECT count(*)=4 FROM pg_catalog.pg_trigger WHERE tgrelid='kaname.grant_delegations'::pg_catalog.regclass AND tgenabled='O' AND tgfoid='kaname.authority_binding_epoch_changed()'::pg_catalog.regprocedure AND tgname IN ('binding_epoch_insert','binding_epoch_update','binding_epoch_delete','binding_epoch_truncate'))`).Scan(&ready)
	if err != nil {
		return nil, err
	}
	if !ready {
		return nil, errors.New("delegation revoke requires protected complete source epochs")
	}
	return &GrantDelegationRevokeParticipant{binding: binding}, ctx.Err()
}

func (p *GrantDelegationRevokeParticipant) GrantDelegationRevokeWriter(ctx context.Context, id domain.GrantDelegationID) (result kaname.GrantDelegationRevokeWriter, err error) {
	if p == nil || p.binding == nil || id == "" {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	stage, err := p.binding.stageWithdrawal(ctx, bindingWithdrawalSelection{DelegationID: id})
	if err != nil {
		return nil, delegationRevokeStageError(err)
	}
	var w *authorityWriteTx
	defer func() {
		if err == nil {
			return
		}
		if w != nil {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			_ = w.Rollback(cleanup)
			cancel()
		}
		stage.close()
		err = delegationRevokeStageError(err)
	}()
	w, err = stage.open(ctx, p.binding.owner, "participant")
	if err != nil {
		return nil, err
	}
	current, err := w.AccessBindingsW().GrantDelegationsW().LockForRevoke(ctx, id)
	if err != nil {
		return nil, err
	}
	if err = stage.lockBindings(ctx, w); err != nil {
		return nil, err
	}
	// Pair, GD row, binding advisory/rows могли ждать legacy writers. Только
	// после всех ожиданий проверяем тот же epoch snapshot и берём DB decision_at.
	if err = stage.recheck(ctx, w); err != nil {
		return nil, err
	}
	return &grantDelegationRevokeTx{
		grantDelegationWriteTx: &grantDelegationWriteTx{authorityWriteTx: w, bundle: p.binding.owner.bundle},
		stage:                  stage, delegation: current,
	}, nil
}

func delegationRevokeStageError(err error) error {
	var pe *pgconn.PgError
	if errors.Is(err, kaname.ErrAuthorityClassificationChanged) || (errors.As(err, &pe) && (pe.Code == "40001" || pe.Code == "40P01")) {
		return errors.Join(iamerr.ErrAborted, err)
	}
	return err
}

type grantDelegationRevokeTx struct {
	*grantDelegationWriteTx
	stage      *bindingWithdrawalStage
	delegation domain.GrantDelegation
	applied    bool
}

func (w *grantDelegationRevokeTx) LockedGrantDelegation() domain.GrantDelegation { return w.delegation }

func (w *grantDelegationRevokeTx) WithdrawGrantDelegation(ctx context.Context, d domain.GrantDelegation, actor string, at time.Time) (int, error) {
	if w.stage == nil || w.applied || d.ID != w.delegation.ID || d.Status != domain.GrantDelegationRevoked {
		return 0, kaname.ErrInvalidAuthorityFencePlan
	}
	revoked := 0
	err := w.stage.visitBindings(ctx, w.authorityWriteTx, func(ctx context.Context, b domain.AccessBinding) error {
		ok, err := w.AccessBindingsW().GrantDelegationsW().RevokeBindingForDelegation(ctx, b.ID, domain.UserID(actor), at)
		if err != nil {
			return err
		}
		// Epoch recheck и row locks исключают пропуск ранее staged ACTIVE строки.
		// Не выпускаем её delete commands после проигранного CAS.
		if !ok {
			return kaname.ErrAuthorityClassificationChanged
		}
		subjects := b.Subjects
		if len(subjects) == 0 {
			subjects = []domain.Subject{{Type: b.SubjectType, ID: b.SubjectID}}
		}
		for _, s := range subjects {
			if err = w.AccessBindingsW().EmitSubjectChangeEvent(ctx, abrepo.SubjectChangeEvent{SubjectID: string(s.ID), SubjectType: string(s.Type), EventType: "binding_revoke", Op: "binding_delete"}); err != nil {
				return err
			}
			if err = w.AccessBindingsW().EmitAuditEvent(ctx, abrepo.AuditEvent{
				EventType: "iam.access_binding.delegation_revoked", Actor: actor, SubjectType: string(s.Type), SubjectID: string(s.ID),
				ResourceType: string(b.ResourceType), ResourceID: b.ResourceID, RoleID: string(b.RoleID), BindingID: string(b.ID), TenantAccountID: string(d.AccountID),
				ExtraPayload: map[string]any{"delegation_id": string(d.ID), "revocation_reason": "delegation_revoked"},
			}); err != nil {
				return err
			}
		}
		revoked++
		return nil
	})
	if err != nil {
		return 0, delegationRevokeStageError(err)
	}
	if err = w.stage.emitDeletes(ctx, w.authorityWriteTx); err != nil {
		return 0, delegationRevokeStageError(err)
	}
	w.applied = true
	return revoked, nil
}
func (w *grantDelegationRevokeTx) Commit(ctx context.Context) error {
	if !w.applied {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	err := w.grantDelegationWriteTx.Commit(ctx)
	if err == nil {
		w.closeStage()
	}
	return delegationRevokeStageError(err)
}
func (w *grantDelegationRevokeTx) Rollback(ctx context.Context) error {
	err := w.grantDelegationWriteTx.Rollback(ctx)
	w.closeStage()
	return err
}
func (w *grantDelegationRevokeTx) closeStage() {
	if w.stage != nil {
		w.stage.close()
		w.stage = nil
	}
}

var _ kaname.GrantDelegationRevokeWriterFactory = (*GrantDelegationRevokeParticipant)(nil)
var _ kaname.GrantDelegationRevokeWriter = (*grantDelegationRevokeTx)(nil)
