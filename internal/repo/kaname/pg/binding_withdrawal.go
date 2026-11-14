// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	ab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/jackc/pgx/v5/pgconn"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (p *BindingStageParticipant) WithdrawBinding(ctx context.Context, id domain.AccessBindingID, kind kaname.BindingWithdrawalKind, actor string, before func(context.Context, kaname.Writer, clients.RelationStore, domain.AccessBinding) error, after func(context.Context, kaname.Writer, domain.AccessBinding) error) (domain.AccessBinding, error) {
	if p == nil || id == "" || kind < kaname.BindingWithdrawalDelete || kind > kaname.BindingWithdrawalExpiry {
		return domain.AccessBinding{}, kaname.ErrInvalidAuthorityFencePlan
	}
	if kind != kaname.BindingWithdrawalExpiry && (before == nil || after == nil) {
		return domain.AccessBinding{}, kaname.ErrInvalidAuthorityFencePlan
	}
	var last error
	for attempt := 0; attempt < authorityEntryAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return domain.AccessBinding{}, err
		}
		out, err := p.withdrawBindingOnce(ctx, id, kind, actor, before, after)
		if err == nil {
			return out, nil
		}
		last = err
		var pe *pgconn.PgError
		if !errors.Is(err, kaname.ErrAuthorityClassificationChanged) && !errors.Is(err, iamerr.ErrAborted) && status.Code(err) != codes.Aborted && (!errors.As(err, &pe) || (pe.Code != "40001" && pe.Code != "40P01")) {
			return domain.AccessBinding{}, err
		}
	}
	return domain.AccessBinding{}, fmt.Errorf("binding withdrawal retry exhausted: %w", errors.Join(iamerr.ErrAborted, last))
}
func (p *BindingStageParticipant) withdrawBindingOnce(ctx context.Context, id domain.AccessBindingID, kind kaname.BindingWithdrawalKind, actor string, before func(context.Context, kaname.Writer, clients.RelationStore, domain.AccessBinding) error, after func(context.Context, kaname.Writer, domain.AccessBinding) error) (domain.AccessBinding, error) {
	stage, err := p.stageWithdrawal(ctx, bindingWithdrawalSelection{BindingID: id, requirePolicy: kind != kaname.BindingWithdrawalExpiry, global: kind == kaname.BindingWithdrawalDelete})
	if kind == kaname.BindingWithdrawalExpiry && errors.Is(err, iamerr.ErrNotFound) {
		return domain.AccessBinding{}, nil
	}
	if err != nil {
		return domain.AccessBinding{}, err
	}
	defer stage.close()
	w, err := stage.open(ctx, p.owner, "participant")
	if err != nil {
		return domain.AccessBinding{}, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = w.Rollback(cleanup)
	}()
	if err = stage.lockBindings(ctx, w); err != nil {
		return domain.AccessBinding{}, err
	}
	current, err := w.AccessBindings().Get(ctx, id)
	if err != nil {
		return domain.AccessBinding{}, err
	}
	// Epoch удерживает ровно тот же полный source graph. Финальное время — после
	// advisory/deactivation row waits; TTL не судится по времени начала TX.
	if err = stage.recheck(ctx, w); err != nil {
		return domain.AccessBinding{}, err
	}
	current.Subjects = stage.binding.Subjects
	if before != nil {
		native := newLiveAdministrativeChecker(w, p.owner.bundle)
		if err = before(ctx, w, native, current); err != nil {
			return domain.AccessBinding{}, err
		}
	}
	out := current
	switch kind {
	case kaname.BindingWithdrawalDelete:
		if err = w.AccessBindingsW().DeleteGuarded(ctx, id); err != nil {
			return domain.AccessBinding{}, err
		}
	case kaname.BindingWithdrawalRevoke:
		revoker := actor
		if revoker == "" {
			revoker = string(current.GrantedByUserID)
		}
		if revoker == "" {
			revoker = "system:revoke"
		}
		out, err = w.AccessBindingsW().RevokeGuarded(ctx, id, domain.UserID(revoker))
		if err != nil {
			return domain.AccessBinding{}, err
		}
		out.Subjects = current.Subjects
	case kaname.BindingWithdrawalExpiry:
		at := w.fence.decisionAt
		if current.Status != domain.AccessBindingStatusActive || current.ExpiresAt == nil || current.ExpiresAt.After(at) {
			return current, nil
		}
		tag, e := w.tx.Exec(ctx, `UPDATE kaname.access_bindings SET status='REVOKED',revoked_at=$2,revocation_reason='EXPIRED' WHERE id=$1 AND status='ACTIVE' AND expires_at<=$2`, string(id), at)
		if e != nil {
			return domain.AccessBinding{}, e
		}
		if tag.RowsAffected() != 1 {
			return domain.AccessBinding{}, kaname.ErrAuthorityClassificationChanged
		}
		// Это применение уже подготовленного снятия O(changed rows), не discovery.
		// У expiry прежний контракт удаляет members и ledger; у soft revoke сохраняет.
		if _, err = w.tx.Exec(ctx, `DELETE FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1`, string(id)); err != nil {
			return domain.AccessBinding{}, err
		}
		if _, err = w.tx.Exec(ctx, `DELETE FROM kaname.access_binding_target_members WHERE binding_id=$1`, string(id)); err != nil {
			return domain.AccessBinding{}, err
		}
		out.Status = domain.AccessBindingStatusRevoked
		out.RevokedAt = &at
		if err = bindingExpiryEvents(ctx, w, current); err != nil {
			return domain.AccessBinding{}, err
		}
	}
	if err = stage.emitDeletes(ctx, w); err != nil {
		return domain.AccessBinding{}, err
	}
	if after != nil {
		if err = after(ctx, w, current); err != nil {
			return domain.AccessBinding{}, err
		}
	}
	if err = ctx.Err(); err != nil {
		return domain.AccessBinding{}, err
	}
	if err = w.Commit(ctx); err != nil {
		return domain.AccessBinding{}, err
	}
	return out, nil
}
func (p *BindingStageParticipant) ExpireStagedBinding(ctx context.Context, id domain.AccessBindingID) error {
	_, err := p.WithdrawBinding(ctx, id, kaname.BindingWithdrawalExpiry, "system:expiry", nil, nil)
	return err
}
func bindingExpiryEvents(ctx context.Context, w kaname.Writer, b domain.AccessBinding) error {
	tenant := ""
	if b.ResourceType == "account" {
		tenant = b.ResourceID
	}
	for _, subject := range b.Subjects {
		if err := w.AccessBindingsW().EmitSubjectChangeEvent(ctx, ab.SubjectChangeEvent{SubjectID: string(subject.ID), SubjectType: string(subject.Type), EventType: "binding_revoke", Op: "binding_delete"}); err != nil {
			return err
		}
		if err := w.AccessBindingsW().EmitAuditEvent(ctx, ab.AuditEvent{EventType: ab.AuditEventTypeRevoked, Actor: "system:expiry", SubjectType: string(subject.Type), SubjectID: string(subject.ID), ResourceType: string(b.ResourceType), ResourceID: b.ResourceID, RoleID: string(b.RoleID), BindingID: string(b.ID), TenantAccountID: tenant}); err != nil {
			return err
		}
	}
	return nil
}

var _ kaname.BindingWithdrawalRunner = (*BindingStageParticipant)(nil)
