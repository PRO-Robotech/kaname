// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"fmt"

	clusterapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/cluster"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/authzplan"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var errClusterAdminRollback = errors.New("cluster final decision rollback failed")

// Проверяется не похожий набор атомов, а само объявление pinned модели. Новая
// форма требует нового footprint; неизвестная форма никогда не расширяет allow.
func (p *ClusterAdminParticipant) validateDecisionModel() error {
	if p == nil || p.repo == nil || p.bundle.Validate() != nil {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	model, err := authzplan.ParseModel(p.bundle.ModelSource())
	if err != nil {
		return err
	}
	typ := model.Type("cluster")
	if typ == nil {
		return kaname.ErrSourceUnconfirmed
	}
	rel := typ.Rel("system_admin")
	if rel == nil || len(rel.Terms) != 1 || rel.Terms[0].Kind != authzplan.TermDirect || len(rel.Terms[0].Direct) != 2 {
		return kaname.ErrSourceUnconfirmed
	}
	seen := map[string]bool{}
	for _, s := range rel.Terms[0].Direct {
		if s.Wildcard || s.Userset != "" || s.Object != "" || s.Condition != "" || (s.Type != "user" && s.Type != "service_account") || seen[s.Type] {
			return kaname.ErrSourceUnconfirmed
		}
		seen[s.Type] = true
	}
	return nil
}

// Callback получает только уже защищённую попытку. Все старые ранние гейты
// UC остаются быстрым отказом, но не служат доказательством после ожидания.
func (p *ClusterAdminParticipant) RunAdminDecision(ctx context.Context, in clusterapp.AdminDecisionIntent, body func(context.Context, service.Tx) (domain.ClusterAdminGrant, error)) (domain.ClusterAdminGrant, error) {
	if err := p.validateDecisionModel(); err != nil {
		return domain.ClusterAdminGrant{}, err
	}
	actor, ok := authzguard.PrincipalSubject(ctx)
	if !ok || actor != domain.FGASubjectRef(string(in.Actor.Type), string(in.Actor.ID)) || in.Actor.Validate() != nil || in.Target.Validate() != nil || body == nil ||
		(in.Actor.Type != domain.SubjectTypeUser && in.Actor.Type != domain.SubjectTypeServiceAccount) ||
		(in.Target.Type != domain.SubjectTypeUser && in.Target.Type != domain.SubjectTypeServiceAccount) ||
		(in.Action != clusterapp.AdminActionGrant && in.Action != clusterapp.AdminActionRevoke) {
		return domain.ClusterAdminGrant{}, iamerr.ErrPermissionDenied
	}
	for attempt := 0; attempt < authorityEntryAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return domain.ClusterAdminGrant{}, err
		}
		result, err := p.runAdminAttempt(ctx, in, body)
		if err == nil {
			return result, nil
		}
		if ctx.Err() != nil {
			return domain.ClusterAdminGrant{}, ctx.Err()
		}
		if errors.Is(err, errClusterAdminRollback) || (!policyRetry(err) && !errors.Is(err, iamerr.ErrAborted) && status.Code(err) != codes.Aborted) {
			return domain.ClusterAdminGrant{}, err
		}
	}
	return domain.ClusterAdminGrant{}, iamerr.ErrAborted
}
func (p *ClusterAdminParticipant) runAdminAttempt(ctx context.Context, in clusterapp.AdminDecisionIntent, body func(context.Context, service.Tx) (domain.ClusterAdminGrant, error)) (result domain.ClusterAdminGrant, err error) {
	txh, err := p.Begin(ctx)
	if err != nil {
		return result, err
	}
	tx := txh.(*clusterAdminParticipantTx)
	defer func() {
		if e := tx.Rollback(ctx); e != nil && !errors.Is(e, pgx.ErrTxClosed) {
			err = errors.Join(err, errClusterAdminRollback, e)
		}
	}()
	// GLOBAL выбран до входа. Закрытый SQL profile ждёт все source/DDL/row/fold
	// и legacy advisory locks, не материализует полный inventory под fence.
	if err = tx.QueryRow(ctx, `SELECT kaname.authority_cluster_admin_preflight($1,$2)`, string(in.Target.Type), string(in.Target.ID)).Scan(&tx.owner.fence.decisionAt); err != nil {
		return result, err
	}
	tx.owner.fence.decisionAt = tx.owner.fence.decisionAt.UTC()
	tx.finalDecision = true
	checker := newLiveAdministrativeChecker(tx.owner, p.bundle)
	if err = authzguard.RequireClusterAdmin(ctx, checker); err != nil {
		return result, err
	}
	state := clusterDecisionSubjectState{tx: tx.Tx}
	// Снятый допуск личности не должен пережить ожидание даже при старом токене.
	if e := clusterapp.AssertAdminGrantTarget(ctx, state, domain.GrantSubjectType(in.Actor.Type), string(in.Actor.ID)); e != nil {
		if status.Code(e) == codes.FailedPrecondition || status.Code(e) == codes.InvalidArgument {
			return result, iamerr.ErrPermissionDenied
		}
		return result, e
	}
	if in.Action == clusterapp.AdminActionGrant {
		if err = clusterapp.AssertAdminGrantTarget(ctx, state, domain.GrantSubjectType(in.Target.Type), string(in.Target.ID)); err != nil {
			return result, err
		}
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	result, err = body(ctx, tx)
	if err != nil {
		return domain.ClusterAdminGrant{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return domain.ClusterAdminGrant{}, err
	}
	return result, nil
}

// Тот же предикат UC, но читатель связан с held TX, не с pool.
type clusterDecisionSubjectState struct{ tx pgx.Tx }

func (s clusterDecisionSubjectState) UserInviteStatus(ctx context.Context, id string) (domain.InviteStatus, error) {
	var value domain.InviteStatus
	err := s.tx.QueryRow(ctx, `SELECT invite_status FROM kaname.users WHERE id=$1`, id).Scan(&value)
	if errors.Is(err, pgx.ErrNoRows) {
		err = iamerr.Wrapf(iamerr.ErrInvalidArg, "User %s not found", id)
	}
	if err != nil {
		return "", fmt.Errorf("cluster subject state: %w", err)
	}
	return value, nil
}
func (s clusterDecisionSubjectState) ServiceAccountEnabled(ctx context.Context, id string) (bool, error) {
	var value bool
	err := s.tx.QueryRow(ctx, `SELECT enabled FROM kaname.service_accounts WHERE id=$1`, id).Scan(&value)
	if errors.Is(err, pgx.ErrNoRows) {
		err = iamerr.Wrapf(iamerr.ErrInvalidArg, "ServiceAccount %s not found", id)
	}
	if err != nil {
		return false, fmt.Errorf("cluster subject state: %w", err)
	}
	return value, nil
}

var _ clusterapp.AdminDecisionRunner = (*ClusterAdminParticipant)(nil)
