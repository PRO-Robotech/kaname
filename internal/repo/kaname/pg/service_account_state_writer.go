// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	sarepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/service_account"
	"github.com/jackc/pgx/v5"
)

// ServiceAccountStateWriters — отдельные prepared Enable/Disable.
// UPDATE состояния и cutoff/audit сохраняются в одной транзакции UC.
type ServiceAccountStateWriters struct{ policy *GrantPolicyWriters }

func NewServiceAccountStateWriters(ctx context.Context, repo *Repository, bundle *granteffect.Bundle) (*ServiceAccountStateWriters, error) {
	if repo == nil || !repo.fullContractMatches(bundle) {
		return nil, kaname.ErrSemanticIdentityUnavailable
	}
	if err := repo.ValidateFullAuthorityBundle(ctx, bundle); err != nil {
		return nil, err
	}
	policy, err := NewGrantPolicyWriters(ctx, repo, bundle)
	if err != nil {
		return nil, err
	}
	return &ServiceAccountStateWriters{policy: policy}, nil
}
func (p *ServiceAccountStateWriters) ServiceAccountStateWriter(ctx context.Context, id domain.ServiceAccountID, enabled bool, actor domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	return p.open(ctx, serviceAccountStateMutation{id: string(id), enabled: enabled}, actor)
}

type serviceAccountStateMutation struct {
	id      string
	enabled bool
}
type serviceAccountStateStage struct {
	request serviceAccountStateMutation
	xmin    string
	auditID domain.AuditEventID
	old     json.RawMessage
	plan    *policyPlan
}

func (p *ServiceAccountStateWriters) stage(ctx context.Context, tx pgx.Tx, request serviceAccountStateMutation, actor domain.Subject) (*serviceAccountStateStage, error) {
	// OLD читается до fences; состояние и provenance повторно проверяются после ожиданий.
	s := &serviceAccountStateStage{request: request, auditID: domain.AuditEventID(newAuditEventID())}
	if err := tx.QueryRow(ctx, `SELECT xmin::text,to_jsonb(o) FROM kaname.service_accounts o WHERE id=$1`, request.id).Scan(&s.xmin, &s.old); err != nil {
		return nil, err
	}
	var old struct {
		Name        string             `json:"name"`
		Owner       string             `json:"owner_user_id"`
		CreatorType domain.SubjectType `json:"created_by_type"`
		CreatorID   domain.SubjectID   `json:"created_by_id"`
	}
	if err := json.Unmarshal(s.old, &old); err != nil {
		return nil, err
	}
	questions := newNativePolicyQuestions()
	if err := questions.add(actor, "v_update", "iam_service_account", request.id); err != nil {
		return nil, err
	}
	in := policyWriteRequest{actor: actor, kind: kaname.AuthorityResource,
		owners: []kaname.AuthorityOwnerRef{{Kind: "service_account", ID: request.id}}, nativeQuestions: questions, consumedReads: 1}
	// Прямой UPDATE меняет epoch целевого субъекта и неизменного создателя.
	in.mutationSubjects = []domain.Subject{{Type: domain.SubjectTypeServiceAccount, ID: domain.SubjectID(request.id)}}
	if old.CreatorID != "" {
		in.mutationSubjects = append(in.mutationSubjects, domain.Subject{Type: old.CreatorType, ID: old.CreatorID})
	}
	var err error
	s.plan, err = p.policy.discoverPolicyPlanWithRows(ctx, tx, in, 1)
	if err != nil {
		return nil, err
	}
	return s, nil
}
func (p *ServiceAccountStateWriters) open(ctx context.Context, request serviceAccountStateMutation, actor domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	if p == nil || p.policy == nil || p.policy.repo == nil || !nativeQuestionToken(request.id) || actor.Validate() != nil {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	conn, err := p.policy.repo.master.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	transferred := false
	defer func() {
		if !transferred {
			conn.Release()
		}
	}()
	// Повторяется только подготовка до возврата writer: новый RR stage и новый RC.
	// Тело UC и Commit остаются у вызывающего и здесь не повторяются.
	var last error
	for attempt := 0; attempt < authorityEntryLimit(ctx); attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		snapshot, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		if err != nil {
			return nil, err
		}
		stage, err := p.stage(ctx, snapshot, request, actor)
		if cleanup := policyRollback(ctx, snapshot); cleanup != nil {
			return nil, errors.Join(err, cleanup)
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			if !preparedSingleEntry(ctx) && policyRetry(err) {
				last = err
				continue
			}
			return nil, err
		}
		intent := stage.plan.intent(p.policy.bundle)
		if err = validateAuthorityIntent(intent); err != nil {
			return nil, err
		}
		owners, err := json.Marshal(intent.Owners)
		if err != nil {
			return nil, err
		}
		tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
		if err != nil {
			return nil, err
		}
		w, err := p.policy.repo.enterAuthority(ctx, tx, intent, owners, intent.Plan.Mode, intent.Plan.Accounts, false, "decision", stage.plan)
		if err == nil {
			err = p.policy.protectPolicyPlan(ctx, w, stage.plan)
		}
		// Сначала fences, затем SA row → minted RX → cutoff key → cutoff row и audit/epoch waits.
		var xmin string
		var current json.RawMessage
		if err == nil {
			err = chargeNativePolicyBudget(stage.plan.nativeBudget, 5, 25)
		}
		if err == nil {
			err = tx.QueryRow(ctx, `SELECT row_xmin,row_value FROM kaname.authority_sa_state_preflight_v4($1,$2,$3)`, request.id, request.enabled, string(stage.auditID)).Scan(&xmin, &current)
		}
		if err == nil && (xmin != stage.xmin || string(current) != string(stage.old)) {
			err = kaname.ErrAuthorityClassificationChanged
		}
		// До тела UC бизнес-строки не менялись. После последнего ожидания
		// повторно проверяем generation, обновляем часы и решаем право по OLD.
		if err == nil {
			err = p.policy.protectPolicyPlan(ctx, w, stage.plan)
		}
		if err == nil {
			_, err = tx.Exec(ctx, `SELECT kaname.authority_scalar_sequence_finalize_v3()`)
		}
		if err == nil {
			semantic := newSemanticAuthorityWriter(w, p.policy.bundle)
			var allowed bool
			allowed, err = semantic.SemanticRelationChecker().Check(ctx, subjectPolicyKey(actor), "v_update", "iam_service_account"+":"+request.id)
			if err == nil && !allowed {
				err = iamerr.Wrapf(iamerr.ErrPermissionDenied, "Service account state authority denied")
			}
			if err == nil {
				err = ctx.Err()
			}
			if err == nil {
				w.tx = &policyLeaseTx{Tx: tx, conn: conn}
				transferred = true
				return &serviceAccountStateWriteTx{metadataWriteTx: &metadataWriteTx{semanticAuthorityWriteTx: semantic, auditID: stage.auditID}, request: request}, nil
			}
		}
		if cleanup := policyRollback(ctx, tx); cleanup != nil {
			return nil, errors.Join(err, cleanup)
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if preparedSingleEntry(ctx) || !policyRetry(err) {
			return nil, err
		}
		last = err
	}
	return nil, iamerr.Wrapf(iamerr.ErrAborted, "%w", serviceAccountStateConflict{cause: last})
}

// Причина доступна внутренней диагностике, но её текст не выходит в публичный отказ.
type serviceAccountStateConflict struct{ cause error }

func (e serviceAccountStateConflict) Error() string { return iamerr.SerializationConflictSyncText }
func (e serviceAccountStateConflict) Unwrap() error { return e.cause }

var _ kaname.ServiceAccountStateWriterFactory = (*ServiceAccountStateWriters)(nil)

// Порт не позволяет подменить подготовленный id/состояние или повторить body.
type serviceAccountStateWriteTx struct {
	*metadataWriteTx
	request serviceAccountStateMutation
	used    bool
}

func (w *serviceAccountStateWriteTx) ServiceAccountsW() sarepo.WriterIface {
	return &serviceAccountStateBody{w: w}
}

type serviceAccountStateBody struct{ w *serviceAccountStateWriteTx }

func (b *serviceAccountStateBody) SetEnabled(ctx context.Context, id domain.ServiceAccountID, enabled bool) (domain.ServiceAccount, error) {
	if b.w.used || string(id) != b.w.request.id || enabled != b.w.request.enabled {
		return domain.ServiceAccount{}, kaname.ErrInvalidAuthorityFencePlan
	}
	b.w.used = true
	return b.w.metadataWriteTx.ServiceAccountsW().SetEnabled(ctx, id, enabled)
}
func (b *serviceAccountStateBody) Insert(context.Context, domain.ServiceAccount) (domain.ServiceAccount, error) {
	return domain.ServiceAccount{}, kaname.ErrInvalidAuthorityFencePlan
}
func (b *serviceAccountStateBody) Update(context.Context, domain.ServiceAccount, []string) (domain.ServiceAccount, error) {
	return domain.ServiceAccount{}, kaname.ErrInvalidAuthorityFencePlan
}
func (b *serviceAccountStateBody) Delete(context.Context, domain.ServiceAccountID) error {
	return kaname.ErrInvalidAuthorityFencePlan
}
