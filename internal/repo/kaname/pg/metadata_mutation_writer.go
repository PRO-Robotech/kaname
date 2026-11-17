// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/jackc/pgx/v5"
)

// MetadataMutationWriters is an explicit full-generation composition port.
// Repository.Writer is never changed. These methods do not serve create/delete,
// enabled-state, owner, parent, or identity mutations.
type MetadataMutationWriters struct{ policy *GrantPolicyWriters }

func NewMetadataMutationWriters(ctx context.Context, repo *Repository, bundle *granteffect.Bundle) (*MetadataMutationWriters, error) {
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
	return &MetadataMutationWriters{policy: policy}, nil
}
func (p *MetadataMutationWriters) AccountMetadataWriter(ctx context.Context, a domain.Account, mask []string, actor domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	return p.open(ctx, metadataMutation{kind: "account", table: "accounts", typ: "account", id: string(a.ID), name: string(a.Name), description: string(a.Description), labels: a.Labels, mask: slices.Clone(mask)}, actor)
}
func (p *MetadataMutationWriters) ProjectMetadataWriter(ctx context.Context, a domain.Project, mask []string, actor domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	return p.open(ctx, metadataMutation{kind: "project", table: "projects", typ: "project", id: string(a.ID), name: string(a.Name), description: string(a.Description), labels: a.Labels, mask: slices.Clone(mask)}, actor)
}
func (p *MetadataMutationWriters) ServiceAccountMetadataWriter(ctx context.Context, a domain.ServiceAccount, mask []string, actor domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	return p.open(ctx, metadataMutation{kind: "service_account", table: "service_accounts", typ: "iam_service_account", id: string(a.ID), name: string(a.Name), description: string(a.Description), labels: a.Labels, mask: slices.Clone(mask)}, actor)
}

type metadataMutation struct {
	kind, table, typ, id, name, description string
	labels                                  domain.Labels
	mask                                    []string
}
type metadataStage struct {
	request metadataMutation
	xmin    string
	auditID domain.AuditEventID
	old     json.RawMessage
	rename  bool
	plan    *policyPlan
}

func (p *MetadataMutationWriters) stage(ctx context.Context, tx pgx.Tx, request metadataMutation, actor domain.Subject) (*metadataStage, error) {
	// table is selected solely by the three closed methods above.
	s := &metadataStage{request: request, auditID: domain.AuditEventID(newAuditEventID())}
	if err := tx.QueryRow(ctx, `SELECT xmin::text,to_jsonb(o) FROM kaname.`+request.table+` o WHERE id=$1`, request.id).Scan(&s.xmin, &s.old); err != nil {
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
	s.rename = (len(request.mask) == 0 || slices.Contains(request.mask, "name")) && old.Name != request.name
	questions := newNativePolicyQuestions()
	if err := questions.add(actor, "v_update", request.typ, request.id); err != nil {
		return nil, err
	}
	in := policyWriteRequest{actor: actor, kind: kaname.AuthorityResource,
		owners: []kaname.AuthorityOwnerRef{{Kind: request.kind, ID: request.id}}, nativeQuestions: questions, consumedReads: 1}
	// Actual policy_epoch UPDATE keys must be exclusive before the final clock.
	// The unchanged owner/creator is read from OLD, never trusted from the PATCH.
	if request.kind == "account" {
		in.mutationSubjects = []domain.Subject{{Type: domain.SubjectTypeUser, ID: domain.SubjectID(old.Owner)}}
	}
	if request.kind == "service_account" {
		in.mutationSubjects = []domain.Subject{{Type: domain.SubjectTypeServiceAccount, ID: domain.SubjectID(request.id)}}
		if old.CreatorID != "" {
			in.mutationSubjects = append(in.mutationSubjects, domain.Subject{Type: old.CreatorType, ID: old.CreatorID})
		}
	}
	var err error
	s.plan, err = p.policy.discoverPolicyPlanWithRows(ctx, tx, in, 1)
	if err != nil {
		return nil, err
	}
	return s, nil
}
func (p *MetadataMutationWriters) open(ctx context.Context, request metadataMutation, actor domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	if p == nil || p.policy == nil || p.policy.repo == nil || !nativeQuestionToken(request.id) || actor.Validate() != nil {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	for _, field := range request.mask {
		if field != "name" && field != "description" && field != "labels" {
			return nil, kaname.ErrInvalidAuthorityFencePlan
		}
	}
	// Exact NEW journal origin выводится из того же mask, что actual UPDATE.
	// Caller передаёт только metadata intent, а server compiler читает locked OLD.
	patch := map[string]any{}
	fields := request.mask
	if len(fields) == 0 {
		fields = []string{"name", "description", "labels"}
	}
	for _, field := range fields {
		switch field {
		case "name":
			patch[field] = request.name
		case "description":
			patch[field] = request.description
		case "labels":
			encoded, err := marshalLabels(request.labels)
			if err != nil {
				return nil, err
			}
			patch[field] = json.RawMessage(encoded)
		}
	}
	encodedPatch, err := json.Marshal(patch)
	if err != nil {
		return nil, err
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
	for attempt := 0; attempt < authorityEntryAttempts; attempt++ {
		snapshot, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		if err != nil {
			return nil, err
		}
		stage, err := p.stage(ctx, snapshot, request, actor)
		if cleanup := policyRollback(ctx, snapshot); cleanup != nil {
			return nil, errors.Join(err, cleanup)
		}
		if err != nil {
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
		// Signed entry/fences precede physical table/row/index waits. The SQL helper
		// takes SRE ONLY for an effective rename; normal metadata takes RowExclusive.
		var xmin string
		var current json.RawMessage
		if err == nil {
			err = chargeNativePolicyBudget(stage.plan.nativeBudget, 4, 23)
		}
		if err == nil {
			err = tx.QueryRow(ctx, `SELECT row_xmin,row_value FROM kaname.authority_metadata_preflight_v4($1,$2,$3,$4,$5::jsonb)`, request.kind, request.id, stage.rename, string(stage.auditID), encodedPatch).Scan(&xmin, &current)
		}
		if err == nil && (xmin != stage.xmin || string(current) != string(stage.old)) {
			err = kaname.ErrAuthorityClassificationChanged
		}
		// No mutation has happened. Recheck the entire captured generation after
		// the last physical wait, then refresh decision_at and ask OLD native rights.
		if err == nil {
			err = p.policy.protectPolicyPlan(ctx, w, stage.plan)
		}
		if err == nil {
			_, err = tx.Exec(ctx, `SELECT kaname.authority_scalar_sequence_finalize_v3()`)
		}
		if err == nil {
			semantic := newSemanticAuthorityWriter(w, p.policy.bundle)
			var allowed bool
			allowed, err = semantic.SemanticRelationChecker().Check(ctx, subjectPolicyKey(actor), "v_update", request.typ+":"+request.id)
			if err == nil && !allowed {
				err = iamerr.Wrapf(iamerr.ErrPermissionDenied, "Metadata update authority denied")
			}
			if err == nil {
				err = ctx.Err()
			}
			if err == nil {
				w.tx = &policyLeaseTx{Tx: tx, conn: conn}
				transferred = true
				return &metadataWriteTx{semanticAuthorityWriteTx: semantic, auditID: stage.auditID}, nil
			}
		}
		if cleanup := policyRollback(ctx, tx); cleanup != nil {
			return nil, errors.Join(err, cleanup)
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !policyRetry(err) {
			return nil, err
		}
	}
	return nil, kaname.ErrAuthorityClassificationChanged
}

// shared.DoWithWriteTx calls Rollback with its original possibly canceled
// worker context. Cleanup must still release fences and the leased connection.
type metadataWriteTx struct {
	*semanticAuthorityWriteTx
	auditID   domain.AuditEventID
	auditUsed bool
}

func (w *metadataWriteTx) EmitAuditEvent(ctx context.Context, ev service.AuditEvent) error {
	if w.auditUsed || w.auditID == "" {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	w.auditUsed = true
	return insertAuditEventWithIDTx(ctx, w.tx, ev, w.auditID)
}
func (w *metadataWriteTx) Rollback(ctx context.Context) error {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return w.semanticAuthorityWriteTx.Rollback(cleanup)
}

var _ kaname.AccountMetadataWriterFactory = (*MetadataMutationWriters)(nil)
var _ kaname.ProjectMetadataWriterFactory = (*MetadataMutationWriters)(nil)
var _ kaname.ServiceAccountMetadataWriterFactory = (*MetadataMutationWriters)(nil)
