// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"time"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/jackc/pgx/v5"
)

// MetadataMutationWriters обслуживает правки метаданных в явно выбранном
// контракте записи. Создание, удаление и смена владельца идут через свои порты.
type MetadataMutationWriters struct{ policy *GrantPolicyWriters }

// LoadLegacyLabelAuthority подключает установленный gen1 handoff к правкам
// меток без смены participation. Второй результат означает, что изменения
// меток требуют этой фабрики даже при ошибке её загрузки.
func (r *Repository) LoadLegacyLabelAuthority(ctx context.Context, model string, keys ...authzmodel.KeyTerm) (*MetadataMutationWriters, bool, error) {
	var phase string
	if err := r.master.QueryRow(ctx, `SELECT phase FROM kaname.authority_semantic_identity WHERE singleton`).Scan(&phase); err != nil {
		return nil, true, err
	}
	switch phase {
	case "uninitialized":
		return nil, false, nil
	case "prepared", "active":
		bundle, err := r.LoadAuthorityBundle(ctx, model, keys...)
		if err != nil {
			return nil, true, err
		}
		writers, err := NewStagedMetadataMutationWriters(ctx, r, bundle)
		return writers, true, err
	default:
		// После закрытия handoff SQL по-прежнему требует доказательство
		// для правки меток. Начинать обычную запись здесь нельзя.
		return nil, true, kaname.ErrSemanticIdentityUnavailable
	}
}

// NewStagedMetadataMutationWriters проверяет доступность подписанного metadata
// entry поколения 1 для указанного bundle и текущего runtime LOGIN.
func NewStagedMetadataMutationWriters(ctx context.Context, repo *Repository, bundle *granteffect.Bundle) (*MetadataMutationWriters, error) {
	if repo == nil || repo.fullContract != nil {
		return nil, kaname.ErrSemanticIdentityUnavailable
	}
	policy, err := NewGrantPolicyWriters(ctx, repo, bundle)
	if err != nil {
		return nil, err
	}
	id := bundle.Identity()
	var ready bool
	if err := repo.master.QueryRow(ctx, `SELECT kaname.authority_metadata_staged_ready_v1($1,$2,$3)`, id.ModelID, id.CatalogID, id.ProjectorVersion).Scan(&ready); err != nil {
		return nil, errors.Join(kaname.ErrSemanticIdentityUnavailable, err)
	}
	if !ready {
		return nil, kaname.ErrSemanticIdentityUnavailable
	}
	return &MetadataMutationWriters{policy: policy}, nil
}

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
	return p.open(ctx, metadataMutation{kind: "account", table: "accounts", typ: "account", id: string(a.ID), name: string(a.Name), description: string(a.Description), labels: a.Labels, accessLabels: a.AccessLabels, mask: slices.Clone(mask)}, actor)
}
func (p *MetadataMutationWriters) ProjectMetadataWriter(ctx context.Context, a domain.Project, mask []string, actor domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	return p.open(ctx, metadataMutation{kind: "project", table: "projects", typ: "project", id: string(a.ID), name: string(a.Name), description: string(a.Description), labels: a.Labels, accessLabels: a.AccessLabels, mask: slices.Clone(mask)}, actor)
}
func (p *MetadataMutationWriters) ServiceAccountMetadataWriter(ctx context.Context, a domain.ServiceAccount, mask []string, actor domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	return p.open(ctx, metadataMutation{kind: "service_account", table: "service_accounts", typ: "iam_service_account", id: string(a.ID), name: string(a.Name), description: string(a.Description), labels: a.Labels, mask: slices.Clone(mask)}, actor)
}

type metadataMutation struct {
	operation                               *mirrorMetadataOperation
	kind, table, typ, id, name, description string
	labels, accessLabels                    domain.Labels
	mode                                    metadataMutationMode
	mask                                    []string
}

// nativeCatalogType подтверждает закрытое соответствие вида, модели и
// физической таблицы до чтения строки или расчёта затронутых выдач.
func (r metadataMutation) nativeCatalogType() string {
	switch {
	case r.kind == "account" && r.table == "accounts" && r.typ == "account":
		return "iam.account"
	case r.kind == "project" && r.table == "projects" && r.typ == "project":
		return "iam.project"
	case r.kind == "service_account" && r.table == "service_accounts" && r.typ == "iam_service_account":
		return "iam.serviceAccount"
	case r.kind == "group" && r.table == "groups" && r.typ == "iam_group" && r.mode == metadataMutationAccessLabels:
		return "iam.group"
	default:
		return ""
	}
}

type metadataStage struct {
	mirrorAccount string
	request       metadataMutation
	xmin          string
	ctid          string
	auditID       domain.AuditEventID
	old           json.RawMessage
	rename        bool
	changed       []string
	plan          *policyPlan
	grant         *metadataGrantCapture
}

func (p *MetadataMutationWriters) stage(ctx context.Context, tx pgx.Tx, request metadataMutation, actor domain.Subject, patch metadataMutationPatch) (*metadataStage, error) {
	if request.catalogType() == "" || !nativeQuestionToken(request.id) {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	s := &metadataStage{request: request, auditID: domain.AuditEventID(newAuditEventID())}
	var scope mirrorMetadataScope
	rootRows := 1
	if request.table == "resource_mirror" {
		var err error
		scope, err = s.readMirrorRoot(ctx, tx)
		if err != nil {
			return nil, err
		}
		s.mirrorAccount = scope.account
		request = s.request
		rootRows = 3 // Зеркало, тип и объектное действие каталога.
		if scope.project != "" {
			rootRows++
		}
	} else if request.kind == "group" {
		// ctid отличает версии строки при повторном UPDATE с тем же xmin.
		if err := tx.QueryRow(ctx, `SELECT o.xmin::text,o.ctid::text,to_jsonb(o) FROM ONLY kaname.groups o WHERE o.id=$1`,
			request.id).Scan(&s.xmin, &s.ctid, &s.old); err != nil {
			return nil, err
		}
	} else {
		// Имя таблицы проверено по закрытому списку IAM.
		if err := tx.QueryRow(ctx, `SELECT xmin::text,to_jsonb(o) FROM kaname.`+request.table+` o WHERE id=$1`, request.id).Scan(&s.xmin, &s.old); err != nil {
			return nil, err
		}
	}
	var old struct {
		Name         string             `json:"name"`
		Description  string             `json:"description"`
		Labels       json.RawMessage    `json:"labels"`
		AccessLabels json.RawMessage    `json:"access_labels"`
		Owner        string             `json:"owner_user_id"`
		CreatorType  domain.SubjectType `json:"created_by_type"`
		CreatorID    domain.SubjectID   `json:"created_by_id"`
	}
	if err := json.Unmarshal(s.old, &old); err != nil {
		return nil, err
	}
	s.rename = patch.Name != nil && old.Name != request.name
	if s.rename {
		s.changed = append(s.changed, "name")
	}
	if patch.Description != nil && old.Description != request.description {
		s.changed = append(s.changed, "description")
	}
	if len(patch.Labels) != 0 {
		before, err := unmarshalLabels(old.Labels)
		if err != nil {
			return nil, err
		}
		if !maps.Equal(before, request.labels) {
			s.changed = append(s.changed, "labels")
		}
	}
	if len(patch.AccessLabels) != 0 {
		var before domain.Labels
		// Для проверки нужен валидный объект со старыми защищёнными метками.
		// Отсутствие данных или null означает, что источник не подтверждён.
		if len(old.AccessLabels) == 0 || string(old.AccessLabels) == "null" {
			return nil, kaname.ErrSourceUnconfirmed
		}
		if err := json.Unmarshal(old.AccessLabels, &before); err != nil || before == nil || before.Validate() != nil {
			return nil, kaname.ErrSourceUnconfirmed
		}
		var after domain.Labels
		if err := json.Unmarshal(patch.AccessLabels, &after); err != nil || after == nil || after.Validate() != nil {
			return nil, kaname.ErrSourceUnconfirmed
		}
		if !maps.Equal(before, after) {
			s.changed = append(s.changed, "access_labels")
		}
	}
	questions := newNativePolicyQuestions()
	if err := questions.add(actor, "v_update", request.typ, request.id); err != nil {
		return nil, err
	}
	owners := []kaname.AuthorityOwnerRef{{Kind: request.kind, ID: request.id}}
	if request.table == "resource_mirror" {
		owners = []kaname.AuthorityOwnerRef{{Kind: "account", ID: scope.account}}
		if scope.project != "" {
			owners = append(owners, kaname.AuthorityOwnerRef{Kind: "project", ID: scope.project})
		}
	}
	in := policyWriteRequest{actor: actor, kind: kaname.AuthorityResource,
		owners: owners, nativeQuestions: questions, consumedReads: 1}
	// Actual policy_epoch UPDATE keys must be exclusive before the final clock.
	// The unchanged owner/creator is read from OLD, never trusted from the PATCH.
	if request.kind == "account" {
		in.mutationSubjects = []domain.Subject{{Type: domain.SubjectTypeUser, ID: domain.SubjectID(old.Owner)}}
	}
	if request.kind == "group" {
		in.mutationSubjects = []domain.Subject{{Type: domain.SubjectTypeGroup, ID: domain.SubjectID(request.id)}}
		if len(s.changed) != 0 {
			// Обычный row guard группы учитывает переходы правил и выдач
			// в других аккаунтах, даже если сама группа остаётся на месте.
			groupScope, err := readGroupObjectUpdateScope(ctx, tx, request.id)
			if err != nil {
				return nil, err
			}
			in.consumedReads++
			in.global = groupScope.global
			if !groupScope.global {
				for _, account := range groupScope.accounts {
					in.additionalAccounts = append(in.additionalAccounts, domain.AccountID(account))
				}
			}
		}
	}
	if request.kind == "service_account" {
		in.mutationSubjects = []domain.Subject{{Type: domain.SubjectTypeServiceAccount, ID: domain.SubjectID(request.id)}}
		if old.CreatorID != "" {
			in.mutationSubjects = append(in.mutationSubjects, domain.Subject{Type: old.CreatorType, ID: old.CreatorID})
		}
	}
	var err error
	s.grant, err = captureMetadataGrant(ctx, tx, p.policy.bundle, request, scope, rootRows, s.old, patch.Labels, patch.AccessLabels)
	if err != nil {
		return nil, err
	}
	if s.grant == nil {
		s.plan, err = p.policy.discoverPolicyPlanWithRows(ctx, tx, in, rootRows)
		return s, err
	}
	in.global = in.global || s.grant.mirrorPolicyGlobal
	in.readRoles = s.grant.roles
	if s.grant.retained != nil {
		if err = s.grant.retained.extendRequest(&in); err != nil {
			return nil, err
		}
	}
	for _, seen := range s.grant.bindings {
		if !seen.Changes {
			continue
		}
		if err = questions.bindingRole(actor, seen.Binding.Scope, seen.Binding.Role); err != nil {
			return nil, err
		}
	}
	s.plan, err = p.policy.discoverPolicyPlanWithRows(ctx, tx, in, rootRows, s.grant.source.budget)
	return s, err
}
func (p *MetadataMutationWriters) open(ctx context.Context, request metadataMutation, actor domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	if request.table == "resource_mirror" {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	writer, err := p.openMetadataTx(ctx, request, actor, nil)
	if err != nil {
		return nil, err
	}
	return writer, nil
}

func (p *MetadataMutationWriters) openMetadataTx(ctx context.Context, request metadataMutation, actor domain.Subject, mirrorWork *int) (*metadataWriteTx, error) {
	if p == nil || p.policy == nil || p.policy.repo == nil || !nativeQuestionToken(request.id) || actor.Validate() != nil ||
		(request.table == "resource_mirror" && mirrorWork == nil) {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	patch, err := prepareMetadataMutationPatch(request)
	if err != nil {
		return nil, err
	}
	encodedPatch, err := json.Marshal(patch)
	if err != nil {
		return nil, err
	}
	repo := p.policy.repo
	purpose := "decision"
	if repo.fullContract == nil {
		// Gen1 допускает participant и на prepared, и на active handoff.
		purpose = "participant"
	}
	conn, err := repo.master.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	transferred := false
	defer func() {
		if !transferred {
			conn.Release()
		}
	}()
	for attempt := 0; attempt < authorityEntryLimit(ctx); attempt++ {
		snapshot, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		if err != nil {
			return nil, err
		}
		stage, err := p.stage(ctx, snapshot, request, actor, patch)
		var ordinaryRR json.RawMessage
		if err == nil && request.table == "resource_mirror" && !slices.Contains(stage.changed, "access_labels") {
			ordinaryRR, err = stage.discoverOrdinaryMirror(ctx, snapshot)
		}
		cleanup := policyRollback(ctx, snapshot)
		if err != nil || cleanup != nil {
			if stage != nil && stage.grant != nil {
				stage.grant.source.lifetime.close()
			}
			return nil, errors.Join(err, cleanup)
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
		protectedChange := request.mode == metadataMutationAccessLabels && slices.Contains(stage.changed, "access_labels")
		ordinaryGroup := request.kind == "group" && !protectedChange
		firstRead, finalRead := policyPlanOrdinaryRead, policyPlanOrdinaryRead
		if protectedChange {
			firstRead = policyPlanBeforeMetadataFreeze
			finalRead = policyPlanBeforeMetadataWrite
		}
		nativeWork := metadataProtectedWorkLimit
		work := &nativeWork
		if request.table == "resource_mirror" {
			work = mirrorWork
		}
		w, err := repo.enterAuthority(ctx, tx, intent, owners, intent.Plan.Mode, intent.Plan.Accounts, false, purpose, stage.plan)
		if err == nil && request.operation != nil {
			err = chargeNativePolicyBudget(stage.plan.nativeBudget, 2, 3)
			if err == nil {
				err = request.operation.lock(ctx, tx, stage.request.catalogRef(), actor)
			}
		}
		if err == nil && ordinaryRR != nil {
			err = stage.reserveOrdinaryMirror(ctx, tx, ordinaryRR, encodedPatch, work)
		}
		if err == nil && protectedChange {
			err = stage.prepareProtected(ctx, tx, patch.AccessLabels, work)
		}
		if err == nil && ordinaryGroup {
			err = stage.reserveGroupOrdinary(ctx, tx, actor, encodedPatch, work)
		}
		if err == nil {
			err = p.policy.protectPolicyPlanAt(ctx, w, stage.plan, firstRead)
		}
		if err == nil && protectedChange {
			err = stage.freezeProtected(ctx, tx, p.policy.bundle, actor, encodedPatch, work)
		}
		if err == nil && !protectedChange && !ordinaryGroup && ordinaryRR == nil {
			// При прежнем значении accessLabels проверяем обычную маску
			// и не резервируем запись защищённого атрибута.
			body := encodedPatch
			if request.mode == metadataMutationAccessLabels {
				ordinary := patch
				ordinary.AccessLabels = nil
				body, err = json.Marshal(ordinary)
			}
			if err == nil {
				var preflight metadataPreflightResult
				preflight, err = stage.preflight(ctx, tx, actor, body, repo.fullContract == nil)
				if err == nil && (preflight.RowXmin != stage.xmin || string(preflight.RowValue) != string(stage.old)) {
					err = kaname.ErrAuthorityClassificationChanged
				}
			}
		}
		if err == nil {
			var semantic *semanticAuthorityWriteTx
			semantic, err = p.finalizeMetadataAuthorization(ctx, w, stage, finalRead)
			if err == nil && (protectedChange || ordinaryGroup) {
				err = stage.approveProtectedApply(ctx, semantic, work)
			}
			if err == nil && ordinaryRR != nil {
				err = stage.acceptOrdinaryMirror(ctx, semantic)
			}
			if err == nil {
				err = ctx.Err()
			}
			if err == nil {
				if stage.grant != nil {
					stage.grant.source.lifetime.close()
				}
				w.tx = &policyLeaseTx{Tx: tx, conn: conn}
				transferred = true
				out := &metadataWriteTx{semanticAuthorityWriteTx: semantic, auditID: stage.auditID, changed: stage.changed}
				if stage.request.kind == "group" {
					out.groupWrite = &groupMetadataWrite{
						actor: string(actor.ID), expectsReconcile: protectedChange || slices.Contains(stage.changed, "labels"),
					}
				}
				if request.operation != nil {
					out.mirrorAccount = stage.mirrorAccount
				}
				if request.mode == metadataMutationAccessLabels || ordinaryRR != nil {
					out.protected = &metadataProtectedWrite{
						root: stage.request.catalogRef(), patch: encodedPatch,
						changesLabel: protectedChange,
					}
					if stage.request.table == "resource_mirror" {
						out.protected.mirrorOld = stage.old
					}
				}
				return out, nil
			}
		}
		if stage.grant != nil {
			stage.grant.source.lifetime.close()
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
	}
	return nil, kaname.ErrAuthorityClassificationChanged
}

// Вызывается после резервирования владельцем. Все проверки относятся к одному
// RR-плану и одному RC writer. Возвращаемый writer не удостоверяет решение в SQL.
func (p *MetadataMutationWriters) finalizeMetadataAuthorization(ctx context.Context, w *authorityWriteTx, s *metadataStage, point policyPlanReadPoint) (*semanticAuthorityWriteTx, error) {
	if s.request.table == "resource_mirror" {
		if err := s.checkMirrorGrantIdentity(); err != nil {
			return nil, err
		}
	}
	if s.grant != nil {
		if err := s.grant.recheck(ctx, w); err != nil {
			return nil, err
		}
		if err := s.grant.verifyProjections(ctx, newSemanticAuthorityWriter(w, p.policy.bundle)); err != nil {
			return nil, err
		}
	}
	if err := p.policy.protectPolicyPlanAt(ctx, w, s.plan, point); err != nil {
		return nil, err
	}
	if _, err := w.tx.Exec(ctx, `SELECT kaname.authority_scalar_sequence_finalize_v3()`); err != nil {
		return nil, err
	}
	if s.request.table == "resource_mirror" {
		lifetime := s.grant.source.lifetime
		if err := lifetime.bind(w); err != nil {
			return nil, err
		}
		if !lifetime.valid(w, p.policy.bundle) {
			return nil, kaname.ErrSourceUnconfirmed
		}
	}
	actor := s.plan.request.actor
	semantic := newSemanticAuthorityWriter(w, p.policy.bundle)
	allowed, err := semantic.SemanticRelationChecker().Check(ctx, subjectPolicyKey(actor), "v_update", s.request.typ+":"+s.request.id)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, iamerr.Wrapf(iamerr.ErrPermissionDenied, "Metadata update authority denied")
	}
	if s.grant != nil {
		if err := s.grant.authorize(ctx, semantic, actor); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return semantic, nil
}

// shared.DoWithWriteTx calls Rollback with its original possibly canceled
// worker context. Cleanup must still release fences and the leased connection.
type metadataWriteTx struct {
	mirrorAccount string
	*semanticAuthorityWriteTx
	auditID    domain.AuditEventID
	auditUsed  bool
	changed    []string
	protected  *metadataProtectedWrite
	groupWrite *groupMetadataWrite
}

func (w *metadataWriteTx) MetadataChangedFields() []string {
	return slices.Clone(w.changed)
}

func (w *metadataWriteTx) EmitAuditEvent(ctx context.Context, ev service.AuditEvent) error {
	if w.groupWrite != nil {
		return w.confirmGroupAudit(ctx, ev)
	}
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
var _ kaname.MetadataUpdateEffects = (*metadataWriteTx)(nil)
