// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

import (
	"fmt"
	"time"

	"go.uber.org/multierr"
)

// AccessBinding — link (subject_type, subject_id) ↔ role_id ↔
// (resource_type, resource_id) with lifecycle fields (status, expires_at,
// granted_by, revoked_at/revoked_by).
//
// State machine: PENDING → ACTIVE → REVOKED (terminal). Transitions are
// atomic CAS-style UPDATEs (no TOCTOU). REVOKED is irreversible via
// `WHERE status IN ('PENDING','ACTIVE')`.
//
// DB partial UNIQUE access_bindings_active_grant_uniq (migration 0003;
// WHERE revoked_at IS NULL) → strict INSERT: a duplicate active grant raises
// ErrAlreadyExists with verbatim text «these permissions are already
// granted to <subject_id> on <res_type>:<res_id>». Re-grant after revoke is
// allowed (revoked rows are out of the partial UNIQUE scope).
type AccessBinding struct {
	ID              AccessBindingID
	SubjectType     SubjectType
	SubjectID       SubjectID
	RoleID          RoleID
	ResourceType    ResourceType
	ResourceID      string              // opaque id (any prefix, cross-service OK)
	Scope           Scope               // RBAC v2 — anchor tier (CLUSTER/ACCOUNT/PROJECT)
	Status          AccessBindingStatus // PENDING|ACTIVE|REVOKED
	ExpiresAt       *time.Time          // nullable — TTL
	GrantedByUserID UserID              // audit
	RevokedAt       *time.Time          // nullable
	RevokedByUserID *UserID             // nullable
	CreatedAt       time.Time

	// MaterializedAt — OUTPUT-ONLY. When this binding's per-object access last
	// became live: MAX(updated_at) over its ACTIVE rows in
	// access_binding_target_members (the reconciler's ledger). Zero when nothing
	// has materialized yet.
	//
	// It exists because Kachō is eventually-consistent by contract: Operation.done
	// means the binding row is DURABLE, never that the FGA tuples are visible
	// (gating done on downstream visibility is forbidden — ban #9). In that window
	// the grantee's 403 is byte-identical to a real denial, leaving the granting
	// admin with nothing to distinguish "propagating" from "wrong grant" and
	// nothing to poll. This field is the observable — NOT a barrier: it is filled
	// by the read path from an already-written ledger and never blocks a write.
	//
	// Legitimately zero forever for a binding that materializes no per-object
	// membership (CLUSTER scope — served by the flat short-circuit; a legacy
	// permissions-only role with no authored rules[]). Zero therefore means "no
	// ACTIVE per-object member", NOT "the grant is broken".
	//
	// Not persisted on the access_bindings row; filled by the read-side batch
	// projection, like Subjects.
	MaterializedAt time.Time

	// DeletionProtection guards the binding from Delete (RBAC explicit-model 2026
	// P6 — D-10, by the image of vpc.address.deletion_protection). The owner
	// auto-binding created on Account.Create sets it true; Delete on a protected
	// binding → FAILED_PRECONDITION (sync pre-check + atomic CAS backstop). Cleared
	// via Update(update_mask=["deletion_protection"]) (C-03). Default false.
	DeletionProtection bool

	// GrantedRelation — ВТОРАЯ ФОРМА выдачи: имя отношения модели, выдаваемое
	// напрямую на области выдачи, взаимоисключающе с RoleID (ограничение БД
	// `access_bindings_grant_form_ck`). Роль раздаёт ГЛАГОЛЫ через свои правила, а
	// встроенные права платформы выражены именованными отношениями
	// (`system_viewer`, `quota_reader`, `viewer` на кластере) — подобрать роль под
	// каждое означало бы завести роли с пустыми правилами.
	//
	// Непусто ТОЛЬКО у системной выдачи: отношение — внутреннее имя, от которого
	// зависит решение о доступе, и выдавать его вправе только платформа. На вход
	// создания это поле не принимается вовсе — его нет в запросе, поэтому «принято
	// и проигнорировано» здесь невозможно by construction.
	GrantedRelation string

	// System — выдача заведена платформой (встроенный доступ: права служебных
	// учёток, публичное чтение справочников). OUTPUT-ONLY на публичном контракте.
	//
	// Отвечает на вопрос «кто выдал» точнее, чем подставленная учётка: выдал не
	// человек, а платформа, поэтому GrantedByUserID у такой выдачи пуст, и это не
	// пробел аудита, а его содержание.
	System bool

	// Subjects — the full multi-subject set (RBAC rules-model 2026).
	// Persisted in the access_binding_subjects child table; SubjectType/
	// SubjectID above remain the legacy single = Subjects[0] (projection +
	// the active-grant UNIQUE anchor). Empty on a row read without the child
	// load — read-side Get/List fills it. On Create the use-case
	// NormalizeSubjects-resolves it from the request before persisting.
	Subjects []Subject

	// Labels — tenant-facing метки САМОГО ресурса AccessBinding. Делают
	// AccessBinding label-selectable наравне с account/project (ARM_LABELS-грант
	// на iam.accessBinding → v_list по `labels @> matchLabels`; List фильтрует
	// viewer ∪ v_list).
	Labels Labels

	// Target — WHICH objects under the scope-anchor the grant applies to
	// (redesign-2026 F8). AllInScope = whole anchor (incl. future); Resources =
	// closed per-object set. The zero value is treated as AllInScope (legacy /
	// internal rows); the public Create RPC rejects a missing target (least-priv).
	Target AccessTarget
}

func (b AccessBinding) Validate() error {
	var errs error
	errs = multierr.Append(errs, b.SubjectType.Validate())
	errs = multierr.Append(errs, b.ResourceType.Validate())
	errs = multierr.Append(errs, b.Labels.Validate())
	// F8: per-object target types must be in the closed registry; arms mutually
	// exclusive. AllInScope / empty (whole-anchor) is always well-formed.
	errs = multierr.Append(errs, b.Target.Validate())
	if b.SubjectID == "" || b.ResourceID == "" {
		errs = multierr.Append(errs, ErrEmpty)
	}
	// РОВНО ОДНА форма выдачи. Обе сразу — два источника материализации у одной
	// строки; ни одной — выдача, которая ничего не выдаёт. То же ограничение
	// стоит в БД (`access_bindings_grant_form_ck`): здесь оно ради тона отказа,
	// там — ради того, что путь записи не один.
	switch {
	case b.RoleID != "" && b.GrantedRelation != "":
		errs = multierr.Append(errs, fmt.Errorf(
			"Illegal argument granted_relation %q together with role_id %q",
			b.GrantedRelation, b.RoleID))
	case b.RoleID == "" && b.GrantedRelation == "":
		errs = multierr.Append(errs, ErrEmpty)
	}
	// Форма отношения — только системная выдача. Причина в комментарии поля.
	if b.GrantedRelation != "" && !b.System {
		errs = multierr.Append(errs, fmt.Errorf(
			"Illegal argument granted_relation %q on a non-system access binding", b.GrantedRelation))
	}
	// Подстановочный субъект («любой аутентифицированный») — тоже только у
	// системной выдачи: это единственный субъект, которого нельзя ни назвать, ни
	// отозвать поимённо.
	if b.SubjectID == "*" && !(b.System && b.SubjectType == "user") {
		errs = multierr.Append(errs, fmt.Errorf(
			"Illegal argument subject_id %q on a non-system access binding", b.SubjectID))
	}
	// Cluster is a singleton scope — resource_id MUST equal
	// ClusterSingletonID. Any other value is rejected up-front so callers
	// can't accidentally create a binding on a non-existent cluster id.
	if b.ResourceType == "cluster" && b.ResourceID != "" && b.ResourceID != ClusterSingletonID {
		errs = multierr.Append(errs, fmt.Errorf(
			"Illegal argument resource_id %q for resource_type=cluster (expected %q)",
			b.ResourceID, ClusterSingletonID))
	}
	// RBAC v2: when Scope is explicitly set (non-zero), it MUST
	// match the (resource_type, resource_id) pair. SCOPE_UNSPECIFIED is
	// accepted at the domain layer; the repo trigger / future writer-tx
	// derives a concrete tier from resource_type.
	if b.Scope != ScopeUnspecified && b.ResourceID != "" {
		if err := b.Scope.ValidateAgainst(string(b.ResourceType), b.ResourceID); err != nil {
			errs = multierr.Append(errs, fmt.Errorf(
				"Illegal argument scope %s vs resource_type=%s resource_id=%s",
				b.Scope, b.ResourceType, b.ResourceID))
		}
	}
	if b.Status != "" {
		errs = multierr.Append(errs, b.Status.Validate())
	}
	if len(b.GrantedByUserID) > 64 {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument granted_by_user_id: length must be <=64"))
	}
	if b.RevokedByUserID != nil && len(*b.RevokedByUserID) > 64 {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument revoked_by_user_id: length must be <=64"))
	}
	if b.ExpiresAt != nil && !b.CreatedAt.IsZero() && !b.ExpiresAt.After(b.CreatedAt) {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument expires_at: must be > created_at"))
	}
	return errs
}

// AccessBindingStatus — enum lifecycle (migration 0011 CHECK).
type AccessBindingStatus string

const (
	AccessBindingStatusPending AccessBindingStatus = "PENDING"
	AccessBindingStatusActive  AccessBindingStatus = "ACTIVE"
	AccessBindingStatusRevoked AccessBindingStatus = "REVOKED"
)

func (s AccessBindingStatus) Validate() error {
	switch s {
	case AccessBindingStatusPending, AccessBindingStatusActive, AccessBindingStatusRevoked:
		return nil
	default:
		return fmt.Errorf("Illegal argument status %q (allowed: PENDING|ACTIVE|REVOKED)", string(s))
	}
}
