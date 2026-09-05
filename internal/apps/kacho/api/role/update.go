// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package role

// update.go — UpdateRoleUseCase. Только custom; account_id / is_system immutable.
// system-role update reject'ится sync ("system role is read-only").

import (
	"context"
	"fmt"
	"log/slog"
	"slices"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho-iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho-iam/internal/catalog"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
)

type UpdateRoleInput struct {
	ID          domain.RoleID
	Name        *domain.RoleName
	Description *domain.Description
	Rules       domain.Rules
	// Labels — own-resource tenant-facing метки самого ресурса Role (НЕ путать с
	// Rule.MatchLabels, отбирающим объекты под грантом). mutable; делают Role
	// label-selectable наравне с account/project (iam-direct ARM_LABELS).
	Labels     domain.Labels
	UpdateMask []string
	// ResourceVersion — xmin OCC token echoed from a prior Get/List; when set on a
	// rules-changing Update it guards against a concurrent edit (A-08/OCC).
	ResourceVersion string
}

var roleMutableFields = map[string]struct{}{
	"name":        {},
	"description": {},
	"rules":       {},
	"labels":      {},
}

var roleImmutableFields = map[string]string{
	"account_id": "accountId is immutable after Role.Create",
	"accountId":  "accountId is immutable after Role.Create",
	"is_system":  "isSystem is immutable after Role.Create",
	"isSystem":   "isSystem is immutable after Role.Create",
	"id":         "id is immutable after Role.Create",
	"created_at": "createdAt is immutable after Role.Create",
	"createdAt":  "createdAt is immutable after Role.Create",
	// permissions is the compiled/derived projection — not directly mutable.
	"permissions": "permissions is immutable after Role.Create",
}

type UpdateRoleUseCase struct {
	repo    Repo
	opsRepo operations.Repo
	// reconciler — FGA tuple reconcile fan-out for a permissions change
	// (nil-safe: when unwired the role UPDATE still succeeds but active-binding
	// tuples are not reconciled — only the case in standalone unit tests of the
	// non-permission paths). Implemented by access_binding.RoleTupleReconciler,
	// wired in the composition root.
	reconciler TupleReconciler
	// membership — RBAC rules-model: re-materializes the role.rules
	// ARM_LABELS membership of every ACTIVE binding after a rules change commits
	// (the fan-out + the bounded-limit guard). nil-safe (unit tests of the
	// non-rules paths leave it unwired; the periodic sweep also re-converges).
	membership RulesMembershipFanout
	// objects — post-commit per-object materializer for the role AS AN OBJECT
	// (iam.role). Distinct from `membership` above: that one re-materializes what the
	// role's RULES grant over other objects, this one re-materializes who may reach
	// THIS role after its OWN labels changed. nil-safe; the co-committed reconcile
	// event + periodic sweep remain the backstop.
	objects ObjectReconciler
	logger  *slog.Logger
	// cat — источник КАТАЛОЖНОГО ФАКТА (kacho#1816). Обязателен по той же
	// причине, что и у создания: проекция «роль → тип × глагол» пишется в той же
	// транзакции, и пустая проекция оставила бы вердикт определённым наполовину.
	cat catalog.Source
}

func NewUpdateRoleUseCase(r Repo, opsRepo operations.Repo, cat catalog.Source) *UpdateRoleUseCase {
	return &UpdateRoleUseCase{repo: r, opsRepo: opsRepo, cat: cat}
}

// WithTupleReconciler wires the FGA tuple reconcile fan-out. nil-safe.
func (u *UpdateRoleUseCase) WithTupleReconciler(r TupleReconciler) *UpdateRoleUseCase {
	u.reconciler = r
	return u
}

// WithMembershipFanout wires the role.rules membership fan-out (the
// bound-check + post-commit per-binding reconcile). nil-safe.
func (u *UpdateRoleUseCase) WithMembershipFanout(m RulesMembershipFanout) *UpdateRoleUseCase {
	u.membership = m
	return u
}

// WithObjectReconciler wires the post-commit per-object materializer used on an
// own-resource LABEL change (parity with the cross-service RegisterResource re-register
// path — see doUpdate). Optional; nil keeps the queue-only behaviour. The logger is
// used only to report a failed pass (the durable event + sweep still re-converge).
func (u *UpdateRoleUseCase) WithObjectReconciler(r ObjectReconciler, logger *slog.Logger) *UpdateRoleUseCase {
	u.objects = r
	u.logger = logger
	return u
}

func (u *UpdateRoleUseCase) Execute(ctx context.Context, in UpdateRoleInput) (*operations.Operation, error) {
	if err := shared.ValidateResourceID(string(in.ID), domain.PrefixRole, "role"); err != nil {
		return nil, err
	}
	if err := shared.ValidateUpdateMask(in.UpdateMask, roleMutableFields, roleImmutableFields); err != nil {
		return nil, err
	}

	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	// Read the role WITH its xmin OCC token so the worker-tx UPDATE
	// is guarded against a concurrent Role.Update (two updates each deriving the
	// FGA fan-out from their own role projection → ledger↔FGA drift). The token is
	// captured on the sync path and echoed into UpdateCAS inside the worker-tx; the
	// loser fails FAILED_PRECONDITION and its whole writer-tx (UPDATE + reconcile
	// fan-out) rolls back atomically (ban #10).
	current, version, err := rd.Roles().GetWithVersion(ctx, in.ID)
	if err != nil {
		_ = rd.Rollback(ctx)
		return nil, shared.MapRepoErr(err)
	}
	if current.IsSystem {
		_ = rd.Rollback(ctx)
		// redesign-2026 F6 (IAM-1-16): a system (seed/cluster-tier) role is immutable
		// — FAILED_PRECONDITION, parity with RoleService.Delete and the proto contract
		// (the resource's state, not the request, forbids the mutation).
		return nil, status.Error(codes.FailedPrecondition, "System role is read-only and cannot be updated")
	}
	_ = rd.Rollback(ctx)
	// Anti-anon floor only. WHO may update this custom role is decided by the
	// MODEL: the api-gateway Checks `v_update@iam_role:<role_id>` before iam is
	// dialed. The former in-service owner-equality check against the owning
	// account's owner_user_id was narrower than that per-object relation and
	// unsatisfiable by a machine principal — security.md «Авторизация живёт в
	// МОДЕЛИ, а не в самодельных проверках». (The is-system refusal above is a
	// resource-STATE check, not authz, and stays.)
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, err
	}

	target := current
	var changed []string
	if in.Name != nil && shared.MaskAllows(in.UpdateMask, "name") && *in.Name != current.Name {
		target.Name = *in.Name
		changed = append(changed, "name")
	}
	if in.Description != nil && shared.MaskAllows(in.UpdateMask, "description") && *in.Description != current.Description {
		target.Description = *in.Description
		changed = append(changed, "description")
	}
	// RBAC rules-model: rules are the authored, mutable field. When they
	// change, recompile the INTERNAL permissions projection (anchor/names; matchLabels
	// excluded; ≤1024 cap) and store both. permissions itself is immutable input
	// (rejected in update_mask above).
	// Набор модулей — ЖИВЫЕ строки каталога (#1927), тот же снимок, которым
	// ниже строится проекция глаголов: обе стороны правила обязаны судиться
	// согласованным множеством, а не двумя моментами времени.
	facts := u.cat.Facts()
	if in.Rules != nil && shared.MaskAllows(in.UpdateMask, "rules") {
		// Validate the new rules first (specific cardinality/wildcard/feed errors),
		// then compile (enforces the ≤1024 compiled-cap).
		if verr := in.Rules.Validate(domain.PolicyOfRole(current.IsSystem, current.OwnerModule), facts); verr != nil {
			return nil, shared.MapValidationErr(verr)
		}
		// Grantable-token gate — parity with Create (see rules_catalog.go). An
		// Update that swaps a valid token for a typo'd one would otherwise silently
		// DEMOTE a working grant to an empty one.
		// Источник — ТОТ ЖЕ снимок живых строк, что и у сегмента модуля выше
		// (#1993). Паритет с Create здесь несущий: приняв роль над заведённым
		// типом и отвергнув её ПРАВКУ, платформа сделала бы роль неисправимой.
		if verr := validateRuleCatalog(in.Rules, current.IsSystem, facts); verr != nil {
			return nil, shared.MapValidationErr(verr)
		}
		compiled, cerr := domain.CompileRules(in.Rules)
		if cerr != nil {
			return nil, shared.MapValidationErr(cerr)
		}
		target.Rules = in.Rules
		target.Permissions = compiled
		changed = append(changed, "rules")
	}
	// labels — own-resource метки. Применяются, только если mask их разрешает
	// (или пустой mask = full-PATCH) И значение изменилось. Изменение labels
	// триггерит iam-direct re-материализацию (см. doUpdate reconcile-event).
	if newLabels, apply := shared.ResolveLabelsUpdate(in.UpdateMask, in.Labels); apply && !shared.LabelsEqual(newLabels, current.Labels) {
		target.Labels = newLabels
		changed = append(changed, "labels")
	}
	if err := target.Validate(facts); err != nil {
		return nil, shared.MapValidationErr(err)
	}

	// OCC: when the caller supplies a resource_version AND the rules are
	// changing, it must match the version read on the sync path; a stale token →
	// FAILED_PRECONDITION (the role was edited concurrently). When omitted, the
	// xmin worker-tx CAS below is the sole guard (last-writer, back-compat).
	if in.ResourceVersion != "" && slices.Contains(changed, "rules") && in.ResourceVersion != version {
		return nil, shared.MapRepoErr(
			iamerr.Wrapf(iamerr.ErrFailedPrecondition, "Role was modified concurrently, retry"))
	}

	// Bound-check: a rules change fans out a per-binding reconcile over
	// the role's ACTIVE bindings. A role carried by more than the contract limit is
	// rejected SYNC (before the Operation) — a single Role.Update must not trigger
	// an unbounded fan-out. Checked only when the rules actually change + the fanout
	// is wired (nil-safe). NOTE: this is a best-effort soft guard (a count read here,
	// the fan-out later), NOT a hard cap — a concurrent grant can push the count past
	// the limit between this check and the fan-out. That is acceptable: the bound only
	// protects against grossly-oversized fan-out, and the per-binding reconcile is
	// idempotent + bounded per binding, so a small overshoot is harmless.
	if u.membership != nil && slices.Contains(changed, "rules") {
		n, cerr := u.membership.CountActiveBindings(ctx, in.ID)
		if cerr != nil {
			return nil, shared.MapRepoErr(cerr)
		}
		if n > MaxRoleFanoutBindings {
			return nil, status.Errorf(codes.FailedPrecondition,
				"role carried by too many bindings to update atomically; split role")
		}
	}

	actor := authzguard.PrincipalUserID(ctx)

	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Update role %s", in.ID),
		&iamv1.UpdateRoleMetadata{RoleId: string(in.ID)},
	)
	if err != nil {
		return nil, err
	}
	if err := u.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}
	maskCopy := append([]string{}, in.UpdateMask...)
	changedCopy := append([]string{}, changed...)
	operations.Run(ctx, u.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return u.doUpdate(ctx, target, maskCopy, actor, changedCopy, version)
	})
	return &op, nil
}

func (u *UpdateRoleUseCase) doUpdate(ctx context.Context, r domain.Role, mask []string, actor string, changed []string, expectedVersion string) (*anypb.Any, error) {
	updated, err := shared.DoWithWriteTx(ctx, u.repo,
		func(ctx context.Context, w Writer) (domain.Role, error) {
			// xmin-CAS: the worker-tx UPDATE is guarded by the version
			// captured on the sync path. A concurrent Role.Update that committed first
			// bumped xmin → this CAS matches 0 rows → ErrFailedPrecondition and the
			// whole writer-tx (incl. the reconcile fan-out below) rolls back.
			upd, uerr := w.RolesW().UpdateCAS(ctx, r, mask, expectedVersion)
			if uerr != nil {
				return domain.Role{}, uerr
			}
			if len(changed) == 0 {
				return upd, nil
			}
			// When the rules (→ compiled permissions) changed, reconcile the
			// FGA tuples of the role's ACTIVE bindings to the new permissions IN THIS
			// writer-tx (atomic with the role UPDATE, ban #10). Without this an active
			// binding keeps its old-tier FGA tuple after a downgrade (orphan = standing
			// privilege). Bounded fan-out (active bindings of this single role),
			// idempotent (unchanged tier → empty delta). nil-safe: in unit tests of
			// the non-rules paths the reconciler may be unwired.
			if u.reconciler != nil && slices.Contains(changed, "rules") {
				if rerr := u.reconciler.ReconcileRoleTuples(ctx, w, upd.ID, upd); rerr != nil {
					return domain.Role{}, rerr
				}
			}
			// RBAC explicit-model: sync role_rule_selectors with the new
			// UNIFIED materializing rules (anchor/names/labels) in the SAME writer-tx
			// (ban #10) so the post-commit membership fan-out (and the reconciler
			// fast-path / sweep) see the new selectors. A removed rule drops its
			// selector here; the per-binding membership re-materialize (eager-revoke by
			// rule_fp) runs post-commit.
			if slices.Contains(changed, "rules") {
				if serr := w.RolesW().ReplaceRuleSelectors(ctx, upd.ID, upd.Rules.MaterializingSelectors()); serr != nil {
					return domain.Role{}, serr
				}
				// Та же пара, что на создании: снятый из правил глагол обязан
				// исчезнуть из проекции, иначе отзыв права не применяется — молча,
				// потому что добавление проходит успешно.
				if verr := w.RolesW().ReplaceRoleVerbs(ctx, upd.ID,
					u.cat.Facts().RoleVerbsFromSelectors(upd.Rules.MaterializingSelectors())); verr != nil {
					return domain.Role{}, verr
				}
				// Проекция ОБЪЯВЛЕННЫХ сегментов — третья сторона того же правила, и
				// пишется она в той же транзакции по той же причине. Отличие от двух
				// предыдущих в том, ЧТО кладётся: те несут только резолвящееся, эта —
				// КАЖДЫЙ объявленный сегмент. На ней стоят ключи в каталог, и именно
				// она отвергает правило, называющее ресурс или глагол, которых на
				// платформе нет либо больше нет (kacho#1030, миграция 20260901113757).
				//
				// Своей проверки каталога здесь НЕТ намеренно: между «спросить» и
				// «записать» помещается снятие ресурса, и правило пережило бы свой
				// референт (запрет #10). Судит ОПЕРАТОР ВСТАВКИ.
				if rerr := w.RolesW().ReplaceRuleRefs(ctx, upd.ID,
					domain.RuleRefsOf(upd.Rules)); rerr != nil {
					return domain.Role{}, rerr
				}
			}
			// changed_fields records WHAT changed (e.g. ["permissions"]) — the
			// full permissions set is intentionally NOT embedded.
			if aerr := w.EmitAuditEvent(ctx, service.AuditEvent{
				EventType:       auditEventRoleUpdated,
				TenantAccountID: string(upd.AccountID),
				Payload: map[string]any{
					"actor":          actor,
					"resource_type":  "role",
					"resource_id":    string(upd.ID),
					"account_id":     string(upd.AccountID),
					"changed_fields": changed,
				},
			}); aerr != nil {
				return domain.Role{}, aerr
			}
			// Изменение own-resource labels может изменить membership iam-direct
			// селектора (правило, матчащее iam.role по меткам). Co-commit reconcile-event
			// в ЭТОЙ writer-tx (ban #10, паритет с user/SA Update) — reconciler ре-оценит
			// затронутые iam.role selector-биндинги (≤2s): label add → грант появляется,
			// label remove/change → eager fall-out. Только при изменении labels.
			if slices.Contains(changed, "labels") {
				if rerr := w.EmitReconcileEvent(ctx, shared.ReconcileEventUpsert, "iam.role", string(upd.ID)); rerr != nil {
					return domain.Role{}, rerr
				}
			}
			return upd, nil
		})
	if err != nil {
		return nil, err
	}

	// OWN-RESOURCE label change ⇒ who may reach THIS role may have flipped ⇒
	// re-materialize this ONE object now instead of waiting out the FIFO reconcile
	// queue. iam.role is label-selectable, so clearing a label an ARM_LABELS grant
	// matches is a REVOCATION. The cross-service twin gets that for free: vpc/compute/
	// nlb re-call InternalIAMService.RegisterResource on a label update, and
	// RegisterResource runs ReconcileObjectForward in-process — the forward's
	// delete-stale guard sees the object already has members, hands it to the FULL
	// ReconcileObject, and the stale grant dies there. The iam-native path had no such
	// pass: it enqueued a resource_reconcile_outbox event and returned, which made
	// revoke latency the DEPTH OF THE GLOBAL RECONCILE QUEUE — strictly FIFO, one
	// worker at ~5 events/s each doing a FULL O(scope) recompute, against an e2e suite
	// producing 5-8 events/s, i.e. a multi-minute backlog. Measured on the stand for
	// the sibling iam.project path: the label-clear event was enqueued at 19:59:18.97
	// and drained at 20:06:49.82 (7m30s); the tuple survived until the 30s periodic
	// sweep reached that binding at 20:00:23, 65s after the clear.
	//
	// Distinct from the rules fan-out below: that one re-materializes what this role
	// GRANTS over other objects, this one re-materializes access TO the role object.
	// It is scheduled BEFORE the rules fan-out on purpose — a mask carrying both
	// "rules" and "labels" must not let a failing rules fan-out (which returns early)
	// suppress the label revoke acceleration; the writer-tx is already committed here.
	//
	// OFF THE done-PATH (ban #9): scheduled detached, because Operation.done reports
	// that the role row is durable, never that its tuples converged. The co-committed
	// reconcile event and the periodic sweep stay the at-least-once backstop, so this
	// changes WHEN the revoke is observed, not WHETHER it happens.
	if slices.Contains(changed, "labels") && u.objects != nil {
		id := string(updated.ID)
		shared.GoPostCommit(ctx, u.logger, "role label re-materialization", func(ctx context.Context) {
			if rerr := u.objects.ReconcileObjectForward(ctx, "iam.role", id); rerr != nil && u.logger != nil {
				u.logger.Error("role update: label re-materialization failed (reconcile event + sweep will retry)",
					"role_id", id, "err", rerr)
			}
		})
	}

	// Membership fan-out: after the rules change + selector-sync committed,
	// re-materialize the role.rules ARM_LABELS membership of every ACTIVE binding of
	// the role (each in its OWN writer-tx, idempotent). A removed rule's per-object
	// members are eager-revoked by rule_fp (no residual); new/edited rules' matched
	// objects are materialized. Bounded by the sync count-check above; nil-safe.
	//
	// OFF THE done-PATH (ban #9), like the label pass above and for the same reason.
	// It used to run inline and a failure returned from the worker-fn, so the
	// operation carried an ERROR for a change that had ALREADY COMMITTED — the role
	// row, the selector projection and the audit row are durable before this line is
	// reached. What the caller does with that error is the damage: it concludes the
	// rules were not applied and retries with the resource version it captured before
	// the first attempt, which its own committed update has already moved, so the
	// retry is refused as a concurrent modification naming a competitor that never
	// existed. Meanwhile the privileges ARE changed.
	//
	// The trigger is not exotic: the pass takes an exclusive advisory lock per
	// binding, the same key the sweep, the revoke and the expiry take, and no lock
	// timeout is set — a wait long enough to hit the statement timeout is an error.
	// Above a few hundred bindings the operation's own deadline is the ceiling.
	//
	// Detaching changes WHEN membership converges, never WHETHER: the co-committed
	// reconcile event and the 30s periodic sweep remain the at-least-once backstop.
	if u.membership != nil && slices.Contains(changed, "rules") {
		id := updated.ID
		shared.GoPostCommit(ctx, u.logger, "role rules membership fan-out", func(ctx context.Context) {
			if ferr := u.membership.ReconcileActiveBindings(ctx, id); ferr != nil && u.logger != nil {
				u.logger.Error("role update: rules membership fan-out failed (reconcile event + sweep will retry)",
					"role_id", string(id), "err", ferr)
			}
		})
	}
	// Эхо мутации проецируется тем же набором, что и чтение: иначе `Create`
	// вернул бы превью, собранное другим источником, чем последующий `Get`.
	updated.TypeVerbs = u.cat.Facts().RolePreviewLookup()
	return marshalRole(updated)
}
