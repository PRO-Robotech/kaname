// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg

// reconcile_adapter.go — pgx adapter implementing the
// reconcile.TxRunner + reconcile.ReconcileStore ports (Clean Architecture: the
// reconcile use-case depends only on these ports; this is the only place that
// touches pgx for the reconciler).
//
// WithTx opens ONE writer-tx for a whole reconcile pass: the membership UPSERTs/
// DELETEs + the per-object fga_outbox emits + the containment audit all commit
// together or roll back together (ban #10). On any error the tx rolls back, so a
// partially-applied diff is impossible. The reconcile commits its OWN tx; the
// resource_reconcile_outbox event is marked sent in a SEPARATE short tx
// (MarkReconcileEventSent) after this commit — at-least-once, redelivery safe
// (the reconcile diff is idempotent), NOT co-committed here.
//
// The store delegates to the existing pg helper packages (target_members,
// resource_mirror, reconcile_outbox) + the fga_outbox/audit_outbox emit
// helpers, all on the caller-owned tx.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/fga_outbox"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/reconcile_outbox"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/resource_mirror"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/target_members"
)

// ReconcileAdapter — composition-root adapter for the reconciler. Holds the
// pool; each reconcile pass opens its own writer-tx.
type ReconcileAdapter struct {
	pool *pgxpool.Pool
}

// NewReconcileAdapter constructs the adapter over a pool.
func NewReconcileAdapter(pool *pgxpool.Pool) *ReconcileAdapter {
	return &ReconcileAdapter{pool: pool}
}

// WithTx runs fn inside a single writer-tx (reconcile.TxRunner). Commit on
// success, rollback on error/panic.
func (a *ReconcileAdapter) WithTx(ctx context.Context, fn func(ctx context.Context, s reconcile.ReconcileStore) error) error {
	tx, err := a.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("reconcile: begin tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	store := &reconcileStore{tx: tx}
	if err := fn(ctx, store); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("reconcile: commit: %w", err)
	}
	committed = true
	return nil
}

// reconcileStore — tx-scoped reconcile.ReconcileStore implementation.
type reconcileStore struct {
	tx pgx.Tx
}

// LoadBinding reads the minimal scope/selector/role facts for a binding inside
// the tx. ok=false when the binding row is gone (deleted).
//
// It takes a `SELECT … FOR UPDATE` lock on the binding row (GetForUpdate) as the
// FIRST statement of the reconcile writer-tx, so two concurrent reconcile passes
// of the same binding serialize on the row-lock (system-design ВЗ-1): the second
// pass blocks here until the first commits its diff, then sees the already-
// materialized member (no status change → idempotent skip) and emits no
// duplicate fga_outbox tuples. The expiry path (ExpireBinding) keeps its CAS
// guard (RevokeExpiredBinding) and ALSO benefits from the lock taken here.
func (s *reconcileStore) LoadBinding(ctx context.Context, bindingID domain.AccessBindingID) (reconcile.BindingScope, bool, error) {
	r := &abReader{tx: s.tx}
	b, err := r.GetForUpdate(ctx, bindingID)
	if err != nil {
		if errors.Is(err, iamerr.ErrNotFound) {
			return reconcile.BindingScope{}, false, nil
		}
		return reconcile.BindingScope{}, false, err
	}

	// Role permissions (verb-bundle) — read inside the tx so the tier derivation
	// is consistent with the binding row read.
	role, err := (&roleReader{tx: s.tx}).Get(ctx, b.RoleID)
	if err != nil {
		// A dangling role (deleted out from under the binding) leaves no perms —
		// the reconciler then emits no tuples (membership stays non-ACTIVE). Treat
		// a missing role as "no coverage" rather than a hard error so a stale
		// mirror event does not crash the worker.
		if !errors.Is(err, iamerr.ErrNotFound) {
			return reconcile.BindingScope{}, false, fmt.Errorf("load role %s: %w", b.RoleID, err)
		}
	}

	return reconcile.BindingScope{
		BindingID:   b.ID,
		Scope:       scopeAnchorFor(b),
		SubjectType: string(b.SubjectType),
		SubjectID:   string(b.SubjectID),
		// RBAC explicit-model 2026 P4 (КФ-3): the dynamic membership source is the
		// role's UNIFIED materializing selectors — ARM_ANCHOR(all) + ARM_NAMES +
		// ARM_LABELS. Empty for a thin (legacy permissions-only) role → no
		// materialized members.
		//
		// SCOPE-AWARE (issue #224 / D-8a / D-9): a wildcard `*.*` rule expands to the
		// full materializable type set ONLY for a BOUNDED scope (ACCOUNT/PROJECT) so
		// the owner becomes an explicit per-object admin on the account's content; a
		// GLOBAL/CLUSTER `*.*` binding (cluster super-admin) yields no content
		// selectors — it is served by the D-9 flat short-circuit, never per-object.
		Selectors: role.Rules.MaterializingSelectorsInScope(b.Scope),
		// Scope-self verbs (D-7 / КФ-3 / C-01): the role's verbs that apply to the
		// binding's OWN scope resource-type, so the reconciler materializes the tier
		// (+ verb-bearing v_*) tuple on the scope object itself (the write-authz /
		// no-access-loss anchor the removed binding-time anchor emit produced).
		ScopeSelfVerbs: role.Rules.ScopeSelfVerbs(string(b.ResourceType)),
		RoleID:         string(b.RoleID),
		Active:         b.Status == domain.AccessBindingStatusActive,
	}, true, nil
}

// AcquireBindingLock takes pg_advisory_xact_lock(hashtext(binding_id)) on the
// reconcile writer-tx (КФ-1). xact-scoped → auto-released on commit/rollback (never
// pool-scoped). Concurrent reconcile passes of the same binding block here until the
// holder commits, then see the already-materialized member (idempotent skip).
func (s *reconcileStore) AcquireBindingLock(ctx context.Context, bindingID domain.AccessBindingID) error {
	if _, err := s.tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, string(bindingID)); err != nil {
		return fmt.Errorf("reconcile: advisory-lock binding %s: %w", bindingID, err)
	}
	return nil
}

// MatchAllInScope returns EVERY mirror object of the given types (ARM_ANCHOR/`all`,
// P4) — no label filter. Containment to the binding's scope is re-asserted by the
// use-case (IsContainedIn), so the query may over-return cluster-wide and the scope
// narrows it.
func (s *reconcileStore) MatchAllInScope(ctx context.Context, types []string) ([]domain.MirrorObject, error) {
	if len(types) == 0 {
		return nil, nil
	}
	rows, err := resource_mirror.AllByTypes(ctx, s.tx, types)
	if err != nil {
		return nil, err
	}
	out := make([]domain.MirrorObject, 0, len(rows))
	for _, row := range rows {
		out = append(out, mirrorRowToDomain(row))
	}
	return out, nil
}

// MatchByIDs returns the mirror objects of the given types whose object_id ∈ ids
// (ARM_NAMES, P4). An id not yet in the mirror is absent (PENDING — the forward path
// picks it up on its RegisterResource).
func (s *reconcileStore) MatchByIDs(ctx context.Context, types, ids []string) ([]domain.MirrorObject, error) {
	if len(types) == 0 || len(ids) == 0 {
		return nil, nil
	}
	rows, err := resource_mirror.ByTypesAndIDs(ctx, s.tx, types, ids)
	if err != nil {
		return nil, err
	}
	out := make([]domain.MirrorObject, 0, len(rows))
	for _, row := range rows {
		out = append(out, mirrorRowToDomain(row))
	}
	return out, nil
}

// MatchAllInScopeIAMDirect returns EVERY IAM-OWN object of the given iam-direct
// types (iam.project / iam.account) read SAME-DB (ARM_ANCHOR/`all`, P4). Containment
// is re-asserted by the use-case.
func (s *reconcileStore) MatchAllInScopeIAMDirect(ctx context.Context, types []string) ([]domain.MirrorObject, error) {
	return s.iamDirectQuery(ctx, types, "", nil)
}

// MatchByIDsIAMDirect returns the IAM-OWN objects of the given iam-direct types
// whose id ∈ ids (ARM_NAMES, P4).
func (s *reconcileStore) MatchByIDsIAMDirect(ctx context.Context, types, ids []string) ([]domain.MirrorObject, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	return s.iamDirectQuery(ctx, types, "ids", ids)
}

// iamDirectScanSpec describes how to read ONE iam-direct (D6) native table for the
// ARM_ANCHOR/ARM_NAMES arms and stamp its containment parents. The SELECT yields
// EXACTLY three columns in order: id, parent_account_id, parent_project_id — so the
// SAME IsContainedIn predicate decides account/project/cluster containment for every
// iam-native type. table/objectType/parentExpr are FIXED literals (never user input).
//
//   - iam.project  → parent_account = projects.account_id, parent_project = own id.
//   - iam.account  → parent_account = own id, parent_project = ” (account is contained
//     in account:<self> + cluster only).
//   - iam.role / iam.group / iam.serviceAccount / iam.user — account-scoped content;
//     parent_account = account_id (COALESCED through the owning project for a
//     project-scoped role/SA so the account-scoped owner binding still contains it),
//     parent_project = project_id (NULL → ”).
//   - iam.accessBinding — scoped by (resource_type, resource_id): account-scoped →
//     parent_account; project-scoped → parent_project (+ its account via the projects
//     join); cluster-scoped → neither (contained only in cluster scope).
type iamDirectScanSpec struct {
	objectType string
	table      string
	// parentAccountExpr / parentProjectExpr are SQL expressions over the table alias
	// `o` (and, for project-scoped rows, the LEFT JOINed projects alias `p`).
	parentAccountExpr string
	parentProjectExpr string
	// join is an optional LEFT JOIN clause (e.g. resolve a project's account_id).
	join string
}

// iamDirectScanSpecs — the closed, per-type read plan. All identifiers are literals.
var iamDirectScanSpecs = map[string]iamDirectScanSpec{
	"iam.project": {
		objectType: "iam.project", table: "kacho_iam.projects",
		parentAccountExpr: "o.account_id", parentProjectExpr: "o.id",
	},
	"iam.account": {
		objectType: "iam.account", table: "kacho_iam.accounts",
		parentAccountExpr: "o.id", parentProjectExpr: "''",
	},
	// account-scoped content (role may also be project-scoped; SA may carry project_id).
	"iam.role": {
		objectType: "iam.role", table: "kacho_iam.roles",
		// A project-scoped role has account_id NULL → resolve it through its project.
		parentAccountExpr: "COALESCE(o.account_id, p.account_id, '')",
		parentProjectExpr: "COALESCE(o.project_id, '')",
		join:              "LEFT JOIN kacho_iam.projects p ON p.id = o.project_id",
	},
	"iam.group": {
		objectType: "iam.group", table: "kacho_iam.groups",
		parentAccountExpr: "o.account_id", parentProjectExpr: "''",
	},
	"iam.serviceAccount": {
		objectType: "iam.serviceAccount", table: "kacho_iam.service_accounts",
		parentAccountExpr: "o.account_id",
		parentProjectExpr: "COALESCE(o.project_id, '')",
	},
	"iam.user": {
		objectType: "iam.user", table: "kacho_iam.users",
		parentAccountExpr: "o.account_id", parentProjectExpr: "''",
	},
	// access_binding is scoped by (resource_type, resource_id): map the scope anchor
	// onto the containment parents so the owner binding contains the bindings of its
	// account/projects (a cluster-scoped binding stays cluster-only — both empty).
	"iam.accessBinding": {
		objectType: "iam.accessBinding", table: "kacho_iam.access_bindings",
		parentAccountExpr: "CASE WHEN o.resource_type = 'account' THEN o.resource_id ELSE COALESCE(p.account_id, '') END",
		parentProjectExpr: "CASE WHEN o.resource_type = 'project' THEN o.resource_id ELSE '' END",
		join:              "LEFT JOIN kacho_iam.projects p ON o.resource_type = 'project' AND p.id = o.resource_id",
	},
}

// iamDirectQuery is the shared iam-direct (D6) read for the ARM_ANCHOR/ARM_NAMES
// arms: it scans each requested iam-native table (per iamDirectScanSpecs) filtered by
// `mode` ("" → all, "ids" → id = ANY(ids)), stamping the containment parents so the
// SAME IsContainedIn predicate decides containment. No peer-call (same-DB) — the
// graph stays acyclic. Extended from iam.project/iam.account to
// the full iam content set (role/group/serviceAccount/user/accessBinding) so a bounded
// owner `*.*` rule forward-materializes per-object admin on iam-native content.
func (s *reconcileStore) iamDirectQuery(ctx context.Context, types []string, mode string, ids []string) ([]domain.MirrorObject, error) {
	if len(types) == 0 {
		return nil, nil
	}
	var out []domain.MirrorObject
	for _, t := range types {
		spec, ok := iamDirectScanSpecs[t]
		if !ok {
			// Not an iam-direct materializable type — skip (the partitioner should
			// not have routed it here; defensive).
			continue
		}
		// All identifiers below are fixed literals from the closed spec map (never
		// user input), so the interpolation is injection-safe.
		q := "SELECT o.id, " + spec.parentAccountExpr + ", " + spec.parentProjectExpr +
			" FROM " + spec.table + " o"
		if spec.join != "" {
			q += " " + spec.join
		}
		var rows pgx.Rows
		var err error
		if mode == "ids" {
			rows, err = s.tx.Query(ctx, q+" WHERE o.id = ANY($1) ORDER BY o.id ASC", ids)
		} else {
			rows, err = s.tx.Query(ctx, q+" ORDER BY o.id ASC")
		}
		if err != nil {
			return nil, fmt.Errorf("reconcile: iam-direct %s %s: %w", spec.objectType, mode, err)
		}
		objs, serr := scanIAMDirect(rows, spec.objectType)
		if serr != nil {
			return nil, serr
		}
		out = append(out, objs...)
	}
	return out, nil
}

// MatchSelector returns mirror objects matching types+matchLabels (labels @>).
func (s *reconcileStore) MatchSelector(ctx context.Context, types []string, matchLabels map[string]string) ([]domain.MirrorObject, error) {
	rows, err := resource_mirror.MatchByLabels(ctx, s.tx, types, matchLabels)
	if err != nil {
		return nil, err
	}
	out := make([]domain.MirrorObject, 0, len(rows))
	for _, row := range rows {
		out = append(out, mirrorRowToDomain(row))
	}
	return out, nil
}

// MatchIAMDirect returns IAM's OWN objects matching the selector labels SAME-DB
// from the native tables (D6, FeedIAMDirect). Под единой моделью видимости —
// ВСЕ iam-native типы (project/account + content user/serviceAccount/group/role/
// accessBinding) label-selectable; их own-table несет колонку `labels` (migration
// 0041) с GIN(jsonb_path_ops) под `@>`. Containment-предикат тот же
// (parentAccountExpr/parentProjectExpr из iamDirectScanSpecs), что и для
// ARM_ANCHOR/ARM_NAMES, поэтому доменный IsContainedIn решает account/project/
// cluster containment единообразно.
//
// `types` содержит ТОЛЬКО iam-direct типы (reconciler партиционирует по feed). No
// peer-call (same-DB) — граф ацикличен, self-mirror отсутствует.
func (s *reconcileStore) MatchIAMDirect(ctx context.Context, types []string, matchLabels map[string]string) ([]domain.MirrorObject, error) {
	if len(types) == 0 || len(matchLabels) == 0 {
		return nil, nil
	}
	labelsJSON, err := json.Marshal(matchLabels)
	if err != nil {
		return nil, fmt.Errorf("reconcile: marshal iam-direct match labels: %w", err)
	}
	var out []domain.MirrorObject
	for _, t := range types {
		spec, ok := iamDirectScanSpecs[t]
		if !ok {
			// Not an iam-direct type — the partitioner should not route it here.
			continue
		}
		// All identifiers below are fixed literals from the closed spec map (never
		// user input), so the interpolation is injection-safe. The own-table
		// `labels @> $1` probe is served by the per-table GIN index (migration 0041).
		q := "SELECT o.id, " + spec.parentAccountExpr + ", " + spec.parentProjectExpr +
			" FROM " + spec.table + " o"
		if spec.join != "" {
			q += " " + spec.join
		}
		q += " WHERE o.labels @> $1::jsonb ORDER BY o.id ASC"
		rows, qerr := s.tx.Query(ctx, q, labelsJSON)
		if qerr != nil {
			return nil, fmt.Errorf("reconcile: iam-direct match labels %s: %w", spec.objectType, qerr)
		}
		objs, serr := scanIAMDirect(rows, spec.objectType)
		if serr != nil {
			return nil, serr
		}
		out = append(out, objs...)
	}
	return out, nil
}

// scanIAMDirect scans (object_id, parent_account_id, parent_project_id) rows into
// MirrorObjects for an iam-direct object type. The three columns are produced by
// iamDirectQuery's per-type SELECT (parentAccountExpr / parentProjectExpr), so the
// SAME IsContainedIn predicate decides account/project/cluster containment uniformly
// across every iam-native type (project/account/role/group/serviceAccount/user/
// accessBinding). Empty-string parents (e.g. a cluster-scoped binding) leave the
// object contained only in a cluster-scope binding (IsContainedIn cluster=true).
func scanIAMDirect(rows pgx.Rows, objectType string) ([]domain.MirrorObject, error) {
	defer rows.Close()
	var out []domain.MirrorObject
	for rows.Next() {
		var id, parentAccount, parentProject string
		if err := rows.Scan(&id, &parentAccount, &parentProject); err != nil {
			return nil, fmt.Errorf("reconcile: scan iam-direct %s row: %w", objectType, err)
		}
		out = append(out, domain.MirrorObject{
			ObjectType:      objectType,
			ObjectID:        id,
			ParentAccountID: parentAccount,
			ParentProjectID: parentProject,
		})
	}
	return out, rows.Err()
}

// GetMirrorObject returns one mirror row (byName containment / PENDING verify).
func (s *reconcileStore) GetMirrorObject(ctx context.Context, objectType, objectID string) (domain.MirrorObject, bool, error) {
	row, ok, err := resource_mirror.GetByObject(ctx, s.tx, objectType, objectID)
	if err != nil {
		return domain.MirrorObject{}, false, err
	}
	if !ok {
		return domain.MirrorObject{}, false, nil
	}
	return mirrorRowToDomain(row), true, nil
}

// CurrentMembers returns the materialized members (diff base) inside the tx.
func (s *reconcileStore) CurrentMembers(ctx context.Context, bindingID domain.AccessBindingID) ([]domain.TargetMember, error) {
	rows, err := target_members.ListByBindingTx(ctx, s.tx, string(bindingID))
	if err != nil {
		return nil, err
	}
	out := make([]domain.TargetMember, 0, len(rows))
	for _, m := range rows {
		out = append(out, domain.TargetMember{
			BindingID:          domain.AccessBindingID(m.BindingID),
			RoleID:             domain.RoleID(m.RoleID),
			RuleFP:             m.RuleFP,
			ObjectType:         m.ObjectType,
			ObjectID:           m.ObjectID,
			VerificationStatus: m.VerificationStatus,
		})
	}
	return out, nil
}

// BindingsForObject returns binding ids with a member referencing the object.
func (s *reconcileStore) BindingsForObject(ctx context.Context, objectType, objectID string) ([]domain.AccessBindingID, error) {
	ids, err := target_members.BindingsForObjectTx(ctx, s.tx, objectType, objectID)
	if err != nil {
		return nil, err
	}
	out := make([]domain.AccessBindingID, 0, len(ids))
	for _, id := range ids {
		out = append(out, domain.AccessBindingID(id))
	}
	return out, nil
}

// SelectorBindingsMatchingObject returns ACTIVE selector-binding ids whose
// selector now matches the object (objectType ∈ types AND mirror.labels @>
// match_labels) — the fast-path source (system-design ВЗ-2). The object's labels
// are read from resource_mirror and probed against each selector's match_labels;
// the GIN index on resource_mirror.labels + the type filter keep it cheap. A
// binding with NO member row yet for the object is INCLUDED (that is the point —
// a brand-new match). Bindings that no longer match are simply not returned.
func (s *reconcileStore) SelectorBindingsMatchingObject(ctx context.Context, objectType, objectID string) ([]domain.AccessBindingID, error) {
	// RBAC rules-model 2026: the fast-path source is the
	// role.rules ARM_LABELS selectors (role_rule_selectors) carried by the binding's
	// ROLE — the legacy per-binding access_binding_selector arm is gone. A brand-new
	// matching object materializes membership for rules-role bindings on the
	// mirror-change event (≤2s), not only on the sweep.
	// RBAC explicit-model 2026 P4 (КФ-3): the fast-path matches ALL selector arms
	// carried by the binding's ROLE (role_rule_selectors now stores anchor/names/
	// labels). The arm decides the predicate: anchor → type only (every object of the
	// type); names → type + object_id ∈ resource_names; labels → type + labels @>
	// match_labels. This lets a freshly-registered object materialize membership for
	// anchor/names bindings on its mirror-change event (forward-mat, D-4), not only on
	// the periodic sweep.
	rows, err := s.tx.Query(ctx,
		`SELECT b.id
		   FROM kacho_iam.role_rule_selectors rrs
		   JOIN kacho_iam.access_bindings b ON b.role_id = rrs.role_id
		   JOIN kacho_iam.resource_mirror m
		     ON m.object_type = $1 AND m.object_id = $2
		  WHERE b.status = 'ACTIVE'
		    AND $1 = ANY(rrs.object_types)
		    AND ( (rrs.arm = 'anchor')
		       OR (rrs.arm = 'names'  AND $2 = ANY(rrs.resource_names))
		       OR (rrs.arm = 'labels' AND m.labels @> rrs.match_labels) )
		  ORDER BY b.id ASC`,
		objectType, objectID)
	if err != nil {
		return nil, fmt.Errorf("reconcile: selector bindings matching object %s:%s: %w", objectType, objectID, err)
	}
	defer rows.Close()
	var out []domain.AccessBindingID
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("reconcile: scan matching selector binding id: %w", err)
		}
		out = append(out, domain.AccessBindingID(id))
	}
	return out, rows.Err()
}

// IAMDirectSelectorBindingsMatchingObject is the iam-direct (D6) analogue of
// SelectorBindingsMatchingObject: ACTIVE selector-binding ids whose selector now
// matches the IAM-OWN object (objectType ∈ types AND the object's OWN-TABLE
// labels @> match_labels). The own table is chosen by objectType
// (iam.project→projects, iam.account→accounts); the labels @> probe is served by
// the per-table GIN index. Same-DB, no mirror. Used by the Q2 label-change
// trigger to pick up a freshly-matching iam-direct object.
func (s *reconcileStore) IAMDirectSelectorBindingsMatchingObject(ctx context.Context, objectType, objectID string) ([]domain.AccessBindingID, error) {
	// ownTable is the iam-native source table for the object type. Под единой
	// моделью видимости ВСЕ iam-native типы несут `labels`-колонку (migration 0041
	// добавил ее на users/service_accounts/roles/access_bindings; projects/accounts/
	// groups несли ее ранее) и все label-selectable — поэтому arm='labels'-ветка
	// включается для каждого типа (hasLabels=true).
	var ownTable string
	switch objectType {
	case "iam.project":
		ownTable = "kacho_iam.projects"
	case "iam.account":
		ownTable = "kacho_iam.accounts"
	case "iam.group":
		ownTable = "kacho_iam.groups"
	case "iam.role":
		ownTable = "kacho_iam.roles"
	case "iam.serviceAccount":
		ownTable = "kacho_iam.service_accounts"
	case "iam.user":
		ownTable = "kacho_iam.users"
	case "iam.accessBinding":
		ownTable = "kacho_iam.access_bindings"
	default:
		// Not an iam-direct selectable type — no fast-path candidates.
		return nil, nil
	}
	// Все iam-native типы под единой моделью видимости label-selectable и несут
	// колонку labels, поэтому arm='labels'-ветка всегда активна.
	hasLabels := true
	// ownTable is a fixed literal chosen from the closed switch above (never user
	// input), so the interpolation is injection-safe.
	//
	// Источник fast-path — селекторы role.rules (role_rule_selectors), несомые ROLE
	// биндинга. Match по IAM-OWN-таблице arm-aware: anchor / names / labels
	// (labels @> match_labels через GIN).
	labelsBranch := ""
	if hasLabels {
		labelsBranch = " OR (rrs.arm = 'labels' AND o.labels @> rrs.match_labels)"
	}
	q := `SELECT b.id
	        FROM kacho_iam.role_rule_selectors rrs
	        JOIN kacho_iam.access_bindings b ON b.role_id = rrs.role_id
	        JOIN ` + ownTable + ` o ON o.id = $2
	       WHERE b.status = 'ACTIVE'
	         AND $1 = ANY(rrs.object_types)
	         AND ( (rrs.arm = 'anchor')
	            OR (rrs.arm = 'names'  AND $2 = ANY(rrs.resource_names))` + labelsBranch + ` )
	       ORDER BY b.id ASC`
	rows, err := s.tx.Query(ctx, q, objectType, objectID)
	if err != nil {
		return nil, fmt.Errorf("reconcile: iam-direct selector bindings matching %s:%s: %w", objectType, objectID, err)
	}
	defer rows.Close()
	var out []domain.AccessBindingID
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("reconcile: scan iam-direct matching binding id: %w", err)
		}
		out = append(out, domain.AccessBindingID(id))
	}
	return out, rows.Err()
}

// UpsertMember materializes/updates a membership row (full rule coordinate).
func (s *reconcileStore) UpsertMember(ctx context.Context, m domain.TargetMember) error {
	return target_members.UpsertTx(ctx, s.tx, target_members.Member{
		BindingID:          string(m.BindingID),
		RoleID:             string(m.RoleID),
		RuleFP:             m.RuleFP,
		ObjectType:         m.ObjectType,
		ObjectID:           m.ObjectID,
		VerificationStatus: m.VerificationStatus,
	})
}

// DeleteMember removes a membership row scoped by rule_fp (so removing one rule's
// member never drops another rule's member of the same object, C-21).
func (s *reconcileStore) DeleteMember(ctx context.Context, bindingID domain.AccessBindingID, ruleFP, objectType, objectID string) error {
	return target_members.DeleteTx(ctx, s.tx, string(bindingID), ruleFP, objectType, objectID)
}

// LedgerTuplesForObject reads the recorded emitted tuples for one object of a
// binding from the access_binding_emitted_tuples ledger (the saved tuple-set the
// role.rules eager-revoke replays when a rule's verbs are gone, C-20/C-21).
func (s *reconcileStore) LedgerTuplesForObject(ctx context.Context, bindingID domain.AccessBindingID, object string) ([]domain.MembershipTuple, error) {
	rows, err := s.tx.Query(ctx,
		`SELECT fga_user, relation, object
		   FROM kacho_iam.access_binding_emitted_tuples
		  WHERE binding_id = $1 AND object = $2`,
		string(bindingID), object)
	if err != nil {
		return nil, fmt.Errorf("reconcile: ledger tuples for object %s: %w", object, err)
	}
	defer rows.Close()
	var out []domain.MembershipTuple
	for rows.Next() {
		var t domain.MembershipTuple
		if err := rows.Scan(&t.User, &t.Relation, &t.Object); err != nil {
			return nil, fmt.Errorf("reconcile: scan ledger tuple: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// TuplesStillClaimedByOtherBindings returns the subset of `tuples` still recorded in
// the emitted-tuple ledger of an ACTIVE binding OTHER than excludeBinding. The ledger
// PK is (binding_id, fga_user, relation, object) — per binding — so two bindings of the
// SAME subject that materialized the IDENTICAL FGA tuple on the SAME object hold TWO
// ledger rows for ONE non-refcounted OpenFGA tuple. Before deleting a tuple the
// reconciler subtracts this set so a shared cross-binding tuple is dropped only when the
// LAST owning binding releases it (label-revoke-vpc CHANGE-01). The join to
// access_bindings requires the other binding be ACTIVE — a REVOKED/expired binding does
// not keep a tuple alive. Empty `tuples` → empty result (no query).
func (s *reconcileStore) TuplesStillClaimedByOtherBindings(ctx context.Context, excludeBinding domain.AccessBindingID, tuples []domain.MembershipTuple) (map[domain.MembershipTuple]struct{}, error) {
	out := make(map[domain.MembershipTuple]struct{})
	if len(tuples) == 0 {
		return out, nil
	}
	// Probe each (fga_user, relation, object) triple against the ledger of every OTHER
	// active binding. The set is small (one member's tuple-set), so a per-tuple EXISTS
	// is cheap and keeps the query index-friendly (PK prefix on fga_user/relation/object
	// is not available, but the access_binding_emitted_tuples object index covers it).
	for _, t := range tuples {
		var exists bool
		err := s.tx.QueryRow(ctx,
			`SELECT EXISTS (
			   SELECT 1
			     FROM kacho_iam.access_binding_emitted_tuples et
			     JOIN kacho_iam.access_bindings ab ON ab.id = et.binding_id
			    WHERE et.binding_id <> $1
			      AND et.fga_user = $2
			      AND et.relation = $3
			      AND et.object   = $4
			      AND ab.status = 'ACTIVE'
			 )`,
			string(excludeBinding), t.User, t.Relation, t.Object).Scan(&exists)
		if err != nil {
			return nil, fmt.Errorf("reconcile: still-claimed probe for %s#%s@%s: %w", t.Object, t.Relation, t.User, err)
		}
		if exists {
			out[t] = struct{}{}
		}
	}
	return out, nil
}

// EmitTupleWrite / EmitTupleDelete enqueue per-object FGA tuples on the tx.
func (s *reconcileStore) EmitTupleWrite(ctx context.Context, tuples []domain.MembershipTuple) error {
	return fga_outbox.EmitWriteTx(ctx, s.tx, membershipTuplesToClients(tuples))
}

func (s *reconcileStore) EmitTupleDelete(ctx context.Context, tuples []domain.MembershipTuple) error {
	return fga_outbox.EmitDeleteTx(ctx, s.tx, membershipTuplesToClients(tuples))
}

// RecordEmittedTuples co-commits the per-member FGA tuples into the persisted
// emitted-tuple ledger (kacho_iam.access_binding_emitted_tuples — F3/#178) on the
// reconcile writer-tx, alongside the matching EmitTupleWrite (ban #10). It mirrors
// abWriter.InsertEmittedTuples (`INSERT … ON CONFLICT DO NOTHING`) so a repeated
// reconcile of the same ACTIVE member is an idempotent no-op. len==0 is a no-op.
func (s *reconcileStore) RecordEmittedTuples(ctx context.Context, bindingID domain.AccessBindingID, tuples []domain.MembershipTuple) error {
	for _, t := range tuples {
		if t.User == "" || t.Relation == "" || t.Object == "" {
			return fmt.Errorf("reconcile: record emitted tuple: incomplete (user=%q relation=%q object=%q)",
				t.User, t.Relation, t.Object)
		}
		if _, err := s.tx.Exec(ctx,
			// source='member': ARM_LABELS per-object tuples owned by the reconciler /
			// RoleMembershipFanout — kept distinct from binding-level rows so a
			// Role.Update binding-level reconcile (ReplaceEmittedTuples) never wipes them.
			// DO UPDATE SET source='member' self-heals any pre-0032 row that defaulted to
			// 'binding' (object-spaces are disjoint, so a real binding↔member collision
			// cannot occur — this only re-tags an existing member row).
			`INSERT INTO kacho_iam.access_binding_emitted_tuples (binding_id, fga_user, relation, object, source)
			 VALUES ($1, $2, $3, $4, 'member')
			 ON CONFLICT (binding_id, fga_user, relation, object) DO UPDATE SET source = 'member'`,
			string(bindingID), t.User, t.Relation, t.Object,
		); err != nil {
			return fmt.Errorf("reconcile: record emitted tuple: %w", err)
		}
	}
	return nil
}

// ForgetEmittedTuples removes exactly the supplied member rows from the ledger on
// the writer-tx (eager-revoke / fell-out / expiry), keeping the ledger lock-step
// with the live FGA tuple set so a later symmetric revoke does not replay a tuple
// that was already revoked. A deleted BINDING's rows are dropped by the FK ON
// DELETE CASCADE (delete.go); this handles the member-level revocations that leave
// the binding row alive. len==0 is a no-op.
func (s *reconcileStore) ForgetEmittedTuples(ctx context.Context, bindingID domain.AccessBindingID, tuples []domain.MembershipTuple) error {
	for _, t := range tuples {
		if _, err := s.tx.Exec(ctx,
			`DELETE FROM kacho_iam.access_binding_emitted_tuples
			  WHERE binding_id = $1 AND fga_user = $2 AND relation = $3 AND object = $4`,
			string(bindingID), t.User, t.Relation, t.Object,
		); err != nil {
			return fmt.Errorf("reconcile: forget emitted tuple: %w", err)
		}
	}
	return nil
}

// EmitContainmentAudit writes the "rejected: not contained in scope" audit event
// (D1/D8 — not silent). Reuses the durable audit_outbox table.
//
// #2: tenant_account_id is the account-keyed compliance-scoping column, so it MUST
// carry the OWNING ACCOUNT id — never the binding's scope id verbatim. For an
// account-scope the scope id IS the account; for a PROJECT-scope the scope id is a
// `prj…` id, so the owning account is resolved on the tx; cluster / cross-service
// scopes write NULL (mirroring the use-case's auditTenantAccountID convention). The
// full scope_id remains in event_payload for tracing — only the account-keyed column
// changes.
func (s *reconcileStore) EmitContainmentAudit(ctx context.Context, bindingID domain.AccessBindingID, objectType, objectID string, scope domain.ScopeAnchor) error {
	payload, err := json.Marshal(map[string]string{
		"binding_id":  string(bindingID),
		"object_type": objectType,
		"object_id":   objectID,
		"scope_type":  scope.Type,
		"scope_id":    scope.ID,
		"reason":      "not contained in scope",
	})
	if err != nil {
		return fmt.Errorf("reconcile: marshal containment audit: %w", err)
	}
	tenantAccountID, err := s.scopeTenantAccountID(ctx, scope)
	if err != nil {
		return err
	}
	if _, err := s.tx.Exec(ctx,
		`INSERT INTO kacho_iam.audit_outbox
			(id, event_type, tenant_account_id, event_payload, status, attempts, created_at, next_attempt_at)
		 VALUES ($1, $2, $3, $4::jsonb, 'pending', 0, now(), now())`,
		newAuditEventID(), "iam.access_binding.containment_rejected", tenantAccountID, payload,
	); err != nil {
		return fmt.Errorf("reconcile: emit containment audit: %w", err)
	}
	return nil
}

// scopeTenantAccountID resolves the account-keyed tenant_account_id value for a
// containment-audit row from the binding's scope anchor (#2):
//
//   - account scope → scope.ID IS the account.
//   - project scope → resolve the project's owning account_id on the tx.
//   - cluster / cross-service / unknown → NULL (no single owning account).
//
// A project that has vanished from under the binding yields NULL rather than an
// error (the audit must still be emitted — the event_payload already carries the
// scope_id for tracing).
func (s *reconcileStore) scopeTenantAccountID(ctx context.Context, scope domain.ScopeAnchor) (any, error) {
	switch scope.Type {
	case "account":
		return nullableString(scope.ID), nil
	case "project":
		var accountID string
		err := s.tx.QueryRow(ctx,
			`SELECT account_id FROM kacho_iam.projects WHERE id = $1`, scope.ID).Scan(&accountID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, nil // project gone → no resolvable account; emit with NULL.
			}
			return nil, fmt.Errorf("reconcile: resolve project owning account: %w", err)
		}
		return nullableString(accountID), nil
	default:
		// cluster / cross-service / unknown — no single owning account.
		return nil, nil
	}
}

// RevokeExpiredBinding CAS-transitions an ACTIVE binding to REVOKED on the tx
// (ban #10 — single-statement UPDATE WHERE status='ACTIVE'). ok=false ⇒ 0 rows
// (already revoked / concurrent Delete won). revoked_at is stamped to satisfy the
// access_bindings_revoked_consistency_ck CHECK.
func (s *reconcileStore) RevokeExpiredBinding(ctx context.Context, bindingID domain.AccessBindingID) (bool, error) {
	tag, err := s.tx.Exec(ctx,
		`UPDATE kacho_iam.access_bindings
		    SET status = 'REVOKED', revoked_at = now()
		  WHERE id = $1 AND status = 'ACTIVE'`,
		string(bindingID),
	)
	if err != nil {
		return false, fmt.Errorf("reconcile: cas revoke expired %s: %w", bindingID, err)
	}
	return tag.RowsAffected() == 1, nil
}

// ListExpiredBindingIDs scans ACTIVE bindings whose TTL has elapsed (D9 expiry,
// index (status, expires_at)). Pool-scoped read.
func (a *ReconcileAdapter) ListExpiredBindingIDs(ctx context.Context) ([]domain.AccessBindingID, error) {
	rows, err := a.pool.Query(ctx,
		`SELECT id FROM kacho_iam.access_bindings
		  WHERE status = 'ACTIVE' AND expires_at IS NOT NULL AND expires_at < now()`)
	if err != nil {
		return nil, fmt.Errorf("reconcile: list expired bindings: %w", err)
	}
	defer rows.Close()
	var out []domain.AccessBindingID
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("reconcile: scan expired binding id: %w", err)
		}
		out = append(out, domain.AccessBindingID(id))
	}
	return out, rows.Err()
}

// membershipTuplesToClients maps the domain tuple to the fga_outbox INSERT shape.
func membershipTuplesToClients(tuples []domain.MembershipTuple) []clients.RelationTuple {
	out := make([]clients.RelationTuple, len(tuples))
	for i, t := range tuples {
		out[i] = clients.RelationTuple{User: t.User, Relation: t.Relation, Object: t.Object}
	}
	return out
}

func mirrorRowToDomain(r resource_mirror.MirrorRow) domain.MirrorObject {
	return domain.MirrorObject{
		ObjectType:      r.ObjectType,
		ObjectID:        r.ObjectID,
		ParentProjectID: r.ParentProjectID,
		ParentAccountID: r.ParentAccountID,
		Labels:          r.Labels,
	}
}

// scopeAnchorFor maps a binding's (resource_type, resource_id) onto the
// containment scope-anchor. The binding's resource_type is "project" | "account"
// | "cluster"; the anchor id is the resource_id.
func scopeAnchorFor(b domain.AccessBinding) domain.ScopeAnchor {
	return domain.ScopeAnchor{Type: string(b.ResourceType), ID: b.ResourceID}
}

// ── reconcile_outbox drain surface (pool-scoped; the worker claims then the
//    reconciler consumes inside its own tx) ────────────────────────────────────

// ClaimReconcileEvents reads the next unsent reconcile events (pool-scoped read).
func (a *ReconcileAdapter) ClaimReconcileEvents(ctx context.Context, limit int) ([]reconcile_outbox.Event, error) {
	return reconcile_outbox.ClaimBatch(ctx, a.pool, limit)
}

// MarkReconcileEventSent marks an event drained on its own short tx (called after
// the reconcile pass for that object committed).
func (a *ReconcileAdapter) MarkReconcileEventSent(ctx context.Context, id int64) error {
	tx, err := a.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("reconcile: begin mark-sent tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := reconcile_outbox.MarkSentTx(ctx, tx, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ListSelectorBindingIDs returns the ids of all bindings whose ROLE carries an
// ARM_LABELS selector (the periodic sweep target). RBAC rules-model 2026:
// the legacy per-binding access_binding_selector arm is gone
// — the sweep targets are exactly the role.rules ARM_LABELS bindings. Pool-scoped
// read; the sweep keeps the per-rule materialization defense-in-depth (a lost
// mirror-change event still re-converges).
func (a *ReconcileAdapter) ListSelectorBindingIDs(ctx context.Context) ([]domain.AccessBindingID, error) {
	rows, err := a.pool.Query(ctx,
		`SELECT DISTINCT b.id
		   FROM kacho_iam.role_rule_selectors rrs
		   JOIN kacho_iam.access_bindings b ON b.role_id = rrs.role_id
		  WHERE b.status = 'ACTIVE'`)
	if err != nil {
		return nil, fmt.Errorf("reconcile: list selector bindings: %w", err)
	}
	defer rows.Close()
	var out []domain.AccessBindingID
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("reconcile: scan selector binding id: %w", err)
		}
		out = append(out, domain.AccessBindingID(id))
	}
	return out, rows.Err()
}

// ── sync-FGA direct-write adapter ─────────────────────────────────────────────

// syncFGAWriter adapts a clients.RelationStore (the production OpenFGAHTTPClient) onto
// the reconcile.SyncFGAWriter port so the reconciler can synchronously apply, AFTER its
// writer-tx commits, the per-object tuples it also enqueued to fga_outbox — closing the
// create-path read-after-write race under the Contract-A flat model. The reconcile use-
// case stays clients-free (Clean Architecture): the mapping lives here, in the pg
// adapter that already depends on both clients and reconcile. WriteTuples is idempotent
// (OpenFGAHTTPClient treats already_exists as success), so the later async drain of the
// SAME fga_outbox rows is a safe no-op.
type syncFGAWriter struct {
	relations clients.RelationStore
	// logger — surfaces per-tuple failures in the resilient fallback pass. nil →
	// warnings are skipped (the async drainer remains the durable retry path).
	logger *slog.Logger
}

// NewSyncFGAWriter builds the reconcile.SyncFGAWriter over a RelationStore. nil-safe:
// a nil RelationStore yields a nil writer, so reconcile.WithSyncFGA(nil) leaves the
// reconciler async-only (existing behaviour) — the composition root can pass an
// unconfigured store without a special case. logger may be nil (per-tuple warnings
// skipped).
func NewSyncFGAWriter(relations clients.RelationStore, logger *slog.Logger) reconcile.SyncFGAWriter {
	if relations == nil {
		return nil
	}
	return &syncFGAWriter{relations: relations, logger: logger}
}

// WriteTuples applies the create-path read-after-write tuple set to OpenFGA. It is the
// SYNC closer for one ReconcileObject/ReconcileBinding pass, so it must be as resilient
// as the async fga_outbox drainer (which applies row-by-row): a fan-out over multiple
// bounded `*.*` ARM_ANCHOR bindings on a populated account can collect a set that (a)
// exceeds OpenFGA's per-request maxTuplesPerWrite (handled by OpenFGAHTTPClient.WriteTuples
// chunking) AND (b) contains a tuple OpenFGA rejects for a sibling object whose tier is
// computed-only (e.g. `iam_role#viewer` accepts no direct user) — which would otherwise
// fail the WHOLE batched write and drop the owner's valid `iam_access_binding#viewer`
// tuple, leaving GET-after-create at 403 (#232). On a batch error we therefore RETRY
// per-tuple so one invalid/over-limit tuple only drops itself; the durable fga_outbox
// enqueue + async drainer remain the at-least-once backstop for any per-tuple failure
// (which the drainer poisons individually). Best-effort: the per-tuple pass returns nil
// even if some tuples fail (logged by the reconciler's applyAfterCommit caller via the
// batch error) — the goal is to land every APPLICABLE tuple synchronously.
func (w *syncFGAWriter) WriteTuples(ctx context.Context, tuples []reconcile.SyncFGATuple) error {
	if len(tuples) == 0 {
		return nil
	}
	out := make([]clients.RelationTuple, len(tuples))
	for i, t := range tuples {
		out[i] = clients.RelationTuple{User: t.User, Relation: t.Relation, Object: t.Object}
	}
	// Fast path — the whole (chunked) batch applies cleanly.
	if err := w.relations.WriteTuples(ctx, out); err == nil {
		return nil
	} else if len(out) == 1 {
		// A single-tuple batch already failed per-tuple — nothing to isolate; surface it.
		return err
	}
	// Resilient path — a tuple in the batch was rejected (computed-only tier on a
	// sibling object, or an over-limit chunk that still tripped). Apply each tuple on
	// its own so a single bad tuple does not strip the rest (notably the owner's valid
	// iam_access_binding viewer/admin tuple). Per-tuple failures are non-fatal here —
	// the async drainer poisons them individually; the create-path closer's job is to
	// land every applicable tuple now.
	for i := range out {
		if err := w.relations.WriteTuples(ctx, out[i:i+1]); err != nil && w.logger != nil {
			// Non-fatal here (the async fga_outbox drainer re-poisons the row and
			// retries durably), but no longer silent (CWE-778): a persistently
			// failing authorization tuple must be observable so an authz gap is
			// diagnosable even if the drainer also lags.
			w.logger.WarnContext(ctx, "sync FGA per-tuple write failed — deferred to the async drainer",
				slog.String("user", out[i].User),
				slog.String("relation", out[i].Relation),
				slog.String("object", out[i].Object),
				slog.String("err", err.Error()),
			)
		}
	}
	return nil
}

var _ reconcile.SyncFGAWriter = (*syncFGAWriter)(nil)
