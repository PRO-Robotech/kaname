// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg

// role_repo.go — pgxpool-impl для role.ReaderIface / WriterIface.
//
// Role: либо custom (account_id NOT NULL, is_system=false), либо system
// (account_id IS NULL, is_system=true).
//
// Within-service refs enforced at the DB level (ban #10):
//   - DB CHECK roles_system_xor_account (мутекс XOR).
//   - partial UNIQUE roles_custom_unique (account_id, name) WHERE is_system=false.
//   - partial UNIQUE roles_system_unique (name) WHERE is_system=true.
//   - FK roles_account_fk (custom only).
//   - DB CHECK iam_permissions_valid (regex + cardinality).
//   - Delete custom-role: atomic CAS WHERE NOT EXISTS access_bindings.role_id +
//     is_system=false (NotFound vs FailedPrecondition с verbatim text).

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/role"
)

type roleReader struct {
	tx pgx.Tx
}

// roleCols — canonical projection. It includes cluster_id + project_id so a
// read populates domain.Role's full scope (ClusterID for system, ProjectID for
// project-scoped custom) — the isRoleAssignable predicate
// (domain.IsRoleAssignable / ScopeGroupOf) reads those fields.
const roleCols = "id, cluster_id, account_id, project_id, name, description, permissions, rules, is_system, created_at, labels"

// rulesToJSON / rulesFromJSON delegate to the domain codec (domain.EncodeRules /
// domain.DecodeRules) — the single source of truth for the roles.rules JSONB shape
// (snake_case, scalar module — CHECK iam_rules_valid, migrations 0025/0033). The seed
// layer (system-role selector projection) decodes the same shape via the same codec.
func rulesToJSON(rules domain.Rules) ([]byte, error) {
	return domain.EncodeRules(rules)
}

func rulesFromJSON(raw []byte) (domain.Rules, error) {
	return domain.DecodeRules(raw)
}

func (r *roleReader) Get(ctx context.Context, id domain.RoleID) (domain.Role, error) {
	row := r.tx.QueryRow(ctx,
		fmt.Sprintf(`SELECT %s FROM roles WHERE id = $1`, roleCols), string(id))
	out, err := scanRole(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Role{}, iamerr.Wrapf(iamerr.ErrNotFound, "Role %s not found", id)
		}
		return domain.Role{}, mapErr(err, "", string(id))
	}
	return out, nil
}

// GetWithVersion returns the role + its xmin::text OCC token. roles
// has no version column, so the row's system xmin is the snapshot Role.Update
// echoes into UpdateCAS for the lost-update guard (the read-modify-write
// OCC-without-version-column pattern). xmin is selected first, then the canonical
// roleCols (scanRoleWithVersion reads the leading xmin slot then delegates to
// scanRole's column order).
func (r *roleReader) GetWithVersion(ctx context.Context, id domain.RoleID) (domain.Role, string, error) {
	var version string
	row := r.tx.QueryRow(ctx,
		fmt.Sprintf(`SELECT xmin::text, %s FROM roles WHERE id = $1`, roleCols), string(id))
	out, err := scanRoleWithVersion(row, &version)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Role{}, "", iamerr.Wrapf(iamerr.ErrNotFound, "Role %s not found", id)
		}
		return domain.Role{}, "", mapErr(err, "", string(id))
	}
	return out, version, nil
}

func (r *roleReader) List(ctx context.Context, f role.ListFilter) ([]domain.Role, string, error) {
	// page_size>MaxPageSize → InvalidArgument (no silent clamp); 0 → default.
	pageSize, err := effectivePageSize(f.PageSize)
	if err != nil {
		return nil, "", err
	}
	conditions := []string{}
	args := []any{}
	argIdx := 1
	if f.AccountID != "" {
		// scope: system roles (catalog floor) OR this Account's custom roles.
		// System roles carry account_id IS NULL, so a plain `account_id = $X`
		// would wrongly drop them — keep them via the is_system disjunct.
		conditions = append(conditions, fmt.Sprintf("(is_system OR account_id = $%d)", argIdx))
		args = append(args, string(f.AccountID))
		argIdx++
	}
	if f.VisibleIDs != nil {
		// Per-object push-down: constrain custom roles to the FGA visible-id
		// set (the caller's `viewer`-tier roles); system roles bypass (catalog
		// floor). Keyset stays dense over the filtered set because the predicate is in
		// SQL, not a post-filter.
		conditions = append(conditions, fmt.Sprintf("(is_system OR id = ANY($%d))", argIdx))
		args = append(args, f.VisibleIDs)
		argIdx++
	}
	if f.IsSystem != nil {
		conditions = append(conditions, fmt.Sprintf("is_system = $%d", argIdx))
		args = append(args, *f.IsSystem)
		argIdx++
	}
	if f.Filter != "" {
		// Простой фильтр по name.
		if name, ok := parseNameFilter(f.Filter); ok {
			conditions = append(conditions, fmt.Sprintf("name = $%d", argIdx))
			args = append(args, name)
			argIdx++
		}
	}
	if f.PageToken != "" {
		ts, id, err := decodePageToken(f.PageToken)
		if err != nil {
			return nil, "", iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument page_token")
		}
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", argIdx, argIdx+1))
		args = append(args, ts, id)
		argIdx += 2
	}
	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}
	q := fmt.Sprintf(`SELECT %s FROM roles %s ORDER BY created_at ASC, id ASC LIMIT $%d`,
		roleCols, where, argIdx)
	args = append(args, pageSize+1)

	rows, err := r.tx.Query(ctx, q, args...)
	if err != nil {
		return nil, "", mapErr(err, "", "")
	}
	defer rows.Close()

	var out []domain.Role
	for rows.Next() {
		ro, err := scanRole(rows)
		if err != nil {
			return nil, "", mapErr(err, "", "")
		}
		out = append(out, ro)
	}
	if err := rows.Err(); err != nil {
		return nil, "", mapErr(err, "", "")
	}
	var nextToken string
	if int64(len(out)) > pageSize {
		last := out[pageSize-1]
		nextToken = encodePageToken(last.CreatedAt, string(last.ID))
		out = out[:pageSize]
	}
	return out, nextToken, nil
}

// ListAssignable — roles assignable on (resourceType, resourceID) per the
// assignability matrix. The WHERE clause is the SQL mirror of
// domain.IsRoleAssignable so keyset pagination stays correct over the filtered
// set:
//
//	system roles (is_system)                         → always
//	account-scoped custom (account_id = $resourceID) → only when type=account
//	project-scoped custom (project_id = $resourceID) → only when type=project
//	cluster                                          → system only
//
// resourceType is account|project|cluster (the use-case validates the whitelist
// + id format before calling). An unknown type yields system-only (defensive).
func (r *roleReader) ListAssignable(ctx context.Context, resourceType, resourceID string, f role.ListFilter) ([]domain.Role, string, error) {
	pageSize, err := effectivePageSize(f.PageSize) // reject >max, no silent clamp
	if err != nil {
		return nil, "", err
	}

	// scopePred — the assignability predicate beyond is_system. For cluster
	// (and any non-account/project type) only system roles qualify, so the
	// extra disjunct is `false`.
	args := []any{}
	argIdx := 1
	var scopePred string
	switch resourceType {
	case "account":
		scopePred = fmt.Sprintf("(account_id = $%d)", argIdx)
		args = append(args, resourceID)
		argIdx++
	case "project":
		scopePred = fmt.Sprintf("(project_id = $%d)", argIdx)
		args = append(args, resourceID)
		argIdx++
	default:
		scopePred = "(false)"
	}

	conditions := []string{fmt.Sprintf("(is_system = true OR %s)", scopePred)}
	if f.PageToken != "" {
		ts, id, err := decodePageToken(f.PageToken)
		if err != nil {
			return nil, "", iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument page_token")
		}
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", argIdx, argIdx+1))
		args = append(args, ts, id)
		argIdx += 2
	}

	q := fmt.Sprintf(`SELECT %s FROM roles WHERE %s ORDER BY created_at ASC, id ASC LIMIT $%d`,
		roleCols, strings.Join(conditions, " AND "), argIdx)
	args = append(args, pageSize+1)

	rows, err := r.tx.Query(ctx, q, args...)
	if err != nil {
		return nil, "", mapErr(err, "", "")
	}
	defer rows.Close()

	var out []domain.Role
	for rows.Next() {
		ro, serr := scanRole(rows)
		if serr != nil {
			return nil, "", mapErr(serr, "", "")
		}
		out = append(out, ro)
	}
	if err := rows.Err(); err != nil {
		return nil, "", mapErr(err, "", "")
	}
	var nextToken string
	if int64(len(out)) > pageSize {
		last := out[pageSize-1]
		nextToken = encodePageToken(last.CreatedAt, string(last.ID))
		out = out[:pageSize]
	}
	return out, nextToken, nil
}

type roleWriter struct {
	roleReader
}

// Insert — только custom-role (caller гарантирует is_system=false + exactly one
// of account_id / project_id set). Persists BOTH the authored rules (rules
// JSONB — public authority) and the caller-supplied compiled permissions
// (internal, derived from rules by the use-case in the same writer-tx; never
// recomputed in SQL — drift hazard). account_id / project_id are written via
// NULLIF($, ”) so the unset scope column is stored NULL (not ”) — required by
// the roles_scope_xor CHECK and the roles_acc/prj_custom_unique partial indexes,
// and by the account_id/project_id FK (an ” would dangle).
func (w *roleWriter) Insert(ctx context.Context, r domain.Role) (domain.Role, error) {
	permsJSON, err := json.Marshal(stringSlice(r.Permissions))
	if err != nil {
		return domain.Role{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument permissions: %s", err.Error())
	}
	rulesJSON, err := rulesToJSON(r.Rules)
	if err != nil {
		return domain.Role{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument rules: %s", err.Error())
	}
	// labels — tenant-facing метки самого ресурса Role (own-resource); НЕ путать
	// с Rule.MatchLabels (object-selector внутри правила). Делают Role label-selectable.
	labelsJSON, err := marshalLabels(r.Labels)
	if err != nil {
		return domain.Role{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument labels: %s", err.Error())
	}
	now := time.Now().UTC()
	q := fmt.Sprintf(`
		INSERT INTO roles (id, account_id, project_id, name, description, permissions, rules, is_system, created_at, labels)
		VALUES ($1, NULLIF($2, ''), NULLIF($3, ''), $4, $5, $6, $7, $8, $9, $10)
		RETURNING %s`, roleCols)
	row := w.tx.QueryRow(ctx, q,
		string(r.ID), string(r.AccountID), string(r.ProjectID), string(r.Name), string(r.Description),
		permsJSON, rulesJSON, r.IsSystem, now, labelsJSON,
	)
	out, err := scanRole(row)
	if err != nil {
		return domain.Role{}, mapErr(err, "", string(r.Name))
	}
	return out, nil
}

// Update — UPDATE на mutable полях. Custom-role: name (с UNIQUE check),
// description, permissions. System-role caller отвергает на use-case-уровне.
func (w *roleWriter) Update(ctx context.Context, r domain.Role, updateMask []string) (domain.Role, error) {
	parts, args, err := roleUpdateSet(r, updateMask)
	if err != nil {
		return domain.Role{}, err
	}
	if len(parts) == 0 {
		return w.Get(ctx, r.ID)
	}
	args = append(args, string(r.ID))
	q := fmt.Sprintf(`UPDATE roles SET %s WHERE id = $%d RETURNING %s`,
		strings.Join(parts, ", "), len(args), roleCols)
	row := w.tx.QueryRow(ctx, q, args...)
	out, err := scanRole(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Role{}, iamerr.Wrapf(iamerr.ErrNotFound, "Role %s not found", r.ID)
		}
		return domain.Role{}, mapErr(err, "", string(r.Name))
	}
	return out, nil
}

// UpdateCAS — Update guarded by an xmin OCC token. It builds the same
// mutable-field SET list as Update, then appends `AND xmin::text = $expected` to the
// WHERE so two concurrent Role.Updates cannot both commit a fan-out derived from
// their own role projection (ledger↔FGA drift). The row-lock serializes them: the
// loser reads the SAME expected version, finds xmin bumped, RETURNING yields 0 rows
// → pgx.ErrNoRows → ErrFailedPrecondition (the caller rolls back its whole writer-tx
// — UPDATE + reconcile fan-out — together, ban #10). expectedVersion=="" skips the
// predicate (unconditional last-writer Update, back-compat). A 0-row result with a
// non-empty token is OCC loss OR not-found; both surface as FailedPrecondition (the
// use-case loaded the role on the sync path, so not-found here means it raced away).
func (w *roleWriter) UpdateCAS(ctx context.Context, r domain.Role, updateMask []string, expectedVersion string) (domain.Role, error) {
	if expectedVersion == "" {
		return w.Update(ctx, r, updateMask)
	}
	parts, args, err := roleUpdateSet(r, updateMask)
	if err != nil {
		return domain.Role{}, err
	}
	if len(parts) == 0 {
		// Nothing to change — re-touch under the OCC guard so a no-op Update still
		// validates the expected version (and bumps xmin for observers).
		parts = append(parts, "id = id")
	}
	args = append(args, string(r.ID), expectedVersion)
	q := fmt.Sprintf(`UPDATE roles SET %s WHERE id = $%d AND xmin::text = $%d RETURNING %s`,
		strings.Join(parts, ", "), len(args)-1, len(args), roleCols)
	row := w.tx.QueryRow(ctx, q, args...)
	out, err := scanRole(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Stable contract text — capital "Role" to match
			// the use-case OCC text in role.update.go (register unified).
			return domain.Role{}, iamerr.Wrapf(iamerr.ErrFailedPrecondition,
				"Role was modified concurrently, retry")
		}
		return domain.Role{}, mapErr(err, "", string(r.Name))
	}
	return out, nil
}

// roleUpdateSet builds the mutable-field SET fragments + bind-args shared by Update
// and UpdateCAS. Returns the `col = $n` parts and the matching arg slice (idx
// starting at 1). An unknown update_mask field → ErrInvalidArg (verbatim text).
func roleUpdateSet(r domain.Role, updateMask []string) ([]string, []any, error) {
	// `rules` is the authored mutable field; when it is set, the use-case has
	// already recompiled `permissions` from the new rules and updates BOTH in the
	// same writer-tx so the stored compiled set never drifts from the authority.
	// `updated_at` is bumped on every applied mutation.
	mutableFields := map[string]bool{"name": true, "description": true, "permissions": true, "rules": true, "labels": true}
	apply := map[string]bool{}
	if len(updateMask) == 0 {
		for k := range mutableFields {
			apply[k] = true
		}
	} else {
		for _, f := range updateMask {
			if !mutableFields[f] {
				return nil, nil, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument update_mask field %q", f)
			}
			apply[f] = true
		}
	}
	// Editing rules implies re-storing the compiled permissions projection.
	if apply["rules"] {
		apply["permissions"] = true
	}
	parts := []string{}
	args := []any{}
	idx := 1
	if apply["name"] {
		parts = append(parts, fmt.Sprintf("name = $%d", idx))
		args = append(args, string(r.Name))
		idx++
	}
	if apply["description"] {
		parts = append(parts, fmt.Sprintf("description = $%d", idx))
		args = append(args, string(r.Description))
		idx++
	}
	if apply["rules"] {
		rulesJSON, err := rulesToJSON(r.Rules)
		if err != nil {
			return nil, nil, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument rules: %s", err.Error())
		}
		parts = append(parts, fmt.Sprintf("rules = $%d", idx))
		args = append(args, rulesJSON)
		idx++
	}
	if apply["permissions"] {
		permsJSON, err := json.Marshal(stringSlice(r.Permissions))
		if err != nil {
			return nil, nil, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument permissions: %s", err.Error())
		}
		parts = append(parts, fmt.Sprintf("permissions = $%d", idx))
		args = append(args, permsJSON)
		idx++
	}
	// labels — own-resource tenant-facing метки; mutable наравне с name/rules.
	if apply["labels"] {
		labelsJSON, err := marshalLabels(r.Labels)
		if err != nil {
			return nil, nil, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument labels: %s", err.Error())
		}
		parts = append(parts, fmt.Sprintf("labels = $%d", idx))
		args = append(args, labelsJSON)
	}
	return parts, args, nil
}

// Delete — the in-use invariant is enforced at the DB level by the FK
// access_bindings_role_fk ON DELETE RESTRICT (ban #10): an unconditional
// DELETE of a role still carrying ANY binding row raises SQLSTATE 23503, mapped to
// FAILED_PRECONDITION "role is in use by access bindings" (no software
// check-then-act / TOCTOU, no pgx leak). The FK fires regardless of the binding's
// status; AccessBindingService.Delete is a HARD delete (purges the row), which is
// what clears the precondition (the text is intentionally not qualified "active").
// The is_system and not-found cases are
// business-state discriminations (NOT FK-expressible), so the DELETE is guarded
// `is_system = false` and a 0-row result is probed to distinguish:
//
//	system role          → FAILED_PRECONDITION "System role ... cannot be deleted"
//	role does not exist  → NOT_FOUND
//
// The single-statement DELETE holds the row-lock, so a concurrent grant on the
// same role serializes and either commits before (this DELETE then trips the FK)
// or after (the grant's FK insert sees the deleted role and fails) — second-
// writer never wins.
func (w *roleWriter) Delete(ctx context.Context, id domain.RoleID) error {
	row := w.tx.QueryRow(ctx,
		`DELETE FROM roles WHERE id = $1 AND is_system = false RETURNING 1`, string(id))
	var one int
	err := row.Scan(&one)
	if err == nil {
		return nil // exactly one custom role deleted
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		// FK RESTRICT (23503) on a still-bound role lands here → FailedPrecondition
		// with the canonical text via the "Role.Delete" kindHint (no constraint/pgx leak).
		return mapErr(err, "Role.Delete", string(id))
	}
	// 0 rows deleted: either system role or non-existent. Probe to discriminate.
	var isSystem bool
	perr := w.tx.QueryRow(ctx, `SELECT is_system FROM roles WHERE id = $1`, string(id)).Scan(&isSystem)
	if perr != nil {
		if errors.Is(perr, pgx.ErrNoRows) {
			return iamerr.Wrapf(iamerr.ErrNotFound, "Role %s not found", id)
		}
		return mapErr(perr, "Role.Delete", string(id))
	}
	if isSystem {
		return iamerr.Wrapf(iamerr.ErrFailedPrecondition, "System role %s cannot be deleted", id)
	}
	// Custom role exists but the guarded DELETE matched 0 rows — should not happen
	// (the only guard is is_system=false). Treat as not-found defensively.
	return iamerr.Wrapf(iamerr.ErrNotFound, "Role %s not found", id)
}

// ReplaceRuleSelectors syncs role_rule_selectors with the role's UNIFIED
// materializing rules (flat explicit RBAC model): ARM_ANCHOR(all) +
// ARM_NAMES + ARM_LABELS. DELETE-all-then-INSERT keyed by role_id inside the caller
// tx, so a removed/edited rule drops/replaces its selector atomically with the rules
// change (ban #10). A rule whose dotted-types are empty (wildcard `*.*` system form,
// served by the cluster super-admin short-circuit) is NOT persisted — it materializes nothing.
func (w *roleWriter) ReplaceRuleSelectors(ctx context.Context, roleID domain.RoleID, selectors []domain.RuleSelector) error {
	if _, err := w.tx.Exec(ctx,
		`DELETE FROM kacho_iam.role_rule_selectors WHERE role_id = $1`, string(roleID)); err != nil {
		// Route SQLSTATE → sentinel (mapErr) rather than bare fmt.Errorf(%w) so a
		// constraint violation maps to the right gRPC code and no pgx text leaks.
		return mapErr(err, "", string(roleID))
	}
	for _, sel := range selectors {
		// A wildcard-only rule projects to zero dotted-types (cluster super-admin
		// `*.*` short-circuit) — nothing to materialize per-object, skip it.
		if len(sel.ObjectTypes) == 0 {
			continue
		}
		labelsJSON, err := json.Marshal(sel.MatchLabels)
		if err != nil {
			return iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument matchLabels: %s", err.Error())
		}
		if string(labelsJSON) == "null" {
			labelsJSON = []byte("{}")
		}
		// pgx encodes a nil []string as SQL NULL, which violates the NOT NULL column
		// (DEFAULT applies only when the column is OMITTED, not when NULL is passed
		// explicitly). Normalize to an empty array so an anchor/labels selector (no
		// names) stores '{}'.
		resourceNames := sel.ResourceNames
		if resourceNames == nil {
			resourceNames = []string{}
		}
		if _, err := w.tx.Exec(ctx,
			`INSERT INTO kacho_iam.role_rule_selectors
			   (role_id, rule_fp, arm, object_types, resource_names, match_labels, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6::jsonb, now(), now())
			 ON CONFLICT (role_id, rule_fp) DO UPDATE
			    SET arm            = EXCLUDED.arm,
			        object_types   = EXCLUDED.object_types,
			        resource_names = EXCLUDED.resource_names,
			        match_labels   = EXCLUDED.match_labels,
			        updated_at     = now()`,
			string(roleID), sel.RuleFP, armText(sel.Arm), sel.ObjectTypes, resourceNames, labelsJSON,
		); err != nil {
			// A CHECK violation (23514 — e.g. match_labels fails kacho_labels_valid)
			// must surface as InvalidArgument, not INTERNAL; mapErr also keeps the pgx
			// constraint text from leaking to the caller.
			return mapErr(err, "", string(roleID))
		}
	}
	return nil
}

// armText maps the domain Arm to the role_rule_selectors.arm enum text.
func armText(a domain.Arm) string {
	switch a {
	case domain.ArmNames:
		return "names"
	case domain.ArmLabels:
		return "labels"
	default:
		return "anchor"
	}
}

// ---- helpers ---------------------------------------------------------------

func scanRole(row scanner) (domain.Role, error) {
	var (
		ro                       domain.Role
		clusterID, accID, projID sql.NullString
		permsJSON, rulesJSON     []byte
		labelsJSON               []byte
	)
	err := row.Scan(
		(*string)(&ro.ID),
		&clusterID,
		&accID,
		&projID,
		(*string)(&ro.Name),
		(*string)(&ro.Description),
		&permsJSON,
		&rulesJSON,
		&ro.IsSystem,
		&ro.CreatedAt,
		&labelsJSON,
	)
	if err != nil {
		return domain.Role{}, err
	}
	if clusterID.Valid {
		ro.ClusterID = domain.ClusterID(clusterID.String)
	}
	if accID.Valid {
		ro.AccountID = domain.AccountID(accID.String)
	}
	if projID.Valid {
		ro.ProjectID = domain.ProjectID(projID.String)
	}
	if err := scanRolePolicy(&ro, permsJSON, rulesJSON); err != nil {
		return domain.Role{}, err
	}
	ro.Labels, err = unmarshalLabels(labelsJSON)
	if err != nil {
		return domain.Role{}, err
	}
	return ro, nil
}

// scanRolePolicy decodes the permissions + rules JSONB columns into the role.
// A legacy permissions-only role (rules='[]') yields ro.Rules == nil/empty.
func scanRolePolicy(ro *domain.Role, permsJSON, rulesJSON []byte) error {
	var perms []string
	if err := json.Unmarshal(permsJSON, &perms); err != nil {
		return fmt.Errorf("unmarshal permissions: %w", err)
	}
	ro.Permissions = make(domain.Permissions, 0, len(perms))
	for _, p := range perms {
		ro.Permissions = append(ro.Permissions, domain.Permission(p))
	}
	rules, err := rulesFromJSON(rulesJSON)
	if err != nil {
		return err
	}
	ro.Rules = rules
	return nil
}

// scanRoleWithVersion scans a row whose FIRST column is xmin::text (the OCC token)
// followed by the canonical roleCols projection. The token is read into *versionOut
// then scanRole's column order is reproduced (GetWithVersion).
func scanRoleWithVersion(row scanner, versionOut *string) (domain.Role, error) {
	var (
		ro                       domain.Role
		clusterID, accID, projID sql.NullString
		permsJSON, rulesJSON     []byte
		labelsJSON               []byte
	)
	err := row.Scan(
		versionOut,
		(*string)(&ro.ID),
		&clusterID,
		&accID,
		&projID,
		(*string)(&ro.Name),
		(*string)(&ro.Description),
		&permsJSON,
		&rulesJSON,
		&ro.IsSystem,
		&ro.CreatedAt,
		&labelsJSON,
	)
	if err != nil {
		return domain.Role{}, err
	}
	if clusterID.Valid {
		ro.ClusterID = domain.ClusterID(clusterID.String)
	}
	if accID.Valid {
		ro.AccountID = domain.AccountID(accID.String)
	}
	if projID.Valid {
		ro.ProjectID = domain.ProjectID(projID.String)
	}
	if err := scanRolePolicy(&ro, permsJSON, rulesJSON); err != nil {
		return domain.Role{}, err
	}
	ro.Labels, err = unmarshalLabels(labelsJSON)
	if err != nil {
		return domain.Role{}, err
	}
	return ro, nil
}

func stringSlice(perms domain.Permissions) []string {
	out := make([]string, 0, len(perms))
	for _, p := range perms {
		out = append(out, string(p))
	}
	return out
}
