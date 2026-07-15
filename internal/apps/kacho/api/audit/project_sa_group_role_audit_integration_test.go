// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package audit_test

// project_sa_group_role_audit_integration_test.go — Project / ServiceAccount /
// Group / Role Create-Update-Delete durable audit_outbox emit. Each asserts
// the created/updated/deleted event_type, actor=principal, resource_id, key
// domain fields, the 22-char id format, and changed_fields on update.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/group"
	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/project"
	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/role"
	service_account "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/service_account"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// ── 5.2-13 Project C/U/D ───────────────────────────────────────────────────────

func TestProjectAudit_5_2_13_CrudEmits(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	owner, accID := seedUserAccount(t, ctx, env.pool, "prj13")

	// Create
	_, err := project.NewCreateProjectUseCase(env.repo, env.opsRepo).Execute(
		withPrincipal(owner), domain.Project{
			AccountID: accID,
			Name:      domain.ProjectName("proj-13"),
			Labels:    domain.Labels{},
		})
	require.NoError(t, err)
	awaitWorkers(t)
	prjID := singleID(t, ctx, env, `SELECT id FROM kacho_iam.projects WHERE name = $1 AND account_id = $2`, "proj-13", string(accID))

	created := requireOneAuditRow(ctx, t, env.pool, "iam.project.created", prjID)
	require.Equal(t, "project", created.payload["resource_type"])
	require.Equal(t, string(accID), created.payload["account_id"])
	require.Equal(t, "proj-13", created.payload["name"])
	require.Equal(t, string(owner), created.payload["actor"])
	require.Regexp(t, evtIDFormat, created.id)

	// Update (name)
	newName := domain.ProjectName("proj-13-renamed")
	_, err = project.NewUpdateProjectUseCase(env.repo, env.opsRepo).Execute(
		withPrincipal(owner), project.UpdateProjectInput{
			ID:         domain.ProjectID(prjID),
			Name:       &newName,
			UpdateMask: []string{"name"},
		})
	require.NoError(t, err)
	awaitWorkers(t)
	upd := requireOneAuditRow(ctx, t, env.pool, "iam.project.updated", prjID)
	require.ElementsMatch(t, []any{"name"}, upd.payload["changed_fields"])
	require.Equal(t, string(owner), upd.payload["actor"])

	// Delete
	_, err = project.NewDeleteProjectUseCase(env.repo, env.opsRepo).Execute(
		withPrincipal(owner), domain.ProjectID(prjID))
	require.NoError(t, err)
	awaitWorkers(t)
	del := requireOneAuditRow(ctx, t, env.pool, "iam.project.deleted", prjID)
	require.Equal(t, string(owner), del.payload["actor"])
}

// ── 5.2-15 ServiceAccount C/U/D ────────────────────────────────────────────────

func TestServiceAccountAudit_5_2_15_CrudEmits(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	owner, accID := seedUserAccount(t, ctx, env.pool, "sa15")

	_, err := service_account.NewCreateServiceAccountUseCase(env.repo, env.opsRepo).Execute(
		withPrincipal(owner), domain.ServiceAccount{
			AccountID:   accID,
			Name:        domain.SvcAccountName("ci-bot-15"),
			Description: domain.Description("created"),
		})
	require.NoError(t, err)
	awaitWorkers(t)
	saID := singleID(t, ctx, env, `SELECT id FROM kacho_iam.service_accounts WHERE name = $1 AND account_id = $2`, "ci-bot-15", string(accID))

	created := requireOneAuditRow(ctx, t, env.pool, "iam.service_account.created", saID)
	require.Equal(t, "service_account", created.payload["resource_type"])
	require.Equal(t, string(accID), created.payload["account_id"])
	require.Equal(t, "ci-bot-15", created.payload["name"])
	require.Equal(t, string(owner), created.payload["actor"])
	require.Regexp(t, evtIDFormat, created.id)

	desc := domain.Description("updated-desc")
	_, err = service_account.NewUpdateServiceAccountUseCase(env.repo, env.opsRepo).Execute(
		withPrincipal(owner), service_account.UpdateServiceAccountInput{
			ID:          domain.ServiceAccountID(saID),
			Description: &desc,
			UpdateMask:  []string{"description"},
		})
	require.NoError(t, err)
	awaitWorkers(t)
	upd := requireOneAuditRow(ctx, t, env.pool, "iam.service_account.updated", saID)
	require.ElementsMatch(t, []any{"description"}, upd.payload["changed_fields"])

	_, err = service_account.NewDeleteServiceAccountUseCase(env.repo, env.opsRepo).Execute(
		withPrincipal(owner), domain.ServiceAccountID(saID))
	require.NoError(t, err)
	awaitWorkers(t)
	del := requireOneAuditRow(ctx, t, env.pool, "iam.service_account.deleted", saID)
	require.Equal(t, string(owner), del.payload["actor"])
}

// ── 5.2-16 Group C/U/D (member± events are not covered here — see EventType list) ─────

func TestGroupAudit_5_2_16_CrudEmits(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	owner, accID := seedUserAccount(t, ctx, env.pool, "grp16")

	_, err := group.NewCreateGroupUseCase(env.repo, env.opsRepo).Execute(
		withPrincipal(owner), domain.Group{
			AccountID: accID,
			Name:      domain.GroupName("devs-16"),
		})
	require.NoError(t, err)
	awaitWorkers(t)
	grpID := singleID(t, ctx, env, `SELECT id FROM kacho_iam.groups WHERE name = $1 AND account_id = $2`, "devs-16", string(accID))

	created := requireOneAuditRow(ctx, t, env.pool, "iam.group.created", grpID)
	require.Equal(t, "group", created.payload["resource_type"])
	require.Equal(t, string(accID), created.payload["account_id"])
	require.Equal(t, "devs-16", created.payload["name"])
	require.Equal(t, string(owner), created.payload["actor"])
	require.Regexp(t, evtIDFormat, created.id)

	desc := domain.Description("group-desc")
	_, err = group.NewUpdateGroupUseCase(env.repo, env.opsRepo).Execute(
		withPrincipal(owner), group.UpdateGroupInput{
			ID:          domain.GroupID(grpID),
			Description: &desc,
			UpdateMask:  []string{"description"},
		})
	require.NoError(t, err)
	awaitWorkers(t)
	upd := requireOneAuditRow(ctx, t, env.pool, "iam.group.updated", grpID)
	require.ElementsMatch(t, []any{"description"}, upd.payload["changed_fields"])

	_, err = group.NewDeleteGroupUseCase(env.repo, env.opsRepo).Execute(
		withPrincipal(owner), domain.GroupID(grpID))
	require.NoError(t, err)
	awaitWorkers(t)
	del := requireOneAuditRow(ctx, t, env.pool, "iam.group.deleted", grpID)
	require.Equal(t, string(owner), del.payload["actor"])
}

// ── 5.2-17 Role C/U/D (no permissions blow-up — id + changed_fields only) ──────

func TestRoleAudit_5_2_17_CrudEmits(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	owner, accID := seedUserAccount(t, ctx, env.pool, "rol17")

	_, err := role.NewCreateRoleUseCase(env.repo, env.opsRepo).Execute(
		withPrincipal(owner), domain.Role{
			AccountID: accID,
			Name:      domain.RoleName("vpc_reader_17"),
			Rules:     domain.Rules{{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get"}}},
		})
	require.NoError(t, err)
	awaitWorkers(t)
	rolID := singleID(t, ctx, env, `SELECT id FROM kacho_iam.roles WHERE name = $1 AND account_id = $2`, "vpc_reader_17", string(accID))

	created := requireOneAuditRow(ctx, t, env.pool, "iam.role.created", rolID)
	require.Equal(t, "role", created.payload["resource_type"])
	require.Equal(t, string(accID), created.payload["account_id"])
	require.Equal(t, string(owner), created.payload["actor"])
	require.Regexp(t, evtIDFormat, created.id)
	// no full permissions blob required — name is fine, but the secret-free
	// payload must not embed an exploded permission matrix beyond changed_fields.

	_, err = role.NewUpdateRoleUseCase(env.repo, env.opsRepo).Execute(
		withPrincipal(owner), role.UpdateRoleInput{
			ID:         domain.RoleID(rolID),
			Rules:      domain.Rules{{Module: "vpc", Resources: []string{"network", "subnet"}, Verbs: []string{"get"}}},
			UpdateMask: []string{"rules"},
		})
	require.NoError(t, err)
	awaitWorkers(t)
	upd := requireOneAuditRow(ctx, t, env.pool, "iam.role.updated", rolID)
	require.ElementsMatch(t, []any{"rules"}, upd.payload["changed_fields"])

	_, err = role.NewDeleteRoleUseCase(env.repo, env.opsRepo).Execute(
		withPrincipal(owner), domain.RoleID(rolID))
	require.NoError(t, err)
	awaitWorkers(t)
	del := requireOneAuditRow(ctx, t, env.pool, "iam.role.deleted", rolID)
	require.Equal(t, string(owner), del.payload["actor"])
}

func singleID(t *testing.T, ctx context.Context, env *testEnv, q, a, b string) string {
	t.Helper()
	var id string
	require.NoError(t, env.pool.QueryRow(ctx, q, a, b).Scan(&id))
	return id
}
