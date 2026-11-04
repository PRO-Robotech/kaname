// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/manifest"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
)

// Неизменённое доказательство штатного посева ограничено заявленными штатными модулями.
func rid12RequireOrdinarySeed(t *testing.T, f *installationNativeWorld, view rid09PublicView, modules ...string) {
	t.Helper()
	var catalog iamv1.ListPermissionCatalogResponse
	f.publicRead(t, "/iam/v1/permissionCatalog", &catalog)
	for _, module := range modules {
		matches := 0
		for _, m := range catalog.Modules {
			if m.Module == module {
				matches++
				require.Len(t, m.Resources, 1)
				require.Equal(t, "objects", m.Resources[0].Resource)
				require.ElementsMatch(t, []string{"get", "list"}, m.Resources[0].Verbs)
			}
		}
		require.Equal(t, 1, matches)
		var sa, group, role, binding string
		require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT id FROM kaname.service_accounts WHERE account_id=$1 AND name=$2`, f.baseline.SystemID, "svc-"+module).Scan(&sa))
		require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT id FROM kaname.groups WHERE account_id=$1 AND name=$2`, f.baseline.SystemID, module+"-readers").Scan(&group))
		require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT id FROM kaname.roles WHERE owner_module=$1 AND name=$2 AND cluster_id='cluster_root' AND live`, module, module+".reader").Scan(&role))
		require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT id FROM kaname.access_bindings WHERE subject_type='group' AND subject_id=$1 AND role_id=$2 AND resource_type='cluster' AND resource_id='cluster_root' AND status='ACTIVE' AND revoked_at IS NULL`, group, role).Scan(&binding))
		require.Contains(t, view.Groups, group)
		require.Contains(t, view.Roles, role)
		require.Contains(t, view.Bindings, binding)
		var writerGroup string
		require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT id FROM kaname.groups WHERE account_id=$1 AND name='module-relation-writers'`, f.baseline.SystemID).Scan(&writerGroup))
		require.Contains(t, view.Members, writerGroup+"/service_account/"+sa)
		var r iamv1.Role
		f.publicRead(t, "/iam/v1/roles/"+role, &r)
		require.Equal(t, module+".reader", r.Name)
		require.Equal(t, "cluster_root", r.ClusterId)
		require.Len(t, r.Rules, 1)
		require.Equal(t, module, r.Rules[0].Module)
		require.Equal(t, []string{"objects"}, r.Rules[0].Resources)
		require.ElementsMatch(t, []string{"get", "list"}, r.Rules[0].Verbs)
		var b iamv1.AccessBinding
		f.publicRead(t, "/iam/v1/accessBindings/"+binding, &b)
		require.Equal(t, role, b.RoleId)
		require.Equal(t, "iam.cluster", b.ScopeType)
		require.Equal(t, "cluster_root", b.ScopeId)
		require.Equal(t, iamv1.AccessBinding_ACTIVE, b.Status)
		require.True(t, b.System)
		require.True(t, b.DeletionProtection)
		require.Len(t, b.Subjects, 1)
		require.Equal(t, iamv1.SubjectType_SUBJECT_TYPE_GROUP, b.Subjects[0].Type)
		require.Equal(t, group, b.Subjects[0].Id)
		require.NotNil(t, b.GetTarget().GetAllInScope())
		require.Nil(t, b.RevokedAt)
		var created time.Time
		require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT created_at FROM kaname.access_bindings WHERE id=$1`, binding).Scan(&created))
		requireNativePublicCreatedAt(t, created, b.CreatedAt)
		requireNativeAuthority(t, f.given, "service_account", sa, 0)
	}
}

func rid12RequireDeclaredCatalogRoles(t *testing.T, f *installationNativeWorld, declarations map[string]*manifest.Manifest, view rid09PublicView) {
	t.Helper()
	var catalog iamv1.ListPermissionCatalogResponse
	f.publicRead(t, "/iam/v1/permissionCatalog", &catalog)
	ordinary := []string{}
	for module, m := range declarations {
		if module != "ridbounds" {
			ordinary = append(ordinary, module)
		}
		found := 0
		for _, entry := range catalog.Modules {
			if entry.Module != module {
				continue
			}
			found++
			require.Len(t, entry.Resources, len(m.Resources))
			for _, resource := range m.Resources {
				matches := 0
				for _, actual := range entry.Resources {
					if actual.Resource != resource.Name {
						continue
					}
					matches++
					require.ElementsMatch(t, []string{"get", "list"}, actual.Verbs)
				}
				require.Equal(t, 1, matches)
			}
		}
		require.Equal(t, 1, found)
		var count int
		require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT count(*) FROM kaname.roles WHERE owner_module=$1 AND live`, module).Scan(&count))
		require.Equal(t, len(m.Roles), count)
		for _, declared := range m.Roles {
			var id string
			require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT id FROM kaname.roles WHERE owner_module=$1 AND name=$2 AND cluster_id='cluster_root' AND live`, module, declared.ID).Scan(&id))
			require.Contains(t, view.Roles, id)
			var got iamv1.Role
			f.publicRead(t, "/iam/v1/roles/"+id, &got)
			var created time.Time
			require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT created_at FROM kaname.roles WHERE id=$1`, id).Scan(&created))
			requireNativePublicCreatedAt(t, created, got.CreatedAt)
			require.Equal(t, declared.ID, got.Name)
			require.Equal(t, "cluster_root", got.ClusterId)
			require.Len(t, got.Rules, len(declared.Rules))
			for i, rule := range declared.Rules {
				require.Equal(t, module, got.Rules[i].Module)
				require.ElementsMatch(t, rule.Resources, got.Rules[i].Resources)
				require.ElementsMatch(t, []string{"get", "list"}, got.Rules[i].Verbs)
			}
		}
	}
	rid12RequireOrdinarySeed(t, f, view, ordinary...)
}
