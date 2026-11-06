// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"net/url"
	"testing"
	"time"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

type rid09PublicView struct {
	Catalog                          string
	Groups, Members, Roles, Bindings map[string]string
}

// Полные штатные страницы O сохраняются независимо от первичных хешей.
// По всем учётным записям, с ролями/AB без области и полным публичным каталогом.
func rid09ReadPublic(t *testing.T, f *installationNativeWorld) rid09PublicView {
	t.Helper()
	f.renewOperator(t, f.given.ctx)
	out := rid09PublicView{Groups: map[string]string{}, Members: map[string]string{}, Roles: map[string]string{}, Bindings: map[string]string{}}
	var catalog iamv1.ListPermissionCatalogResponse
	f.publicRead(t, "/iam/v1/permissionCatalog", &catalog)
	out.Catalog = rid08CanonicalMessage(t, &catalog)
	for _, account := range rid08PrimaryAccounts(t, f) {
		seen := map[string]bool{}
		token := ""
		for {
			require.False(t, seen[token])
			seen[token] = true
			q := url.Values{"accountId": {account.ID}, "pageSize": {"2"}, "pageToken": {token}}
			var page iamv1.ListGroupsResponse
			f.publicRead(t, "/iam/v1/groups?"+q.Encode(), &page)
			for _, item := range page.Groups {
				require.NotNil(t, item)
				require.NotContains(t, out.Groups, item.Id)
				var got iamv1.Group
				f.publicRead(t, "/iam/v1/groups/"+url.PathEscape(item.Id), &got)
				require.True(t, proto.Equal(item, &got))
				require.Equal(t, account.ID, got.AccountId)
				out.Groups[got.Id] = rid08CanonicalMessage(t, &got)
				members := map[string]bool{}
				memberToken := ""
				for {
					require.False(t, members[memberToken])
					members[memberToken] = true
					mq := url.Values{"pageSize": {"2"}, "pageToken": {memberToken}}
					var mp iamv1.ListGroupMembersResponse
					f.publicRead(t, "/iam/v1/groups/"+url.PathEscape(got.Id)+":listMembers?"+mq.Encode(), &mp)
					for _, m := range mp.Members {
						require.NotNil(t, m)
						key := got.Id + "/" + m.MemberType + "/" + m.MemberId
						require.NotContains(t, out.Members, key)
						out.Members[key] = rid08CanonicalMessage(t, m)
					}
					memberToken = mp.NextPageToken
					if memberToken == "" {
						break
					}
				}
			}
			token = page.NextPageToken
			if token == "" {
				break
			}
		}
	}
	token := ""
	seen := map[string]bool{}
	for {
		require.False(t, seen[token])
		seen[token] = true
		q := url.Values{"pageSize": {"20"}, "pageToken": {token}}
		var page iamv1.ListRolesResponse
		f.publicRead(t, "/iam/v1/roles?"+q.Encode(), &page)
		for _, item := range page.Roles {
			require.NotNil(t, item)
			require.NotContains(t, out.Roles, item.Id)
			var got iamv1.Role
			f.publicRead(t, "/iam/v1/roles/"+url.PathEscape(item.Id), &got)
			require.True(t, proto.Equal(item, &got))
			out.Roles[got.Id] = rid08CanonicalMessage(t, &got)
		}
		token = page.NextPageToken
		if token == "" {
			break
		}
	}
	token = ""
	seen = map[string]bool{}
	for {
		require.False(t, seen[token])
		seen[token] = true
		q := url.Values{"pageSize": {"20"}, "pageToken": {token}, "includeRevoked": {"true"}}
		var page iamv1.ListAccessBindingsResponse
		f.publicRead(t, "/iam/v1/accessBindings?"+q.Encode(), &page)
		for _, item := range page.AccessBindings {
			require.NotNil(t, item)
			require.NotContains(t, out.Bindings, item.Id)
			var got iamv1.AccessBinding
			f.publicRead(t, "/iam/v1/accessBindings/"+url.PathEscape(item.Id), &got)
			// Независимо наблюдаемые полные строки PRIMARY остаются авторитетным
			// оракулом нулевой разницы. Обогащение публичного чтения сохраняется, не обнуляется.
			require.Equal(t, item.Id, got.Id)
			require.Equal(t, item.RoleId, got.RoleId)
			require.Equal(t, item.Status, got.Status)
			out.Bindings[got.Id] = rid08CanonicalMessage(t, &got)
		}
		token = page.NextPageToken
		if token == "" {
			break
		}
	}
	// Это настоящие чистые миры; кластерные полномочия администратора O должны видеть полную
	// публичную ведомость сущностей, а не только подмножество конкретного модуля.
	for table, got := range map[string]int{"groups": len(out.Groups), "group_members": len(out.Members), "roles": len(out.Roles), "access_bindings": len(out.Bindings)} {
		var count int
		require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT count(*) FROM kaname.`+table).Scan(&count))
		require.Equal(t, count, got, "complete ordinary public census: %s", table)
	}
	return out
}
func rid09RequireNoDelivery(t *testing.T, f *installationNativeWorld, accounts []string) {
	t.Helper()
	var count int
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT
 (SELECT count(*) FROM kaname.catalog_module WHERE module IN ('ridfirst','ridsecond'))+
 (SELECT count(*) FROM kaname.catalog_resource WHERE module IN ('ridfirst','ridsecond'))+
 (SELECT count(*) FROM kaname.catalog_verb WHERE module IN ('ridfirst','ridsecond'))+
 (SELECT count(*) FROM kaname.roles WHERE owner_module IN ('ridfirst','ridsecond'))+
 (SELECT count(*) FROM kaname.service_accounts WHERE name IN ('svc-ridfirst','svc-ridsecond'))+
 (SELECT count(*) FROM kaname.groups WHERE name IN ('ridfirst-readers','ridsecond-readers'))+
 (SELECT count(*) FROM kaname.grant_delegations)`).Scan(&count))
	require.Zero(t, count, "all resources of both manifests absent, not merely zero GD")
	require.Empty(t, rid08GDOperations(t, f))
	f.requirePublicDeliveredPairs(t)
	for _, account := range append(append([]string{}, accounts...), f.baseline.SystemID) {
		var gd iamv1.ListGrantDelegationsResponse
		f.publicRead(t, "/iam/v1/grantDelegations?"+url.Values{"accountId": {account}, "pageSize": {"2"}}.Encode(), &gd)
		require.Empty(t, gd.GrantDelegations)
		require.Empty(t, gd.NextPageToken)
	}
}
func rid09RequireFullDelivery(t *testing.T, f *installationNativeWorld, view rid09PublicView) {
	t.Helper()
	var catalog iamv1.ListPermissionCatalogResponse
	f.publicRead(t, "/iam/v1/permissionCatalog", &catalog)
	for _, module := range []string{"ridfirst", "ridsecond"} {
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
