// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"encoding/json"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/installruntime"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gopkg.in/yaml.v3"
)

type rid10World struct {
	w                    *ridLifecycleWorld
	subject, namedSystem string
	accountsBefore       []rid08AccountRow
}

func rid10Prepare(t *testing.T) *rid10World {
	t.Helper()
	full := ridLifecycleDelivery(t, false)
	// Judge exact full/staging bytes before any PG. Only GD declarations are
	// removed for ordinary catalog/I/W setup; no GD or binding is SQL-seeded.
	var doc map[string]any
	require.NoError(t, yaml.Unmarshal(full.First, &doc))
	seed, ok := doc["seed"].(map[string]any)
	require.True(t, ok)
	delete(seed, "grantDelegations")
	staged, err := yaml.Marshal(doc)
	require.NoError(t, err)
	_, err = manifest.Load(staged)
	require.NoError(t, err)
	f := newInstallationNativeWorldProfile(t, 7200, "", true)
	accounts, namedSystem, _, _ := rid08SetupN3(t, f)
	before := rid08PrimaryAccounts(t, f)
	p := f.apply(t, installruntime.DeliveryInput{Manifests: installruntime.RIDDeliveryFixture{First: staged}, CredentialFile: f.creator.CredentialFile})
	results, err := p.Results()
	require.NoError(t, err)
	require.Empty(t, results)
	require.Equal(t, before, rid08PrimaryAccounts(t, f))
	require.JSONEq(t, "[]", rid08PrimaryGD(t, f))
	require.Empty(t, rid08GDOperations(t, f))
	f.renewOperator(t, f.given.ctx)
	f.requireSameCredential(t)
	requireNativeAuthority(t, f.given, "user", f.operator.UserID(), 1)
	requireNativeAuthority(t, f.given, "service_account", f.creator.ID, 1)
	w := &ridLifecycleWorld{f: f, accounts: accounts, delivery: installruntime.DeliveryInput{Manifests: full, CredentialFile: f.creator.CredentialFile}}
	var issuerID, writerID string
	for _, raw := range f.ridList(t, "/iam/v1/serviceAccounts", "serviceAccounts", url.Values{"accountId": {f.baseline.SystemID}}) {
		var sa iamv1.ServiceAccount
		require.NoError(t, protojson.Unmarshal(raw, &sa))
		if sa.Name == "kacho-registry" {
			require.Empty(t, writerID)
			writerID = sa.Id
		}
		if sa.Name == "rid-public-issuer" {
			require.Empty(t, issuerID)
			issuerID = sa.Id
		}
	}
	require.NotEmpty(t, issuerID)
	require.Equal(t, authzguard.ServiceAccountIDForService("registry"), writerID)
	require.NotEqual(t, issuerID, writerID)
	var writer iamv1.ServiceAccount
	f.publicRead(t, "/iam/v1/serviceAccounts/"+writerID, &writer)
	require.Equal(t, "kacho-registry", writer.Name)
	require.Equal(t, f.baseline.SystemID, writer.AccountId)
	rosterFound := false
	for _, entry := range f.session.Environment {
		if strings.HasPrefix(entry, "KANAME_AUTHN__MODULE_IDENTITIES=") {
			for _, identity := range strings.Split(strings.TrimPrefix(entry, "KANAME_AUTHN__MODULE_IDENTITIES="), ",") {
				if identity == "kaname/kacho-registry=module-writer@internal" {
					rosterFound = true
				}
			}
		}
	}
	require.True(t, rosterFound)
	writerGroupFound := false
	for _, raw := range f.ridList(t, "/iam/v1/groups", "groups", url.Values{"accountId": {f.baseline.SystemID}}) {
		var group iamv1.Group
		require.NoError(t, protojson.Unmarshal(raw, &group))
		if group.Name != "module-relation-writers" {
			continue
		}
		require.False(t, writerGroupFound)
		writerGroupFound = true
		writerMember := false
		for _, raw := range f.ridList(t, "/iam/v1/groups/"+group.Id+":listMembers", "members", nil) {
			var member iamv1.GroupMember
			require.NoError(t, protojson.Unmarshal(raw, &member))
			require.False(t, member.MemberType == "service_account" && member.MemberId == issuerID, "I must not be a module writer")
			if member.MemberType == "service_account" && member.MemberId == writerID {
				writerMember = true
			}
		}
		require.True(t, writerMember)
	}
	require.True(t, writerGroupFound)
	require.NotEqual(t, f.creator.ID, issuerID)
	requireNativeAuthority(t, f.given, "service_account", issuerID, 0)
	for _, raw := range f.ridList(t, "/iam/v1/roles", "roles", nil) {
		var role iamv1.Role
		require.NoError(t, protojson.Unmarshal(raw, &role))
		if role.Name == "registry.puller" {
			w.pull = role.Id
		}
		if role.Name == "registry.pusher" {
			w.push = role.Id
		}
	}
	require.NotEmpty(t, w.pull)
	require.NotEmpty(t, w.push)
	require.NotEqual(t, w.pull, w.push)

	w.issuer = f.ridKey(t, issuerID, f.baseline.SystemID, "rid10-issuer")
	w.project = ridResponseID(t, f.ridOperation(t, "POST", "/iam/v1/projects", f.operator.Bearer(), map[string]any{"accountId": accounts[0], "name": "rid-public-project"}, 0))
	var project iamv1.Project
	f.publicRead(t, "/iam/v1/projects/"+w.project, &project)
	require.Equal(t, w.project, project.Id)
	require.Equal(t, accounts[0], project.AccountId, "actual project belongs to the grant scope")
	w.object = "rid-native-registry"
	w.repository = "rid-native-repository"
	conn, err := f.wire.ModuleWriter(filepath.Join(f.session.Root, "pki"))
	require.NoError(t, err)
	defer conn.Close()
	module := iamv1.NewInternalIAMServiceClient(conn)
	for _, entry := range []struct {
		modelType, dottedType, id, pointer, parentType, parentID string
		chain                                                    []string
	}{
		{"registry_registry", "registry.registries", w.object, "project", "project", w.project, []string{"project:" + w.project, "account:" + accounts[0]}},
		{"registry_repository", "registry.repositories", w.repository, "parent", "registry_registry", w.object, []string{"registry_registry:" + w.object, "project:" + w.project, "account:" + accounts[0]}},
	} {
		object := entry.modelType + ":" + entry.id
		// Observe the actually applied policy before writing: model name, dotted
		// catalog type, structural pointer and explicitly permitted owner writes.
		var dotted string
		var names, types, writes []string
		require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT dotted,parent_names,parent_types,writes FROM kaname.catalog_resource WHERE object_type=$1 AND live`, entry.modelType).Scan(&dotted, &names, &types, &writes))
		require.Equal(t, entry.dottedType, dotted)
		require.Equal(t, []string{entry.pointer}, names)
		require.Equal(t, []string{entry.parentType}, types)
		require.Contains(t, writes, "owner:user")
		// The existing RegisterResource protocol derives parenthood from a
		// pointer fact. An owner write cannot create that fact implicitly.
		// Registry follows the existing seed_registry_resource producer; repository
		// follows the same protocol with its already registered container as parent.
		for _, tuple := range []struct{ subject, relation string }{
			{entry.parentType + ":" + entry.parentID, entry.pointer},
			{"user:" + f.operator.UserID(), "owner"},
		} {
			_, err = module.RegisterResource(f.given.ctx, &iamv1.RegisterResourceRequest{SubjectId: tuple.subject, Relation: tuple.relation, Object: object, ParentProjectId: w.project, ParentAccountId: accounts[0], ParentChain: entry.chain, SourceVersion: timestamppb.Now()})
			require.NoError(t, err, "ordinary registration %s relation %s", entry.dottedType, tuple.relation)
			check, e := module.Check(f.given.ctx, &iamv1.CheckRequest{SubjectId: tuple.subject, Relation: tuple.relation, Object: object, Consistency: iamv1.CheckRequest_HIGHER_CONSISTENCY})
			require.NoError(t, e)
			require.True(t, check.Allowed, "actual registered pointer/owner")
		}
		// Observe the result under catalog vocabulary and the complete ordered
		// chain under model vocabulary; no observer writes domain state.
		var parentProject, parentAccount string
		var chain []string
		require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT m.parent_project_id,m.parent_account_id,
 (SELECT COALESCE(array_agg(e.parent_type||':'||e.parent_id ORDER BY e.depth),ARRAY[]::text[]) FROM kaname.resource_parent_edge e WHERE e.object_type=$3 AND e.object_id=$2)
 FROM kaname.resource_mirror m WHERE m.object_type=$1 AND m.object_id=$2`, entry.dottedType, entry.id, entry.modelType).Scan(&parentProject, &parentAccount, &chain))
		require.Equal(t, w.project, parentProject)
		require.Equal(t, accounts[0], parentAccount)
		require.Equal(t, entry.chain, chain)
	}

	requireNativeAuthority(t, f.given, "service_account", w.issuer.ID, 0)
	subject := f.ridSA(t, accounts[0], "rid10-first-grantee")
	require.JSONEq(t, "[]", rid08PrimaryGD(t, f))
	require.Empty(t, rid08GDOperations(t, f))
	rid08Write(t, f.session.Root, "rid10-staging", map[string]any{"setupOnly": true, "accounts": accounts, "canonicalSystem": f.baseline.SystemID, "namedSystemTenant": namedSystem, "issuer": w.issuer.ID, "writer": writerID, "gdCount": 0, "operationCount": 0, "firstScope": accounts[0]})
	return &rid10World{w: w, subject: subject, namedSystem: namedSystem, accountsBefore: before}
}

func (x *rid10World) grantFirst(t *testing.T) *iamv1.AccessBinding {
	w := x.w
	require.NotNil(t, w.gd)
	require.Equal(t, w.accounts[0], w.gd.AccountId)
	w.issuerToken = w.f.ridToken(t, w.issuer)
	return w.grant(t, map[string]any{"subjectType": "service_account", "subjectId": x.subject, "roleId": w.pull, "scopeType": "iam.account", "scopeId": w.accounts[0], "target": map[string]any{"resources": map[string]any{"resources": []any{map[string]any{"type": "registry.registries", "id": w.object}}}}})
}

// Stable primary rows for pre-existing grants; includes retired history. Authn,
// admin transition and normal Operation bookkeeping are observed separately.
func rid10BindingRows(t *testing.T, w *ridLifecycleWorld) string {
	t.Helper()
	var out string
	require.NoError(t, w.f.given.pool.QueryRow(w.f.given.ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(b) ORDER BY id),'[]'::jsonb)::text FROM kaname.access_bindings b`).Scan(&out))
	var decoded []json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(out), &decoded))
	require.NotEmpty(t, decoded)
	return out
}
