// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/testsupport/installruntime"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gopkg.in/yaml.v3"
)

type ridLifecycleOperation struct {
	ID    string `json:"id"`
	Done  bool   `json:"done"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
	Response json.RawMessage `json:"response"`
	Metadata json.RawMessage `json:"metadata"`
}
type ridLifecycleWorld struct {
	f                                       *installationNativeWorld
	delivery                                installruntime.DeliveryInput
	accounts                                []string
	issuer                                  *installruntime.StandingCreator
	issuerToken                             string
	pull, push, project, object, repository string
	gd                                      *iamv1.GrantDelegation
}

func ridLifecycleDelivery(t *testing.T, systemClass bool) installruntime.RIDDeliveryFixture {
	t.Helper()
	raw, err := os.ReadFile("../../internal/manifest/testdata/registry.delegation-fixture.yaml")
	require.NoError(t, err)
	raw, err = publicreadfixture.WithWrites(raw)
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, yaml.Unmarshal(raw, &doc))
	subjects := []string{"SUBJECT_TYPE_SERVICE_ACCOUNT"}
	if systemClass {
		subjects = append(subjects, "SUBJECT_TYPE_SYSTEM_CLASS")
	}
	doc["seed"] = map[string]any{
		"serviceAccounts":  []any{map[string]any{"account": "system", "name": "rid-public-issuer"}, map[string]any{"account": "system", "name": "kacho-registry"}},
		"groups":           []any{map[string]any{"account": "system", "name": "rid-public-readers"}},
		"accessBindings":   []any{map[string]any{"subjects": []any{map[string]any{"type": "group", "name": "rid-public-readers"}}, "roleId": "registry.puller", "scopeType": "iam.cluster", "scopeId": "cluster_root", "target": "allInScope"}},
		"joins":            []any{map[string]any{"serviceAccount": map[string]any{"account": "system", "name": "kacho-registry"}, "group": map[string]any{"account": "system", "name": "module-relation-writers"}, "why": "Generic RID fixture uses the existing module writer mechanism"}},
		"grantDelegations": []any{map[string]any{"delegate": map[string]any{"account": "system", "name": "rid-public-issuer"}, "roleIds": []string{"registry.puller"}, "targetTypes": []string{"registry.registries"}, "subjectTypes": subjects}},
	}
	raw, err = yaml.Marshal(doc)
	require.NoError(t, err)
	return installruntime.RIDDeliveryFixture{First: raw}
}
func (f *installationNativeWorld) ridRequest(t *testing.T, method, path, bearer string, body any) (int, json.RawMessage) {
	t.Helper()
	var raw json.RawMessage
	code, err := f.wire.JSON(f.given.ctx, method, path, bearer, body, &raw)
	require.NoError(t, err)
	return code, raw
}
func (f *installationNativeWorld) ridOperation(t *testing.T, method, path, bearer string, body any, wantCode int) ridLifecycleOperation {
	t.Helper()
	code, raw := f.ridRequest(t, method, path, bearer, body)
	require.Equal(t, 200, code)
	var op ridLifecycleOperation
	require.NoError(t, json.Unmarshal(raw, &op))
	require.NotEmpty(t, op.ID)
	ctx, cancel := context.WithTimeout(f.given.ctx, 30*time.Second)
	defer cancel()
	for !op.Done {
		select {
		case <-ctx.Done():
			t.Fatal("ordinary lifecycle Operation did not complete")
		case <-time.After(25 * time.Millisecond):
		}
		code, raw = f.ridRequest(t, http.MethodGet, "/operations/"+op.ID, bearer, nil)
		require.Equal(t, 200, code)
		previous := op.ID
		require.NoError(t, json.Unmarshal(raw, &op))
		require.Equal(t, previous, op.ID)
	}
	if wantCode == 0 {
		require.Nil(t, op.Error)
		require.NotEmpty(t, op.Response)
	} else {
		require.NotNil(t, op.Error)
		require.Equal(t, wantCode, op.Error.Code)
	}
	return op
}
func ridResponseID(t *testing.T, op ridLifecycleOperation) string {
	t.Helper()
	var out struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(op.Response, &out))
	require.NotEmpty(t, out.ID)
	return out.ID
}
func (f *installationNativeWorld) ridSA(t *testing.T, account, name string) string {
	return ridResponseID(t, f.ridOperation(t, "POST", "/iam/v1/serviceAccounts", f.operator.Bearer(), map[string]any{"accountId": account, "name": name}, 0))
}
func (f *installationNativeWorld) ridList(t *testing.T, path, field string, query url.Values) []json.RawMessage {
	t.Helper()
	if query == nil {
		query = url.Values{}
	}
	query.Set("pageSize", "2")
	token := ""
	seen := map[string]bool{}
	var all []json.RawMessage
	for {
		require.False(t, seen[token], "public pagination token repeated")
		seen[token] = true
		query.Set("pageToken", token)
		code, raw := f.ridRequest(t, "GET", path+"?"+query.Encode(), f.operator.Bearer(), nil)
		require.Equal(t, 200, code)
		var page map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(raw, &page))
		var rows []json.RawMessage
		if page[field] != nil {
			require.NoError(t, json.Unmarshal(page[field], &rows))
		}
		require.LessOrEqual(t, len(rows), 2)
		all = append(all, rows...)
		token = ""
		if page["nextPageToken"] != nil {
			require.NoError(t, json.Unmarshal(page["nextPageToken"], &token))
		}
		if token == "" {
			return all
		}
	}
}
func (f *installationNativeWorld) ridToken(t *testing.T, key *installruntime.StandingCreator) string {
	t.Helper()
	token, err := f.wire.ExchangeLifecycleKey(f.given.ctx, key, "https://kaname.local", "https://kaname.local", func(secret string) { f.secrets = append(f.secrets, secret) })
	// Never print token/PEM through assertion values.
	f.secrets = append(f.secrets, token.Bearer, token.Assertion)
	require.NoError(t, err)
	require.NotEmpty(t, token.Bearer)
	return token.Bearer
}
func (f *installationNativeWorld) ridKey(t *testing.T, id, account, label string) *installruntime.StandingCreator {
	t.Helper()
	key, err := f.wire.IssueStandingKey(f.given.ctx, f.operator, id, account, filepath.Join(f.session.Root, label+".credential.json"), func(secret string) { f.secrets = append(f.secrets, secret) })
	require.NoError(t, err)
	f.secrets = append(f.secrets, key.SecretMaterial()...)
	raw, err := os.ReadFile(key.CredentialFile)
	require.NoError(t, err)
	f.secrets = append(f.secrets, string(raw))
	return key
}
func (f *installationNativeWorld) ridAdmin(t *testing.T, id string, grant bool) {
	t.Helper()
	f.renewOperator(t, f.given.ctx)
	conn, err := f.wire.Gateway(f.wire.InternalGatewayAddress())
	require.NoError(t, err)
	defer conn.Close()
	client := iamv1.NewInternalClusterServiceClient(conn)
	var raw []byte
	if grant {
		op, e := client.GrantAdmin(f.operator.GatewayContext(f.given.ctx), &iamv1.GrantClusterAdminRequest{SubjectType: iamv1.ClusterGrantSubjectType_SERVICE_ACCOUNT, SubjectId: id})
		require.NoError(t, e)
		raw, err = protojson.Marshal(op)
	} else {
		op, e := client.RevokeAdmin(f.operator.GatewayContext(f.given.ctx), &iamv1.RevokeClusterAdminRequest{SubjectType: iamv1.ClusterGrantSubjectType_SERVICE_ACCOUNT, SubjectId: id})
		require.NoError(t, e)
		raw, err = protojson.Marshal(op)
	}
	require.NoError(t, err)
	var op installruntime.Operation
	require.NoError(t, json.Unmarshal(raw, &op))
	_, err = f.wire.AwaitOperation(f.given.ctx, f.operator.Bearer(), op)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(f.given.ctx, 20*time.Second)
	defer cancel()
	for {
		admins, e := client.ListAdmins(f.operator.GatewayContext(ctx), &iamv1.ListClusterAdminsRequest{})
		require.NoError(t, e)
		found, independentO := false, false
		for _, a := range admins.Admins {
			if a.SubjectId == id && a.SubjectType == iamv1.ClusterGrantSubjectType_SERVICE_ACCOUNT {
				found = true
			}
			if a.SubjectId == f.operator.UserID() && a.SubjectType == iamv1.ClusterGrantSubjectType_USER {
				independentO = true
			}
		}
		require.True(t, independentO)
		if found == grant {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("admin transition not materialized")
		case <-time.After(25 * time.Millisecond):
		}
	}
}
func newRIDLifecycleWorld(t *testing.T, mode string, systemClass bool) *ridLifecycleWorld {
	t.Helper()
	f := newInstallationNativeWorldProfile(t, 7200, "", true)

	// Constructor already compared the full stock catalog before/after base,
	// recorded real no-delivery receipts, and checked zero delivered I/W/GD.

	accounts := []string{f.tenantID}
	if mode == "S2" {
		accounts = f.createRID02Accounts(t)
	}
	in := installruntime.DeliveryInput{Manifests: ridLifecycleDelivery(t, systemClass), CredentialFile: f.creator.CredentialFile}
	if mode == "S1" {
		in.TenantAccountID = &f.tenantID
	}
	requireNativeOK(t, f.apply(t, in), len(accounts))
	f.renewOperator(t, f.given.ctx)
	w := &ridLifecycleWorld{f: f, delivery: in, accounts: accounts}
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
	for _, account := range accounts {
		list := w.delegations(t, account)
		require.Len(t, list, 1)
		gd := list[0]
		require.Equal(t, issuerID, gd.Delegate.Id)
		require.Equal(t, f.creator.ID, gd.DelegatedBy.Id)
		require.Equal(t, "service_account", gd.DelegatedBy.Type)
		require.Equal(t, []string{w.pull}, gd.RoleIds)
		require.Equal(t, []string{"registry.registries"}, gd.TargetTypes)
		expected := []iamv1.SubjectType{iamv1.SubjectType_SUBJECT_TYPE_SERVICE_ACCOUNT}
		if systemClass {
			expected = append(expected, iamv1.SubjectType_SUBJECT_TYPE_SYSTEM_CLASS)
		}
		require.ElementsMatch(t, expected, gd.SubjectTypes)
		require.Equal(t, iamv1.GrantDelegation_ACTIVE, gd.Status)
		if account == f.tenantID {
			w.gd = gd
		}
	}
	w.issuer = f.ridKey(t, issuerID, f.baseline.SystemID, "issuer")
	w.issuerToken = f.ridToken(t, w.issuer)
	w.project = ridResponseID(t, f.ridOperation(t, "POST", "/iam/v1/projects", f.operator.Bearer(), map[string]any{"accountId": f.tenantID, "name": "rid-public-project"}, 0))
	w.object = "rid-native-registry"
	w.repository = "rid-native-repository"
	conn, err := f.wire.ModuleWriter(filepath.Join(f.session.Root, "pki"))
	require.NoError(t, err)
	defer conn.Close()
	module := iamv1.NewInternalIAMServiceClient(conn)
	for _, entry := range []struct {
		object string
		chain  []string
	}{{"registry_registry:" + w.object, []string{"project:" + w.project, "account:" + f.tenantID}}, {"registry_repository:" + w.repository, []string{"registry_registry:" + w.object, "project:" + w.project, "account:" + f.tenantID}}} {
		_, err = module.RegisterResource(f.given.ctx, &iamv1.RegisterResourceRequest{SubjectId: "user:" + f.operator.UserID(), Relation: "owner", Object: entry.object, ParentProjectId: w.project, ParentAccountId: f.tenantID, ParentChain: entry.chain, SourceVersion: timestamppb.Now()})
		require.NoError(t, err)
		check, e := module.Check(f.given.ctx, &iamv1.CheckRequest{SubjectId: "user:" + f.operator.UserID(), Relation: "owner", Object: entry.object, Consistency: iamv1.CheckRequest_HIGHER_CONSISTENCY})
		require.NoError(t, e)
		require.True(t, check.Allowed)
	}

	for _, account := range accounts {
		for _, subject := range []string{issuerID, f.creator.ID} {
			judged, e := module.Check(f.given.ctx, &iamv1.CheckRequest{SubjectId: "service_account:" + subject, Relation: "admin", Object: "account:" + account, Consistency: iamv1.CheckRequest_HIGHER_CONSISTENCY})
			require.NoError(t, e)
			// C's cluster admin may imply account admin in the relation model. The
			// issuer must have neither; C's direct tenant grants are checked at retirement.
			if subject == issuerID {
				require.False(t, judged.Allowed, "I must not acquire account administrator authority")
			}
		}
	}
	return w
}
func (w *ridLifecycleWorld) delegations(t *testing.T, account string) []*iamv1.GrantDelegation {
	t.Helper()
	var out []*iamv1.GrantDelegation
	for _, raw := range w.f.ridList(t, "/iam/v1/grantDelegations", "grantDelegations", url.Values{"accountId": {account}}) {
		gd := new(iamv1.GrantDelegation)
		require.NoError(t, protojson.Unmarshal(raw, gd))
		var got iamv1.GrantDelegation
		w.f.publicRead(t, "/iam/v1/grantDelegations/"+gd.Id, &got)
		require.True(t, proto.Equal(gd, &got))
		out = append(out, gd)
		var creator, delegate, status string
		var created time.Time
		require.NoError(t, w.f.given.pool.QueryRow(w.f.given.ctx, `SELECT delegated_by_id,delegate_id,status,created_at FROM kaname.grant_delegations WHERE id=$1`, gd.Id).Scan(&creator, &delegate, &status, &created))
		require.Equal(t, creator, gd.DelegatedBy.Id)
		require.Equal(t, delegate, gd.Delegate.Id)
		require.Equal(t, status, gd.Status.String())
		requireNativePublicCreatedAt(t, created, gd.CreatedAt)
	}
	var count int
	require.NoError(t, w.f.given.pool.QueryRow(w.f.given.ctx, `SELECT count(*) FROM kaname.grant_delegations WHERE account_id=$1`, account).Scan(&count))
	require.Len(t, out, count)
	return out
}
func (w *ridLifecycleWorld) bindingInput(subjectType, subject, role, targetType, target string) map[string]any {
	return map[string]any{"subjectType": subjectType, "subjectId": subject, "roleId": role, "scopeType": "iam.account", "scopeId": w.f.tenantID, "target": map[string]any{"resources": map[string]any{"resources": []any{map[string]any{"type": targetType, "id": target}}}}}
}
func (w *ridLifecycleWorld) grant(t *testing.T, body any) *iamv1.AccessBinding {
	t.Helper()
	rawRequest, err := json.Marshal(body)
	require.NoError(t, err)
	var request iamv1.CreateAccessBindingRequest
	require.NoError(t, protojson.Unmarshal(rawRequest, &request))
	beforeBindings, beforeOperations := w.grantIdentityCensus(t)
	op := w.f.ridOperation(t, "POST", "/iam/v1/accessBindings", w.issuerToken, body, 0)
	require.NotContains(t, beforeOperations, op.ID)
	var binding iamv1.AccessBinding
	var response, metadata anypb.Any
	require.NoError(t, protojson.Unmarshal(op.Response, &response))
	require.True(t, response.MessageIs(&binding))
	require.NoError(t, response.UnmarshalTo(&binding))
	require.NoError(t, protojson.Unmarshal(op.Metadata, &metadata))
	var creation iamv1.CreateAccessBindingMetadata
	require.True(t, metadata.MessageIs(&creation))
	require.NoError(t, metadata.UnmarshalTo(&creation))
	require.Equal(t, binding.Id, creation.AccessBindingId)
	require.Equal(t, w.f.tenantID, creation.AccountId)
	require.NotEmpty(t, binding.Id)
	require.NotContains(t, beforeBindings, binding.Id)
	w.requireGrantRequest(t, &request, &binding)
	var got iamv1.AccessBinding
	w.f.publicRead(t, "/iam/v1/accessBindings/"+binding.Id, &got)
	require.True(t, proto.Equal(&binding, &got))
	w.requireGrantRequest(t, &request, &got)
	require.Equal(t, iamv1.AccessBinding_ACTIVE, got.Status)
	require.Equal(t, w.gd.Id, got.DelegationId)
	var resource string
	require.NoError(t, w.f.given.pool.QueryRow(w.f.given.ctx, `SELECT resource_id FROM kaname.operations WHERE id=$1`, op.ID).Scan(&resource))
	require.Equal(t, binding.Id, resource)
	afterBindings, afterOperations := w.grantIdentityCensus(t)
	require.ElementsMatch(t, append(beforeBindings, binding.Id), afterBindings)
	require.ElementsMatch(t, append(beforeOperations, op.ID), afterOperations)
	return &got
}
func (w *ridLifecycleWorld) snapshot(t *testing.T) string {
	t.Helper()
	var s string
	require.NoError(t, w.f.given.pool.QueryRow(w.f.given.ctx, `SELECT jsonb_build_array(COALESCE((SELECT jsonb_agg(to_jsonb(g) ORDER BY id) FROM kaname.grant_delegations g),'[]'),COALESCE((SELECT jsonb_agg(to_jsonb(b) ORDER BY id) FROM kaname.access_bindings b),'[]'))::text`).Scan(&s))
	return s
}
func (w *ridLifecycleWorld) denied(t *testing.T, path, bearer string, body any) {
	t.Helper()
	before := w.snapshot(t)
	var n int
	require.NoError(t, w.f.given.pool.QueryRow(w.f.given.ctx, `SELECT count(*) FROM kaname.operations`).Scan(&n))
	code, raw := w.f.ridRequest(t, "POST", path, bearer, body)
	require.Equal(t, 403, code)
	var refusal struct {
		Code        int
		Message, ID string
	}
	require.NoError(t, json.Unmarshal(raw, &refusal))
	require.Equal(t, 7, refusal.Code)
	require.Equal(t, "permission denied", refusal.Message)
	require.Empty(t, refusal.ID)
	var after int
	require.NoError(t, w.f.given.pool.QueryRow(w.f.given.ctx, `SELECT count(*) FROM kaname.operations`).Scan(&after))
	require.Equal(t, n, after)
	require.Equal(t, before, w.snapshot(t))
}
func (w *ridLifecycleWorld) refusedApply(t *testing.T, want installationResult) {
	t.Helper()
	f := w.f
	stop, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	require.NoError(t, f.session.Stop(stop))
	cancel()
	before := w.snapshot(t)
	watch := f.wire.StartReadinessWatch(f.given.ctx)
	defer watch.Stop()
	spawnAt := time.Now().UTC()
	p, err := f.session.StartDelivery(f.given.ctx, w.delivery)
	require.NoError(t, err)
	ctx, c := context.WithTimeout(f.given.ctx, 60*time.Second)
	defer c()
	err = p.Wait(ctx)
	samples := watch.Stop()
	evidence, marshalErr := json.Marshal(map[string]any{"spawnAt": spawnAt, "terminalObservedAt": time.Now().UTC(), "samples": samples})
	require.NoError(t, marshalErr)
	require.NoError(t, os.WriteFile(filepath.Join(filepath.Dir(p.StdoutPath), "refused-readiness.json"), evidence, 0600))
	var exit *exec.ExitError
	require.ErrorAs(t, err, &exit)
	require.Equal(t, 1, exit.ExitCode())
	require.NotEmpty(t, samples)
	require.False(t, samples[0].FinishedAt.After(spawnAt))
	require.True(t, samples[0].TransportFailed)
	for _, s := range samples {
		require.NotEqual(t, 200, s.HTTPStatus)
	}
	results, e := p.Results()
	require.NoError(t, e)
	require.Len(t, results, 1)
	var got installationResult
	require.NoError(t, json.Unmarshal(results[0], &got))
	require.Equal(t, want, got)
	require.Equal(t, before, w.snapshot(t))
	err = f.session.Stop(ctx)
	var same *exec.ExitError
	require.ErrorAs(t, err, &same)
	require.Equal(t, 1, same.ExitCode())
	// Restore only normal listeners/catalog, with NO delegation declarations.
	// Retired/deleted C remains unchanged and supplies no authority to this path.
	w.catalogOnly(t)
	require.Equal(t, before, w.snapshot(t))
}
func (w *ridLifecycleWorld) gdCreateBody(account, delegate string) map[string]any {
	return map[string]any{"accountId": account, "delegate": map[string]any{"type": "SUBJECT_TYPE_SERVICE_ACCOUNT", "id": delegate}, "roleIds": []string{w.pull}, "targetTypes": []string{"registry.registries"}, "subjectTypes": []string{"SUBJECT_TYPE_SERVICE_ACCOUNT"}}
}
func (w *ridLifecycleWorld) catalogOnly(t *testing.T) {
	t.Helper()
	var doc map[string]any
	require.NoError(t, yaml.Unmarshal(w.delivery.Manifests.First, &doc))
	seed, ok := doc["seed"].(map[string]any)
	require.True(t, ok)
	delete(seed, "grantDelegations")
	raw, err := yaml.Marshal(doc)
	require.NoError(t, err)
	p, err := w.f.session.StartCatalogOnly(w.f.given.ctx, installruntime.RIDDeliveryFixture{First: raw})
	require.NoError(t, err)
	require.NoError(t, p.OwnsListeners(9090, 9091, 9095, 9096, 9097, 9098, 9099, 9100))
	results, err := p.Results()
	require.NoError(t, err)
	require.Empty(t, results, "no delegation stage was requested")
	w.f.renewOperator(t, w.f.given.ctx)
}

// Registered by the opt-in constructor before first Start and provisioning.
// The existing default/RID01 cleanup is left unchanged.
func (f *installationNativeWorld) ridLifecycleCleanup(t *testing.T) {
	t.Helper()
	if f == nil || f.session == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	if err := f.session.Stop(ctx); err != nil {
		t.Errorf("lifecycle native shutdown: %v", err)
	}
	cancel()
	secrets := append([]string{}, f.secrets...)
	if f.creator != nil {
		secrets = append(secrets, f.creator.SecretMaterial()...)
		if f.creator.CredentialFile != "" {
			raw, err := os.ReadFile(f.creator.CredentialFile)
			if err != nil {
				t.Error("standing credential unavailable for stream audit")
			} else {
				secrets = append(secrets, string(raw))
			}
		}
	}
	for _, p := range f.session.History {
		if p == nil {
			t.Error("nil owned process in lifecycle history")
			continue
		}
		reap, c := context.WithTimeout(context.Background(), 10*time.Second)
		_ = p.Wait(reap)
		if reap.Err() != nil {
			t.Error("lifecycle native reap incomplete")
		}
		c()
		rid02CheckStreams(t, []string{p.StdoutPath, p.StderrPath}, secrets)
	}
}

func (w *ridLifecycleWorld) grantIdentityCensus(t *testing.T) ([]string, []string) {
	t.Helper()
	var bindings, operations []string
	require.NoError(t, w.f.given.pool.QueryRow(w.f.given.ctx, `SELECT COALESCE(array_agg(id::text ORDER BY id), ARRAY[]::text[]) FROM kaname.access_bindings`).Scan(&bindings))
	require.NoError(t, w.f.given.pool.QueryRow(w.f.given.ctx, `SELECT COALESCE(array_agg(id::text ORDER BY id), ARRAY[]::text[]) FROM kaname.operations`).Scan(&operations))
	return bindings, operations
}
func (w *ridLifecycleWorld) requireGrantRequest(t *testing.T, request *iamv1.CreateAccessBindingRequest, got *iamv1.AccessBinding) {
	t.Helper()
	subjects := request.Subjects
	if len(subjects) == 0 {
		kind, ok := map[string]iamv1.SubjectType{"user": iamv1.SubjectType_SUBJECT_TYPE_USER, "service_account": iamv1.SubjectType_SUBJECT_TYPE_SERVICE_ACCOUNT, "group": iamv1.SubjectType_SUBJECT_TYPE_GROUP, "system_class": iamv1.SubjectType_SUBJECT_TYPE_SYSTEM_CLASS}[request.SubjectType]
		require.True(t, ok)
		subjects = []*iamv1.Subject{{Type: kind, Id: request.SubjectId}}
	}
	require.Len(t, got.Subjects, len(subjects))
	for i, subject := range subjects {
		require.True(t, proto.Equal(subject, got.Subjects[i]), "canonical subject index %d", i)
	}
	legacy := map[iamv1.SubjectType]string{iamv1.SubjectType_SUBJECT_TYPE_USER: "user", iamv1.SubjectType_SUBJECT_TYPE_SERVICE_ACCOUNT: "service_account", iamv1.SubjectType_SUBJECT_TYPE_GROUP: "group", iamv1.SubjectType_SUBJECT_TYPE_SYSTEM_CLASS: "system_class"}
	require.Equal(t, legacy[subjects[0].Type], got.SubjectType)
	require.Equal(t, subjects[0].Id, got.SubjectId)
	require.Equal(t, request.RoleId, got.RoleId)
	require.Equal(t, request.ScopeType, got.ScopeType)
	require.Equal(t, request.ScopeId, got.ScopeId)
	require.NotNil(t, request.Target)
	require.True(t, proto.Equal(request.Target, got.Target), "exact requested target")
	require.True(t, proto.Equal(request.ExpiresAt, got.ExpiresAt))
	require.Equal(t, request.DeletionProtection, got.DeletionProtection)
	require.Equal(t, request.Labels, got.Labels)
}
