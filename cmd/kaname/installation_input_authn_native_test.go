// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/tokenpolicy"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/testsupport/installruntime"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"
)

type rid11Case struct {
	Variant, Mode string
	Active, Twin  bool
}

func (c rid11Case) key() string {
	state := "absent"
	if c.Active {
		state = "ACTIVE"
	}
	return c.Variant + "/" + c.Mode + "/" + state
}
func rid11Cases(twin bool) []rid11Case {
	var out []rid11Case
	for _, variant := range []string{"credential-missing", "credential-unreadable", "deleted-creator", "revoked-key", "bad-signature", "authority", "backend"} {
		for _, mode := range []string{"S1", "S2"} {
			for _, active := range []bool{false, true} {
				out = append(out, rid11Case{variant, mode, active, twin})
			}
		}
	}
	out = append(out, rid11Case{"account", "S1", false, twin}, rid11Case{"census", "S2", false, twin}, rid11Case{"census", "S2", true, twin})
	return out
}
func (c rid11Case) expected() installationResult {
	if c.Twin {
		n := 1
		if c.Mode == "S2" {
			n = 3
		}
		return installationResult{Stage: "delegation", Code: "OK", CompletedPairs: n}
	}
	switch c.Variant {
	case "credential-missing", "credential-unreadable":
		return installationResult{Stage: "input", Code: "INSTALL_INPUT_INVALID", Field: "credentialFile"}
	case "deleted-creator", "revoked-key", "bad-signature":
		return installationResult{Stage: "authentication", Code: "UNAUTHENTICATED"}
	case "authority":
		return installationResult{Stage: "preflight-authority", Code: "PERMISSION_DENIED", Field: "moduleSeedInstaller.credentialFile"}
	case "backend":
		return installationResult{Stage: "preflight-authority", Code: "UNAVAILABLE", Field: "moduleSeedInstaller.credentialFile"}
	case "account":
		return installationResult{Stage: "input", Code: "NOT_FOUND", Field: "tenantAccountId"}
	case "census":
		return installationResult{Stage: "census", Code: "INTERNAL", Field: "accounts"}
	}
	panic("unlisted RID11 variant")
}
func (c rid11Case) returnCode() codes.Code {
	if c.Twin {
		return codes.OK
	}
	switch c.Variant {
	case "credential-missing", "credential-unreadable":
		return codes.Unknown
	case "deleted-creator", "revoked-key", "bad-signature":
		return codes.Unauthenticated
	case "authority":
		return codes.PermissionDenied
	case "backend":
		return codes.Unavailable
	case "account":
		return codes.NotFound
	case "census":
		return codes.Internal
	}
	panic("unlisted RID11 variant")
}

type rid11Proof struct {
	Case                                                          rid11Case
	Accounts                                                      []string
	CanonicalSystem, NamedSystem, Creator, Issuer, ManifestSHA256 string
	Before, After                                                 ridWholeDeliverySnapshot
	Returned                                                      rid11Return
	Expected                                                      installationResult
	RawStreamsAudited, PublicTokenRefused, Ready                  bool
	NewmanExecuted                                                bool
	HistoryBeforeMutation, HistoryAfterRun                        string
	PairRowsBefore, PairRowsAfter                                 string
	MutationOperations                                            []string
	CreatorBefore                                                 rid11Identity
	CreatorAfterRevoke, CreatorCurrent                            *rid11Identity
	DeletedAfterMutation, DeletedAfterRun                         *rid11AbsentIdentity
	KeysAfterRevoke, KeysAfterRun                                 *rid11KeyAbsence
	IssuerBefore, IssuerAfter                                     *rid11Identity
}

// Optional future live public observer; nil is recorded as NOT_EXECUTED. It is
// never evidence that Newman ran. No secrets are copied to this receipt.
type rid11LivePublicConsumer func(*testing.T, *installationNativeWorld, rid11Case, string)

func rid11Prepare(t *testing.T, c rid11Case) (*ridLifecycleWorld, string) {
	setup := func(t *testing.T, f *installationNativeWorld) []string {
		ids, _, _, _ := rid08SetupN3(t, f)
		return ids
	}
	var w *ridLifecycleWorld
	if c.Active {
		w = newRIDLifecycleWorldAccounts(t, c.Mode, false, setup)
		subject := w.f.ridSA(t, w.f.tenantID, "rid11-existing-grantee")
		g := w.grant(t, w.bindingInput("service_account", subject, w.pull, "registry.registries", w.object))
		require.Equal(t, w.gd.Id, g.DelegationId)
		require.Equal(t, iamv1.AccessBinding_ACTIVE, g.Status)
	} else {
		f := newInstallationNativeWorldLifecycle(t, 7200, "", true, true)
		ids := []string{f.tenantID}
		if c.Mode == "S2" {
			ids = setup(t, f)
		}
		in := installruntime.DeliveryInput{Manifests: ridLifecycleDelivery(t, false), CredentialFile: f.creator.CredentialFile}
		if c.Mode == "S1" {
			in.TenantAccountID = &f.tenantID
		}
		w = &ridLifecycleWorld{f: f, accounts: ids, delivery: in}
		requireNativeNoDelivery(t, f.given)
	}
	named := ""
	if c.Mode == "S2" {
		require.Len(t, w.accounts, 3)
		require.NoError(t, w.f.given.pool.QueryRow(w.f.given.ctx, `SELECT id FROM kaname.accounts WHERE name='system-tenant'`).Scan(&named))
		require.Contains(t, w.accounts, named)
		require.NotEqual(t, w.f.baseline.SystemID, named)
		require.NotContains(t, w.accounts, w.f.baseline.SystemID)
	}
	return w, named
}

// Credential mutations live exclusively in the existing private fixture store.
// The original creator credential remains readable for the full post-reap audit.
func rid11Mutate(t *testing.T, w *ridLifecycleWorld, c rid11Case, p *rid11Proof) string {
	return rid11MutateObserved(t, w, c, p, nil)
}
func rid11MutateObserved(t *testing.T, w *ridLifecycleWorld, c rid11Case, p *rid11Proof, public *rid11PublicContext) string {
	f := w.f
	credential := f.creator.CredentialFile
	if c.Twin {
		return credential
	}
	switch c.Variant {
	case "credential-missing":
		credential = filepath.Join(f.session.Root, "rid11-credential-does-not-exist")
		_, err := os.Stat(credential)
		require.True(t, os.IsNotExist(err))
	case "credential-unreadable":
		raw, err := os.ReadFile(credential)
		require.NoError(t, err)
		credential = filepath.Join(f.session.Root, "rid11-unreadable-private-credential")
		require.NoError(t, os.WriteFile(credential, raw, 0600))
		require.NoError(t, os.Chmod(credential, 0000))
		t.Cleanup(func() { _ = os.Chmod(credential, 0600) })
		probe, err := os.Open(credential)
		if probe != nil {
			_ = probe.Close()
		}
		require.True(t, os.IsPermission(err), "unreadable premise requires actual OS permission refusal; root bypass is not accepted")
	case "bad-signature":
		raw, err := os.ReadFile(credential)
		require.NoError(t, err)
		var input installationCredential
		require.NoError(t, json.Unmarshal(raw, &input))
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		der, err := x509.MarshalECPrivateKey(key)
		require.NoError(t, err)
		input.PrivateKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
		f.secrets = append(f.secrets, input.PrivateKeyPEM)
		changed, err := json.Marshal(input)
		require.NoError(t, err)
		f.secrets = append(f.secrets, string(changed))
		credential = filepath.Join(f.session.Root, "rid11-wrong-signing-key-private.json")
		require.NoError(t, os.WriteFile(credential, changed, 0600))
	case "revoked-key", "deleted-creator":
		op := f.ridOperation(t, "DELETE", "/iam/v1/serviceAccounts/"+f.creator.ID+"/keys/"+f.creator.KeyID, f.operator.Bearer(), nil, 0)
		p.MutationOperations = append(p.MutationOperations, op.ID)
		afterRevoke := rid11ReadIdentity(t, f, f.creator.ID)
		rid11RequireSameIdentity(t, p.CreatorBefore, afterRevoke)
		p.CreatorAfterRevoke = &afterRevoke
		p.KeysAfterRevoke = rid11RequireKeysAbsent(t, f, true)
		if c.Variant == "deleted-creator" {
			public.liveAfterRevoke(t, w)
			op = f.ridOperation(t, "DELETE", "/iam/v1/serviceAccounts/"+f.creator.ID, f.operator.Bearer(), nil, 0)
			p.MutationOperations = append(p.MutationOperations, op.ID)
			p.DeletedAfterMutation = rid11RequireCreatorAbsent(t, f)
		}
	case "authority":
		f.ridAdmin(t, f.creator.ID, false)
		f.ridAuthorityMaterialized(t, f.creator.ID, false)
	case "account":
		missing := "acc00000000000000000"
		code, _ := f.ridRequest(t, "GET", "/iam/v1/accounts/"+missing, f.operator.Bearer(), nil)
		require.Equal(t, 404, code)
		w.delivery.TenantAccountID = &missing
	}
	return credential
}

func rid11Start(t *testing.T, w *ridLifecycleWorld, c rid11Case, credential string) *rid02OwnedChild {
	f := w.f
	root := filepath.Join(f.session.Root, "rid11-config")
	require.NoError(t, os.Mkdir(root, 0700))
	dir := filepath.Join(root, "delivery")
	_, err := w.delivery.Manifests.Write(dir, false)
	require.NoError(t, err)
	installer := map[string]any{"credentialFile": credential}
	if w.delivery.TenantAccountID != nil {
		installer["tenantAccountId"] = *w.delivery.TenantAccountID
	}
	raw, err := yaml.Marshal(map[string]any{"manifests": map[string]any{"dir": dir, "required": true}, "moduleSeedInstaller": installer})
	require.NoError(t, err)
	config := filepath.Join(root, "config.yaml")
	require.NoError(t, os.WriteFile(config, raw, 0600))
	executable := rid06HashExecutable(t)
	child := startRIDInstallationChild(t, f, "rid11-child", rid11ChildInput{ConfigPath: config, EvidenceDir: filepath.Join(f.session.Root, "rid11-child"), Creator: f.creator.ID, Variant: c.Variant, Twin: c.Twin}, f.session.Environment, rid11ChildEnv, "TestRID11OwnedInputAuthnStartupChild", "4m")
	parentCG, err := os.ReadFile("/proc/self/cgroup")
	require.NoError(t, err)
	childCG, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", child.cmd.Process.Pid))
	require.NoError(t, err)
	require.True(t, bytes.Equal(parentCG, childCG))
	memory, err := os.ReadFile("/sys/fs/cgroup/memory.max")
	require.NoError(t, err)
	require.Equal(t, "4294967296", strings.TrimSpace(string(memory)))
	swap, err := os.ReadFile("/sys/fs/cgroup/memory.swap.max")
	require.NoError(t, err)
	require.Equal(t, "0", strings.TrimSpace(string(swap)))
	rid08Write(t, child.dir, "provenance", map[string]any{"testBinarySHA256": executable, "baseProductionSHA256": f.session.BinarySHA256, "pid": child.cmd.Process.Pid, "starttime": child.start, "cgroup": string(childCG), "variant": c, "authorityFaultSelectableOnlyByOwnedTest": true})
	t.Cleanup(func() { require.Equal(t, executable, rid06HashExecutable(t)) })
	rid09ArmAndRelease(t, f, child)
	return child
}
func rid11Ready(t *testing.T, f *installationNativeWorld, c *rid02OwnedChild) {
	ctx, cancel := context.WithTimeout(f.given.ctx, 60*time.Second)
	defer cancel()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-c.exited:
			t.Fatal("RID11 lawful startup exited before readiness")
		default:
		}
		attempt, stop := context.WithTimeout(ctx, time.Second)
		err := f.wire.ProductionReady(attempt)
		stop()
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("RID11 readiness deadline")
		case <-ticker.C:
		}
	}
	c.seenEvent = true
	require.NoError(t, installruntime.CheckOwnedListeners(c.cmd.Process.Pid, c.dir, installruntime.DefaultNativePorts().All()...))
}

// Public OAuth twin uses the SAME supplied credential fields and normal ES256
// assertion contract, including the wrong signature material when requested.
func rid11FreshInputAssertion(t *testing.T, f *installationNativeWorld, credential string) (string, time.Time) {
	raw, err := os.ReadFile(credential)
	require.NoError(t, err)
	var input installationCredential
	require.NoError(t, json.Unmarshal(raw, &input))
	key, err := jwt.ParseECPrivateKeyFromPEM([]byte(input.PrivateKeyPEM))
	require.NoError(t, err)
	nonce := make([]byte, 24)
	_, err = rand.Read(nonce)
	require.NoError(t, err)
	now := time.Now().UTC().Truncate(time.Second)
	assertion := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.RegisteredClaims{Issuer: input.ClientID, Subject: input.ClientID, Audience: jwt.ClaimStrings{"https://kaname.local"}, ID: hex.EncodeToString(nonce), IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(60 * time.Second))})
	assertion.Header["typ"] = tokenpolicy.TokenTypeClientAssertion
	assertion.Header["kid"] = input.KeyID
	proof, err := assertion.SignedString(key)
	require.NoError(t, err)
	f.secrets = append(f.secrets, proof)
	return proof, now.Add(60 * time.Second)
}
func rid11PublicRefusal(t *testing.T, f *installationNativeWorld, credential string) {
	proof, _ := rid11FreshInputAssertion(t, f, credential)
	pki := filepath.Join(f.session.Root, "pki")
	ca, err := os.ReadFile(filepath.Join(pki, "ca.crt"))
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(ca))
	cert, err := tls.LoadX509KeyPair(filepath.Join(pki, "srv.crt"), filepath.Join(pki, "srv.key"))
	require.NoError(t, err)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{cert}, ServerName: "localhost", MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	form := url.Values{"grant_type": {"client_credentials"}, "client_assertion_type": {tokenpolicy.ClientAssertionType}, "client_assertion": {proof}, "audience": {"https://kaname.local"}}
	req, err := http.NewRequestWithContext(f.given.ctx, "POST", f.wire.IssuanceURL+"/iam/v1/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := client.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	require.Equal(t, 401, res.StatusCode)
	var out struct {
		Error string `json:"error"`
	}
	require.NoError(t, json.NewDecoder(res.Body).Decode(&out))
	require.Equal(t, "invalid_client", out.Error)
}

// Full identity evidence is restricted to the SA resource/table, never key rows.
// Primary includes every identity column, including future fields; public is the
// complete typed API message, not an id-only existence check.
type rid11Identity struct {
	Public  *iamv1.ServiceAccount
	Primary string
}
type rid11AbsentIdentity struct{ HTTPStatus, Code, PrimaryRows int }
type rid11KeyAbsence struct {
	PublicListExecuted                             bool
	PublicRows, PrimaryKeyRows, PrimaryCreatorKeys int
}

func rid11ReadIdentity(t *testing.T, f *installationNativeWorld, id string) rid11Identity {
	t.Helper()
	var got iamv1.ServiceAccount
	f.publicRead(t, "/iam/v1/serviceAccounts/"+id, &got)
	require.Equal(t, id, got.Id)
	var raw string
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT to_jsonb(s)::text FROM kaname.service_accounts s WHERE id=$1`, id).Scan(&raw))
	var row struct {
		ID          string            `json:"id"`
		AccountID   string            `json:"account_id"`
		Name        string            `json:"name"`
		Description string            `json:"description"`
		CreatedAt   time.Time         `json:"created_at"`
		Enabled     bool              `json:"enabled"`
		Labels      map[string]string `json:"labels"`
	}
	require.NoError(t, json.Unmarshal([]byte(raw), &row))
	require.Equal(t, row.ID, got.Id)
	require.Equal(t, row.AccountID, got.AccountId)
	require.Equal(t, row.Name, got.Name)
	require.Equal(t, row.Description, got.Description)
	require.Equal(t, row.Enabled, got.Enabled)
	require.Equal(t, len(row.Labels), len(got.Labels))
	for k, v := range row.Labels {
		require.Equal(t, v, got.Labels[k])
	}
	requireNativePublicCreatedAt(t, row.CreatedAt, got.CreatedAt)
	return rid11Identity{Public: &got, Primary: raw}
}
func rid11RequireSameIdentity(t *testing.T, before, after rid11Identity) {
	t.Helper()
	require.NotNil(t, before.Public)
	require.NotNil(t, after.Public)
	require.True(t, proto.Equal(before.Public, after.Public), "complete public SA identity changed")
	require.JSONEq(t, before.Primary, after.Primary, "complete primary SA identity changed")
}
func rid11RequireCreatorAbsent(t *testing.T, f *installationNativeWorld) *rid11AbsentIdentity {
	t.Helper()
	code, raw := f.ridRequest(t, "GET", "/iam/v1/serviceAccounts/"+f.creator.ID, f.operator.Bearer(), nil)
	var body struct {
		Code int `json:"code"`
	}
	require.NoError(t, json.Unmarshal(raw, &body))
	out := &rid11AbsentIdentity{HTTPStatus: code, Code: body.Code}
	require.Equal(t, 404, out.HTTPStatus)
	require.Equal(t, int(codes.NotFound), out.Code)
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT count(*) FROM kaname.service_accounts WHERE id=$1`, f.creator.ID).Scan(&out.PrimaryRows))
	require.Zero(t, out.PrimaryRows)
	return out
}
func rid11RequireKeysAbsent(t *testing.T, f *installationNativeWorld, liveCreator bool) *rid11KeyAbsence {
	t.Helper()
	out := &rid11KeyAbsence{PublicListExecuted: liveCreator}
	// After Delete the parent resource itself is absent. Its public NOT_FOUND is
	// observed separately; the primary proves that no orphan key survived.
	if liveCreator {
		out.PublicRows = len(f.ridList(t, "/iam/v1/serviceAccounts/"+f.creator.ID+"/keys", "keys", nil))
		require.Zero(t, out.PublicRows)
	}
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT (SELECT count(*) FROM kaname.service_account_oauth_clients WHERE id=$1),(SELECT count(*) FROM kaname.service_account_oauth_clients WHERE sva_id=$2)`, f.creator.KeyID, f.creator.ID).Scan(&out.PrimaryKeyRows, &out.PrimaryCreatorKeys))
	require.Zero(t, out.PrimaryKeyRows)
	require.Zero(t, out.PrimaryCreatorKeys)
	return out
}

// Resolve declared I independently from GD. Neither a delegation's delegate ID
// nor an already accepted winner is allowed to choose this oracle's identity.
func rid11DeclaredIssuer(t *testing.T, w *ridLifecycleWorld) rid11Identity {
	t.Helper()
	f := w.f
	var declared, writer *iamv1.ServiceAccount
	seen := map[string]bool{}
	rows := f.ridList(t, "/iam/v1/serviceAccounts", "serviceAccounts", url.Values{"accountId": {f.baseline.SystemID}})
	for _, raw := range rows {
		var sa iamv1.ServiceAccount
		require.NoError(t, protojson.Unmarshal(raw, &sa))
		require.False(t, seen[sa.Id])
		seen[sa.Id] = true
		require.Equal(t, f.baseline.SystemID, sa.AccountId)
		switch sa.Name {
		case "rid-public-issuer":
			require.Nil(t, declared)
			declared = &sa
		case "kacho-registry":
			require.Nil(t, writer)
			writer = &sa
		}
	}
	var count int
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT count(*) FROM kaname.service_accounts WHERE account_id=$1`, f.baseline.SystemID).Scan(&count))
	require.Len(t, rows, count)
	require.NotNil(t, declared)
	require.NotNil(t, writer)
	require.Equal(t, authzguard.ServiceAccountIDForService("registry"), writer.Id)
	identity := rid11ReadIdentity(t, f, declared.Id)
	require.True(t, proto.Equal(declared, identity.Public), "independent SYS List/Get mismatch")
	require.Equal(t, "rid-public-issuer", identity.Public.Name)
	require.Equal(t, f.baseline.SystemID, identity.Public.AccountId)
	require.True(t, identity.Public.Enabled)
	require.NotEqual(t, f.creator.ID, declared.Id)
	require.NotEqual(t, writer.Id, declared.Id)
	require.NotContains(t, f.baseline.ServiceAccounts, declared.Id)
	requireNativeAuthority(t, f.given, "service_account", declared.Id, 0)
	f.ridAuthorityMaterialized(t, declared.Id, false)
	conn, err := f.wire.ModuleWriter(filepath.Join(f.session.Root, "pki"))
	require.NoError(t, err)
	defer conn.Close()
	module := iamv1.NewInternalIAMServiceClient(conn)
	for _, account := range w.accounts {
		judged, err := module.Check(f.given.ctx, &iamv1.CheckRequest{SubjectId: "service_account:" + declared.Id, Relation: "admin", Object: "account:" + account, Consistency: iamv1.CheckRequest_HIGHER_CONSISTENCY})
		require.NoError(t, err)
		require.False(t, judged.Allowed, "declared I cannot have account admin")
	}
	return identity
}
func rid11CheckPairs(t *testing.T, w *ridLifecycleWorld) rid11Identity {
	f := w.f
	issuer := rid11DeclaredIssuer(t, w)
	var pull string
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT id FROM kaname.roles WHERE name='registry.puller'`).Scan(&pull))
	require.NotEmpty(t, pull)
	for _, account := range w.accounts {
		list := w.delegations(t, account) // full pages, independent Gets, primary count and createdAt
		require.Len(t, list, 1)
		gd := list[0]
		require.Equal(t, iamv1.GrantDelegation_ACTIVE, gd.Status)
		require.Equal(t, account, gd.AccountId)
		require.Equal(t, []string{pull}, gd.RoleIds)
		require.NotNil(t, gd.DelegatedBy)
		require.Equal(t, f.creator.ID, gd.DelegatedBy.Id)
		require.Equal(t, "service_account", gd.DelegatedBy.Type)
		require.Equal(t, []string{"registry.registries"}, gd.TargetTypes)
		require.Equal(t, []iamv1.SubjectType{iamv1.SubjectType_SUBJECT_TYPE_SERVICE_ACCOUNT}, gd.SubjectTypes)
		require.Equal(t, "registry", gd.Module)
		require.NotNil(t, gd.Delegate)
		require.Equal(t, iamv1.SubjectType_SUBJECT_TYPE_SERVICE_ACCOUNT, gd.Delegate.Type)
		require.Equal(t, issuer.Public.Id, gd.Delegate.Id)
		require.NotNil(t, gd.CreatedAt)
		require.NoError(t, gd.CreatedAt.CheckValid())
		require.Nil(t, gd.RevokedAt)
		require.Nil(t, gd.RevokedBy)
		var primaryModule, primaryAccount, primaryType, activeID string
		var roles, targets, subjects []string
		require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT module,account_id,delegated_by_type,active_delegate_id,role_ids,target_types,subject_types FROM kaname.grant_delegations WHERE id=$1`, gd.Id).Scan(&primaryModule, &primaryAccount, &primaryType, &activeID, &roles, &targets, &subjects))
		require.Equal(t, gd.Module, primaryModule)
		require.Equal(t, gd.AccountId, primaryAccount)
		require.Equal(t, gd.DelegatedBy.Type, primaryType)
		require.Equal(t, issuer.Public.Id, activeID)
		require.Equal(t, gd.RoleIds, roles)
		require.Equal(t, gd.TargetTypes, targets)
		require.Equal(t, []string{"service_account"}, subjects)
	}
	require.Empty(t, w.delegations(t, f.baseline.SystemID))
	return issuer
}
func rid11World(t *testing.T, c rid11Case, consumer rid11LivePublicConsumer) rid11Proof {
	w, named := rid11Prepare(t, c)
	f := w.f
	public := rid11PublicConsumer(t, w, c)
	p := rid11Proof{Case: c, Accounts: w.accounts, CanonicalSystem: f.baseline.SystemID, NamedSystem: named, Creator: f.creator.ID, ManifestSHA256: ridWholeDigest(t, string(w.delivery.Manifests.First)), Expected: c.expected(), NewmanExecuted: consumer != nil}
	p.CreatorBefore = rid11ReadIdentity(t, f, f.creator.ID)
	require.Equal(t, f.baseline.SystemID, p.CreatorBefore.Public.AccountId)
	require.Equal(t, "rid-native-standing-creator", p.CreatorBefore.Public.Name)
	require.True(t, p.CreatorBefore.Public.Enabled)
	if c.Active {
		identity := rid11CheckPairs(t, w)
		p.IssuerBefore = &identity
		require.Equal(t, w.issuer.ID, identity.Public.Id)
	}
	if consumer != nil {
		consumer(t, f, c, "before")
	}
	public.before(t, w)
	if c.Active {
		p.HistoryBeforeMutation = w.snapshot(t)
	}
	credential := rid11MutateObserved(t, w, c, &p, public)
	if c.Active {
		require.Equal(t, p.HistoryBeforeMutation, w.snapshot(t), "the single changed authentication/input fact must preserve prior GD/G history")
	}
	rid09StopBase(t, f)
	p.Before = ridReadWholeDelivery(t, f)
	p.PairRowsBefore = rid08PrimaryGD(t, f)
	ops := rid08GDOperations(t, f)
	public.beforeStartup(t, w, credential)
	rid08Write(t, f.session.Root, "rid11-before", p.Before)
	watch := f.wire.StartReadinessWatch(f.given.ctx)
	defer watch.Stop()
	spawned := time.Now().UTC()
	child := rid11Start(t, w, c, credential)
	if c.Twin {
		rid11Ready(t, f, child)
		p.Ready = true
		watch.Stop()
		rid06ReadResult(t, child, p.Expected)
		f.renewOperator(t, f.given.ctx)
		identity := rid11CheckPairs(t, w)
		p.Issuer = identity.Public.Id
		p.IssuerAfter = &identity
		if p.IssuerBefore != nil {
			rid11RequireSameIdentity(t, *p.IssuerBefore, identity)
		}
		current := rid11ReadIdentity(t, f, f.creator.ID)
		rid11RequireSameIdentity(t, p.CreatorBefore, current)
		p.CreatorCurrent = &current
		if consumer != nil {
			consumer(t, f, c, "after-positive")
		}
		public.afterPositive(t, w)
		rid06GracefulStop(t, child)
	} else {
		rid06WaitExit(t, child, 1)
		observations := watch.Stop()
		require.NotEmpty(t, observations)
		require.False(t, observations[0].FinishedAt.After(spawned))
		require.True(t, observations[0].TransportFailed)
		for _, o := range observations {
			require.NotEqual(t, http.StatusOK, o.HTTPStatus)
		}
		rid08Write(t, child.dir, "readiness-observations", observations)
		rid06ReadResult(t, child, p.Expected)
	}
	rid10Read(t, child, "actual-return", &p.Returned)
	require.Equal(t, int32(c.returnCode()), p.Returned.Code)
	require.Equal(t, !c.Twin, p.Returned.ErrorPresent)
	require.True(t, p.Returned.CaptureOK && p.Returned.MessageMatches)
	p.RawStreamsAudited = true // wait/gracefulStop call mandatory single-Wait afterReap.
	p.After = ridReadWholeDelivery(t, f)
	p.PairRowsAfter = rid08PrimaryGD(t, f)
	if c.Active {
		p.HistoryAfterRun = w.snapshot(t)
		require.Equal(t, p.HistoryBeforeMutation, p.HistoryAfterRun, "all original GD/G rows, including history, preserved")
	}
	rid08Write(t, f.session.Root, "rid11-after", p.After)
	if !c.Twin {
		require.Equal(t, p.PairRowsBefore, p.PairRowsAfter, "all GD rows/history preserved")
		require.Equal(t, ops, rid08GDOperations(t, f), "no delegation Operation created")
		if c.Variant != "census" {
			ridRequireWholeDeliveryUnchanged(t, p.Before, p.After)
		} else {
			for _, table := range []string{"grant_delegations", "cluster_admin_grants", "accounts", "service_account_oauth_clients"} {
				require.Equal(t, p.Before.Delivery[table], p.After.Delivery[table])
			}
			if c.Active {
				require.Equal(t, p.Before.Delivery["access_bindings"], p.After.Delivery["access_bindings"])
			}
			var page rid08PageObservation
			rid10Read(t, child, "page-01", &page)
			require.Equal(t, 1, page.Page)
			require.True(t, page.ContextLive && page.ReadOnlyRepeatableRead)
			require.False(t, page.Fault)
			rid10Read(t, child, "page-02", &page)
			require.Equal(t, 2, page.Page)
			require.True(t, page.ContextLive && page.ReadOnlyRepeatableRead && page.Fault)
			_, err := os.Stat(filepath.Join(child.dir, "page-03.json"))
			require.True(t, os.IsNotExist(err))
		}
		if c.Variant == "credential-missing" || c.Variant == "credential-unreadable" {
			require.Zero(t, p.Returned.MaterialObservations)
			require.Zero(t, p.Returned.ProofObservations)
			require.Zero(t, p.Returned.AuthorityCalls)
			for _, table := range []string{"client_assertion_replay", "access_tokens"} {
				require.Equal(t, p.Before.Bookkeeping[table], p.After.Bookkeeping[table], "input refusal did not reach shared authentication")
			}
		}
		if c.Variant == "backend" {
			require.Equal(t, 1, p.Returned.AuthorityCalls)
			require.True(t, p.Returned.ActualCreator && p.Returned.ActualQuestion && p.Returned.ContextLive && p.Returned.ForwardAllowed && p.Returned.Injected)
		}
		if c.Variant == "authority" {
			require.Equal(t, 1, p.Returned.AuthorityCalls)
			require.True(t, p.Returned.ActualCreator && p.Returned.ActualQuestion && p.Returned.ContextLive)
			require.False(t, p.Returned.ForwardAllowed || p.Returned.Injected)
		}
		// Read-only public consequences after the stopped-process primary proof.
		// Ordinary no-delivery startup cannot repair deleted C or restore authority.
		public.beforeRestore(t, w, p.Returned)
		base, err := f.session.StartBase(f.given.ctx)
		require.NoError(t, err)
		require.NoError(t, base.OwnsListeners(installruntime.DefaultNativePorts().All()...))
		f.renewOperator(t, f.given.ctx)
		if c.Variant == "deleted-creator" {
			p.DeletedAfterRun = rid11RequireCreatorAbsent(t, f)
		} else {
			current := rid11ReadIdentity(t, f, f.creator.ID)
			rid11RequireSameIdentity(t, p.CreatorBefore, current)
			p.CreatorCurrent = &current
		}
		if c.Variant == "deleted-creator" || c.Variant == "revoked-key" {
			p.KeysAfterRun = rid11RequireKeysAbsent(t, f, c.Variant == "revoked-key")
		}
		if c.Variant == "deleted-creator" || c.Variant == "revoked-key" || c.Variant == "bad-signature" {
			rid11PublicRefusal(t, f, credential)
			p.PublicTokenRefused = true
		}
		if c.Variant == "authority" {
			f.ridAuthorityMaterialized(t, f.creator.ID, false)
		}
		if c.Active {
			identity := rid11CheckPairs(t, w)
			p.Issuer = identity.Public.Id
			p.IssuerAfter = &identity
			require.NotNil(t, p.IssuerBefore)
			rid11RequireSameIdentity(t, *p.IssuerBefore, identity)
			require.Equal(t, p.HistoryBeforeMutation, w.snapshot(t), "ordinary base restart/public auth refusal must preserve prior GD/G history")
			require.Equal(t, p.PairRowsBefore, rid08PrimaryGD(t, f))
			for _, account := range w.accounts {
				require.Len(t, w.delegations(t, account), 1)
			}
		}
		if consumer != nil {
			consumer(t, f, c, "after-negative")
		}
		public.afterNegative(t, w)
	} else {
		require.Positive(t, p.Returned.ProofObservations)
		require.True(t, p.Returned.ActualCreator && p.Returned.ActualQuestion && p.Returned.ForwardAllowed)
		require.False(t, p.Returned.Injected)
		require.Equal(t, p.Before.Delivery["cluster_admin_grants"], p.After.Delivery["cluster_admin_grants"])
		if c.Active {
			require.Equal(t, p.PairRowsBefore, p.PairRowsAfter)
			require.Equal(t, p.Before.Delivery["access_bindings"], p.After.Delivery["access_bindings"])
		}
	}
	if public != nil {
		p.NewmanExecuted = public.complete(t)
	}
	rid08Write(t, f.session.Root, "rid11-proof", p)
	return p
}
func rid11Matrix(t *testing.T, twin bool, consumer rid11LivePublicConsumer) []rid11Proof {
	var out []rid11Proof
	for _, c := range rid11Cases(twin) {
		kind := "negative"
		if twin {
			kind = "lawful-control"
		}
		t.Run(c.key()+"/"+kind, func(t *testing.T) { out = append(out, rid11World(t, c, consumer)) })
	}
	return out
}
