// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package access_binding_test

// Приёмочные пробы записи аккаунта используют настоящий проверенный слушатель mTLS,
// производственные извлечение идентичности/политику вызывающего, читателей области и запись,
// установленную модель и постоянные начальные назначения. Существующие миры DP/PB
// поставляют манифест и канонические проекты/контейнеры.
import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleseed"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
	ab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/moduleroster"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

type awWorld struct {
	*dpWorld
	roster  moduleidentity.Roster
	gate    *authzguard.RelationWriteGate
	plan    seed.RegistrationWriterPlan
	clients map[string]iamv1.InternalIAMServiceClient
	direct  map[string]context.Context
}

func newAWWorld(t *testing.T) *awWorld {
	t.Helper()
	return newAWWorldFromDP(t, newDPWorld(t))
}
func newAWWorldFromDP(t *testing.T, d *dpWorld) *awWorld {
	t.Helper()
	// Настоящая SA модуля устанавливается обычной записью начальных данных модуля, никогда
	// не вставкой результирующего кортежа fga_writer или его выдачи через SQL.
	require.NoError(t, kanamepg.NewModuleSeedWriteRepo(d.pool).RunInWriteTx(d.ctx, func(ctx context.Context, w moduleseed.Writer) error {
		for _, m := range []string{"registry", "vpc"} {
			if _, err := w.UpsertServiceAccount(ctx, "system", "kacho-"+m, "account writer probe"); err != nil {
				return err
			}
			if _, err := w.JoinGroup(ctx, "system", "kacho-"+m, "system", "module-relation-writers"); err != nil {
				return err
			}
		}
		return nil
	}))
	a := &awWorld{dpWorld: d, clients: map[string]iamv1.InternalIAMServiceClient{}, direct: map[string]context.Context{}}
	a.roster = moduleroster.Roster(t)
	a.plan = seed.RegistrationWriterPlan{Assignments: []domain.RegistrationAccountWriter{
		{AssignmentID: "aw-registry-a", AccountID: string(a.accA), Module: "registry"},
		{AssignmentID: "aw-vpc-b", AccountID: string(a.accB), Module: "vpc"},
	}, Disabled: []domain.DisabledRegistrationModule{{AccountID: string(a.accA), Module: "vpc", Reason: "fixture's existing networks intentionally disabled for this module"}}}
	require.NoError(t, a.apply(a.plan))
	a.gate = authzguard.NewRelationWriteGate(a.door).WithProductionMode(true).WithModuleRoster(a.roster)
	a.reg = internaliam.NewRegisterResourceUseCase(
		kanamepg.NewFGAOutboxEmitter(), kanamepg.NewResourceMirrorEmitter(), kanamepg.NewRegistrationTxBeginner(a.pool), kanamepg.NewCatalogTypeReader(), kanamepg.NewPublicReadPublisher(), accessbindingapp.NewUnregisteredKeyWithdrawal(kanamepg.NewUnregisteredKeyStore(), pcrFacts{a.pcrWorld}), kanamepg.NewRegistrationAudit(), kanamepg.NewRegistrationScopeReader(),
	).WithRegistrationAuthority(a.gate).WithReconcile(kanamepg.NewReconcileEventEmitter()).WithObjectReconciler(a.rec, nil).WithResidualTupleReader(kanamepg.NewResidualTupleReader(a.pool))
	a.startListener(t)
	return a
}
func (w *awWorld) apply(p seed.RegistrationWriterPlan) error {
	return seed.ApplyRegistrationAccountWriters(w.ctx, kanamepg.NewRegistrationAccountWriterStore(w.pool), w.roster, p)
}

// startListener использует производственную сборку TLS и загрузчик списка AuthN;
// сертификаты создаются исключительно для этого изолированного слушателя.
func (w *awWorld) startListener(t *testing.T, additionalModules ...string) {
	t.Helper()
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "aw-ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	require.NoError(t, err)
	ca, err = x509.ParseCertificate(der)
	require.NoError(t, err)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	caPath := filepath.Join(dir, "ca.pem")
	require.NoError(t, os.WriteFile(caPath, caPEM, 0600))
	serial := int64(2)
	issue := func(name, san string, server bool) tls.Certificate {
		serial++
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		if server {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			tmpl.DNSNames = []string{"localhost"}
		} else {
			u, err := url.Parse(san)
			require.NoError(t, err)
			tmpl.URIs = []*url.URL{u}
		}
		certDER, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &k.PublicKey, key)
		require.NoError(t, err)
		keyDER, err := x509.MarshalPKCS8PrivateKey(k)
		require.NoError(t, err)
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		require.NoError(t, os.WriteFile(filepath.Join(dir, name+".crt"), certPEM, 0600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, name+".key"), keyPEM, 0600))
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		require.NoError(t, err)
		return cert
	}
	issue("server", "", true)
	cfg := config.AuthNConfig{ModuleIdentities: []string{"kacho/kacho-registry=module-writer@aw-ca", "kacho/kacho-vpc=module-writer@aw-ca"}, ClientIssuers: []string{"aw-ca=" + caPath}}
	for _, module := range additionalModules {
		cfg.ModuleIdentities = append(cfg.ModuleIdentities, "kacho/kacho-"+module+"=module-writer@aw-ca")
	}
	w.roster, err = cfg.LoadModuleRoster()
	require.NoError(t, err)
	w.gate = authzguard.NewRelationWriteGate(w.door).WithProductionMode(true).WithModuleRoster(w.roster)
	w.reg.WithRegistrationAuthority(w.gate)
	mtls := config.MTLSConfig{InternalServerMTLS: grpcsrv.TLSServer{Enable: true, CertFile: filepath.Join(dir, "server.crt"), KeyFile: filepath.Join(dir, "server.key"), ClientCAFiles: []string{caPath}}}
	creds, err := mtls.InternalServerCreds()
	require.NoError(t, err)
	chain := grpcsrv.PrincipalExtractUnary(moduleroster.Domain(), grpcsrv.NewTrustedForwarders("spiffe://kacho.cloud/ns/kacho/sa/kacho-api-gateway"))
	chain = append(chain, authzguard.NewCallerPolicy(true, authzguard.GatewayFrontedInternalRPCs()).WithModuleRoster(w.roster).Unary())
	s := grpc.NewServer(creds, grpc.ChainUnaryInterceptor(chain...))
	h := internaliam.NewHandler(internaliam.NewLookupSubjectUseCase(nil), nil).WithResourceRegistrar(w.reg, w.gate)
	iamv1.RegisterInternalIAMServiceServer(s, h)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(s.Stop)
	go func() { _ = s.Serve(listener) }()
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	for _, module := range append([]string{"registry", "vpc", "intruder", "nonmodule"}, additionalModules...) {
		ns, name := "kacho", module
		if module == "intruder" {
			ns = "intruder"
			name = "registry"
		}
		if module == "nonmodule" {
			name = "other-service"
		}
		cert := issue(module, "spiffe://kacho.cloud/ns/"+ns+"/sa/kacho-"+name, false)
		cc, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, ServerName: "localhost", RootCAs: roots, Certificates: []tls.Certificate{cert}})))
		require.NoError(t, err)
		t.Cleanup(func() { _ = cc.Close() })
		w.clients[module] = iamv1.NewInternalIAMServiceClient(cc)
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		require.NoError(t, err)
		ctx := peer.NewContext(w.ctx, &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf, ca}}}}})
		w.direct[module] = grpcsrv.WithCertIdentityIn(ctx, moduleroster.Domain(), "spiffe://kacho.cloud/ns/"+ns+"/sa/kacho-"+name, true)

	}
}
func (w *awWorld) call(module string, r *iamv1.RegisterResourceRequest) error {
	ctx, cancel := context.WithTimeout(w.ctx, 5*time.Second)
	defer cancel()
	_, err := w.clients[module].RegisterResource(ctx, r)
	return err
}
func (w *awWorld) unregister(module string, r *iamv1.RegisterResourceRequest) error {
	ctx, cancel := context.WithTimeout(w.ctx, 5*time.Second)
	defer cancel()
	_, err := w.clients[module].UnregisterResource(ctx, &iamv1.UnregisterResourceRequest{SubjectId: r.SubjectId, Relation: r.Relation, Object: r.Object, SourceVersion: dpVersion()})
	return err
}

// Каждый интервал настройки использует отдельную идентичность назначения, чтобы
// фикстура проверяла тот же запрет восстановления, что и установка.
func (w *awWorld) withRegistryB(id string, fn func()) {
	w.t.Helper()
	p := w.plan
	p.Assignments = append(append([]domain.RegistrationAccountWriter{}, p.Assignments...), domain.RegistrationAccountWriter{AssignmentID: id, AccountID: string(w.accB), Module: "registry"})
	require.NoError(w.t, w.apply(p))
	fn()
	require.NoError(w.t, w.apply(w.plan))
}
func (w *awWorld) snapshot() string {
	return registrationAccessSnapshot(w.t, w.ctx, w.pool)
}
func registrationAccessSnapshot(t *testing.T, ctx context.Context, pool *pgxpool.Pool) string {
	t.Helper()
	var out string
	// Отказ аудита намеренно проверяется отдельно от равенства состояния доступа.
	require.NoError(t, pool.QueryRow(ctx, `SELECT jsonb_build_array(
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM kaname.resource_mirror t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM kaname.resource_parent_edge t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM kaname.resource_registration_scope t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM kaname.object_project_binding t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM kaname.relation_fact t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM kaname.fga_outbox t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM kaname.resource_reconcile_outbox t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM kaname.access_bindings t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM kaname.access_binding_emitted_tuples t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM kaname.access_binding_target_members t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM kaname.public_read_publication t))::text`).Scan(&out))
	return out
}
func (w *awWorld) denied(f func() error) {
	w.t.Helper()
	before := w.snapshot()
	err := f()
	require.Equal(w.t, codes.PermissionDenied, status.Code(err))
	require.Equal(w.t, "permission denied", status.Convert(err).Message())
	require.Empty(w.t, status.Convert(err).Details())
	require.Equal(w.t, before, w.snapshot())
}

func TestAccountWriter_AW01To11_CanonicalAccountAndModule(t *testing.T) {
	w := newAWWorld(t)
	t.Run("AW01-registry-A-not-B", func(t *testing.T) {
		w.denied(func() error { return w.call("registry", w.regIn("aw01-b", w.prjC, w.accB)) })
		require.NoError(t, w.call("registry", w.regIn("aw01-a", w.prjA, w.accA)))
	})
	t.Run("AW02-vpc-B-not-A", func(t *testing.T) {
		r := dpReq("project:"+string(w.prjA), "project", dpNetType+":enp_aw02", string(w.prjA), string(w.accA))
		w.denied(func() error { return w.call("vpc", r) })
		r.SubjectId = "project:" + string(w.prjC)
		r.ParentProjectId = string(w.prjC)
		r.ParentAccountId = string(w.accB)
		require.NoError(t, w.call("vpc", r))
	})
	t.Run("AW03-cluster-is-irrelevant", func(t *testing.T) {
		w := newAWWorld(t)
		p := w.plan
		p.Assignments = append([]domain.RegistrationAccountWriter{}, p.Assignments[1:]...)
		require.NoError(t, w.apply(p))
		allowed, err := w.door.Check(w.ctx, "service_account:"+authzguard.ServiceAccountIDForService("registry"), "fga_writer", "cluster:"+domain.ClusterSingletonID)
		require.NoError(t, err)
		require.True(t, allowed)
		w.denied(func() error { return w.call("registry", w.regIn("aw03-cluster-only", w.prjA, w.accA)) })
		p.Assignments = append(p.Assignments, domain.RegistrationAccountWriter{AssignmentID: "aw03-explicit-a", AccountID: string(w.accA), Module: "registry"})
		require.NoError(t, w.apply(p))
		require.NoError(t, w.call("registry", w.regIn("aw03", w.prjA, w.accA)))
		w.denied(func() error { return w.call("registry", w.regIn("aw03-b", w.prjC, w.accB)) })
		p.RetireClusterWriter = true
		require.NoError(t, w.apply(p))
		allowed, err = w.door.Check(w.ctx, "service_account:"+authzguard.ServiceAccountIDForService("registry"), "fga_writer", "cluster:"+domain.ClusterSingletonID)
		require.NoError(t, err)
		require.False(t, allowed)
		require.NoError(t, w.call("registry", w.regIn("aw03-without-cluster", w.prjA, w.accA)))
	})
	t.Run("AW04-omitted-claims", func(t *testing.T) {
		for _, chain := range [][]string{nil, {"account:" + string(w.accB)}} {
			r := dpReq("project:"+string(w.prjC), "project", pcrRegType+":aw04-b", "", "", chain...)
			w.denied(func() error { return w.call("registry", r) })
		}
		require.NoError(t, w.call("registry", dpReq("project:"+string(w.prjA), "project", pcrRegType+":aw04-a", "", "")))
		require.NoError(t, w.call("registry", dpReq("project:"+string(w.prjA), "project", pcrRegType+":aw04-a-short", "", "", "account:"+string(w.accA))))
		require.NoError(t, w.unregister("registry", dpReq("project:"+string(w.prjA), "project", pcrRegType+":aw04-a", "", "")))
	})
	t.Run("AW05-false-claim-before-account", func(t *testing.T) {
		r := w.regIn("aw05", w.prjC, w.accA)
		before := w.snapshot()
		err := w.call("registry", r)
		require.Equal(t, codes.FailedPrecondition, status.Code(err))
		requireP8(t, err, r.Object, "AW05: ложный аккаунт")
		require.Equal(t, before, w.snapshot())
		r = w.regIn("aw05", w.prjC, w.accB)
		w.denied(func() error { return w.call("registry", r) })
		w.withRegistryB("aw05-explicit-b", func() { require.NoError(t, w.call("registry", r)) })
		for _, chain := range [][]string{
			{"project:" + string(w.prjA), "account:" + string(w.accB)},
			{"project:" + string(w.prjC), "account:" + string(w.accA)},
		} {
			r := dpReq("project:"+string(w.prjC), "project", pcrRegType+":aw05-chain", "", "", chain...)
			before := w.snapshot()
			requireP8(t, w.call("registry", r), r.Object, "AW05: ложная цепь")
			require.Equal(t, before, w.snapshot())
		}
	})
	t.Run("AW06-container-account", func(t *testing.T) {
		require.NoError(t, w.call("registry", w.regIn("aw06-ka", w.prjA, w.accA)))
		w.withRegistryB("aw06-b-setup", func() { require.NoError(t, w.call("registry", w.regIn("aw06-kb", w.prjC, w.accB))) })
		for _, claims := range []bool{false, true} {
			r := dpReq(pcrRegType+":aw06-kb", "parent", pcrRepoType+":aw06-kb/app", "", "")
			if claims {
				r.ParentProjectId = string(w.prjC)
				r.ParentAccountId = string(w.accB)
				r.ParentChain = []string{pcrRegType + ":aw06-kb", "project:" + string(w.prjC), "account:" + string(w.accB)}
			}
			w.denied(func() error { return w.call("registry", r) })
		}
		forged := dpReq(pcrRegType+":aw06-kb", "parent", pcrRepoType+":aw06-kb/forged", string(w.prjA), string(w.accA))
		before := w.snapshot()
		requireP8(t, w.call("registry", forged), forged.Object, "AW06: claim не меняет аккаунт контейнера")
		require.Equal(t, before, w.snapshot())
		require.NoError(t, w.call("registry", dpReq(pcrRegType+":aw06-ka", "parent", pcrRepoType+":aw06-ka/app", "", "")))
		require.NoError(t, w.call("registry", dpReq(pcrRegType+":aw06-ka", "parent", pcrRepoType+":aw06-ka/short", "", "", "account:"+string(w.accA))))
		require.NoError(t, w.call("registry", dpReq(pcrRegType+":aw06-ka", "parent", pcrRepoType+":aw06-ka/full", string(w.prjA), string(w.accA), pcrRegType+":aw06-ka", "project:"+string(w.prjA), "account:"+string(w.accA))))
	})
	t.Run("AW07-writes-derived-from-object", func(t *testing.T) {
		require.NoError(t, w.call("registry", w.regIn("aw07-a", w.prjA, w.accA)))
		w.withRegistryB("aw07-b-setup", func() { require.NoError(t, w.call("registry", w.regIn("aw07-b", w.prjC, w.accB))) })
		for _, chain := range [][]string{nil, {"account:" + string(w.accB)}} {
			w.denied(func() error {
				return w.call("registry", ownerOn("user:"+string(w.usrA), pcrRegType+":aw07-b", "", "", chain...))
			})
		}
		require.NoError(t, w.call("registry", ownerOn("user:"+string(w.usrA), pcrRegType+":aw07-a", "", "")))
		require.NoError(t, w.call("registry", ownerOn("user:"+string(w.usrA), pcrRegType+":aw07-a", "", "", "account:"+string(w.accA))))
	})
	t.Run("AW09-real-cert-undeclared-namespace", func(t *testing.T) {
		w.denied(func() error { return w.call("intruder", w.regIn("aw09", w.prjA, w.accA)) })
		r := w.regIn("aw09-lawful", w.prjA, w.accA)
		require.NoError(t, w.call("registry", r))
		child := dpReq(r.Object, "parent", pcrRepoType+":aw09-lawful/app", "", "")
		require.NoError(t, w.call("registry", child))
		pub := dpReq("system_class:anonymous", "v_get", child.Object, "", "")
		for _, caller := range []string{"intruder", "nonmodule"} {
			w.denied(func() error { return w.call(caller, r) })
			w.denied(func() error { return w.unregister(caller, r) })
			w.denied(func() error { return w.call(caller, pub) })
			w.denied(func() error { return w.unregister(caller, pub) })
		}
		require.NoError(t, w.call("registry", pub))
		require.NoError(t, w.unregister("registry", pub))
		require.NoError(t, w.unregister("registry", r))
	})
	t.Run("AW10-policy-before-unknown-parent", func(t *testing.T) {
		w.denied(func() error {
			return w.call("registry", dpReq("project:"+dpPrjZ, "project", dpNetType+":enp_aw10", "", ""))
		})
		w.denied(func() error {
			return w.call("registry", dpReq("group:"+w.grpA, "owner", pcrRegType+":aw10-outside-policy", "", ""))
		})
		w.denied(func() error {
			return w.call("registry", dpReq("user:"+string(w.usrA), "editor", pcrRegType+":aw10-outside-writes", "", ""))
		})
		require.NoError(t, w.call("registry", w.regIn("aw10-lawful", w.prjA, w.accA)))
	})
	t.Run("AW11-unknown-parent-keeps-DP", func(t *testing.T) {
		before := w.snapshot()
		err := w.call("registry", dpReq("project:"+dpPrjZ, "project", pcrRegType+":aw11", "", ""))
		require.Equal(t, codes.FailedPrecondition, status.Code(err))
		requireP8(t, err, pcrRegType+":aw11", "AW11: неизвестный родитель")
		require.Equal(t, before, w.snapshot())
		require.NoError(t, w.call("registry", w.regIn("aw11-lawful", w.prjA, w.accA)))
	})
}

func TestAccountWriter_AW12To18And23_Lifecycle(t *testing.T) {
	w := newAWWorld(t)
	reg := w.regIn("aw-lifecycle", w.prjA, w.accA)
	require.NoError(t, w.call("registry", reg))
	t.Run("AW14-publication-both-subjects", func(t *testing.T) {
		childA := dpReq(pcrRegType+":aw-lifecycle", "parent", pcrRepoType+":aw-lifecycle/app", "", "")
		require.NoError(t, w.call("registry", childA))
		childB := dpReq(pcrRegType+":aw14-kb", "parent", pcrRepoType+":aw14-kb/app", "", "")
		w.withRegistryB("aw14-b-setup", func() {
			require.NoError(t, w.call("registry", w.regIn("aw14-kb", w.prjC, w.accB)))
			require.NoError(t, w.call("registry", childB))
			require.NoError(t, w.call("registry", dpReq("user:*", "v_get", childB.Object, "", "")))
		})
		for _, sub := range []string{"user:*", "system_class:anonymous"} {
			pubB := dpReq(sub, "v_get", childB.Object, "", "")
			w.denied(func() error { return w.call("registry", pubB) })
			w.denied(func() error { return w.unregister("registry", pubB) })
			pubA := dpReq(sub, "v_get", childA.Object, "", "")
			require.NoError(t, w.call("registry", pubA))
			require.NoError(t, w.unregister("registry", pubA))
		}
	})
	t.Run("AW15-unknown-cleanup-never-writes-tombstone", func(t *testing.T) {
		w.denied(func() error { return w.unregister("registry", w.regIn("unknown-aw15", w.prjA, w.accA)) })
		for _, subject := range []string{"user:*", "system_class:anonymous"} {
			pub := dpReq(subject, "v_get", pcrRepoType+":unknown-aw15/app", "", "")
			w.denied(func() error { return w.call("registry", pub) })
			w.denied(func() error { return w.unregister("registry", pub) })
		}
	})
	t.Run("AW16-IAM-root-remains-forbidden", func(t *testing.T) {
		w.denied(func() error {
			return w.call("registry", dpReq("user:"+string(w.usrA), "owner", "account:"+string(w.accA), "", ""))
		})
		w.denied(func() error {
			return w.call("registry", dpReq("user:"+string(w.usrA), "owner", "project:"+string(w.prjA), "", ""))
		})
		w.denied(func() error {
			return w.call("registry", dpReq("cluster:"+domain.ClusterSingletonID, "owner", pcrRegType+":aw16-cluster-only", "", ""))
		})
		require.NoError(t, w.call("registry", w.regIn("aw16-lawful", w.prjA, w.accA)))
	})
	t.Run("AW17-direct-usecase-no-identity-or-authority", func(t *testing.T) {
		before := w.snapshot()
		err := w.reg.Register(context.Background(), reg)
		require.Equal(t, codes.PermissionDenied, status.Code(err))
		require.Equal(t, before, w.snapshot())
		w.reg.WithRegistrationAuthority(nil)
		err = w.reg.Register(w.ctx, reg)
		require.Equal(t, codes.PermissionDenied, status.Code(err))
		require.Equal(t, before, w.snapshot())
		err = w.reg.Unregister(w.ctx, &iamv1.UnregisterResourceRequest{SubjectId: reg.SubjectId, Relation: reg.Relation, Object: reg.Object})
		require.Equal(t, codes.PermissionDenied, status.Code(err))
		require.Equal(t, before, w.snapshot())
		err = w.reg.Register(w.ctx, dpReq("user:*", "v_get", pcrRepoType+":aw-lifecycle/app", "", ""))
		require.Equal(t, codes.PermissionDenied, status.Code(err))
		require.Equal(t, before, w.snapshot())
		w.reg.WithRegistrationAuthority(authzguard.NewRelationWriteGate(nil).WithModuleRoster(w.roster))
		err = w.reg.Register(w.direct["registry"], reg)
		require.Equal(t, codes.PermissionDenied, status.Code(err))
		require.Equal(t, before, w.snapshot())
		w.reg.WithRegistrationAuthority(w.gate)
		require.NoError(t, w.reg.Register(w.direct["registry"], w.regIn("aw17-direct-ok", w.prjA, w.accA)))
		before = w.snapshot()
		err = w.reg.Register(w.direct["registry"], w.regIn("aw17-direct-b", w.prjC, w.accB))
		require.Equal(t, codes.PermissionDenied, status.Code(err))
		require.Equal(t, before, w.snapshot())
		childA := dpReq(reg.Object, "parent", pcrRepoType+":aw17-direct-a/app", "", "")
		require.NoError(t, w.call("registry", childA))
		regB := w.regIn("aw17-direct-b-cleanup", w.prjC, w.accB)
		childB := dpReq(regB.Object, "parent", pcrRepoType+":aw17-direct-b-cleanup/app", "", "")
		w.withRegistryB("aw17-direct-b-setup", func() {
			require.NoError(t, w.call("registry", regB))
			require.NoError(t, w.call("registry", childB))
		})
		// Исправная authority не заменяет личность и право на аккаунт:
		// прямые cleanup/publication проходят те же ворота, что и listener.
		for _, tc := range []struct {
			ctx   context.Context
			reg   *iamv1.RegisterResourceRequest
			child *iamv1.RegisterResourceRequest
		}{
			{context.Background(), reg, childA},
			{w.direct["registry"], regB, childB},
		} {
			pub := dpReq("system_class:anonymous", "v_get", tc.child.Object, "", "")
			w.denied(func() error { return w.reg.Register(tc.ctx, pub) })
			w.denied(func() error {
				return w.reg.Unregister(tc.ctx, &iamv1.UnregisterResourceRequest{SubjectId: pub.SubjectId, Relation: pub.Relation, Object: pub.Object, SourceVersion: dpVersion()})
			})
			w.denied(func() error {
				return w.reg.Unregister(tc.ctx, &iamv1.UnregisterResourceRequest{SubjectId: tc.reg.SubjectId, Relation: tc.reg.Relation, Object: tc.reg.Object, SourceVersion: dpVersion()})
			})
		}
		pubA := dpReq("system_class:anonymous", "v_get", childA.Object, "", "")
		require.NoError(t, w.reg.Register(w.direct["registry"], pubA))
		require.NoError(t, w.reg.Unregister(w.direct["registry"], &iamv1.UnregisterResourceRequest{SubjectId: pubA.SubjectId, Relation: pubA.Relation, Object: pubA.Object, SourceVersion: dpVersion()}))
		require.NoError(t, w.reg.Unregister(w.direct["registry"], &iamv1.UnregisterResourceRequest{SubjectId: childA.SubjectId, Relation: childA.Relation, Object: childA.Object, SourceVersion: dpVersion()}))
	})
	t.Run("AW12-AW23-revocation-before-every-version-fast-path", func(t *testing.T) {
		// Снимаем A через полный список установки: защищённый жизненный цикл и
		// снятие выпущенного набора. Независимое B сохраняется.
		p := w.plan
		p.Assignments = p.Assignments[1:]
		require.NoError(t, w.apply(p))
		for _, v := range []*timestamppb.Timestamp{reg.SourceVersion, timestamppb.New(time.Unix(1, 0)), dpVersion()} {
			r := *reg
			r.SourceVersion = v
			w.denied(func() error { return w.call("registry", &r) })
		}
		w.denied(func() error { return w.unregister("registry", reg) })
		w.denied(func() error {
			return w.call("registry", dpReq("user:*", "v_get", pcrRepoType+":aw-lifecycle/app", "", ""))
		})
		require.NoError(t, w.call("vpc", dpReq("project:"+string(w.prjC), "project", dpNetType+":enp_aw12_b", "", "")))
		require.NoError(t, w.apply(w.plan))
		w.denied(func() error { return w.call("registry", reg) })
	})
}

func TestAccountWriter_AW19To22_BootstrapLedger(t *testing.T) {
	w := newAWWorld(t)
	t.Run("AW19-visible-named-relation-no-role", func(t *testing.T) {
		rd, err := w.repo.Reader(w.ctx)
		require.NoError(t, err)
		defer func() { _ = rd.Rollback(w.ctx) }()
		rows, _, err := rd.AccessBindings().ListByAccount(w.ctx, w.accA, ab.AccountPageFilter{PageSize: 100})
		require.NoError(t, err)
		found := false
		for _, b := range rows {
			if b.GrantedRelation == "fga_writer" {
				found = true
				require.True(t, b.System)
				require.Empty(t, b.RoleID)
				require.Equal(t, authzguard.ServiceAccountIDForService("registry"), string(b.SubjectID))
				got, err := rd.AccessBindings().Get(w.ctx, b.ID)
				require.NoError(t, err)
				require.Equal(t, b.ID, got.ID)
			}
		}
		require.True(t, found)
		before := w.snapshot()
		require.NoError(t, w.apply(w.plan))
		require.Equal(t, before, w.snapshot())
	})
	t.Run("AW20-entire-invalid-plan-refused", func(t *testing.T) {
		p := w.plan
		p.Assignments = append(append([]domain.RegistrationAccountWriter{}, p.Assignments...), domain.RegistrationAccountWriter{AssignmentID: "invalid", AccountID: "acc-absent", Module: "registry"})
		before := w.snapshot()
		require.Error(t, w.apply(p))
		require.Equal(t, before, w.snapshot())
		p = w.plan
		p.Assignments = append([]domain.RegistrationAccountWriter{}, p.Assignments...)
		p.Assignments[0].AccountID = string(w.accB)
		require.Error(t, w.apply(p))
		require.Equal(t, before, w.snapshot())
	})
	t.Run("AW21-future-account-needs-explicit-assignment", func(t *testing.T) {
		acc := seedAccountByOwner(t, w.ctx, w.pool, "aw-c", w.usrA)
		prj := seedProjectInAccount(t, w.ctx, w.pool, acc, "aw-c-prj")
		r := w.regIn("aw21", prj, acc)
		w.denied(func() error { return w.call("registry", r) })
		p := w.plan
		p.Assignments = append(append([]domain.RegistrationAccountWriter{}, p.Assignments...), domain.RegistrationAccountWriter{AssignmentID: "aw-c-explicit", AccountID: string(acc), Module: "registry"})
		require.NoError(t, w.apply(p))
		require.NoError(t, w.call("registry", r))
		p.Assignments = append([]domain.RegistrationAccountWriter{}, p.Assignments[1:]...)
		require.NoError(t, w.apply(p))
		w.denied(func() error { return w.call("registry", w.regIn("aw21-a-withdrawn", w.prjA, w.accA)) })
		require.NoError(t, w.call("registry", w.regIn("aw21-c-retained", prj, acc)))
		require.NoError(t, w.call("vpc", dpReq("project:"+string(w.prjC), "project", dpNetType+":enp_aw21_b", "", "")))
	})
	t.Run("AW22-old-blanket-retirement-rollback-reupgrade", func(t *testing.T) {
		// Отдельный снимок A/B: создание C в AW21 уже расходует третье
		// допустимое создание аккаунта владельцем в общем окне admission.
		w := newAWWorld(t)
		var active int
		require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.access_bindings b JOIN kaname.groups g ON g.id=b.subject_id WHERE b.is_system AND b.resource_type='cluster' AND b.granted_relation='fga_writer' AND b.status='ACTIVE' AND g.name='module-relation-writers'`).Scan(&active))
		require.Positive(t, active, "the upgrade fixture must start with a standing historical blanket")
		allowed, err := w.door.Check(w.ctx, "service_account:"+authzguard.ServiceAccountIDForService("registry"), "fga_writer", "cluster:"+domain.ClusterSingletonID)
		require.NoError(t, err)
		require.True(t, allowed)
		w.denied(func() error { return w.call("registry", w.regIn("aw22-before-b", w.prjC, w.accB)) })
		c := seedAccountByOwner(t, w.ctx, w.pool, "aw22-new-c", w.usrA)
		pc := seedProjectInAccount(t, w.ctx, w.pool, c, "aw22-new-c-project")
		requestC := w.regIn("aw22-c", pc, c)
		w.denied(func() error { return w.call("registry", requestC) })
		p := w.plan
		p.RetireClusterWriter = true
		require.NoError(t, w.apply(p))
		allowed, err = w.door.Check(w.ctx, "service_account:"+authzguard.ServiceAccountIDForService("registry"), "fga_writer", "cluster:"+domain.ClusterSingletonID)
		require.NoError(t, err)
		require.False(t, allowed)
		// Обычная запись начальных данных старого бинарного файла снова пытается выдать прежний общий доступ.
		// Постоянный барьер снятия в БД, действующий и для старого бинарного файла,
		// атомарно отказывает. Вход регистрации при откате остаётся закрытым.
		before := w.snapshot()
		err = kanamepg.NewModuleSeedWriteRepo(w.pool).RunInWriteTx(w.ctx, func(ctx context.Context, writer moduleseed.Writer) error {
			_, e := writer.GrantRelation(ctx, moduleseed.Subject{Kind: "group", Account: "system", Name: "module-relation-writers"}, "fga_writer", "cluster", domain.ClusterSingletonID)
			return e
		})
		// Если детерминированный исторический id уже существует отозванным, обычный быстрый
		// путь начальных данных ничего не делает; иначе барьер БД отвергает новую строку.
		if err != nil {
			require.Contains(t, err.Error(), "retired")
		}
		require.Equal(t, before, w.snapshot())
		require.NoError(t, w.apply(w.plan))
		require.NoError(t, w.apply(p))
		allowed, err = w.door.Check(w.ctx, "service_account:"+authzguard.ServiceAccountIDForService("registry"), "fga_writer", "cluster:"+domain.ClusterSingletonID)
		require.NoError(t, err)
		require.False(t, allowed)
		w.denied(func() error { return w.call("registry", w.regIn("aw22-after-b", w.prjC, w.accB)) })
		w.denied(func() error { return w.call("registry", requestC) })
		require.NoError(t, w.call("registry", w.regIn("aw22-after-a", w.prjA, w.accA)))
	})
}

// Отдельный пул чтения обнаруживает случайные вложенные чтения иерархии, когда
// запись заняла единственное соединение регистрации; полномочия читаются обычным пулом.
func TestAccountWriter_SingleRegistrationConnection(t *testing.T) {
	w := newAWWorld(t)
	cfg := w.pool.Config().Copy()
	cfg.MaxConns = 1
	p, err := pgxpool.NewWithConfig(w.ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(p.Close)
	w.reg = internaliam.NewRegisterResourceUseCase(
		kanamepg.NewFGAOutboxEmitter(), kanamepg.NewResourceMirrorEmitter(),
		kanamepg.NewRegistrationTxBeginner(p), kanamepg.NewCatalogTypeReader(),
		kanamepg.NewPublicReadPublisher(), accessbindingapp.NewUnregisteredKeyWithdrawal(kanamepg.NewUnregisteredKeyStore(), pcrFacts{w.pcrWorld}),
		kanamepg.NewRegistrationAudit(), kanamepg.NewRegistrationScopeReader(),
	).WithRegistrationAuthority(w.gate)
	w.startListener(t)
	require.NoError(t, w.call("registry", w.regIn("aw-one-pool", w.prjA, w.accA)))
}

func TestAccountWriter_AW08_AllMatchingPointersNeedAuthority(t *testing.T) {
	w := newAWWorld(t)
	p := w.plan
	p.Assignments = append(append([]domain.RegistrationAccountWriter{}, p.Assignments...), domain.RegistrationAccountWriter{AssignmentID: "aw08-registry-b", AccountID: string(w.accB), Module: "registry"})
	require.NoError(t, w.apply(p))
	require.NoError(t, w.call("registry", w.regIn("aw08", w.prjA, w.accA)))
	require.NoError(t, w.call("registry", w.regIn("aw08", w.prjC, w.accB)))
	// Оба факта указателей проекта сохраняются; пустые утверждения допускают обе канонические области.
	require.NoError(t, w.apply(w.plan))
	r := ownerOn("user:"+string(w.usrA), pcrRegType+":aw08", "", "")
	w.denied(func() error { return w.call("registry", r) })
	p.Assignments[len(p.Assignments)-1].AssignmentID = "aw08-registry-b-new"
	require.NoError(t, w.apply(p))
	require.NoError(t, w.call("registry", r))
	require.NoError(t, w.call("registry", w.regIn("aw08-same", w.prjA, w.accA)))
	require.NoError(t, w.call("registry", w.regIn("aw08-same", w.prjA2, w.accA)))
	require.NoError(t, w.call("registry", ownerOn("user:"+string(w.usrA), pcrRegType+":aw08-same", "", "")))
}

func TestAccountWriter_AW13_CleanupIgnoresCurrentWritesPolicy(t *testing.T) {
	w := newAWWorld(t)
	rA := w.regIn("aw13-a", w.prjA, w.accA)
	require.NoError(t, w.call("registry", rA))
	require.NoError(t, w.call("registry", ownerOn("user:"+string(w.usrA), rA.Object, "", "")))
	rB := w.regIn("aw13-b", w.prjC, w.accB)
	w.withRegistryB("aw13-b-setup", func() {
		require.NoError(t, w.call("registry", rB))
		require.NoError(t, w.call("registry", ownerOn("user:"+string(w.usrA), rB.Object, "", "")))
	})
	w.redeliverP0()
	w.denied(func() error { return w.unregister("registry", rB) })
	require.NoError(t, w.unregister("registry", rA))
	var n int
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.relation_fact WHERE object_type=$1 AND object_id=$2`, pcrRegType, "aw13-a").Scan(&n))
	require.Zero(t, n)
}

type awUnavailableChecker struct{}

func (awUnavailableChecker) Check(context.Context, string, string, string) (bool, error) {
	return false, errors.New("backend private address must not escape")
}
func TestAccountWriter_AW18_BackendOutageIsUnavailable(t *testing.T) {
	w := newAWWorld(t)
	r := w.regIn("aw18", w.prjA, w.accA)
	require.NoError(t, w.call("registry", r))
	child := dpReq(r.Object, "parent", pcrRepoType+":aw18/app", "", "")
	require.NoError(t, w.call("registry", child))
	gate := authzguard.NewRelationWriteGate(awUnavailableChecker{}).WithProductionMode(true).WithModuleRoster(w.roster)
	w.reg.WithRegistrationAuthority(gate)
	for _, call := range []func() error{
		func() error { return w.call("registry", r) },
		func() error { return w.unregister("registry", r) },
		func() error {
			return w.call("registry", dpReq("system_class:anonymous", "v_get", child.Object, "", ""))
		},
	} {
		before := w.snapshot()
		err := call()
		require.Equal(t, codes.Unavailable, status.Code(err))
		require.Equal(t, "authz backend unavailable", status.Convert(err).Message())
		require.Equal(t, before, w.snapshot())
	}
	w.reg.WithRegistrationAuthority(w.gate)
	require.NoError(t, w.call("registry", w.regIn("aw18-restored", w.prjA, w.accA)))
}

func TestAccountWriter_PermanentBindingPreservesUnregisterRetry(t *testing.T) {
	w := newAWWorld(t)
	doc, err := publicreadfixture.PermanentProjectDocument()
	require.NoError(t, err)
	m, err := manifest.Load(doc)
	require.NoError(t, err)
	w.applyDelivered("AW permanent binding", m)
	r := w.regIn("aw-permanent", w.prjA, w.accA)
	require.NoError(t, w.call("registry", r))
	require.NoError(t, w.unregister("registry", r))
	require.NoError(t, w.unregister("registry", r))
	// Сохранённый постоянный проект не подменяет отозванные полномочия.
	p := w.plan
	p.Assignments = p.Assignments[1:]
	require.NoError(t, w.apply(p))
	w.denied(func() error { return w.unregister("registry", r) })
}

func TestAccountWriter_FirstUpgradeCensusIsNotARestartGate(t *testing.T) {
	w := newDPWorld(t)
	roster := moduleroster.Roster(t)
	store := kanamepg.NewRegistrationAccountWriterStore(w.pool)
	// Пустой план при существующих регистрациях неполон, пока для каждой
	// пропущенной канонической пары нет явного решения об отключении модуля.
	var before int
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.registration_account_writer_assignment`).Scan(&before))
	require.Error(t, seed.ApplyRegistrationAccountWriters(w.ctx, store, roster, seed.RegistrationWriterPlan{Assignments: []domain.RegistrationAccountWriter{}}))
	var after int
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.registration_account_writer_assignment`).Scan(&after))
	require.Equal(t, before, after)
	plan := seed.RegistrationWriterPlan{Assignments: []domain.RegistrationAccountWriter{}, Disabled: []domain.DisabledRegistrationModule{
		{AccountID: string(w.accA), Module: "registry", Reason: "operator disabled old registry"},
		{AccountID: string(w.accA), Module: "vpc", Reason: "operator disabled old vpc"},
	}}
	require.NoError(t, seed.ApplyRegistrationAccountWriters(w.ctx, store, roster, plan))
	// После переключения сохранение старых объектов не отвергает намеренно пустой план.
	require.NoError(t, seed.ApplyRegistrationAccountWriters(w.ctx, store, roster, seed.RegistrationWriterPlan{Assignments: []domain.RegistrationAccountWriter{}}))
}

func TestAccountWriter_ProductionDeclarationAndEmptyInstall(t *testing.T) {
	ctx := context.Background()
	pool := poolFromDSN(t, setupTestDB(t))
	store := kanamepg.NewRegistrationAccountWriterStore(pool)
	roster := moduleroster.Roster(t)
	state := func() string {
		var out string
		require.NoError(t, pool.QueryRow(ctx, `SELECT jsonb_build_array(
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM kaname.registration_account_writer_assignment t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM kaname.registration_account_writer_switch t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM kaname.access_bindings t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM kaname.access_binding_subjects t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM kaname.access_binding_emitted_tuples t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM kaname.relation_fact t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM kaname.fga_outbox t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM kaname.audit_outbox t))::text`).Scan(&out))
		return out
	}
	before := state()
	cfg := config.Config{AuthN: config.AuthNConfig{Mode: config.ModeProduction}}
	require.EqualError(t, cfg.ValidateRegistrationAccountWriters(), "registration-account-writers must be explicitly declared")
	require.Equal(t, before, state())
	cfg.RegistrationAccountWriters = &config.RegistrationAccountWritersConfig{}
	require.EqualError(t, cfg.ValidateRegistrationAccountWriters(), "registration-account-writers.assignments must be explicitly declared (an empty list disables registrars)")
	require.Equal(t, before, state())
	// Ошибочное назначение не должно зафиксировать даже первый switch.
	require.Error(t, seed.ApplyRegistrationAccountWriters(ctx, store, roster, seed.RegistrationWriterPlan{
		Assignments: []domain.RegistrationAccountWriter{{AssignmentID: "aw-empty-invalid", AccountID: "acc-absent", Module: "registry"}},
	}))
	require.Equal(t, before, state())
	cfg.RegistrationAccountWriters.Assignments = []domain.RegistrationAccountWriter{}
	require.NoError(t, cfg.ValidateRegistrationAccountWriters())
	plan := seed.RegistrationWriterPlan{Assignments: cfg.RegistrationAccountWriters.Assignments}
	require.NoError(t, seed.ApplyRegistrationAccountWriters(ctx, store, roster, plan))
	var assignments, accountWriters, switched int
	require.NoError(t, pool.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM kaname.registration_account_writer_assignment),
 (SELECT count(*) FROM kaname.access_bindings WHERE resource_type='account' AND granted_relation='fga_writer' AND status='ACTIVE'),
 (SELECT count(*) FROM kaname.registration_account_writer_switch)`).Scan(&assignments, &accountWriters, &switched))
	require.Zero(t, assignments)
	require.Zero(t, accountWriters)
	require.Equal(t, 1, switched)
	applied := state()
	require.NoError(t, seed.ApplyRegistrationAccountWriters(ctx, store, roster, plan))
	require.Equal(t, applied, state())
}

func TestAccountWriter_PermanentProjectValidationAndPrecedence(t *testing.T) {
	w := newAWWorld(t)
	doc, err := publicreadfixture.PermanentProjectDocument()
	require.NoError(t, err)
	m, err := manifest.Load(doc)
	require.NoError(t, err)
	w.applyDelivered("AW04/AW11 permanent project", m)
	// Сокращение claims не отменяет обязательную форму постоянного проекта.
	r := w.regIn("aw-pb-form", w.prjA, w.accA)
	r.ParentProjectId = ""
	before := w.snapshot()
	requireP2(t, w.call("registry", r), "parent_project_id", "parent_project_id: required for object type "+pcrRegType+" with a permanent project", "AW04: постоянный проект")
	require.Equal(t, before, w.snapshot())
	r = w.regIn("aw-pb-form", w.prjA, w.accA)
	r.ParentChain = []string{"account:" + string(w.accA)}
	requireP2(t, w.call("registry", r), "parent_chain", "parent_chain: must name the project for object type "+pcrRegType+" with a permanent project", "AW04: проект в цепи")
	require.Equal(t, before, w.snapshot())
	r = w.regIn("aw-pb-form", w.prjA, w.accA)
	require.NoError(t, w.call("registry", r))
	var boundProject string
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT project_id FROM kaname.object_project_binding WHERE object_type=$1 AND object_id='aw-pb-form'`, pcrRegType).Scan(&boundProject))
	require.Equal(t, string(w.prjA), boundProject)
	// Без права B всё равно первым остаётся прежний отказ привязки.
	before = w.snapshot()
	requireP4(t, w.call("registry", w.regIn("aw-pb-form", w.prjC, w.accB)), r.Object, w.prjA, "AW11: PB до account deny")
	require.Equal(t, before, w.snapshot())
	requireP4(t, w.call("registry", w.regIn("aw-pb-form", domain.ProjectID(dpPrjZ), w.accB)), r.Object, w.prjA, "AW11: PB до неизвестного проекта")
	require.Equal(t, before, w.snapshot())
	// Равная и старая версии не заменяют проверку привязки быстрого пути;
	// при разрешённом аккаунте A другой проект A2 тоже остаётся запрещённым.
	for _, target := range []struct {
		project domain.ProjectID
		account domain.AccountID
	}{
		{w.prjC, w.accB},
		{domain.ProjectID(dpPrjZ), w.accB},
		{w.prjA2, w.accA},
	} {
		for _, version := range []*timestamppb.Timestamp{r.SourceVersion, timestamppb.New(time.Unix(1, 0)), dpVersion()} {
			request := w.regIn("aw-pb-form", target.project, target.account)
			request.SourceVersion = version
			requireP4(t, w.call("registry", request), r.Object, w.prjA, "AW11: PB при каждой версии и каждом отказе")
			require.Equal(t, before, w.snapshot())
		}
	}
	require.NoError(t, w.call("registry", w.regIn("aw-pb-form", w.prjA, w.accA)))
}

func TestAccountWriter_RefusalAuditIsSeparateFromAccessState(t *testing.T) {
	w := newAWWorld(t)
	r := w.regIn("aw-audit-refused", w.prjC, w.accB)
	count := func() int {
		var n int
		require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.audit_outbox
 WHERE event_type=$1 AND event_payload #>> '{object,id}'='aw-audit-refused'`, auditRegistered).Scan(&n))
		return n
	}
	require.Zero(t, count())
	w.denied(func() error { return w.call("registry", r) })
	require.Equal(t, 1, count())
	var payload map[string]any
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT event_payload FROM kaname.audit_outbox
 WHERE event_type=$1 AND event_payload #>> '{object,id}'='aw-audit-refused'`, auditRegistered).Scan(&payload))
	require.Equal(t, "permission_denied", payload["outcome"])
	require.Equal(t, "service_account:"+authzguard.ServiceAccountIDForService("registry"), payload["actor"])
	require.Equal(t, "registry", payload["module"])
	require.Equal(t, r.SubjectId, payload["subject"])
	require.Equal(t, r.Relation, payload["relation"])
	require.Equal(t, map[string]any{"type": pcrRegTgt, "id": "aw-audit-refused"}, payload["object"])
	// Законный близнец пишет обычное событие, не отказ, через тот же listener.
	require.NoError(t, w.call("registry", w.regIn("aw-audit-lawful", w.prjA, w.accA)))
	var outcome string
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT event_payload->>'outcome' FROM kaname.audit_outbox
 WHERE event_type=$1 AND event_payload #>> '{object,id}'='aw-audit-lawful'`, auditRegistered).Scan(&outcome))
	require.Equal(t, "registered", outcome)
}

func TestAccountWriter_AW19_PublicRevokeDeleteAndReseed(t *testing.T) {
	for _, action := range []string{"revoke", "delete"} {
		t.Run(action, func(t *testing.T) {
			w := newAWWorld(t)
			var id string
			require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT binding_id FROM kaname.registration_account_writer_assignment WHERE assignment_id='aw-registry-a'`).Scan(&id))
			w.ownerMayRemove("AW19 public lifecycle", id)
			get := accessbindingapp.NewGetAccessBindingUseCase(w.repo).WithRelationStore(w.door, nil).WithRelationQueries(w.door)
			list := accessbindingapp.NewListByAccountUseCase(w.repo).WithRelationStore(w.door, nil).WithRelationQueries(w.door)
			del := accessbindingapp.NewDeleteAccessBindingUseCase(w.repo, w.ops).WithRelationStore(w.door, nil)
			revoke := accessbindingapp.NewRevokeAccessBindingUseCase(w.repo, w.ops).WithRelationStore(w.door, nil)
			update := accessbindingapp.NewUpdateAccessBindingUseCase(w.repo, w.ops).WithRelationStore(w.door, nil)
			h := accessbindingapp.NewHandler(nil, del, get, nil, nil, list, nil).WithRevoke(revoke).WithUpdate(update)
			actor := asUser(w.ctx, w.usrA)
			b, err := h.Get(actor, &iamv1.GetAccessBindingRequest{AccessBindingId: id})
			require.NoError(t, err)
			require.Equal(t, "fga_writer", b.GetGrantedRelation())
			require.Empty(t, b.GetRoleId())
			require.True(t, b.GetSystem())
			listed, err := h.ListByAccount(actor, &iamv1.ListAccessBindingsByAccountRequest{AccountId: string(w.accA), PageSize: 100})
			require.NoError(t, err)
			found := false
			for _, b := range listed.GetAccessBindings() {
				if b.GetId() == id {
					found = true
				}
			}
			require.True(t, found)
			r := w.regIn("aw19-before", w.prjA, w.accA)
			require.NoError(t, w.call("registry", r))
			protected := w.snapshot()
			if action == "revoke" {
				_, err = h.Revoke(actor, &iamv1.RevokeAccessBindingRequest{AccessBindingId: id})
			} else {
				_, err = h.Delete(actor, &iamv1.DeleteAccessBindingRequest{AccessBindingId: id})
			}
			require.Equal(t, codes.FailedPrecondition, status.Code(err))
			require.Equal(t, protected, w.snapshot())
			op, err := h.Update(actor, &iamv1.UpdateAccessBindingRequest{AccessBindingId: id, UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"deletion_protection"}}, DeletionProtection: false})
			require.NoError(t, err)
			require.Nil(t, awaitOp(t, w.ctx, w.ops, op.GetId()).Error)
			if action == "revoke" {
				op, err = h.Revoke(actor, &iamv1.RevokeAccessBindingRequest{AccessBindingId: id})
			} else {
				op, err = h.Delete(actor, &iamv1.DeleteAccessBindingRequest{AccessBindingId: id})
			}
			require.NoError(t, err)
			require.Nil(t, awaitOp(t, w.ctx, w.ops, op.GetId()).Error)
			w.denied(func() error { return w.call("registry", w.regIn("aw19-after", w.prjA, w.accA)) })
			require.NoError(t, w.apply(w.plan))
			w.startListener(t) // Заново строим связанную с издателем идентичность и проверку запроса после повторного заполнения.
			w.denied(func() error { return w.call("registry", r) })
			require.NoError(t, w.call("vpc", dpReq("project:"+string(w.prjC), "project", dpNetType+":enp_aw19_b", "", "")))
			// Новая идентичность — единственный явный механизм повторного предоставления полномочий.
			p := w.plan
			p.Assignments = append([]domain.RegistrationAccountWriter{}, p.Assignments...)
			p.Assignments[0].AssignmentID = "aw19-new-identity"
			require.NoError(t, w.apply(p))
			require.NoError(t, w.call("registry", w.regIn("aw19-new", w.prjA, w.accA)))
		})
	}
}

func TestAccountWriter_LegacyOmittedClaimsUpgradeCleanupAndPublication(t *testing.T) {
	d := newDPWorld(t)
	top := dpReq("project:"+string(d.prjA), "project", pcrRegType+":aw-legacy-root", "", "")
	child := dpReq(pcrRegType+":"+pcrX, "parent", pcrRepoType+":"+pcrX+"/aw-legacy", "", "")
	require.NoError(t, d.reg.Register(d.ctx, top))
	require.NoError(t, d.reg.Register(d.ctx, child))
	// Восстанавливаем снимок до #1031: две регистрации сделаны
	// обычным путём #982, необязательные утверждения остаются пустыми, факты указателей сохранены,
	// а канонического реестра, появившегося только в новой версии, ещё не было.
	_, err := d.pool.Exec(d.ctx, `DELETE FROM kaname.resource_registration_scope`)
	require.NoError(t, err)
	w := newAWWorldFromDP(t, d) // Перепись первого переключения должна вывести прежние указатели.
	var project, account string
	var chain []string
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT parent_project_id,parent_account_id FROM kaname.resource_mirror WHERE object_type='registry.registries' AND object_id='aw-legacy-root'`).Scan(&project, &account))
	require.Empty(t, project)
	require.Empty(t, account)
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT coalesce(array_agg(parent_type || ':' || parent_id ORDER BY depth),ARRAY[]::text[]) FROM kaname.resource_parent_edge WHERE object_type=$1 AND object_id=$2`, pcrRegType, "aw-legacy-root").Scan(&chain))
	require.Empty(t, chain)
	// Запасной путь при работе использует тот же канонический разрешитель, что и перепись
	// первого переключения, включая указатель контейнера и полностью пропущенное утверждение.
	pub := dpReq("system_class:anonymous", "v_get", child.Object, "", "")
	require.NoError(t, w.call("registry", pub))
	require.NoError(t, w.unregister("registry", pub))
	require.NoError(t, w.unregister("registry", child))
	require.NoError(t, w.unregister("registry", top))
	w.denied(func() error { return w.unregister("registry", w.regIn("aw-truly-unknown", w.prjA, w.accA)) })
}

// Изменяемые имена не определяют принадлежность снимаемого и не блокируют чужие группы.
func TestAccountWriter_RetirementOwnsImmutableInstallationAssignment(t *testing.T) {
	w := newAWWorld(t)
	var ownedGroup, ownedAccount, cluster string
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT group_id,account_id,cluster_id FROM kaname.registration_legacy_cluster_writer_identity WHERE singleton`).Scan(&ownedGroup, &ownedAccount, &cluster))
	require.Equal(t, domain.ClusterSingletonID, cluster)
	var standing int
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.access_bindings b WHERE kaname.registration_owns_legacy_cluster_writer(b) AND b.status='ACTIVE'`).Scan(&standing))
	require.Positive(t, standing)
	allowed, err := w.door.Check(w.ctx, "service_account:"+authzguard.ServiceAccountIDForService("registry"), "fga_writer", "cluster:"+cluster)
	require.NoError(t, err)
	require.True(t, allowed)
	// Обычной записью группы переименовываем только изменяемое поле; координаты
	// принадлежности и всё ещё действующая базовая выдача сохраняются.
	tx, err := w.repo.Writer(w.ctx)
	require.NoError(t, err)
	g, err := tx.Groups().Get(w.ctx, domain.GroupID(ownedGroup))
	require.NoError(t, err)
	require.Equal(t, ownedAccount, string(g.AccountID))
	g.Name = "renamed-installation-writers"
	_, err = tx.GroupsW().Update(w.ctx, g, []string{"name"})
	require.NoError(t, err)
	require.NoError(t, tx.Commit(w.ctx))
	// Одноимённая группа в аккаунте арендатора — другое назначение. Её
	// системная выдача создаётся существующей записью начальных выдач/выпущенных кортежей.
	grantForeign := func(account domain.AccountID, name string) error {
		var accountName string
		require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT name FROM kaname.accounts WHERE id=$1`, string(account)).Scan(&accountName))
		return kanamepg.NewModuleSeedWriteRepo(w.pool).RunInWriteTx(w.ctx, func(ctx context.Context, writer moduleseed.Writer) error {
			if _, e := writer.UpsertGroup(ctx, accountName, name, "Foreign tenant group with the same legacy seed name"); e != nil {
				return e
			}
			_, e := writer.GrantRelation(ctx, moduleseed.Subject{Kind: "group", Account: accountName, Name: name}, "fga_writer", "cluster", cluster)
			return e
		})
	}
	require.NoError(t, grantForeign(w.accA, "module-relation-writers"))
	var foreign string
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT id FROM kaname.groups WHERE account_id=$1 AND name='module-relation-writers'`, string(w.accA)).Scan(&foreign))
	var foreignBinding, before string
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT b.id,to_jsonb(b)::text FROM kaname.access_bindings b WHERE b.subject_type='group' AND b.subject_id=$1 AND b.granted_relation='fga_writer' AND b.resource_type='cluster' AND b.resource_id=$2 AND b.status='ACTIVE'`, foreign, cluster).Scan(&foreignBinding, &before))
	// Общий предикат также отвергает координату кластера, отличную от единственной допустимой.
	var otherClusterOwned bool
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT kaname.registration_owns_legacy_cluster_writer(jsonb_populate_record(NULL::kaname.access_bindings,to_jsonb(b)||jsonb_build_object('resource_id','cluster-not-this-installation'))) FROM kaname.access_bindings b WHERE b.subject_id=$1 AND b.granted_relation='fga_writer' AND b.status='ACTIVE'`, ownedGroup).Scan(&otherClusterOwned))
	require.False(t, otherClusterOwned)
	p := w.plan
	p.RetireClusterWriter = true
	require.NoError(t, w.apply(p))
	var active int
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.access_bindings b WHERE kaname.registration_owns_legacy_cluster_writer(b) AND b.status='ACTIVE'`).Scan(&active))
	require.Zero(t, active, "renamed owned assignment must actually retire")
	allowed, err = w.door.Check(w.ctx, "service_account:"+authzguard.ServiceAccountIDForService("registry"), "fga_writer", "cluster:"+cluster)
	require.NoError(t, err)
	require.False(t, allowed)

	var after string
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT to_jsonb(b)::text FROM kaname.access_bindings b WHERE b.id=$1`, foreignBinding).Scan(&after))
	require.Equal(t, before, after, "foreign same-name binding and deletion protection must remain unchanged")
	var foreignFact bool
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT EXISTS(SELECT 1 FROM kaname.relation_fact WHERE object_type='cluster' AND object_id=$1 AND relation='fga_writer' AND subject=$2)`, cluster, "group:"+foreign+"#member").Scan(&foreignFact))
	require.True(t, foreignFact)
	// Барьер INSERT принимает другое несвязанное одноимённое назначение арендатора после
	// снятия, продолжая отвергать восстановление переименованной принадлежащей группы.
	require.NoError(t, grantForeign(w.accB, "module-relation-writers"))
	accessBefore := w.snapshot()
	err = kanamepg.NewModuleSeedWriteRepo(w.pool).RunInWriteTx(w.ctx, func(ctx context.Context, writer moduleseed.Writer) error {
		_, e := writer.GrantRelation(ctx, moduleseed.Subject{Kind: "group", Account: "system", Name: string(g.Name)}, "fga_writer", "cluster", cluster)
		return e
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "retired")
	require.Equal(t, accessBefore, w.snapshot())
	// Выполняем НАСТОЯЩУЮ полную прежнюю последовательность начальных данных сервиса. После обычного
	// переименования естественный ключ свободен, поэтому UpsertGroup создал бы новый ID;
	// барьер пространства имён установки должен отвергнуть всю транзакцию.
	fullSeedBefore := w.snapshot()
	err = kanamepg.NewModuleSeedWriteRepo(w.pool).RunInWriteTx(w.ctx, func(ctx context.Context, writer moduleseed.Writer) error {
		if _, e := writer.UpsertGroup(ctx, "system", "module-relation-writers", "Module service accounts allowed to write relation tuples through iam (issue #914)"); e != nil {
			return e
		}
		_, e := writer.GrantRelation(ctx, moduleseed.Subject{Kind: "group", Account: "system", Name: "module-relation-writers"}, "fga_writer", "cluster", cluster)
		return e
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "seed namespace is retired")
	require.Equal(t, fullSeedBefore, w.snapshot())
	var replacement int
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.groups WHERE account_id=$1 AND name='module-relation-writers'`, ownedAccount).Scan(&replacement))
	require.Zero(t, replacement, "old seed must not leave a replacement group")
	// Полная одноимённая последовательность всё ещё законна в чужом аккаунте арендатора.
	var tenantName string
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT name FROM kaname.accounts WHERE id=$1`, string(w.accB)).Scan(&tenantName))
	require.NoError(t, kanamepg.NewModuleSeedWriteRepo(w.pool).RunInWriteTx(w.ctx, func(ctx context.Context, writer moduleseed.Writer) error {
		if _, e := writer.UpsertGroup(ctx, tenantName, "module-relation-writers", "Foreign tenant group with the same legacy seed name"); e != nil {
			return e
		}
		_, e := writer.GrantRelation(ctx, moduleseed.Subject{Kind: "group", Account: tenantName, Name: "module-relation-writers"}, "fga_writer", "cluster", cluster)
		return e
	}))

	require.NoError(t, w.apply(p))
	w.denied(func() error { return w.call("registry", w.regIn("aw-immutable-b", w.prjC, w.accB)) })
	require.NoError(t, w.call("registry", w.regIn("aw-immutable-a", w.prjA, w.accA)))
}

// Замену, уже созданную полной старой последовательностью, нельзя молча
// принять принадлежащей установке. Снятие должно атомарно отказать для проверки.
func TestAccountWriter_RetirementRefusesRecreatedLegacySeedNamespace(t *testing.T) {
	w := newAWWorld(t)
	var originalGroup, cluster string
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT group_id,cluster_id FROM kaname.registration_legacy_cluster_writer_identity WHERE singleton`).Scan(&originalGroup, &cluster))
	tx, err := w.repo.Writer(w.ctx)
	require.NoError(t, err)
	g, err := tx.Groups().Get(w.ctx, domain.GroupID(originalGroup))
	require.NoError(t, err)
	g.Name = "renamed-before-retirement"
	_, err = tx.GroupsW().Update(w.ctx, g, []string{"name"})
	require.NoError(t, err)
	require.NoError(t, tx.Commit(w.ctx))
	require.NoError(t, kanamepg.NewModuleSeedWriteRepo(w.pool).RunInWriteTx(w.ctx, func(ctx context.Context, writer moduleseed.Writer) error {
		if _, e := writer.UpsertGroup(ctx, "system", "module-relation-writers", "Module service accounts allowed to write relation tuples through iam (issue #914)"); e != nil {
			return e
		}
		_, e := writer.GrantRelation(ctx, moduleseed.Subject{Kind: "group", Account: "system", Name: "module-relation-writers"}, "fga_writer", "cluster", cluster)
		return e
	}))
	before := w.snapshot()
	p := w.plan
	p.RetireClusterWriter = true
	err = w.apply(p)
	require.Error(t, err)
	require.Contains(t, err.Error(), "seed namespace was recreated")
	require.Equal(t, before, w.snapshot())
	var retired bool
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT cluster_writer_retired_at IS NOT NULL FROM kaname.registration_account_writer_switch WHERE singleton`).Scan(&retired))
	require.False(t, retired, "refusal must not report retirement complete")
}
