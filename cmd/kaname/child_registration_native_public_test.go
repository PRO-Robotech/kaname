// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/schemaguard"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	"github.com/PRO-Robotech/kaname/internal/testsupport/installruntime"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gopkg.in/yaml.v3"
)

// Отдельно включаемый исходный кандидат приёмки. Skip не является доказательством
// #1045: запуск требует зафиксированных native binary/migrator и отдельного
// evidence root действующего installation harness. Подмена principal запрещена.
func TestChildRegistrationNativePublicRESTAndGRPC(t *testing.T) {
	if testing.Short() || os.Getenv("KANAME_CHILD_PUBLIC_ACCEPTANCE") != "1" {
		t.Skip("child registration requires an explicit native stand")
	}
	delivery := childNativePublicDelivery(t)
	f := newInstallationNativeWorldProfile(t, 7200, "", true)
	// Второй человек — тот же начальный Given церемонии до FULL. Права
	// не сеются: read-only привязку ниже выдаёт обычный публичный API.
	readerGiven := &ceremonyWorld{t: t, id: "CHILD-PUBLIC-READER", ctx: f.given.ctx, pool: f.given.pool, logs: &lockedBuffer{}}
	readerGiven.seedPerson()
	readerGiven.markPerson()
	readerGiven.session = readerGiven.seedSession("2")
	f.secrets = append(f.secrets, readerGiven.session.bearer.CookieValue())
	plan := installruntime.RegistryRegistrationWriterPlan([]string{f.tenantID})
	input := installruntime.DeliveryInput{RegistrationWriters: plan, Manifests: delivery, CredentialFile: f.creator.CredentialFile}
	process := f.apply(t, input)
	rid09AwaitBaseRoleProjections(t, f.given.ctx, process)
	startChildNativeFull(t, f, process, input)
	// Bearer действительно выдан ceremony после FULL запуска и принят /me.
	f.renewOperator(t, f.given.ctx)
	reader, err := f.wire.ExchangeOperator(f.given.ctx, installruntime.OperatorGiven{
		UserID: string(readerGiven.user), SessionBearer: readerGiven.session.bearer.CookieValue(),
		ClientID: f.given.ic1.rec.ClientID, ClientSecret: f.given.ic1.secret, RedirectURI: lineA1R,
	})
	require.NoError(t, err)
	f.secrets = append(f.secrets, reader.Bearer())
	require.NotEqual(t, f.operator.UserID(), reader.UserID())
	requireNativeAuthority(t, f.given, "user", reader.UserID(), 0)
	scenes := []nativeRegisteredChild{{parent: "public-parent"}, {parent: "other-parent"}}
	moduleConn, err := f.wire.ModuleWriter(filepath.Join(f.session.Root, "pki"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = moduleConn.Close() })
	module := iamv1.NewInternalIAMServiceClient(moduleConn)
	var targetParents []map[string]any
	var parentIDs []string
	for i := range scenes {
		scene := &scenes[i]
		scene.project = ridResponseID(t, f.ridOperation(t, http.MethodPost, "/iam/v1/projects", f.operator.Bearer(),
			map[string]any{"accountId": f.tenantID, "name": "project-" + scene.parent}, 0))
		scene.child = scene.parent + "/candidate"
		_, err = module.RegisterResource(f.given.ctx, &iamv1.RegisterResourceRequest{
			SubjectId: "project:" + scene.project, Relation: "project", Object: "registry_child_probe_container:" + scene.parent,
			ParentProjectId: scene.project, ParentAccountId: f.tenantID,
			ParentChain: []string{"project:" + scene.project, "account:" + f.tenantID}, SourceVersion: timestamppb.Now(),
		})
		require.NoError(t, err)
		parentIDs = append(parentIDs, scene.parent)
		targetParents = append(targetParents, map[string]any{"type": "registry.childProbeContainers", "id": scene.parent})
	}
	require.NotEqual(t, scenes[0].project, scenes[1].project)
	var roleID, readerRoleID string
	for _, raw := range f.ridList(t, "/iam/v1/roles", "roles", nil) {
		var role iamv1.Role
		require.NoError(t, protojson.Unmarshal(raw, &role))
		if role.Name == "registry.child_public_reader" {
			require.Empty(t, readerRoleID)
			readerRoleID = role.Id
		}
		if role.Name == "registry.child_public_registrar" {
			require.Empty(t, roleID)
			roleID = role.Id
		}
	}
	require.NotEmpty(t, roleID)
	require.NotEmpty(t, readerRoleID)
	binding := ridResponseID(t, f.ridOperation(t, http.MethodPost, "/iam/v1/accessBindings", f.operator.Bearer(), map[string]any{
		"subjectType": "user", "subjectId": f.operator.UserID(), "roleId": roleID,
		"scopeType": "iam.account", "scopeId": f.tenantID,
		"target": map[string]any{"resources": map[string]any{"resources": targetParents}},
	}, 0))
	// Ждём факт именно этой привязки. Проверка Check для cluster admin
	// может дать доступ и без материализации нового правила.
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		ctx, cancel := context.WithTimeout(f.given.ctx, time.Second)
		defer cancel()
		var materialized int
		require.NoError(c, f.given.pool.QueryRow(ctx, `SELECT count(DISTINCT f.object_id)
 FROM kaname.access_binding_emitted_tuples e
 JOIN kaname.relation_fact f ON f.object_type='registry_child_probe_container'
 AND f.object_id=ANY($2::text[]) AND f.relation=e.relation AND f.subject=e.fga_user
 WHERE e.binding_id=$1 AND e.fga_user=$3 AND e.relation='child_registrar'
 AND e.object='registry_child_probe_container:'||f.object_id AND e.source='member'`,
			binding, parentIDs, "user:"+f.operator.UserID()).Scan(&materialized))
		require.Equal(c, len(scenes), materialized, "штатные факты обоих родителей должны принадлежать этой привязке")
	}, 30*time.Second, 50*time.Millisecond)
	for i := range scenes {
		scene := &scenes[i]
		var response json.RawMessage
		code, err := f.wire.JSON(f.given.ctx, http.MethodPost, "/iam/v1/childRegistrations:register", f.operator.Bearer(),
			map[string]any{"resourceType": "registry.childProbeChildren", "resourceId": scene.child}, &response)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
		var created iamv1.RegisterChildResponse
		require.NoError(t, protojson.Unmarshal(response, &created))
		require.NotNil(t, created.GetVersion())
		require.NoError(t, created.GetVersion().CheckValid())
		scene.version = created.GetVersion().AsTime()
		requireNativeRegisteredChild(t, f, *scene)
	}

	first, other := scenes[0], scenes[1]
	for _, extra := range []map[string]any{
		{"parentId": other.parent},
		{"parentChain": []string{"registry_child_probe_container:" + other.parent, "project:" + other.project, "account:" + f.tenantID}},
	} {
		extra["resourceType"], extra["resourceId"] = "registry.childProbeChildren", first.child
		var response json.RawMessage
		code, err := f.wire.JSON(f.given.ctx, http.MethodPost, "/iam/v1/childRegistrations:register", f.operator.Bearer(), extra, &response)
		require.NoError(t, err)
		require.Equal(t, http.StatusForbidden, code)
		require.JSONEq(t, `{"code":7,"message":"permission denied","details":[]}`, string(response))
		for _, scene := range scenes {
			requireNativeRegisteredChild(t, f, scene)
		}
	}

	// Прямой публичный gRPC предъявляет только настоящий bearer.
	publicConn := childNativePublicGRPC(t, filepath.Join(f.session.Root, "pki"))
	ctx := metadata.AppendToOutgoingContext(f.given.ctx, "authorization", "Bearer "+f.operator.Bearer())
	replayed, err := iamv1.NewChildRegistrationServiceClient(publicConn).Register(ctx,
		&iamv1.RegisterChildRequest{ResourceType: "registry.childProbeChildren", ResourceId: first.child})
	require.NoError(t, err)
	require.True(t, first.version.Equal(replayed.GetVersion().AsTime()))
	requireNativeRegisteredChild(t, f, first)
	requireNativeChildReadOnlyDenials(t, f, reader, readerRoleID, scenes)
}

// 02/04 проверяют право чтения конкретного родителя через публичную авторизацию.
// У синтетического модуля нет предметного Get; ответ Check не выдаётся за чтение.
func requireNativeChildReadOnlyDenials(t *testing.T, f *installationNativeWorld, reader *installruntime.VerifiedOperator, role string, scenes []nativeRegisteredChild) {
	t.Helper()
	parent := scenes[0].parent
	check := func(c require.TestingT, relation string) bool {
		var raw json.RawMessage
		ctx, cancel := context.WithTimeout(f.given.ctx, time.Second)
		defer cancel()
		code, err := f.wire.JSON(ctx, http.MethodPost, "/iam/v1/authorize:check", reader.Bearer(), map[string]any{
			"subject":  "user:" + reader.UserID(),
			"resource": map[string]any{"type": "registry_child_probe_container", "id": parent},
			"action":   "registry.childProbeContainers.get", "requiredRelation": relation,
		}, &raw)
		require.NoError(c, err)
		require.Equal(c, http.StatusOK, code)
		var response iamv1.AuthorizeCheckResponse
		require.NoError(c, protojson.Unmarshal(raw, &response))
		return response.Allowed
	}
	require.False(t, check(t, ""), "до привязки у отдельного человека нет права чтения этого родителя")
	binding := ridResponseID(t, f.ridOperation(t, http.MethodPost, "/iam/v1/accessBindings", f.operator.Bearer(), map[string]any{
		"subjectType": "user", "subjectId": reader.UserID(), "roleId": role,
		"scopeType": "iam.account", "scopeId": f.tenantID,
		"target": map[string]any{"resources": map[string]any{"resources": []map[string]any{
			{"type": "registry.childProbeContainers", "id": parent},
		}}},
	}, 0))
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		var materialized int
		require.NoError(c, f.given.pool.QueryRow(f.given.ctx, `SELECT count(*)
 FROM kaname.access_binding_emitted_tuples e JOIN kaname.relation_fact f
 ON f.object_type='registry_child_probe_container' AND f.object_id=$2
 AND f.relation=e.relation AND f.subject=e.fga_user
 WHERE e.binding_id=$1 AND e.fga_user=$3 AND e.relation='v_get'
 AND e.object='registry_child_probe_container:'||$2 AND e.source='member'`,
			binding, parent, "user:"+reader.UserID()).Scan(&materialized))
		require.Positive(c, materialized, "право чтения материализовано именно публичной привязкой")
		require.True(c, check(c, ""), "настоящий bearer получает get именно родителя")
	}, 30*time.Second, 50*time.Millisecond)
	require.False(t, check(t, "child_registrar"), "read-only не даёт отдельного глагола создания")
	requireNativeAuthority(t, f.given, "user", reader.UserID(), 0)

	candidates := []string{scenes[0].child, parent + "/reader-denied", "missing-parent/reader-denied"}
	var missing int
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT count(*) FROM kaname.resource_mirror
 WHERE object_type='registry.childProbeContainers' AND object_id='missing-parent'`).Scan(&missing))
	require.Zero(t, missing)
	// Не сравниваем изменяемые статусы фоновых очередей. Неизменяемые receipts
	// фиксируют весь расход успешных созданий, включая оба законных близнеца.
	receipts := func() string {
		var raw []byte
		require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY child_id,source_version),'[]')
 FROM kaname.authority_child_creation c WHERE child_type='registry.childProbeChildren'`).Scan(&raw))
		return string(raw)
	}
	before := receipts()
	for _, child := range candidates {
		var response json.RawMessage
		code, err := f.wire.JSON(f.given.ctx, http.MethodPost, "/iam/v1/childRegistrations:register", reader.Bearer(),
			map[string]any{"resourceType": "registry.childProbeChildren", "resourceId": child}, &response)
		require.NoError(t, err)
		require.Equal(t, http.StatusForbidden, code)
		require.JSONEq(t, `{"code":7,"message":"permission denied","details":[]}`, string(response))
		if child != scenes[0].child {
			var effects int
			require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT
 (SELECT count(*) FROM kaname.resource_mirror WHERE object_type='registry.childProbeChildren' AND object_id=$1)+
 (SELECT count(*) FROM kaname.resource_parent_edge WHERE object_type='registry_child_probe_child' AND object_id=$1)+
 (SELECT count(*) FROM kaname.resource_registration_scope WHERE object_type='registry_child_probe_child' AND object_id=$1)+
 (SELECT count(*) FROM kaname.relation_fact WHERE object_type='registry_child_probe_child' AND object_id=$1)+
 (SELECT count(*) FROM kaname.authority_child_creation WHERE child_type='registry.childProbeChildren' AND child_id=$1)+
 (SELECT count(*) FROM kaname.fga_outbox WHERE payload->>'object'='registry_child_probe_child:'||$1)+
 (SELECT count(*) FROM kaname.resource_reconcile_outbox WHERE object_type='registry.childProbeChildren' AND object_id=$1)+
 (SELECT count(*) FROM kaname.audit_outbox WHERE event_payload#>>'{object,id}'=$1)`, child).Scan(&effects))
			require.Zero(t, effects, "отказ не создаёт регистрацию, версию, отношения или успешные эффекты")
		}
		require.JSONEq(t, before, receipts(), "отказ не расходует успешные создания")
		for _, scene := range scenes {
			requireNativeRegisteredChild(t, f, scene)
		}
	}
	var denials int
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT count(*) FROM kaname.audit_outbox
 WHERE event_type='iam.child_registration.refused' AND event_payload=$1::jsonb`,
		`{"actor":"user:`+reader.UserID()+`","outcome":"permission_denied","reason":"permission_denied"}`).Scan(&denials))
	require.Equal(t, len(candidates), denials, "все запросы отвергнуты проверкой права без раскрытия координат")
}

type nativeRegisteredChild struct {
	parent, project, child string
	version                time.Time
}

func requireNativeRegisteredChild(t *testing.T, f *installationNativeWorld, scene nativeRegisteredChild) {
	t.Helper()
	childID, parentID, project := scene.child, scene.parent, scene.project
	var version time.Time
	var account, actualProject, actor string
	var chain []string
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT source_version,parent_account_id,parent_project_id,
 (SELECT array_agg(parent_type||':'||parent_id ORDER BY depth) FROM kaname.resource_parent_edge
 WHERE object_type='registry_child_probe_child' AND object_id=$1)
 FROM kaname.resource_mirror WHERE object_type='registry.childProbeChildren' AND object_id=$1`, childID).
		Scan(&version, &account, &actualProject, &chain))
	require.True(t, version.Equal(scene.version))
	require.Equal(t, f.tenantID, account)
	require.Equal(t, project, actualProject)
	require.Equal(t, []string{"registry_child_probe_container:" + parentID, "project:" + project, "account:" + f.tenantID}, chain)
	var scopes, expectedScopes, facts, expectedFacts, receipts, audits int
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT
 (SELECT count(*) FROM kaname.resource_registration_scope WHERE object_type='registry_child_probe_child' AND object_id=$1),
 (SELECT count(*) FROM kaname.resource_registration_scope WHERE object_type='registry_child_probe_child' AND object_id=$1 AND account_id=$2 AND project_id=$3),
 (SELECT count(*) FROM kaname.relation_fact WHERE object_type='registry_child_probe_child' AND object_id=$1),
 (SELECT count(*) FROM kaname.relation_fact WHERE object_type='registry_child_probe_child' AND object_id=$1 AND relation='parent' AND subject=$4 AND source_version=$5),
 (SELECT count(*) FROM kaname.authority_child_creation WHERE child_type='registry.childProbeChildren' AND child_id=$1 AND user_id=$6 AND source_version=$5),
 (SELECT count(*) FROM kaname.audit_outbox WHERE event_payload#>>'{object,id}'=$1),
 (SELECT event_payload->>'actor' FROM kaname.audit_outbox WHERE event_payload#>>'{object,id}'=$1 LIMIT 1)`,
		childID, f.tenantID, project, "registry_child_probe_container:"+parentID, version, f.operator.UserID()).
		Scan(&scopes, &expectedScopes, &facts, &expectedFacts, &receipts, &audits, &actor))
	require.Equal(t, 1, scopes)
	require.Equal(t, 1, expectedScopes)
	require.Equal(t, 1, facts)
	require.Equal(t, 1, expectedFacts)
	require.Equal(t, 1, receipts)
	require.Equal(t, 1, audits)
	require.Equal(t, "user:"+f.operator.UserID(), actor)
}

// Начальный запуск доставляет каталог. Отдельный операторский переход
// активирует его на той же базе до запуска службы под ограниченным LOGIN.
func startChildNativeFull(t *testing.T, f *installationNativeWorld, staged *installruntime.Process, input installruntime.DeliveryInput) {
	t.Helper()
	var config struct {
		Manifests struct {
			Dir string `yaml:"dir"`
		} `yaml:"manifests"`
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(staged.StdoutPath), "..", "config.yaml"))
	require.NoError(t, err)
	require.NoError(t, yaml.Unmarshal(raw, &config))
	require.True(t, filepath.IsAbs(config.Manifests.Dir))
	require.Equal(t, f.session.Root, filepath.Dir(config.Manifests.Dir))

	ctx, cancel := context.WithTimeout(f.given.ctx, 20*time.Second)
	err = f.session.Stop(ctx)
	cancel()
	require.NoError(t, err)

	runtimePool := fullStartupRuntimePool(t, f.given.ctx, f.given.pool)
	runtime := runtimePool.Config().ConnConfig
	f.secrets = append(f.secrets, runtime.Password)
	// Воспроизводим права оператора из штатного rollout на том же LOGIN.
	owner := f.given.pool.Config().ConnConfig
	// #nosec G204 -- используется локальный psql и штатный SQL из точного чекаута.
	grant := exec.CommandContext(f.given.ctx, "psql", "-X", "--no-password",
		"--set=runtime_role="+runtime.User, "--set=migration_role="+owner.User,
		"--file="+filepath.Join(f.stand.Root, "deploy", "sql", "authority-runtime-role.sql"))
	grant.Env = []string{
		"PGHOST=" + owner.Host, "PGPORT=" + strconv.Itoa(int(owner.Port)),
		"PGDATABASE=" + owner.Database, "PGUSER=" + owner.User,
		"PGPASSWORD=" + owner.Password, "PGSSLMODE=require",
	}
	grantOut, err := grant.CombinedOutput()
	require.NoError(t, os.WriteFile(filepath.Join(f.session.Root, "native-runtime-grants.log"), grantOut, 0600))
	require.NoError(t, err, "штатная настройка ограниченного LOGIN, см. закрытый журнал стенда")
	require.NoError(t, schemaguard.CheckFromFS(migrations.FS, schemaguard.PgxVersionReader(runtimePool))(f.given.ctx),
		"runtime LOGIN должен читать применённую версию")
	var journalReadAll, journalWrite bool
	require.NoError(t, runtimePool.QueryRow(f.given.ctx, `SELECT
 has_table_privilege(current_user,'goose_db_version','SELECT'),
 has_table_privilege(current_user,'goose_db_version','INSERT,UPDATE,DELETE,TRUNCATE')`).
		Scan(&journalReadAll, &journalWrite))
	require.False(t, journalReadAll)
	require.False(t, journalWrite)
	t.Cleanup(func() {
		stop, close := context.WithTimeout(context.Background(), 20*time.Second)
		defer close()
		require.NoError(t, f.session.Stop(stop))
	})
	ownerEnv, err := f.stand.Environment(nil)
	require.NoError(t, err)
	binary := os.Getenv("KANAME_RID_MIGRATOR")
	require.True(t, filepath.IsAbs(binary))
	for _, action := range []string{"stage-full", "activate-full", "verify-full"} {
		// #nosec G204 -- путь артефакта и каталог созданы стендом, команды перечислены явно.
		cmd := exec.CommandContext(f.given.ctx, binary, "authority-bundle", action, "--manifest-dir", config.Manifests.Dir)
		cmd.Dir = f.session.Root
		cmd.Env = append(append([]string{}, ownerEnv...), "KANAME_CONFIG_PATH="+filepath.Join(f.session.Root, "migrator.yaml"))
		out, err := cmd.CombinedOutput()
		require.NoError(t, os.WriteFile(filepath.Join(f.session.Root, "native-"+action+".log"), out, 0600))
		require.NoError(t, err, "операторский переход %s, см. закрытый журнал стенда", action)
	}

	for i, entry := range f.session.Environment {
		name, _, _ := strings.Cut(entry, "=")
		switch name {
		case "KANAME_DB_USER":
			f.session.Environment[i] = name + "=" + runtime.User
		case "KANAME_DB_PASSWORD":
			f.session.Environment[i] = name + "=" + runtime.Password
		}
	}
	input.ExtraConfig = map[string]any{"authority-protocol": map[string]any{
		"participation":  "participant",
		"full-semantics": true,
	}}
	process := f.apply(t, input)
	rid09AwaitBaseRoleProjections(t, f.given.ctx, process)
}

// Сохраняем существующий независимый registry fixture и добавляем только
// пробные типы/роль. Реальная служба svc-registry этому миру не требуется.
func childNativePublicDelivery(t *testing.T) installruntime.RIDDeliveryFixture {
	t.Helper()
	delivery := ridLifecycleDelivery(t, false)
	var doc, extra map[string]any
	require.NoError(t, yaml.Unmarshal(delivery.First, &doc))
	require.NoError(t, yaml.Unmarshal([]byte(`resources:
  - name: childProbeContainers
    objectType: registry_child_probe_container
    parents: [project]
    producer: authored
    verbs: [get]
    relations:
      - {name: child_registrar, definition: "[user]"}
  - name: childProbeChildren
    objectType: registry_child_probe_child
    parents:
      - {name: parent, type: registry_child_probe_container}
    producer: authored
    verbs: [get]
    containerVerbs:
      - {name: registerChild, parent: parent, relation: child_registrar}
    childRegistration:
      verb: registerChild
      parentSegments: 1
      maxChildren: 4
      maxCreates: 4
      windowSeconds: 60
roles:
  - id: registry.child_public_reader
    description: Read-only parent permission without child registration
    tier: {tierType: iam.cluster, tierId: cluster_root}
    rules:
      - module: registry
        resources: [childProbeContainers]
        classes: [get]
  - id: registry.child_public_registrar
    description: Independent public child registration probe
    tier: {tierType: iam.cluster, tierId: cluster_root}
    rules:
      - module: registry
        resources: [childProbeContainers]
        classes: [get]
        children:
          - resources: [childProbeChildren]
            classes: [registerChild]
`), &extra))
	for _, key := range []string{"resources", "roles"} {
		base, ok := doc[key].([]any)
		require.True(t, ok)
		added, ok := extra[key].([]any)
		require.True(t, ok)
		doc[key] = append(base, added...)
	}
	var err error
	delivery.First, err = yaml.Marshal(doc)
	require.NoError(t, err)
	_, err = manifest.Load(delivery.First)
	require.NoError(t, err)
	return delivery
}

func childNativePublicGRPC(t *testing.T, pki string) *grpc.ClientConn {
	t.Helper()
	ca, err := os.ReadFile(filepath.Join(pki, "ca.crt"))
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(ca))
	leaf, err := tls.LoadX509KeyPair(filepath.Join(pki, "srv.crt"), filepath.Join(pki, "srv.key"))
	require.NoError(t, err)
	conn, err := grpc.NewClient("localhost:9090", grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		RootCAs: roots, Certificates: []tls.Certificate{leaf}, ServerName: "localhost", MinVersion: tls.VersionTLS12,
	})))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}
