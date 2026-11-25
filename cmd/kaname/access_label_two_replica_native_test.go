// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/bindingset"
	"github.com/PRO-Robotech/kaname/internal/testsupport/installruntime"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// Два процесса Kaname используют одну подготовленную модель полномочий gen1.
// Владелец миграций задаёт тестовые определения меток и исходный допуск apply.
// Записи меток и все решения проверяются через штатный TLS API.
func TestAccessLabelsTwoNativeReplicas(t *testing.T) {
	if os.Getenv("KANAME_ACCESS_LABEL_REPLICA_ACCEPTANCE") != "1" {
		t.Skip("NOT_EXECUTED: requires an explicitly leased native access-label acceptance job and KANAME_RID_* frozen artifacts")
	}
	f := newInstallationNativeWorldConfigured(t, 7200, "", false, false, nativeWorldOptions{boundedPostgres: true})
	ctx := f.given.ctx
	reader := &ceremonyWorld{t: t, id: "ACCESS-LABEL-NATIVE-READER", ctx: ctx, pool: f.given.pool, logs: &lockedBuffer{}, clientAudiences: []string{"https://kaname.local"}}
	reader.seedPerson()
	reader.markPerson()
	reader.session = reader.seedSession("2")
	reader.ic1 = reader.seedClient("access-label-native-reader", domain.InteractiveClientActive, []string{lineA1R})
	credential, err := f.wire.ExchangeOperator(ctx, installruntime.OperatorGiven{UserID: string(reader.user), SessionBearer: reader.session.bearer.CookieValue(), ClientID: reader.ic1.rec.ClientID, ClientSecret: reader.ic1.secret, RedirectURI: lineA1R})
	require.NoError(t, err)
	f.secrets = append(f.secrets, reader.session.bearer.CookieValue(), reader.ic1.secret, credential.Bearer())
	require.NotEqual(t, string(f.given.user), string(reader.user))
	requireNativeAuthority(t, reader, "user", string(reader.user), 0)
	stop, cancel := context.WithTimeout(ctx, 20*time.Second)
	require.NoError(t, f.session.Stop(stop))
	cancel()
	// Первый процесс работает до подготовки модели gen1. Останавливаем его до
	// исходной настройки полномочий, чтобы он не увидел промежуточную схему.
	seedNativeAccessLabelApplySource(t, f)
	before, headBefore := nativeAccessLabelMigrationRows(t, f)
	connectionA := provisionNativeRuntime(t, f, filepath.Join(f.session.Root, "writer-a-runtime-grants.log"))
	nativeAccessLabelBootstrap(t, f, connectionA.User)
	// Подключаем второй LOGIN к той же подготовленной модели.
	connectionB := provisionNativeRuntime(t, f, filepath.Join(f.session.Root, "reader-b-runtime-grants.log"))
	require.NotEqual(t, connectionA.User, connectionB.User)
	replicas := []*nativeAccessLabelReplica{
		startNativeAccessLabelReplica(t, f, "writer-a", installruntime.DefaultNativePorts(), connectionA, nil),
		startNativeAccessLabelReplica(t, f, "reader-b", installruntime.SecondNativePorts(), connectionB, nil),
	}
	require.NotEqual(t, replicas[0].pid, replicas[1].pid)
	continuing := func() {
		for _, r := range replicas {
			r.assertContinuing(t)
		}
	}
	continuing()
	a, b := replicas[0].wire, replicas[1].wire
	root := f.tenantID
	mutation := func(stage, method, path string, body any) installruntime.Operation {
		t.Helper()
		var op installruntime.Operation
		code, e := a.JSON(ctx, method, path, f.operator.Bearer(), body, &op)
		require.NoError(t, e)
		require.Equal(t, http.StatusOK, code)
		op, e = a.AwaitOperation(ctx, f.operator.Bearer(), op)
		if e != nil && op.Error != nil {
			recordNativeAccessLabelMutationFailure(t, f, stage, op.ID)
		}
		require.NoError(t, e, "этап %s", stage)
		require.True(t, op.Done)
		require.Nil(t, op.Error)
		continuing()
		return op
	}
	mutation("initial-labels", http.MethodPatch, "/iam/v1/accounts/"+url.PathEscape(root), map[string]any{
		"accountId": root, "accessLabels": map[string]string{"team": "before", "keep": "yes"}, "updateMask": "accessLabels",
	})
	makeBinding := func(name, key, value string) string {
		t.Helper()
		op := mutation("create-selector-role", http.MethodPost, "/iam/v1/roles", map[string]any{
			"name": name, "definitionTier": map[string]string{"tierType": "iam.account", "tierId": root},
			"rules": []any{map[string]any{"module": "iam", "resources": []string{"account"}, "verbs": []string{"get"}, "matchAccessLabels": map[string]string{key: value}}},
		})
		var role struct {
			ID string `json:"roleId"`
		}
		require.NoError(t, json.Unmarshal(op.Metadata, &role))
		require.NotEmpty(t, role.ID)
		op = mutation("create-selector-binding", http.MethodPost, "/iam/v1/accessBindings", map[string]any{
			"subjects": []any{map[string]string{"type": "SUBJECT_TYPE_USER", "id": string(reader.user)}},
			"roleId":   role.ID, "scopeType": "iam.account", "scopeId": root,
			"target": map[string]any{"resources": map[string]any{"resources": []any{map[string]string{"type": "iam.account", "id": root}}}},
		})
		var binding struct {
			ID string `json:"accessBindingId"`
		}
		require.NoError(t, json.Unmarshal(op.Metadata, &binding))
		require.NotEmpty(t, binding.ID)
		return binding.ID
	}
	losing := makeBinding("replica_old_reader", "team", "before")
	keeping := makeBinding("replica_keep_reader", "keep", "yes")
	require.NotEqual(t, losing, keeping)
	// До первого чтения на втором экземпляре проверяем обе материализованные
	// привязки и обоих держателей выдачи.
	var members, holders int
	require.Eventually(t, func() bool {
		e := f.given.pool.QueryRow(ctx, `SELECT
   (SELECT count(DISTINCT binding_id) FROM kaname.access_binding_target_members
    WHERE binding_id=ANY($1::text[]) AND object_type='iam.account' AND object_id=$2 AND verification_status='ACTIVE'),
   (SELECT count(DISTINCT binding_id) FROM kaname.access_binding_emitted_tuples
    WHERE binding_id=ANY($1::text[]) AND member_object_type='iam.account' AND member_object_id=$2
      AND fga_user=$3 AND relation='v_get' AND object='account:'||$2)`, []string{losing, keeping}, root, "user:"+string(reader.user)).Scan(&members, &holders)
		return e == nil && members == 2 && holders == 2
	}, 45*time.Second, 50*time.Millisecond)
	sequence := runAccessLabelTwoReplicaSequence(t, ctx, a, b, f.given.pool, f.operator.Bearer(), credential.Bearer(), root, string(reader.user), losing, keeping, continuing)
	sequence.Baseline.ActiveMembers, sequence.Baseline.LedgerHolders = members, holders
	after, headAfter := nativeAccessLabelMigrationRows(t, f)
	require.Equal(t, headBefore, headAfter)
	require.Equal(t, before, after, "no migration ledger write during setup/bootstrap/observations")
	observations := nativeAccessLabelObservations{
		SchemaVersion: 1, Scenario: "access-label-two-replicas", BinarySHA256: f.session.BinarySHA256,
		MigratorSHA256:      nativeAccessLabelDigest(t, os.Getenv("KANAME_RID_MIGRATOR")),
		MigrationHeadBefore: headBefore, MigrationHeadAfter: headAfter, MigrationRowsUnchanged: true,
		Baseline: sequence.Baseline, Retained: sequence.Retained, Pending: sequence.Pending,
	}
	for _, r := range replicas {
		observations.Replicas = append(observations.Replicas, r.observation(t))
	}
	raw, err := json.MarshalIndent(observations, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(f.session.Root, "access-label-two-replica-observations.json"), append(raw, '\n'), 0600))
	// Process.Stop записывает состояние завершения через t.Cleanup. Проверяющий
	// скрипт принимает наблюдение только после успешной уборки.
}

// Сохраняем подробности отказа отдельно от закрытой сводки приёмки. Источник
// журнала привязан к PostgreSQL, который создал этот тест.
func recordNativeAccessLabelMutationFailure(t *testing.T, f *installationNativeWorld, stage, operationID string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(f.given.ctx), 5*time.Second)
	defer cancel()
	failure := struct {
		Stage   string `json:"stage"`
		Code    int    `json:"code"`
		Message string `json:"message"`
	}{Stage: stage}
	err := f.given.pool.QueryRow(ctx, `SELECT error_code,left(error_message,4096)
 FROM kaname.operations WHERE id=$1 AND done AND error_code IS NOT NULL`, operationID).Scan(&failure.Code, &failure.Message)
	if err == nil {
		raw, _ := json.Marshal(failure)
		if err := os.WriteFile(filepath.Join(f.session.Root, "access-label-operation-failure.json"), raw, 0600); err != nil {
			t.Log("не удалось сохранить подробности отказа операции")
		}
	}
	var pg struct {
		ContainerID string `json:"containerId"`
	}
	ownership, err := os.ReadFile(filepath.Join(f.session.Root, "pg-ownership.json"))
	if err != nil || json.Unmarshal(ownership, &pg) != nil || len(pg.ContainerID) != 64 {
		return
	}
	if _, err := hex.DecodeString(pg.ContainerID); err != nil {
		return
	}
	log, err := os.OpenFile(filepath.Join(f.session.Root, "access-label-postgres-failure.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer log.Close()
	// #nosec G204 -- идентификатор созданного тестом контейнера проверен выше.
	command := exec.CommandContext(ctx, "docker", "logs", "--tail", "120", pg.ContainerID)
	command.Stdout, command.Stderr = log, log
	if err := command.Run(); err != nil {
		t.Log("не удалось прочитать журнал PostgreSQL тестового стенда")
	}
}

type nativeAccessLabelReplicaObservation struct {
	Name              string `json:"name"`
	PID               int    `json:"pid"`
	BinarySHA256      string `json:"binary_sha256"`
	ConfigSHA256      string `json:"config_sha256"`
	Ports             []int  `json:"ports"`
	SameCgroup        bool   `json:"same_cgroup"`
	IdentityUnchanged bool   `json:"identity_unchanged"`
	ListenersOwned    bool   `json:"listeners_owned"`
}
type nativeAccessLabelObservations struct {
	SchemaVersion          int                                   `json:"schema_version"`
	Scenario               string                                `json:"scenario"`
	BinarySHA256           string                                `json:"binary_sha256"`
	MigratorSHA256         string                                `json:"migrator_sha256"`
	MigrationHeadBefore    int64                                 `json:"migration_head_before"`
	MigrationHeadAfter     int64                                 `json:"migration_head_after"`
	Replicas               []nativeAccessLabelReplicaObservation `json:"replicas"`
	Baseline               nativeAccessLabelBaseline             `json:"baseline"`
	Retained               nativeAccessLabelRetained             `json:"retained"`
	Pending                nativeAccessLabelPending              `json:"pending"`
	MigrationRowsUnchanged bool                                  `json:"migration_rows_unchanged"`
}
type nativeAccessLabelReplica struct {
	name         string
	wire         *installruntime.Wire
	process      *installruntime.Process
	ports        installruntime.NativePorts
	identity     []byte
	identityPath string
	pid          int
}

func (r *nativeAccessLabelReplica) assertContinuing(t *testing.T) {
	t.Helper()
	raw, err := os.ReadFile(r.identityPath)
	require.NoError(t, err)
	require.Equal(t, r.identity, raw, "same PID/executable/config receipt")
	require.NoError(t, r.process.OwnsListeners(r.ports.All()...))
	parentGroup, err := os.ReadFile("/proc/self/cgroup")
	require.NoError(t, err)
	childGroup, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", r.pid))
	require.NoError(t, err)
	require.Equal(t, parentGroup, childGroup)
}
func (r *nativeAccessLabelReplica) observation(t *testing.T) nativeAccessLabelReplicaObservation {
	t.Helper()
	r.assertContinuing(t)
	return nativeAccessLabelReplicaObservation{Name: r.name, PID: r.pid, BinarySHA256: r.process.BinarySHA256, ConfigSHA256: r.process.ConfigSHA256, Ports: r.ports.All(), SameCgroup: true, IdentityUnchanged: true, ListenersOwned: true}
}
func startNativeAccessLabelReplica(t *testing.T, f *installationNativeWorld, name string, ports installruntime.NativePorts, connection, executor *pgx.ConnConfig) *nativeAccessLabelReplica {
	t.Helper()
	values, err := ports.EnvironmentOverrides()
	require.NoError(t, err)
	values["KANAME_REPOSITORY__POSTGRES__URL"] = (&url.URL{Scheme: "postgres", User: url.User(connection.User), Host: "127.0.0.1:" + f.stand.PGPort, Path: "/kaname", RawQuery: "sslmode=require&application_name=" + name}).String()
	values["KANAME_DB_PASSWORD"] = connection.Password
	values["KANAME_REPOSITORY__POSTGRES__REPLICA_BUDGET"] = "2"
	doc := map[string]any{
		"authority-protocol": map[string]any{"participation": "participant", "full-semantics": executor != nil},
		"manifests":          map[string]any{"dir": "", "required": false},
	}
	if executor != nil {
		const passwordEnv = "USER_METADATA_TEST_DB_PASSWORD"
		values[passwordEnv] = executor.Password
		values["KANAME_REPOSITORY__POSTGRES__MAX_CONNS"] = "8"
		doc["repository"] = map[string]any{"postgres": map[string]any{"role-writer": map[string]any{
			"user": executor.User, "password-from-env": passwordEnv, "max-conns": 4,
		}}}
	}
	environment := nativeAccessLabelEnvironment(f.session.Environment, values, "KANAME_DB_HOST", "KANAME_DB_PORT", "KANAME_DB_USER", "KANAME_DB_NAME", "KANAME_BOOTSTRAP_ROOT_EMAIL")
	config, err := installruntime.FullStartupConfig(doc, f.writerPlan)
	require.NoError(t, err)
	root := filepath.Join(f.session.Root, name)
	require.NoError(t, os.Mkdir(root, 0700))
	configPath := filepath.Join(root, "config.yaml")
	require.NoError(t, os.WriteFile(configPath, config, 0600))
	ridRegistrationStartupProof(t, root, config, f.writerPlan)
	wire, err := installruntime.NewWireAtPorts(filepath.Join(f.session.Root, "pki"), ports)
	require.NoError(t, err)
	t.Cleanup(wire.Close)
	process, err := installruntime.Start(f.given.ctx, installruntime.Input{Binary: f.session.Binary, ExpectedBinarySHA256: f.session.BinarySHA256, ConfigFile: configPath, Environment: environment, EvidenceDir: filepath.Join(root, "process")})
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := process.Stop(ctx); err != nil {
			t.Errorf("native %s cleanup: %v", name, err)
		}
		if err := process.CheckSecretAbsence(f.secrets...); err != nil {
			t.Errorf("native %s secret check: %v", name, err)
		}
	})
	ready, cancel := context.WithTimeout(f.given.ctx, 90*time.Second)
	err = process.AwaitReady(ready, wire.ProductionReady)
	cancel()
	require.NoError(t, err, "participant must become ready on its own listener")
	path := filepath.Join(root, "process", "process.json")
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var identity struct {
		PID int `json:"pid"`
	}
	require.NoError(t, json.Unmarshal(raw, &identity))
	require.Positive(t, identity.PID)
	r := &nativeAccessLabelReplica{name: name, wire: wire, process: process, ports: ports, identity: raw, identityPath: path, pid: identity.PID}
	r.assertContinuing(t)
	return r
}
func nativeAccessLabelEnvironment(base []string, values map[string]string, remove ...string) []string {
	merged := map[string]string{}
	for _, entry := range base {
		key, value, _ := strings.Cut(entry, "=")
		merged[key] = value
	}
	for _, key := range remove {
		delete(merged, key)
	}
	for key, value := range values {
		merged[key] = value
	}
	out := make([]string, 0, len(merged))
	for key, value := range merged {
		out = append(out, key+"="+value)
	}
	sort.Strings(out)
	return out
}
func nativeAccessLabelDigest(t *testing.T, path string) string {
	t.Helper()
	require.True(t, filepath.IsAbs(path))
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func nativeAccessLabelMigrationRows(t *testing.T, f *installationNativeWorld) ([]byte, int64) {
	t.Helper()
	var rows []byte
	var head int64
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(v) ORDER BY id),'[]'::jsonb),COALESCE(max(version_id) FILTER (WHERE is_applied),0) FROM goose_db_version v`).Scan(&rows, &head))
	return rows, head
}
func nativeAccessLabelBootstrap(t *testing.T, f *installationNativeWorld, runtimeRole string) {
	t.Helper()
	path := filepath.Join(f.session.Root, "metadata-owner.yaml")
	require.NoError(t, os.WriteFile(path, []byte("{}\n"), 0600))
	env := nativeAccessLabelEnvironment(f.session.Environment, map[string]string{"KANAME_CONFIG_PATH": path})
	binary := os.Getenv("KANAME_RID_MIGRATOR")
	_ = nativeAccessLabelDigest(t, binary)
	log, err := os.OpenFile(filepath.Join(f.session.Root, "metadata-bootstrap.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(f.given.ctx, 45*time.Second)
	defer cancel()
	// #nosec G204 -- Зафиксированный тестовый бинарник и постоянная подкоманда, без shell.
	cmd := exec.CommandContext(ctx, binary, "authority-bundle", "bootstrap", "--image-only", "--runtime-role", runtimeRole)
	cmd.Dir, cmd.Env, cmd.Stdout, cmd.Stderr = f.session.Root, env, log, log
	err = cmd.Run()
	closeErr := log.Close()
	require.NoError(t, closeErr)
	require.NoError(t, err, "actual metadata bootstrap; see private metadata-bootstrap.log")
	var prepared bool
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT a.phase='prepared' AND p.enforcement='compatibility'
 AND c.required_contract=1 AND c.staged_contract=1
 FROM kaname.authority_semantic_identity a CROSS JOIN kaname.authority_writer_protocol p CROSS JOIN kaname.authority_writer_contract c
 WHERE a.singleton AND p.singleton AND c.singleton`).Scan(&prepared))
	require.True(t, prepared)
}

// Тестовые определения и полномочие apply создаются до handoff тем же
// способом, что в seedMetadataActualApplySource.
func seedNativeAccessLabelApplySource(t *testing.T, f *installationNativeWorld) {
	t.Helper()
	ctx := f.given.ctx
	var uninitialized bool
	require.NoError(t, f.given.pool.QueryRow(ctx, `SELECT a.phase='uninitialized' AND NOT EXISTS(SELECT 1 FROM kaname.authority_bundle_handoff)
 FROM kaname.authority_semantic_identity a WHERE singleton`).Scan(&uninitialized))
	require.True(t, uninitialized, "Given must precede the authority handoff")
	var definitions []string
	for _, d := range []struct {
		key    string
		values []string
	}{{"team", []string{"before", "after"}}, {"keep", []string{"yes", "no"}}} {
		var id string
		require.NoError(t, f.given.pool.QueryRow(ctx, `INSERT INTO kaname.authority_access_label_definition(scope_kind,scope_id,module,resource,label_key)
   VALUES('account',$1,'iam','account',$2) RETURNING id::text`, f.tenantID, d.key).Scan(&id))
		for _, value := range d.values {
			_, err := f.given.pool.Exec(ctx, `INSERT INTO kaname.authority_access_label_value(definition_id,label_value) VALUES($1::uuid,$2)`, id, value)
			require.NoError(t, err)
		}
		definitions = append(definitions, id)
	}
	_, bundle := fullStartupTestBundle(t, ctx, f.given.pool)
	source := domain.Role{ID: domain.RoleID(ids.NewID(domain.PrefixRole)), AccountID: domain.AccountID(f.tenantID), Name: "native_metadata_apply",
		Rules: domain.Rules{{Module: "iam", Resources: []string{"accessLabel"}, Verbs: []string{"apply"}, ResourceNames: definitions}}}
	ordinary, caps, err := domain.SplitGrantCapabilityRules(source.Rules)
	require.NoError(t, err)
	require.Len(t, caps, 2)
	source.Permissions, err = domain.CompileRules(ordinary)
	require.NoError(t, err)
	projection, err := bundle.Projection(source)
	require.NoError(t, err)
	seed, err := kanamepg.New(f.given.pool, nil).Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = seed.Rollback(context.WithoutCancel(ctx)) }()
	_, err = seed.RolesW().Insert(ctx, source)
	require.NoError(t, err)
	require.NoError(t, seed.RolesW().ReplaceRuleSelectors(ctx, source.ID, projection.Selectors))
	require.NoError(t, seed.RolesW().ReplaceRoleVerbs(ctx, source.ID, projection.Verbs))
	subject := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(f.given.user)}
	binding, err := bindingset.Insert(ctx, seed.AccessBindingsW(), domain.AccessBinding{
		ID: domain.AccessBindingID(ids.NewID("acb")), SubjectType: subject.Type, SubjectID: subject.ID, Subjects: []domain.Subject{subject},
		RoleID: source.ID, ResourceType: "account", ResourceID: f.tenantID, Scope: domain.DeriveFromResourceType("account"), Status: domain.AccessBindingStatusActive, Target: domain.AccessTarget{AllInScope: true},
	})
	require.NoError(t, err)
	require.NoError(t, seed.Commit(ctx))
	private, err := f.given.pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = private.Rollback(context.WithoutCancel(ctx)) }()
	_, err = private.Exec(ctx, `UPDATE kaname.access_bindings SET grant_capability_version=1 WHERE id=$1`, binding.ID)
	require.NoError(t, err)
	_, err = private.Exec(ctx, `ALTER TABLE kaname.authority_role_access_label_rule DISABLE TRIGGER authority_role_access_label_rule_closed`)
	require.NoError(t, err)
	for _, cap := range caps {
		_, err = private.Exec(ctx, `INSERT INTO kaname.authority_role_access_label_rule(role_id,rule_fp,definition_id) VALUES($1,$2,$3::uuid)`, source.ID, cap.RuleFP, string(cap.DefinitionID))
		require.NoError(t, err)
	}
	_, err = private.Exec(ctx, `ALTER TABLE kaname.authority_role_access_label_rule ENABLE TRIGGER authority_role_access_label_rule_closed`)
	require.NoError(t, err)
	require.NoError(t, private.Commit(ctx))
	var exact bool
	require.NoError(t, f.given.pool.QueryRow(ctx, `SELECT
  (SELECT count(*) FROM kaname.authority_role_access_label_rule WHERE role_id=$1)=2
  AND (SELECT grant_capability_version=1 FROM kaname.access_bindings WHERE id=$2)
  AND EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='kaname.authority_role_access_label_rule'::regclass
   AND tgname='authority_role_access_label_rule_closed' AND tgenabled='O')`, source.ID, binding.ID).Scan(&exact))
	require.True(t, exact)
}
