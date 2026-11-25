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

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/testsupport/installruntime"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// Два процесса Kaname используют одну опубликованную модель полномочий FULL.
// Владелец миграций задаёт тестовые определения меток и исходный допуск apply.
// Записи меток и все решения проверяются через штатный TLS API.
func TestAccessLabelsTwoNativeReplicas(t *testing.T) {
	if os.Getenv("KANAME_ACCESS_LABEL_REPLICA_ACCEPTANCE") != "1" {
		t.Skip("NOT_EXECUTED: requires an explicitly leased native access-label acceptance job and KANAME_RID_* frozen artifacts")
	}
	f := newInstallationNativeWorldConfigured(t, 7200, "", false, false, nativeWorldOptions{boundedPostgres: true})
	ctx, pool := f.given.ctx, f.given.pool
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
	// Исходный процесс уже выпустил удостоверение читателя. Готовим FULL
	// и публикуем модель до старта обеих реплик.
	before, headBefore := nativeAccessLabelMigrationRows(t, f)
	nativeAccessLabelBootstrap(t, f)
	primary := provisionNativeRuntime(t, f, filepath.Join(f.session.Root, "account-runtime-grants.log"))
	executor := primary.Copy()
	executor.User, executor.Password = fullStartupRestrictedLogin(t, ctx, pool)
	f.secrets = append(f.secrets, executor.Password)
	_, err = pool.Exec(ctx, `SELECT kaname.authority_role_actor_login_configure_v1($1::regrole,$2::regrole)`, primary.User, executor.User)
	require.NoError(t, err)
	replicas := []*nativeAccessLabelReplica{
		startNativeAccessLabelReplica(t, f, "writer-a", installruntime.DefaultNativePorts(), primary, executor),
		startNativeAccessLabelReplica(t, f, "reader-b", installruntime.SecondNativePorts(), primary, executor),
	}
	require.NotEqual(t, replicas[0].pid, replicas[1].pid)
	// Начальная запись меток начинается после штатного пересчёта проекций.
	ridAwaitRoleProjectionsAt(t, ctx, replicas[0].process, "account-labels-replica-a")
	ridAwaitRoleProjectionsAt(t, ctx, replicas[1].process, "account-labels-replica-b")
	f.renewOperator(t, ctx)
	continuing := func() {
		for _, r := range replicas {
			r.assertContinuing(t)
		}
	}
	continuing()
	a, b := replicas[0].wire, replicas[1].wire
	root := f.tenantID
	mutation := func(writer, observer *installruntime.Wire, stage, method, path string, body any) installruntime.Operation {
		t.Helper()
		bearer := f.operator.Bearer()
		var raw json.RawMessage
		code, e := writer.JSON(ctx, method, path, bearer, body, &raw)
		if code != 0 && code != http.StatusOK {
			var failure struct {
				Code *int `json:"code"`
			}
			if json.Unmarshal(raw, &failure) == nil && failure.Code != nil {
				t.Fatalf("этап %s: HTTP %d, код gRPC %d", stage, code, *failure.Code)
			}
			t.Fatalf("этап %s: HTTP %d", stage, code)
		}
		require.NoError(t, e, "этап %s", stage)
		require.Equal(t, http.StatusOK, code, "этап %s", stage)
		var op installruntime.Operation
		require.NoError(t, json.Unmarshal(raw, &op), "этап %s", stage)
		require.NotEmpty(t, op.ID, "этап %s", stage)
		op, e = observer.AwaitOperation(ctx, bearer, installruntime.Operation{ID: op.ID})
		if e != nil && op.Error != nil {
			recordNativeAccessLabelMutationFailure(t, f, stage, op.ID)
		}
		require.NoError(t, e, "этап %s", stage)
		require.True(t, op.Done)
		require.Nil(t, op.Error)
		continuing()
		return op
	}
	mutation(a, b, "initial-labels", http.MethodPatch, "/iam/v1/accounts/"+url.PathEscape(root), map[string]any{
		"accountId": root, "accessLabels": map[string]string{"team": "before", "keep": "yes"}, "updateMask": "accessLabels",
	})
	makeBinding := func(writer, observer *installruntime.Wire, name, key, value string) string {
		t.Helper()
		op := mutation(writer, observer, "create-selector-role", http.MethodPost, "/iam/v1/roles", map[string]any{
			"name": name, "definitionTier": map[string]string{"tierType": "iam.account", "tierId": root},
			"rules": []any{map[string]any{"module": "iam", "resources": []string{"account"}, "verbs": []string{"get"}, "matchAccessLabels": map[string]string{key: value}}},
		})
		var role struct {
			ID string `json:"roleId"`
		}
		require.NoError(t, json.Unmarshal(op.Metadata, &role))
		require.NotEmpty(t, role.ID)
		op = mutation(writer, observer, "create-selector-binding", http.MethodPost, "/iam/v1/accessBindings", map[string]any{
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
	losing := makeBinding(a, b, "replica_old_reader", "team", "before")
	keeping := makeBinding(b, a, "replica_keep_reader", "keep", "yes")
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
	sequence := runAccessLabelTwoReplicaSequence(t, ctx, a, b, f.given.pool, f.operator.Bearer(), credential.Bearer(), root, string(reader.user), losing, keeping,
		continuing, func(stage, operationID string) { recordNativeAccessLabelMutationFailure(t, f, stage, operationID) })
	sequence.Baseline.ActiveMembers, sequence.Baseline.LedgerHolders = members, holders
	after, headAfter := nativeAccessLabelMigrationRows(t, f)
	require.Equal(t, headBefore, headAfter)
	require.Equal(t, before, after, "no migration ledger write during setup/bootstrap/observations")
	observations := nativeAccessLabelObservations{
		SchemaVersion: 3, Scenario: "access-label-two-replicas", BinarySHA256: f.session.BinarySHA256,
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
func nativeAccessLabelBootstrap(t *testing.T, f *installationNativeWorld) {
	t.Helper()
	ctx, pool := f.given.ctx, f.given.pool
	owner := kanamepg.New(pool, nil)
	// Исходный аккаунт вставлен фикстурой. Проводим его связи через
	// штатный журнал, как при создании аккаунта.
	account := domain.Account{ID: domain.AccountID(f.tenantID), OwnerUserID: f.given.user}
	writer, err := owner.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = writer.Rollback(context.WithoutCancel(ctx)) }()
	var tuples []service.RelationTuple
	for _, fact := range account.StructuralFacts() {
		tuples = append(tuples, service.RelationTuple{User: fact.User, Relation: fact.Relation, Object: fact.Object})
	}
	require.NoError(t, writer.EmitFGARelationWrite(ctx, tuples))
	require.NoError(t, writer.Commit(ctx))

	var definitions []kanamepg.AccessLabelDeclarationResult
	for _, d := range []struct {
		key    string
		values []string
	}{{"team", []string{"before", "after"}}, {"keep", []string{"yes", "no"}}} {
		definition, err := owner.AddAccessLabelValues(ctx, kanamepg.AccessLabelDeclaration{
			Account: f.tenantID, Module: "iam", Resource: "account", Key: d.key, Values: d.values,
		})
		require.NoError(t, err)
		definitions = append(definitions, definition)
	}
	_, bundle := fullStartupTestBundle(t, ctx, pool)
	require.NoError(t, owner.StageFullAuthorityBundle(ctx, bundle))
	require.NoError(t, owner.ActivateFullAuthorityBundle(ctx, bundle))
	for _, definition := range definitions {
		_, err := owner.IssueInitialAccessLabelApply(ctx, kanamepg.InitialAccessLabelApply{
			Account: f.tenantID, DefinitionID: domain.AccessLabelDefinitionID(definition.ID), ExpectedRevision: definition.Revision,
		}, bundle)
		require.NoError(t, err)
	}

	ownerFile := filepath.Join(f.session.Root, "account-publication-owner.yaml")
	require.NoError(t, os.WriteFile(ownerFile, []byte("{}\n"), 0600))
	migrator := os.Getenv("KANAME_RID_MIGRATOR")
	_ = publicationNativeDigest(t, migrator)
	bootstrap := startPublicationOwnerCommand(t, ctx, f.session.Root, "account-publication", publicationNativeEnvironment(f.session.Environment,
		map[string]string{"KANAME_CONFIG_PATH": ownerFile}), migrator, "authority-bundle", "bootstrap-publication", "--image-only")
	bootstrap.await(t, 90*time.Second)
}
