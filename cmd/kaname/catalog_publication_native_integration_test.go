// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/installruntime"
	"github.com/stretchr/testify/require"
)

// Явный запуск использует зафиксированные бинарники RID, закрытый каталог
// доказательств, ограниченный тестовый процесс и выделенный PostgreSQL.
// В приёмке работают штатные serve и migrator, REST с TLS и Bearer.
func TestCatalogPublicationTwoNativeReplicas(t *testing.T) {
	if os.Getenv("KANAME_CATALOG_PUBLICATION_ACCEPTANCE") != "1" {
		t.Skip("NOT_EXECUTED: requires an explicitly leased native publication acceptance job and KANAME_RID_* frozen artifacts")
	}
	f := newInstallationNativeWorldConfigured(t, 7200, "", false, false, nativeWorldOptions{boundedPostgres: true})
	ctx := f.given.ctx
	// Второму пользователю не выдаём кластерных прав. Токен выдаётся и
	// проверяется по штатному TLS через ту же церемонию, что у оператора.
	reader := &ceremonyWorld{t: t, id: "CATALOG-NATIVE-READER", ctx: ctx, pool: f.given.pool, logs: &lockedBuffer{}, clientAudiences: []string{"https://kaname.local"}}
	reader.seedPerson()
	reader.markPerson()
	reader.session = reader.seedSession("2")
	reader.ic1 = reader.seedClient("catalog-native-reader", domain.InteractiveClientActive, []string{lineA1R})
	credential, err := f.wire.ExchangeOperator(ctx, installruntime.OperatorGiven{UserID: string(reader.user), SessionBearer: reader.session.bearer.CookieValue(), ClientID: reader.ic1.rec.ClientID, ClientSecret: reader.ic1.secret, RedirectURI: lineA1R})
	require.NoError(t, err)
	f.secrets = append(f.secrets, reader.session.bearer.CookieValue(), reader.ic1.secret, credential.Bearer())
	requireNativeAuthority(t, reader, "user", string(reader.user), 0)
	stop, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	require.NoError(t, f.session.Stop(stop))
	cancel()
	var migrationBefore []byte
	var migrationHead int64
	require.NoError(t, f.given.pool.QueryRow(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(v) ORDER BY id),'[]'::jsonb),COALESCE(max(version_id) FILTER (WHERE is_applied),0) FROM goose_db_version v`).Scan(&migrationBefore, &migrationHead))

	// Подготовка завершена до перехода владельца. Обе реплики используют
	// отдельные runtime-учётки, активацией модели занимается migrator.
	ownerConfig := filepath.Join(f.session.Root, "publication-owner.yaml")
	require.NoError(t, os.WriteFile(ownerConfig, []byte("{}\n"), 0600))
	ownerEnvironment := publicationNativeEnvironment(f.session.Environment, map[string]string{"KANAME_CONFIG_PATH": ownerConfig})
	migrator := os.Getenv("KANAME_RID_MIGRATOR")
	migratorDigest := publicationNativeDigest(t, migrator)
	bootstrap := startPublicationOwnerCommand(t, ctx, f.session.Root, "bootstrap-publication", ownerEnvironment, migrator, "authority-bundle", "bootstrap-publication", "--image-only")
	bootstrap.await(t, 90*time.Second)
	follower := startPublicationOwnerCommand(t, ctx, f.session.Root, "follow-publications", ownerEnvironment, migrator, "authority-bundle", "follow-publications", "--interval=250ms")

	const window = 15 * time.Second
	var replicas []*nativePublicationReplica
	for i, ports := range []installruntime.NativePorts{installruntime.DefaultNativePorts(), installruntime.SecondNativePorts()} {
		// Фикстура создаёт LOGIN с NOSUPERUSER, NOBYPASSRLS, NOINHERIT и
		// штатными разрешениями службы.
		label := fmt.Sprintf("publication-replica-%d", i+1)
		connection := provisionNativeRuntime(t, f, filepath.Join(f.session.Root, label+"-runtime-grants.log"))
		values, err := ports.EnvironmentOverrides()
		require.NoError(t, err)
		values["KANAME_REPOSITORY__POSTGRES__URL"] = (&url.URL{Scheme: "postgres", User: url.User(connection.User), Host: fmt.Sprintf("127.0.0.1:%s", f.stand.PGPort), Path: "/kaname", RawQuery: "sslmode=require&application_name=" + label}).String()
		values["KANAME_DB_PASSWORD"] = connection.Password
		values["KANAME_REPOSITORY__POSTGRES__REPLICA_BUDGET"] = "2"
		values[catalogSnapshotRefreshKnob] = strconv.FormatInt(window.Milliseconds(), 10)
		environment := publicationNativeEnvironment(f.session.Environment, values,
			"KANAME_DB_HOST", "KANAME_DB_PORT", "KANAME_DB_USER", "KANAME_DB_NAME", "KANAME_BOOTSTRAP_ROOT_EMAIL")
		config, err := installruntime.FullStartupConfig(map[string]any{
			"authority-protocol": map[string]any{"participation": "participant", "full-semantics": true},
			"manifests":          map[string]any{"dir": "", "required": false},
		}, f.writerPlan)
		require.NoError(t, err)
		root := filepath.Join(f.session.Root, label)
		require.NoError(t, os.Mkdir(root, 0700))
		configPath := filepath.Join(root, "config.yaml")
		require.NoError(t, os.WriteFile(configPath, config, 0600))
		ridRegistrationStartupProof(t, root, config, f.writerPlan)
		wire, err := installruntime.NewWireAtPorts(filepath.Join(f.session.Root, "pki"), ports)
		require.NoError(t, err)
		t.Cleanup(wire.Close)
		process, err := installruntime.Start(ctx, installruntime.Input{Binary: f.session.Binary, ExpectedBinarySHA256: f.session.BinarySHA256, ConfigFile: configPath, Environment: environment, EvidenceDir: filepath.Join(root, "process")})
		require.NoError(t, err)
		t.Cleanup(func() {
			cleanup, done := context.WithTimeout(context.Background(), 20*time.Second)
			defer done()
			require.NoError(t, process.Stop(cleanup))
			require.NoError(t, process.CheckSecretAbsence(f.secrets...))
		})
		ready, done := context.WithTimeout(ctx, 90*time.Second)
		var lastProbeError error
		err = process.AwaitReady(ready, func(attempt context.Context) error {
			lastProbeError = wire.ProductionReady(attempt)
			return lastProbeError
		})
		done()
		require.NoError(t, err, "Реплика FULL не подтвердила готовность. Последняя ошибка пробы %v", lastProbeError)
		identityPath := filepath.Join(root, "process", "process.json")
		identity, err := os.ReadFile(identityPath)
		require.NoError(t, err)
		var record struct {
			PID int `json:"pid"`
		}
		require.NoError(t, json.Unmarshal(identity, &record))
		require.Positive(t, record.PID)
		parentGroup, err := os.ReadFile("/proc/self/cgroup")
		require.NoError(t, err)
		childGroup, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", record.PID))
		require.NoError(t, err)
		require.Equal(t, parentGroup, childGroup, "both replicas inherit the capped acceptance job")
		replicas = append(replicas, &nativePublicationReplica{wire: wire, process: process, ports: ports, identity: identity, identityPath: identityPath, pid: record.PID})
	}
	require.NotEqual(t, replicas[0].pid, replicas[1].pid)
	for _, replica := range replicas {
		replica.assertContinuing(t)
		var catalog nativePublicationCatalog
		code, err := replica.wire.JSON(ctx, http.MethodGet, "/iam/v1/permissionCatalog", credential.Bearer(), nil, &catalog)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
		require.Nil(t, catalog.erpContract())
	}

	publish := func(replica *nativePublicationReplica, document string) nativePublicationModel {
		t.Helper()
		var plan nativePublicationModel
		code, err := replica.wire.JSON(ctx, http.MethodPost, "/iam/v1/catalog/modules/erp:planPublication", f.operator.Bearer(), map[string]any{"document": []byte(document)}, &plan)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
		require.NotEmpty(t, plan.StateToken)
		var operation installruntime.Operation
		code, err = replica.wire.JSON(ctx, http.MethodPost, "/iam/v1/catalog/modules/erp:applyPublication", f.operator.Bearer(), map[string]any{"document": []byte(document), "stateToken": plan.StateToken}, &operation)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
		require.True(t, operation.Done)
		require.Nil(t, operation.Error)
		var result nativePublicationModel
		require.NoError(t, json.Unmarshal(operation.Response, &result))
		require.Equal(t, plan.ModelRevision, result.ModelRevision)
		require.Equal(t, plan.ModelDigest, result.ModelDigest)
		return result
	}
	converge := func(started time.Time, document string, model nativePublicationModel, expected []string) {
		t.Helper()
		remaining := window - time.Since(started)
		require.Positive(t, remaining, "publication itself exceeded convergence window")
		require.Eventually(t, func() bool {
			for _, replica := range replicas {
				attempt, done := context.WithDeadline(ctx, started.Add(window))
				var catalog nativePublicationCatalog
				code, err := replica.wire.JSON(attempt, http.MethodGet, "/iam/v1/permissionCatalog", credential.Bearer(), nil, &catalog)
				var plan nativePublicationModel
				if err == nil && code == http.StatusOK && equalPublicationVerbs(catalog.erpContract(), expected) {
					code, err = replica.wire.JSON(attempt, http.MethodPost, "/iam/v1/catalog/modules/erp:planPublication", f.operator.Bearer(), map[string]any{"document": []byte(document)}, &plan)
				}
				done()
				if err != nil || code != http.StatusOK || plan.ModelRevision != model.ModelRevision || plan.ModelDigest != model.ModelDigest {
					return false
				}
			}
			return true
		}, remaining, 50*time.Millisecond, "real owner follower and both existing replicas must converge within configured window")
		for _, replica := range replicas {
			replica.assertContinuing(t)
		}
		follower.assertRunning(t)
	}
	checkAction := func(replica *nativePublicationReplica, verb, relation string) {
		t.Helper()
		action := "erp.contract." + verb
		var decision struct {
			Allowed     bool     `json:"allowed"`
			DenyReasons []string `json:"denyReasons"`
		}
		code, err := replica.wire.JSON(ctx, http.MethodPost, "/iam/v1/authorize:check", credential.Bearer(), map[string]any{
			"subject":  "user:" + string(reader.user),
			"resource": map[string]string{"type": "erp_contract_item", "id": "unregistered-contract"},
			"action":   action,
		}, &decision)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
		require.False(t, decision.Allowed, "публикация каталога сама не выдаёт прав")
		require.Len(t, decision.DenyReasons, 1)
		if relation == "" {
			require.Equal(t, fmt.Sprintf("action %q does not resolve to a known relation", action), decision.DenyReasons[0])
			return
		}
		require.Contains(t, decision.DenyReasons[0], fmt.Sprintf("lacks relation %q", relation))
	}
	started := time.Now()
	first := publish(replicas[0], replicaPublicationDocument)
	require.Equal(t, "2", first.ModelRevision)
	converge(started, replicaPublicationDocument, first, []string{"get", "sign"})
	firstElapsed := time.Since(started)
	for _, replica := range replicas {
		checkAction(replica, "get", "v_get")
		checkAction(replica, "sign", "v_sign")
		checkAction(replica, "approve", "")
	}
	secondDocument := strings.Replace(replicaPublicationDocument, "revision: 1", "revision: 2", 1) + "      - {name: approve, class: update}\n"
	started = time.Now()
	second := publish(replicas[1], secondDocument)
	require.Equal(t, "3", second.ModelRevision)
	converge(started, secondDocument, second, []string{"get", "sign", "approve"})
	secondElapsed := time.Since(started)
	for _, replica := range replicas {
		checkAction(replica, "get", "v_get")
		checkAction(replica, "sign", "v_sign")
		checkAction(replica, "approve", "v_approve")
		checkAction(replica, "cancel", "")
	}
	type storedCatalog struct {
		models, parts int
		head, active  int64
		manualHold    bool
		digest        string
		rowsSHA256    [sha256.Size]byte
	}
	readStoredCatalog := func(t *testing.T) storedCatalog {
		t.Helper()
		var stored storedCatalog
		var rows []byte
		require.NoError(t, f.given.pool.QueryRow(ctx, `
			SELECT (SELECT count(*) FROM kaname.publication_model_revision),
			       (SELECT count(*) FROM kaname.module_part_revision WHERE module = 'erp'),
			       head.revision, head.digest, activation.revision, activation.manual_hold,
			       jsonb_build_object(
			         'modules', (SELECT jsonb_agg(to_jsonb(m) ORDER BY m.module) FROM kaname.catalog_module m),
			         'resources', (SELECT jsonb_agg(to_jsonb(r) ORDER BY r.module, r.resource) FROM kaname.catalog_resource r),
			         'verbs', (SELECT jsonb_agg(to_jsonb(v) ORDER BY v.module, v.resource, v.verb) FROM kaname.catalog_verb v))
			FROM (SELECT revision, digest FROM kaname.publication_model_revision ORDER BY revision DESC LIMIT 1) head
			CROSS JOIN kaname.authority_publication_activation activation
			WHERE activation.singleton
		`).Scan(&stored.models, &stored.parts, &stored.head, &stored.digest, &stored.active, &stored.manualHold, &rows))
		stored.rowsSHA256 = sha256.Sum256(rows)
		return stored
	}
	accepted := readStoredCatalog(t)
	require.Equal(t, 3, accepted.models)
	require.Equal(t, 2, accepted.parts)
	require.Equal(t, int64(3), accepted.head)
	require.Equal(t, accepted.head, accepted.active)
	require.False(t, accepted.manualHold)
	require.Equal(t, second.ModelDigest, accepted.digest)
	assertUnchanged := func(t *testing.T) {
		t.Helper()
		require.Equal(t, accepted, readStoredCatalog(t), "повтор или отказ не меняет строки каталога и активную редакцию")
	}
	repeated := publish(replicas[0], secondDocument)
	require.Equal(t, second.ModelRevision, repeated.ModelRevision)
	require.Equal(t, second.ModelDigest, repeated.ModelDigest)
	assertUnchanged(t)
	for _, rejected := range []struct {
		name, bearer, document string
		status                 int
		grpcCode               int
	}{
		{"anonymous", "", secondDocument, http.StatusForbidden, 7},
		{"non-operator", credential.Bearer(), secondDocument, http.StatusForbidden, 7},
		{"invalid-document", f.operator.Bearer(), "apiVersion: [", http.StatusBadRequest, 3},
		{"revision-collision", f.operator.Bearer(), strings.Replace(secondDocument, "approve", "cancel", 1), http.StatusBadRequest, 9},
		{"type-ownership-collision", f.operator.Bearer(), strings.Replace(strings.Replace(secondDocument, "revision: 2", "revision: 3", 1), "name: contract", "name: invoice", 1), http.StatusBadRequest, 9},
	} {
		t.Run(rejected.name, func(t *testing.T) {
			for _, action := range []string{"planPublication", "applyPublication"} {
				request := map[string]any{"document": []byte(rejected.document)}
				if action == "applyPublication" {
					request["stateToken"] = "must-not-commit"
				}
				var refusal struct {
					Code int `json:"code"`
				}
				code, err := replicas[0].wire.JSON(ctx, http.MethodPost, "/iam/v1/catalog/modules/erp:"+action, rejected.bearer, request, &refusal)
				require.NoError(t, err)
				require.Equal(t, rejected.status, code)
				require.Equal(t, rejected.grpcCode, refusal.Code, "distinguish ownership/revision preconditions from malformed input")
				assertUnchanged(t)
			}
		})
	}
	t.Run("foreign-type-ownership-collision", func(t *testing.T) {
		// Пространства типов erp и erp-contract имеют общую допустимую часть.
		// Меняем один только тип: свободный проходит Plan, занятый отвергается.
		contested := strings.Replace(replicaPublicationDocument, "module: erp", "module: erp-contract", 1)
		available := strings.Replace(contested, "erp_contract_item", "erp_contract_alternative", 1)
		endpoint := "/iam/v1/catalog/modules/erp-contract:"
		var plan nativePublicationModel
		code, err := replicas[1].wire.JSON(ctx, http.MethodPost, endpoint+"planPublication", f.operator.Bearer(), map[string]any{"document": []byte(available)}, &plan)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
		require.NotEmpty(t, plan.StateToken)
		for _, action := range []string{"planPublication", "applyPublication"} {
			request := map[string]any{"document": []byte(contested)}
			if action == "applyPublication" {
				request["stateToken"] = plan.StateToken
			}
			var refusal struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			}
			code, err := replicas[1].wire.JSON(ctx, http.MethodPost, endpoint+action, f.operator.Bearer(), request, &refusal)
			require.NoError(t, err)
			require.Equal(t, http.StatusBadRequest, code)
			require.Equal(t, 9, refusal.Code)
			require.Contains(t, refusal.Message, "тип erp_contract_item уже принадлежит")
			assertUnchanged(t)
		}
	})
	for _, replica := range replicas {
		replica.assertContinuing(t)
		var catalog nativePublicationCatalog
		code, err := replica.wire.JSON(ctx, http.MethodGet, "/iam/v1/permissionCatalog", credential.Bearer(), nil, &catalog)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
		require.True(t, equalPublicationVerbs(catalog.erpContract(), []string{"get", "sign", "approve"}))
		for _, module := range catalog.Modules {
			require.NotEqual(t, "erp-contract", module.Module)
		}
	}
	follower.assertRunning(t)
	var migrationAfter []byte
	require.NoError(t, f.given.pool.QueryRow(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(v) ORDER BY id),'[]'::jsonb) FROM goose_db_version v`).Scan(&migrationAfter))
	require.Equal(t, migrationBefore, migrationAfter, "catalog publication does not execute or record a schema migration")
	migrationDigest := sha256.Sum256(migrationBefore)
	require.Equal(t, f.session.BinarySHA256, publicationNativeDigest(t, f.session.Binary))
	require.Equal(t, migratorDigest, publicationNativeDigest(t, migrator))
	if t.Failed() {
		return
	}
	receipt, err := json.Marshal(map[string]any{"test": t.Name(), "replicaPIDs": []int{replicas[0].pid, replicas[1].pid}, "binarySHA256": f.session.BinarySHA256, "migratorSHA256": migratorDigest, "firstRevision": first.ModelRevision, "finalRevision": second.ModelRevision, "finalDigest": second.ModelDigest, "firstConvergenceMs": firstElapsed.Milliseconds(), "secondConvergenceMs": secondElapsed.Milliseconds(), "configuredWindowMs": window.Milliseconds(), "unchangedMigrationHead": migrationHead, "migrationLedgerSHA256": hex.EncodeToString(migrationDigest[:]), "transport": "production REST TLS presented Bearer", "owner": "migrator follow-publications"})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(f.session.Root, "publication-native-observations.json"), receipt, 0600))
}

type nativePublicationModel struct {
	StateToken    string `json:"stateToken"`
	ModelRevision string `json:"modelRevision"`
	ModelDigest   string `json:"modelDigest"`
}
type nativePublicationCatalog struct {
	Modules []struct {
		Module    string `json:"module"`
		Resources []struct {
			Resource string   `json:"resource"`
			Verbs    []string `json:"verbs"`
		} `json:"resources"`
	} `json:"modules"`
}

func (c nativePublicationCatalog) erpContract() []string {
	for _, module := range c.Modules {
		if module.Module == "erp" {
			for _, resource := range module.Resources {
				if resource.Resource == "contract" {
					return resource.Verbs
				}
			}
		}
	}
	return nil
}
func equalPublicationVerbs(actual, expected []string) bool {
	left, right := append([]string{}, actual...), append([]string{}, expected...)
	sort.Strings(left)
	sort.Strings(right)
	return strings.Join(left, "\n") == strings.Join(right, "\n")
}

type nativePublicationReplica struct {
	wire         *installruntime.Wire
	process      *installruntime.Process
	ports        installruntime.NativePorts
	identity     []byte
	identityPath string
	pid          int
}

func (r *nativePublicationReplica) assertContinuing(t *testing.T) {
	t.Helper()
	identity, err := os.ReadFile(r.identityPath)
	require.NoError(t, err)
	require.Equal(t, r.identity, identity, "same PID, executable and config receipt")
	require.NoError(t, r.process.OwnsListeners(r.ports.All()...), "the original process still owns every configured listener")
}
func publicationNativeDigest(t *testing.T, path string) string {
	t.Helper()
	require.True(t, filepath.IsAbs(path))
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}
func publicationNativeEnvironment(base []string, values map[string]string, remove ...string) []string {
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
	var out []string
	for key, value := range merged {
		out = append(out, key+"="+value)
	}
	sort.Strings(out)
	return out
}

type publicationOwnerCommand struct {
	cmd  *exec.Cmd
	done chan struct{}
	err  error
}

func startPublicationOwnerCommand(t *testing.T, ctx context.Context, root, name string, environment []string, binary string, args ...string) *publicationOwnerCommand {
	t.Helper()
	log, err := os.OpenFile(filepath.Join(root, name+".log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	require.NoError(t, err)
	command := exec.CommandContext(ctx, binary, args...)
	command.Dir, command.Env, command.Stdout, command.Stderr = root, environment, log, log
	run := &publicationOwnerCommand{cmd: command, done: make(chan struct{})}
	if err := command.Start(); err != nil {
		_ = log.Close()
		require.NoError(t, err)
	}
	go func() { run.err = errors.Join(command.Wait(), log.Close()); close(run.done) }()
	t.Cleanup(func() {
		select {
		case <-run.done:
			return
		default:
		}
		_ = command.Process.Signal(syscall.SIGTERM)
		select {
		case <-run.done:
			require.NoError(t, run.err)
		case <-time.After(15 * time.Second):
			_ = command.Process.Kill()
			<-run.done
			t.Error("owner command required forced cleanup")
		}
	})
	return run
}
func (r *publicationOwnerCommand) await(t *testing.T, timeout time.Duration) {
	t.Helper()
	select {
	case <-r.done:
		require.NoError(t, r.err, "owner command failed; inspect its private log")
	case <-time.After(timeout):
		t.Fatal("owner command exceeded fixture deadline")
	}
}
func (r *publicationOwnerCommand) assertRunning(t *testing.T) {
	t.Helper()
	select {
	case <-r.done:
		t.Fatalf("owner follower exited: %v", r.err)
	default:
	}
}
