// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package installruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/moby/moby/client"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

// NativeStand повторно использует уже исполненную подготовку стенда и жизненный цикл TLS
// PostgreSQL с точной проверкой владения. Создание требует явной аренды исполнения
// вызывающего; помощник не вызывается инициализацией пакета или чистыми тестами.
type NativeStand struct{ Root, Evidence, PGPort string }

// Environment сохраняет штатную политику стенда, перемещая каждый нативный
// слушатель на петлевой адрес. Переопределения — явные входы фикстуры; вызывающие не должны
// использовать их для изменения допуска, идентичности, политики шлюза или лимитов ресурсов.
func (s *NativeStand) Environment(overrides map[string]string) ([]string, error) {
	raw, err := os.ReadFile(filepath.Join(s.Evidence, "run", "native-environment.json"))
	if err != nil {
		return nil, err
	}
	var values map[string]string
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil, err
	}
	values["KANAME_DB_PORT"] = s.PGPort
	for name, port := range map[string]int{"ENDPOINT": 9090, "INTERNAL_ENDPOINT": 9091, "METRICS_ENDPOINT": 9095,
		"REGISTRY_TOKEN__ENDPOINT": 9096, "JWKS_PROXY__ENDPOINT": 9097, "REST_ENDPOINT": 9098, "INTERNAL_REST_ENDPOINT": 9099, "LOGIN_LANE_ENDPOINT": 9100} {
		values["KANAME_API_SERVER__"+name] = fmt.Sprintf("tcp://127.0.0.1:%d", port)
	}
	for _, name := range []string{"HOME", "PATH", "GOMAXPROCS", "GOMEMLIMIT"} {
		if value, exists := os.LookupEnv(name); exists {
			values[name] = value
		}
	}
	for name, value := range overrides {
		values[name] = value
	}
	var names []string
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]string, 0, len(names))
	for _, name := range names {
		result = append(result, name+"="+values[name])
	}
	return result, nil
}

// RunMigrator вызывает штатную нативную команду миграции до начального
// Given. Её полный вывод закрыт; миграция/операция данных не подменяются.
func (s *NativeStand) RunMigrator(ctx context.Context, binary string, environment []string) error {
	if !filepath.IsAbs(binary) {
		return fmt.Errorf("absolute migrator artifact required")
	}
	config := filepath.Join(s.Evidence, "migrator.yaml")
	if err := os.WriteFile(config, []byte("{}\n"), 0600); err != nil {
		return err
	}
	log, err := os.OpenFile(filepath.Join(s.Evidence, "migrator.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer log.Close()
	cmd := exec.CommandContext(ctx, binary, "up")
	cmd.Dir = s.Evidence
	cmd.Env = append(append([]string{}, environment...), "KANAME_CONFIG_PATH="+config)
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ordinary migrator failed; see private log: %w", err)
	}
	return nil
}

func (s *NativeStand) StartMailbox(t *testing.T, ctx context.Context, environment []string) {
	t.Helper()
	pki := filepath.Join(s.Evidence, "pki")
	log, err := os.OpenFile(filepath.Join(s.Evidence, "mailbox.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	require.NoError(t, err)
	cmd := exec.CommandContext(ctx, "python3", filepath.Join(s.Root, ".github/scripts/stand-mailbox.py"), "serve",
		"--host", "127.0.0.1", "--smtp-port", "14465", "--http-port", "18025", "--cert", filepath.Join(pki, "srv.crt"), "--key", filepath.Join(pki, "srv.key"))
	cmd.Dir = s.Evidence
	cmd.Env = environment
	cmd.Stdout, cmd.Stderr = log, log
	require.NoError(t, cmd.Start())
	pid := cmd.Process.Pid
	raw, _ := json.Marshal(map[string]any{"name": "mailbox", "pid": pid})
	require.NoError(t, os.WriteFile(filepath.Join(s.Evidence, "mailbox-process.json"), raw, 0600))
	done := make(chan error, 1)
	go func() { done <- cmd.Wait(); log.Close() }()
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		timer := time.NewTimer(15 * time.Second)
		defer timer.Stop()
		forced := false
		select {
		case <-done:
		case <-timer.C:
			forced = true
			_ = cmd.Process.Kill()
			<-done
		}
		raw, _ := json.Marshal(map[string]any{"pid": pid, "forced": forced, "exited": true})
		_ = os.WriteFile(filepath.Join(s.Evidence, "mailbox-cleanup.json"), raw, 0600)
		if forced {
			t.Error("native mailbox required forced cleanup")
		}
	})
}

func PrepareNativeStand(t *testing.T, ctx context.Context, repository, evidence string, deliveredRegistry bool) *NativeStand {
	t.Helper()
	registry := "0"
	if deliveredRegistry {
		registry = "1"
	}
	root, err := filepath.Abs(repository)
	require.NoError(t, err)
	require.NoError(t, validateStandPath(evidence), "reject unsafe native stand paths before preparation")
	require.NoError(t, os.Mkdir(evidence, 0700), "each run needs a fresh evidence directory")
	// Генерируем ровно существующие PKI/конфигурацию стенда до любого контейнера.
	prepare := exec.CommandContext(ctx, "bash", filepath.Join(root, ".github/scripts/stand-own.sh"), "prepare-native")
	// Любой случайный относительный вывод относится к этому закрытому запуску, а не дереву исходников.
	prepare.Dir = evidence
	var cleanEnvironment []string
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "KANAME_") {
			cleanEnvironment = append(cleanEnvironment, entry)
		}
	}
	prepare.Env = append(cleanEnvironment, "KANAME_STAND_REGISTRY_WORLD="+registry,
		"KANAME_STAND_PKI="+filepath.Join(evidence, "pki"),
		"KANAME_STAND_RUNDIR="+filepath.Join(evidence, "run"),
		"KANAME_STAND_BIN="+filepath.Join(evidence, "delivery"))
	prepared, err := prepare.CombinedOutput()
	require.NoError(t, os.WriteFile(filepath.Join(evidence, "prepare.log"), prepared, 0600))
	require.NoError(t, err, "stand preparation failed; see private prepare.log")
	pg, err := postgres.Run(ctx, "postgres:16-alpine", postgres.WithDatabase("kaname"),
		postgres.WithUsername("kaname"), postgres.WithPassword("stand"), postgres.BasicWaitStrategies())
	require.NoError(t, err)
	// Сразу регистрируем уборку; используем новый срок даже после отказа задания.
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		err := pg.Terminate(cleanup)
		status := map[string]any{"containerId": pg.GetContainerID(), "terminateSucceeded": err == nil}
		raw, _ := json.Marshal(status)
		_ = os.WriteFile(filepath.Join(evidence, "pg-cleanup.json"), raw, 0600)
		if err != nil {
			t.Errorf("owned PostgreSQL termination: %v", err)
		}
	})
	cli, err := client.New(client.FromEnv, client.WithAPIVersionNegotiation())
	require.NoError(t, err)
	defer cli.Close()
	inspect, err := cli.ContainerInspect(ctx, pg.GetContainerID(), client.ContainerInspectOptions{})
	require.NoError(t, err)
	// Фиксируем имена анонимных томов, пока точный контейнер задачи ещё существует.
	ownership, err := json.Marshal(map[string]any{"containerId": pg.GetContainerID(), "mounts": inspect.Container.Mounts})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(evidence, "pg-ownership.json"), ownership, 0600))
	for _, suffix := range []string{"crt", "key"} {
		material, err := os.ReadFile(filepath.Join(evidence, "pki", "pg."+suffix))
		require.NoError(t, err)
		// Секретов нет в argv, окружении Docker, журнале, монтировании хоста или сокете.
		command := "umask 077; cat > /var/lib/postgresql/server." + suffix + "; chown postgres:postgres /var/lib/postgresql/server." + suffix
		require.NoError(t, ownedExec(ctx, cli, pg.GetContainerID(), []string{"sh", "-ec", command}, material))
	}
	for _, sql := range []string{
		"ALTER SYSTEM SET ssl_cert_file = '/var/lib/postgresql/server.crt'",
		"ALTER SYSTEM SET ssl_key_file = '/var/lib/postgresql/server.key'",
		"ALTER SYSTEM SET ssl = 'on'", "SELECT pg_reload_conf()",
	} {
		require.NoError(t, ownedExec(ctx, cli, pg.GetContainerID(), []string{"psql", "-U", "kaname", "-d", "kaname", "-v", "ON_ERROR_STOP=1", "-c", sql}, nil))
	}
	port, err := pg.MappedPort(ctx, "5432/tcp")
	require.NoError(t, err)
	return &NativeStand{Root: root, Evidence: evidence, PGPort: port.Port()}
}

// ownedExec использует существующий захваченный транспорт Docker SDK, принятый
// проверенным ретранслятором. Чтение до EOF ПЕРЕД inspect предотвращает ложный нулевой код
// ещё не начавшегося exec. На вход идёт только новый собственный ID.
func ownedExec(ctx context.Context, cli *client.Client, id string, command []string, stdin []byte) error {
	created, err := cli.ExecCreate(ctx, id, client.ExecCreateOptions{Cmd: command,
		AttachStdin: len(stdin) > 0, AttachStdout: true, AttachStderr: true, Privileged: false})
	if err != nil {
		return err
	}
	attached, err := cli.ExecAttach(ctx, created.ID, client.ExecAttachOptions{})
	if err != nil {
		return err
	}
	defer attached.Close()
	if len(stdin) > 0 {
		if _, err := io.Copy(attached.Conn, bytes.NewReader(stdin)); err != nil {
			return err
		}
		if err := attached.CloseWrite(); err != nil {
			return err
		}
	}
	if _, err := io.Copy(io.Discard, attached.Reader); err != nil {
		return err
	}
	result, err := cli.ExecInspect(ctx, created.ID, client.ExecInspectOptions{})
	if err != nil {
		return err
	}
	if result.Running || result.ExitCode != 0 {
		return fmt.Errorf("owned exec did not finish successfully: running=%v code=%d", result.Running, result.ExitCode)
	}
	return nil
}
