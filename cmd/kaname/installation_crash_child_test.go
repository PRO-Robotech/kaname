// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"
	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/corelib/operations/operationspb"
	gdapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/grant_delegation"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/personmarks"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/stretchr/testify/require"
)

const rid02ChildInputEnv = "KANAME_RID02_CHILD_INPUT"

type rid02ChildInput struct {
	Action         string            `json:"action"`
	Operation      string            `json:"operation"`
	Proposed       string            `json:"proposed"`
	Boundary       string            `json:"boundary"`
	CredentialFile string            `json:"credentialFile"`
	ManifestDir    string            `json:"manifestDir"`
	Creator        string            `json:"creator"`
	Input          gdapp.CreateInput `json:"input"`
}
type rid02ChildEvent struct {
	Stage     string `json:"stage"`
	Operation string `json:"operation"`
	PID       int    `json:"pid"`
}

// Эта точка входа не создаёт фикстуру и не подставляет субъекта. Родитель
// передаёт только принадлежащие фикстуре БД/профиль и тот же настоящий публично выданный ключ C.
// Производственная подпись -> проверка утверждения -> выдача -> считыватель предъявленных токенов
// устанавливают C до настоящего вызова ExecuteInstallation.
func TestRID02OwnedInstallationChild(t *testing.T) {
	path := os.Getenv(rid02ChildInputEnv)
	if path == "" {
		t.Skip("private owned child entrypoint")
	}
	secretInventory := os.NewFile(5, "rid02-anonymous-secret-inventory")
	if secretInventory != nil {
		t.Cleanup(func() { _ = secretInventory.Close() })
	}
	require.NotNil(t, secretInventory)
	inventoryInfo, err := secretInventory.Stat()
	require.NoError(t, err, "anonymous inventory descriptor must be available")
	require.True(t, inventoryInfo.Mode().IsRegular() && inventoryInfo.Mode().Perm() == 0600)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var input rid02ChildInput
	require.NoError(t, json.Unmarshal(raw, &input))
	deadline, ok := t.Deadline()
	require.True(t, ok)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	cfg, err := config.Load("")
	require.NoError(t, err)
	cfg.ModuleSeedInstaller.CredentialFile = input.CredentialFile
	cfg.Manifests.Dir = input.ManifestDir
	cfg.Manifests.Required = true
	pool, err := coredb.NewPool(ctx, cfg.DSN())
	require.NoError(t, err)
	defer pool.Close()
	logger := quietLogger()
	manifests, err := loadDeliveredManifests(logger, cfg.Manifests)
	require.NoError(t, err)
	model, err := prepareComposedModel(logger, manifests)
	require.NoError(t, err)
	relations := authzcascade.WrapAdmitted(relverdict.NewPreparedAsker(pool, model.plans), personmarks.New(pool))
	keys, signer, err := buildTokenSigning(ctx, pool, cfg, logger)
	require.NoError(t, err)
	reader, err := preparePresentedReader(pool, cfg, keys, logger)
	require.NoError(t, err)
	auth, err := prepareInstallationAuthentication(pool, cfg, signer, reader, logger)
	require.NoError(t, err)
	// FD5 закрыто выделен родителем и удалён из каталога ДО Start.
	// Дописываем записи, сохраняя предыдущие токены при обновлении.
	saveSecrets := func() {
		saveErr := json.NewEncoder(secretInventory).Encode([]string{auth.credential.PrivateKeyPEM, auth.accessToken})
		if saveErr != nil {
			t.Fatal("anonymous issued-secret inventory write failed")
		}
	}
	verified, err := auth.Authenticate(ctx)
	saveSecrets()
	require.NoError(t, err)
	principal, ok := operations.PrincipalFromContextOK(verified)
	require.True(t, ok)
	require.Equal(t, operations.Principal{Type: "service_account", ID: input.Creator, DisplayName: input.Creator}, principal)
	require.NoError(t, authzguard.RequireClusterAdmin(verified, relations))
	rows := kanamepg.NewCatalogRepo(pool)
	halves, err := rows.ReadCatalogHalves(ctx)
	require.NoError(t, err)
	snapshot, err := catalog.NewSnapshot(halves, rows, logger, nil)
	require.NoError(t, err)
	events := os.NewFile(3, "rid02-events")
	require.NotNil(t, events)
	defer events.Close()
	control := os.NewFile(4, "rid02-control")
	require.NotNil(t, control)
	defer control.Close()
	enc := json.NewEncoder(events)
	dec := json.NewDecoder(control)
	if input.Action == "lock-pending" || input.Action == "terminal-refusal" {
		// Отдельное доказательство настоящего протокола репозитория; оно не представляется возобновлённым
		// успешным исполнителем за пределами его штатного четырёхминутного срока выполнения.
		writer, err := kanamepg.New(pool, nil).Writer(verified)
		require.NoError(t, err)
		defer writer.Rollback(context.Background())
		cap, ok := writer.(installationTransactionControl)
		require.True(t, ok)
		err = cap.LockPendingInstallationOperation(verified, input.Operation, input.Input.AccountID, input.Proposed)
		if input.Action == "terminal-refusal" {
			require.NoError(t, verified.Err(), "fresh verified context must be live")
			require.ErrorIs(t, err, iamerr.ErrFailedPrecondition)
			require.NoError(t, enc.Encode(rid02ChildEvent{Stage: "terminal-refused", Operation: input.Operation, PID: os.Getpid()}))
		} else {
			require.NoError(t, err)
			require.NoError(t, enc.Encode(rid02ChildEvent{Stage: "row-locked", Operation: input.Operation, PID: os.Getpid()}))
			var action string
			require.NoError(t, dec.Decode(&action))
			require.Equal(t, "continue", action)
		}
		require.NoError(t, writer.Rollback(context.Background()))
		return
	}
	normal := operations.NewRepo(pool, "kaname")
	observed := &rid02ObservedOperation{}
	var boundaryReached atomic.Bool
	boundary := func(workerCtx context.Context, stage, id string) error {
		if stage != input.Boundary || !boundaryReached.CompareAndSwap(false, true) {
			return nil
		}
		if err := enc.Encode(rid02ChildEvent{Stage: stage, Operation: id, PID: os.Getpid()}); err != nil {
			return err
		}
		// Родитель владеет этой паузой IPC и точным процессом ОС. Ожидание не подделывает
		// результат БД и не сбрасывает часы. Штатный контекст исполнителя сохраняется.
		var action string
		if err := dec.Decode(&action); err != nil {
			return err
		}
		switch action {
		case "continue":
			return nil
		case "cancel":
			if err := workerCtx.Err(); err != nil {
				return fmt.Errorf("Cancel boundary requires live worker context: %w", err)
			}
			current, err := auth.Authenticate(ctx)
			saveSecrets()
			if err != nil {
				return err
			}
			cancelled, err := operationspb.NewHandler(normal).Cancel(current, &operationpb.CancelOperationRequest{OperationId: id})
			if err != nil {
				return err
			}
			if !cancelled.GetDone() {
				return fmt.Errorf("authorized Cancel did not terminalize Operation")
			}
			return nil
		default:
			return fmt.Errorf("unknown owned child control action")
		}
	}
	ops := &rid02CrashOperations{Repo: normal, observed: observed}
	repo := &rid02CrashRepo{Repository: kanamepg.New(pool, nil), operation: observed, boundary: boundary}
	create := gdapp.NewCreateGrantDelegationUseCase(repo, ops, snapshot).WithRelationStore(relations, logger).WithInstallationModel(model.plans)
	op, err := create.ExecuteInstallation(verified, input.Input)
	require.NoError(t, err)
	// Ждём настоящего отправленного исполнителя, а не только видимый бит done (Cancel
	// может выставить его, пока старая запись ещё приостановлена).
	require.NoError(t, operations.Wait(ctx))
	attempts, err := json.Marshal(observed.terminalAttempts())
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(filepath.Dir(path), "terminal-attempts.json"), attempts, 0600))
	saved, err := normal.Get(ctx, op.ID)
	require.NoError(t, err)
	require.True(t, saved.Done)
	require.NoError(t, enc.Encode(rid02ChildEvent{Stage: "worker-finished", Operation: op.ID, PID: os.Getpid()}))
}
