// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/observability"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/refusaldomain"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
)

const rid06ChildInputEnv = "KANAME_RID06_FULL_STARTUP_CHILD_INPUT"

type rid06ChildInput struct {
	ConfigPath  string `json:"configPath"`
	Creator     string `json:"creator"`
	Account     string `json:"account"`
	PairOrdinal int64  `json:"pairOrdinal"`
}

// Инструментированный ТЕСТОВЫЙ исполняемый файл выполняет настоящий полный корень запуска. Это
// не опубликованный исполняемый файл, новая команда продукта или прямая подмена Execute.
// Конфигурация, аутентификация, поставка, защиты, слушатели и завершение
// используют тот же полный корень, что и штатный runServe(cfg).
func TestRID06OwnedFullStartupChild(t *testing.T) {
	path := os.Getenv(rid06ChildInputEnv)
	if path == "" {
		t.Skip("private owned full-startup child entrypoint")
	}
	own := func(fd uintptr, name string) *os.File {
		f := os.NewFile(fd, name)
		if f != nil {
			t.Cleanup(func() { _ = f.Close() })
		}
		require.NotNil(t, f)
		return f
	}
	// Унаследованные ExtraFiles автоматически не становятся опрашиваемыми дескрипторами os.Pipe.
	// Помечаем неблокирующими только эти принадлежащие фикстуре концы IPC ДО NewFile, чтобы сроки
	// регистрировались в опросчике Go. Очистка устанавливается до проверок ошибок.
	eventModeErr := syscall.SetNonblock(3, true)
	events := own(3, "rid06-events")
	require.NoError(t, eventModeErr)
	controlModeErr := syscall.SetNonblock(4, true)
	control := own(4, "rid06-control")
	require.NoError(t, controlModeErr)
	inventory := own(5, "rid06-anonymous-inventory")
	info, err := inventory.Stat()
	require.NoError(t, err)
	require.True(t, info.Mode().IsRegular() && info.Mode().Perm() == 0600)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var input rid06ChildInput
	require.NoError(t, json.Unmarshal(raw, &input))
	require.Positive(t, input.PairOrdinal)
	require.NotEmpty(t, input.Account)
	cfg, err := config.Load(input.ConfigPath)
	require.NoError(t, err)
	require.NoError(t, cfg.Validate())
	require.NoError(t, refusaldomain.Declare(refusaldomain.ProductSuffix))
	var mu sync.Mutex
	var captureErr error
	// Захват синхронен настоящей производственной выдаче, ДО любого
	// последующего отказа. Секреты получает только анонимный FD5, никогда квитанции/журналы.
	observe := func(pem, token string) {
		mu.Lock()
		defer mu.Unlock()
		if captureErr == nil {
			captureErr = json.NewEncoder(inventory).Encode([]string{pem, token})
		}
	}
	observationError := func() error {
		mu.Lock()
		defer mu.Unlock()
		if captureErr != nil {
			return fmt.Errorf("anonymous secret capture failed")
		}
		return nil
	}
	decorator := func(real kanamerepo.Repository) kanamerepo.Repository {
		r := &rid06FullStartupRepo{ridBoundaryRepo: &ridBoundaryRepo{Repository: real}}
		r.beforeWriter = func(ctx context.Context, ordinal int64) error {
			if ordinal != input.PairOrdinal {
				return nil
			}
			if err := observationError(); err != nil {
				return err
			}
			principal, ok := operations.PrincipalFromContextOK(ctx)
			if !ok || principal.Type != "service_account" || principal.ID != input.Creator {
				return fmt.Errorf("full startup boundary lacks actual creator identity")
			}
			// Operation уже создана настоящим use-case, но writer ещё не открыт.
			// Пауза после Writer удерживала бы compatibility fence и не дала бы O
			// зафиксировать Revoke. После release все штатные locks берутся без изменений.
			deadline := time.Now().Add(20 * time.Second)
			if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
				deadline = d
			}
			pendingCtx, cancel := context.WithDeadline(ctx, deadline)
			defer cancel()
			operation, err := rid06PendingBeforeWriter(pendingCtx, cfg.SingleConnDSN(), input.Creator, input.Account)
			if err != nil {
				return err
			}
			if err := events.SetWriteDeadline(deadline); err != nil {
				return err
			}
			if err := control.SetReadDeadline(deadline); err != nil {
				return err
			}
			stop := context.AfterFunc(ctx, func() { _ = control.SetReadDeadline(time.Now()) })
			defer stop()
			if err := json.NewEncoder(events).Encode(rid02ChildEvent{Stage: "before-pair", Operation: operation, PID: os.Getpid()}); err != nil {
				return err
			}
			var action string
			if err := json.NewDecoder(control).Decode(&action); err != nil {
				return fmt.Errorf("owned before-pair control failed: %w", err)
			}
			if action != "continue" {
				return fmt.Errorf("unexpected owned before-pair action")
			}
			return ctx.Err()
		}
		return r
	}
	err = runServe(cfg, installationServeDependencies{decorateInstallationRepository: decorator, observeCredential: observe})
	require.NoError(t, observationError())
	if err != nil {
		observability.NewSlogger(os.Stderr).Error("kaname exited with error", "err", err)
		t.Error("actual complete startup returned failure; structured private result retained")
	}
}

// Одно встраивание репозитория теряет этот необязательный первичный порт. Передаём его
// настоящему репозиторию; чтение и первичный результат не подменяются.
type rid06FullStartupRepo struct{ *ridBoundaryRepo }

func (r *rid06FullStartupRepo) ReaderFromPrimary(ctx context.Context) (kanamerepo.Reader, error) {
	p, ok := r.Repository.(interface {
		ReaderFromPrimary(context.Context) (kanamerepo.Reader, error)
	})
	if !ok {
		return nil, fmt.Errorf("actual repository lacks primary reader")
	}
	return p.ReaderFromPrimary(ctx)
}

// Независимое PRIMARY-чтение только наблюдает уже committed Operation. Соединение
// закрывается до сигнала родителю; ни writer TX, ни блокировка строки не создаются.
func rid06PendingBeforeWriter(ctx context.Context, dsn, creator, account string) (string, error) {
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return "", fmt.Errorf("pending Operation primary connection failed")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = conn.Close(cleanup)
	}()
	var recovery bool
	if err := conn.QueryRow(ctx, "SELECT pg_is_in_recovery()").Scan(&recovery); err != nil || recovery {
		return "", fmt.Errorf("pending Operation requires actual PRIMARY")
	}
	meta, err := anypb.New(&iamv1.CreateGrantDelegationMetadata{})
	if err != nil {
		return "", err
	}
	rows, err := conn.Query(ctx, `SELECT id,metadata_data,resource_id FROM kaname.operations
 WHERE NOT done AND principal_type='service_account' AND principal_id=$1
 AND account_id=$2 AND metadata_type=$3 ORDER BY id LIMIT 2`, creator, account, meta.TypeUrl)
	if err != nil {
		return "", fmt.Errorf("pending Operation primary census failed")
	}
	defer rows.Close()
	operation := ""
	for rows.Next() {
		var id, resource string
		var data []byte
		if err := rows.Scan(&id, &data, &resource); err != nil {
			return "", fmt.Errorf("pending Operation primary row invalid")
		}
		var decoded iamv1.CreateGrantDelegationMetadata
		if operation != "" || id == "" || resource == "" ||
			(&anypb.Any{TypeUrl: meta.TypeUrl, Value: data}).UnmarshalTo(&decoded) != nil ||
			decoded.AccountId != account || decoded.GrantDelegationId != resource {
			return "", fmt.Errorf("pending Operation exact identity is missing or ambiguous")
		}
		operation = id
	}
	if rows.Err() != nil || operation == "" || ctx.Err() != nil {
		return "", fmt.Errorf("pending Operation primary census incomplete")
	}
	return operation, nil
}
