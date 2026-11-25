// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"os"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Пуск службы владеет возвращаемым пулом. При отказе пул закрывается,
// а ошибка завершает пуск.
func prepareRolePolicyPool(ctx context.Context, cfg config.Config, primary *pgxpool.Pool, profile *fullStartupProfile) (*pgxpool.Pool, *kanamepg.RolePolicyWriters, error) {
	settings := cfg.Repository.Postgres.RoleWriter
	if err := settings.Validate(); err != nil {
		return nil, nil, err
	}
	if !settings.Enabled() {
		return nil, nil, nil
	}
	if primary == nil || profile == nil || profile.primary == nil {
		return nil, nil, fmt.Errorf("repository.postgres.role-writer requires the prepared full startup profile")
	}
	password := "" // У отдельной учётной записи свой пароль.
	if settings.PasswordFromEnv != "" {
		var present bool
		password, present = os.LookupEnv(settings.PasswordFromEnv)
		if !present || password == "" {
			return nil, nil, fmt.Errorf("repository.postgres.role-writer.password-from-env is missing or empty")
		}
	}
	// Копия настроек сохраняет адрес, TLS и поведение основного пула.
	roleConfig := primary.Config()
	roleConfig.ConnConfig.User = settings.User
	roleConfig.ConnConfig.Password = password
	if settings.MaxConns > 0 {
		roleConfig.MaxConns = int32(settings.MaxConns)
	}
	roleConfig.MinConns = min(roleConfig.MinConns, roleConfig.MaxConns)
	roleConfig.MinIdleConns = min(roleConfig.MinIdleConns, roleConfig.MaxConns)
	// До открытия пула проверяем сумму лимитов на одну реплику.
	total := int64(primary.Config().MaxConns) + int64(roleConfig.MaxConns)
	if total <= 0 || total > 1<<31-1 {
		return nil, nil, fmt.Errorf("repository.postgres.role-writer: combined pool cap exceeds int32")
	}
	ceiling, err := coredb.ReadConnCeiling(ctx, primary)
	if err != nil {
		return nil, nil, fmt.Errorf("role-writer database connection ceiling: %w", err)
	}
	if err := connBudgetComplaint(int32(total), cfg.Repository.Postgres.ReplicaBudget, ceiling); err != nil {
		return nil, nil, fmt.Errorf("repository.postgres.role-writer.max-conns included in combined pool cap: %w", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, roleConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("role-writer pool creation: %w", err)
	}
	success := false
	defer func() {
		if !success {
			pool.Close()
		}
	}()
	if err := pool.Ping(ctx); err != nil {
		return nil, nil, fmt.Errorf("role-writer pool ping: %w", err)
	}
	repository := kanamepg.New(pool, nil)
	contract, err := kanamepg.NewFullWriterContract(ctx, repository, profile.bundle)
	if err != nil {
		return nil, nil, fmt.Errorf("role-writer full contract: %w", err)
	}
	repository, err = repository.WithFullWriterContract(contract)
	if err != nil {
		return nil, nil, err
	}
	writers, err := kanamepg.NewRolePolicyWriters(ctx, profile.primary, repository, profile.bundle)
	if err != nil {
		return nil, nil, fmt.Errorf("role-writer dependency: %w", err)
	}
	success = true
	return pool, writers, nil
}
