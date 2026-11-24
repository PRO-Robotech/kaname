// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os/signal"
	"syscall"
	"time"

	"github.com/PRO-Robotech/corelib/migratorcli/cobraargs"
	"github.com/PRO-Robotech/kaname/internal/authzsnapshot"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"
)

func newFollowPublicationsCmd(opts *rootOptions) *cobra.Command {
	var interval time.Duration
	cmd := &cobra.Command{
		Use:   "follow-publications",
		Short: "Активировать последующие подтверждённые публикации каталога",
		Args:  cobraargs.NoExtraArguments,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if interval <= 0 {
				return fmt.Errorf("интервал опроса публикаций должен быть положительным")
			}
			dsn, err := validatedMigrationDSN(opts)
			if err != nil {
				return err
			}
			cfg, err := pgxpool.ParseConfig(dsn)
			if err != nil {
				return err
			}
			cfg.MaxConns = 1
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGTERM, syscall.SIGINT)
			defer stop()
			pool, err := pgxpool.NewWithConfig(ctx, cfg)
			if err != nil {
				return err
			}
			defer pool.Close()
			return followCatalogPublications(ctx, cmd, pool, interval)
		},
	}
	cmd.Flags().DurationVar(&interval, "interval", 2*time.Second, "Интервал чтения журнала публикаций")
	return cmd
}

// Следит за последовательностью уже допущенных публикаций. Первоначальную
// активацию выполняет владелец отдельной явной командой.
func followCatalogPublications(ctx context.Context, cmd *cobra.Command, pool *pgxpool.Pool, interval time.Duration) error {
	repo := kanamepg.New(pool, nil)
	out := json.NewEncoder(cmd.OutOrStdout())
	var observed int64
	var lastFailure string
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for ctx.Err() == nil {
		attempt, cancel := context.WithTimeout(ctx, 30*time.Second)
		next, activated, err := followCatalogPublicationOnce(attempt, pool, repo, observed)
		cancel()
		if err != nil && ctx.Err() == nil {
			if err.Error() != lastFailure {
				cmd.PrintErrf("активация публикации каталога отложена: %v\n", err)
			}
			lastFailure = err.Error()
		}
		if err == nil {
			lastFailure = ""
			observed = next
			if activated {
				if err := out.Encode(map[string]any{"action": "activate-publication", "revision": observed}); err != nil {
					return err
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
	return nil
}

func followCatalogPublicationOnce(ctx context.Context, pool *pgxpool.Pool, repo *kanamepg.Repository, observed int64) (int64, bool, error) {
	var head int64
	err := pool.QueryRow(ctx, `
		SELECT COALESCE((SELECT revision FROM kaname.publication_model_revision ORDER BY revision DESC LIMIT 1), 0)
	`).Scan(&head)
	if err != nil {
		return observed, false, err
	}
	if head < observed {
		return observed, false, authzsnapshot.ErrUnconfirmed
	}
	if head == observed {
		return observed, false, nil
	}
	candidate, err := repo.LoadPublicationAuthorityBundle(ctx)
	if err != nil {
		return observed, false, err
	}
	if candidate.Revision != head {
		return observed, false, authzsnapshot.ErrUnconfirmed
	}
	activated, err := repo.AdvanceNextCatalogPublication(ctx, candidate)
	if err != nil {
		return observed, false, err
	}
	return head, activated, nil
}
