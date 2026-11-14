// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Проба только входа runner: настоящий pool/driver формирует ConnectError,
// DialFunc не открывает сеть. Bundle не нужен: до authority/read/body дело
// не доходит. Положительное полномочие доказывается отдельной actual FB29.
func TestBindingDecisionEntryFailureKeepsBackendClassification(t *testing.T) {
	for _, mode := range []string{"create", "update", "delegated"} {
		t.Run(mode, func(t *testing.T) {
			cfg, err := pgxpool.ParseConfig("host=127.0.0.1 port=5432 user=private_entry database=private_entry sslmode=disable")
			require.NoError(t, err)
			cfg.MaxConns, cfg.MinConns = 1, 0
			cause := &pgconn.PgError{Code: "28000", Message: "private_login is not permitted to log in"}
			var dials atomic.Int32
			cfg.ConnConfig.DialFunc = func(context.Context, string, string) (net.Conn, error) {
				dials.Add(1)
				return nil, cause
			}
			pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
			require.NoError(t, err)
			defer pool.Close()
			writers := &GrantPolicyWriters{repo: New(pool, nil)}
			actor := domain.Subject{Type: domain.SubjectTypeUser, ID: "usr_entry_probe"}
			proposed := domain.AccessBinding{ID: "ab_entry_probe"}
			called := 0
			apply := func(context.Context, kaname.SemanticAuthorityWriter, domain.AccessBinding, domain.Role) error {
				called++
				return nil
			}
			if mode == "delegated" {
				actor.Type = domain.SubjectTypeServiceAccount
				err = writers.RunDelegatedBindingDecision(context.Background(), actor, proposed, nil, apply)
			} else {
				err = writers.RunBindingDecision(context.Background(), actor, proposed, mode == "create", nil, apply)
			}
			require.ErrorIs(t, err, iamerr.ErrUnavailable)
			require.ErrorIs(t, err, cause)
			var envelope *pgconn.ConnectError
			require.ErrorAs(t, err, &envelope)
			require.EqualValues(t, 1, dials.Load(), "ошибка LOGIN не запускает повтор решения")
			require.Zero(t, called, "ошибка входа не допускает бизнес-тело")
			require.Zero(t, pool.Stat().AcquiredConns())
			wire := status.Convert(shared.MapRepoErr(err))
			require.Equal(t, codes.Unavailable, wire.Code())
			require.Equal(t, shared.UnavailableMessage, wire.Message())
		})
	}
}

func TestBindingDecisionEntryValidationAndCancellationStayDistinct(t *testing.T) {
	// Пустой Repository делает любое ошибочное продвижение к Acquire заметным:
	// эти отказы обязаны произойти до обращения к pool.
	writers := &GrantPolicyWriters{repo: &Repository{}}
	actor := domain.Subject{Type: domain.SubjectTypeUser, ID: "usr_entry_probe"}
	proposed := domain.AccessBinding{ID: "ab_entry_probe"}
	called := 0
	t.Cleanup(func() { require.Zero(t, called, "входной отказ дошёл до бизнес-тела") })
	apply := func(context.Context, kaname.SemanticAuthorityWriter, domain.AccessBinding, domain.Role) error {
		called++
		return nil
	}
	t.Run("invalid_plan", func(t *testing.T) {
		err := writers.RunBindingDecision(context.Background(), actor, domain.AccessBinding{}, true, nil, apply)
		require.ErrorIs(t, err, kaname.ErrInvalidAuthorityFencePlan)
		require.NotErrorIs(t, err, iamerr.ErrUnavailable)
	})
	t.Run("delegated_wrong_actor", func(t *testing.T) {
		err := writers.RunDelegatedBindingDecision(context.Background(), actor, proposed, nil, apply)
		require.ErrorIs(t, err, iamerr.ErrPermissionDenied)
		require.Equal(t, codes.PermissionDenied, status.Code(shared.MapRepoErr(err)))
	})
	for _, tc := range []struct {
		name     string
		deadline bool
		cause    error
	}{
		{"canceled", false, context.Canceled}, {"deadline", true, context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var ctx context.Context
			var cancel context.CancelFunc
			if tc.deadline {
				ctx, cancel = context.WithDeadline(context.Background(), time.Unix(1, 0))
			} else {
				ctx, cancel = context.WithCancel(context.Background())
			}
			cancel()
			err := writers.RunBindingDecision(ctx, actor, proposed, true, nil, apply)
			require.ErrorIs(t, err, tc.cause)
			require.Equal(t, codes.Unavailable, status.Code(shared.MapRepoErr(err)))
		})
	}
}
