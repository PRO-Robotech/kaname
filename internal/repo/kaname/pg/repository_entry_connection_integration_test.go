// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// Проверяется настоящий отказ PostgreSQL при открытии соединения, без DML
// бизнес-таблиц и без подмены авторизатора. Пулы имеют ровно по одной lease.
func TestRepositoryEntryConnectionFailureAndRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("требуется PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	dsn := pgtest.NewDB(t)
	admin, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	defer admin.Close()
	role := fmt.Sprintf("entry_probe_%d", time.Now().UnixNano())
	quoted := pgx.Identifier{role}.Sanitize()
	_, err = admin.Exec(ctx, "CREATE ROLE "+quoted+" LOGIN PASSWORD 'entry_probe_only'")
	require.NoError(t, err)
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		_, dropErr := admin.Exec(cleanup, "DROP ROLE "+quoted)
		require.NoError(t, dropErr)
	}()
	newPool := func(name string) *pgxpool.Pool {
		cfg, parseErr := pgxpool.ParseConfig(dsn)
		require.NoError(t, parseErr)
		cfg.ConnConfig.User = role
		cfg.ConnConfig.Password = "entry_probe_only"
		cfg.ConnConfig.RuntimeParams["application_name"] = name
		cfg.ConnConfig.RuntimeParams["default_transaction_isolation"] = "repeatable read"
		cfg.MaxConns, cfg.MinConns = 1, 0
		pool, poolErr := pgxpool.NewWithConfig(ctx, cfg)
		require.NoError(t, poolErr)
		return pool
	}
	primary, replica := newPool("entry_primary"), newPool("entry_replica")
	defer primary.Close()
	defer replica.Close()
	repo := New(primary, replica)
	type opened struct {
		tx       pgx.Tx
		rollback func(context.Context) error
	}
	ports := []struct {
		name                             string
		pool                             *pgxpool.Pool
		application, readOnly, isolation string
		open                             func(*testing.T, context.Context) (opened, error)
	}{
		{"Reader", replica, "entry_replica", "on", "repeatable read", func(t *testing.T, c context.Context) (opened, error) {
			r, e := repo.Reader(c)
			if e != nil {
				require.Nil(t, r)
				return opened{}, e
			}
			return opened{r.(*readTx).tx, r.Rollback}, nil
		}},
		{"Writer", primary, "entry_primary", "off", "repeatable read", func(t *testing.T, c context.Context) (opened, error) {
			w, e := repo.Writer(c)
			if e != nil {
				require.Nil(t, w)
				return opened{}, e
			}
			return opened{w.(*writeTx).tx, w.Rollback}, nil
		}},
		{"ReaderFromPrimary", primary, "entry_primary", "on", "repeatable read", func(t *testing.T, c context.Context) (opened, error) {
			r, e := repo.ReaderFromPrimary(c)
			if e != nil {
				require.Nil(t, r)
				return opened{}, e
			}
			return opened{r.(*readTx).tx, r.Rollback}, nil
		}},
		{"MembershipReader", replica, "entry_replica", "on", "repeatable read", func(t *testing.T, c context.Context) (opened, error) {
			s, e := repo.MembershipReader(c)
			if e != nil {
				require.Nil(t, s)
				return opened{}, e
			}
			return opened{s.(*membershipSession).tx, func(c context.Context) error { s.Close(c); return nil }}, nil
		}},
		{"PoolTxBeginner", primary, "entry_primary", "off", "repeatable read", func(t *testing.T, c context.Context) (opened, error) {
			raw, e := NewPoolTxBeginner(primary).Begin(c)
			if e != nil {
				require.Nil(t, raw)
				return opened{}, e
			}
			tx := raw.(pgx.Tx)
			return opened{tx, tx.Rollback}, nil
		}},
		{"RegistrationTxBeginner", primary, "entry_primary", "off", "read committed", func(t *testing.T, c context.Context) (opened, error) {
			raw, e := NewRegistrationTxBeginner(primary).Begin(c)
			if e != nil {
				require.Nil(t, raw)
				return opened{}, e
			}
			tx := raw.(pgx.Tx)
			return opened{tx, tx.Rollback}, nil
		}},
	}
	for _, port := range ports {
		t.Run(port.name, func(t *testing.T) {
			assertSuccess := func() {
				o, openErr := port.open(t, ctx)
				require.NoError(t, openErr)
				defer func() {
					cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
					defer stop()
					_ = o.rollback(cleanup)
				}()
				require.EqualValues(t, 1, port.pool.Stat().AcquiredConns())
				var application, readOnly, isolation, user string
				require.NoError(t, o.tx.QueryRow(ctx, `SELECT current_setting('application_name'), current_setting('transaction_read_only'), current_setting('transaction_isolation'), current_user`).Scan(&application, &readOnly, &isolation, &user))
				require.Equal(t, port.application, application)
				require.Equal(t, port.readOnly, readOnly)
				require.Equal(t, port.isolation, isolation)
				require.Equal(t, role, user)
				// Сервер действительно запрещает запись в read-only TX, а не только
				// сообщает желаемую настройку. Временная таблица не затрагивает IAM.
				_, writeErr := o.tx.Exec(ctx, "CREATE TEMP TABLE entry_mode_probe (n int) ON COMMIT DROP")
				if port.readOnly == "on" {
					var pgErr *pgconn.PgError
					require.ErrorAs(t, writeErr, &pgErr)
					require.Equal(t, "25006", pgErr.Code)
				} else {
					require.NoError(t, writeErr)
				}
				require.NoError(t, o.rollback(ctx))
				require.Zero(t, port.pool.Stat().AcquiredConns())
			}
			assertSuccess()
			_, err = admin.Exec(ctx, "ALTER ROLE "+quoted+" NOLOGIN")
			require.NoError(t, err)
			primary.Reset()
			replica.Reset()
			o, failure := port.open(t, ctx)
			require.Nil(t, o.tx)
			require.NoError(t, ctx.Err())
			require.ErrorIs(t, failure, iamerr.ErrUnavailable)
			var envelope *pgconn.ConnectError
			require.ErrorAs(t, failure, &envelope)
			var startup *pgconn.PgError
			require.ErrorAs(t, failure, &startup)
			require.Equal(t, "28000", startup.Code)
			wire := status.Convert(shared.MapRepoErr(failure))
			require.Equal(t, codes.Unavailable, wire.Code())
			require.Equal(t, shared.UnavailableMessage, wire.Message())
			require.Zero(t, primary.Stat().AcquiredConns())
			require.Zero(t, replica.Stat().AcquiredConns())
			_, err = admin.Exec(ctx, "ALTER ROLE "+quoted+" LOGIN")
			require.NoError(t, err)
			assertSuccess()
			canceled, stop := context.WithCancel(ctx)
			stop()
			o, failure = port.open(t, canceled)
			require.Nil(t, o.tx)
			require.ErrorIs(t, failure, context.Canceled)
			require.Equal(t, codes.Unavailable, status.Code(shared.MapRepoErr(failure)))
			require.Zero(t, port.pool.Stat().AcquiredConns())
		})
	}
}
