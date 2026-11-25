// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package seed_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

// Наблюдаем результат настоящего входа после возврата из OpenParticipant.
type reseedAdmissionProbe struct {
	*kanamepg.Repository
	opens      int
	afterFirst func(kaname.Writer, error)
}

func (p *reseedAdmissionProbe) InstallationAuthorityWriter(ctx context.Context, kind kaname.AuthorityOperation) (kaname.Writer, error) {
	p.opens++
	w, err := p.Repository.InstallationAuthorityWriter(ctx, kind)
	if p.opens == 1 {
		p.afterFirst(w, err)
	}
	return w, err
}

func TestRoleVerbReseedRecoversAfterPostgresConsumerAdmissionTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	baseCtx, pool := newReseedPool(t)
	ctx, cancel := context.WithTimeout(baseCtx, time.Minute)
	defer cancel()
	first := seedProbeSystemRole(t, ctx, pool, "rol-admission-a", "probe.admission.a", materializingRules)
	second := seedProbeSystemRole(t, ctx, pool, "rol-admission-b", "probe.admission.b", materializingRules)
	require.Zero(t, projectionSizeOf(t, ctx, pool, first))
	require.Zero(t, projectionSizeOf(t, ctx, pool, second))

	cfg := pool.Config()
	cfg.MaxConns = 1
	writerPool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	defer writerPool.Close()
	var pid uint32
	require.NoError(t, writerPool.AcquireFunc(ctx, func(conn *pgxpool.Conn) error {
		pid = conn.Conn().PgConn().PID()
		_, err := conn.Exec(ctx, `SET statement_timeout = '3s'`)
		return err
	}))

	holder, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer holder.Rollback(baseCtx)
	_, err = holder.Exec(ctx, `SELECT pg_advisory_xact_lock(1262569292,0)`)
	require.NoError(t, err)

	probe := &reseedAdmissionProbe{Repository: kanamepg.New(writerPool, nil)}
	probe.afterFirst = func(w kaname.Writer, err error) {
		if w != nil {
			_ = w.Rollback(ctx)
			t.Fatal("первый вход получил writer при удержанном consumer-admission")
		}
		var backend *pgconn.PgError
		require.ErrorAs(t, err, &backend)
		require.Equal(t, "57014", backend.Code)
		require.Equal(t, "canceling statement due to statement timeout", backend.Message)
		require.NoError(t, ctx.Err())
		require.NoError(t, writerPool.AcquireFunc(ctx, func(conn *pgxpool.Conn) error {
			pg := conn.Conn().PgConn()
			require.Equal(t, pid, pg.PID())
			require.Equal(t, byte('I'), pg.TxStatus(), "исходная транзакция уже откачена")
			_, err := conn.Exec(ctx, `RESET statement_timeout`)
			return err
		}))
		require.NoError(t, holder.Rollback(ctx))
	}

	census, err := seed.ReseedSystemRoleVerbs(ctx, probe, pool, catalogfixture.Facts(), nil)
	require.NoError(t, err)
	require.True(t, census.Completed)
	require.GreaterOrEqual(t, census.Examined, 2)
	require.Equal(t, census.Examined+1, probe.opens)
	require.Equal(t, census.Examined, census.Reseeded)
	require.Zero(t, census.Failed)
	require.Positive(t, projectionSizeOf(t, ctx, pool, first))
	require.Positive(t, projectionSizeOf(t, ctx, pool, second))
}
