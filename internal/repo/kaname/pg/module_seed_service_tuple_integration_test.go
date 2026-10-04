// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// module_seed_service_tuple_integration_test.go — служебный кортеж строки
// `notifications` доезжает до ПРЯМОГО ФАКТА через журнал, и повтор посева его не
// пишет заново (приёмка NTF-1, NTF1-F01 кортеж `reader`, NTF1-F03, NTF1-F21 (а);
// замысел З17).
//
// Утверждается факт, а не вызов: решение о доступе принимает `relation_fact`, и
// «журнал записан» было бы утверждением о глаголе, а не о свойстве.
package pg_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleseed"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// notificationsProbeManifest — фикстурный модуль `probe` со строкой F01.
const notificationsProbeManifest = `
apiVersion: iam/v1
module: probe
resources: []
notifications: {namespace: probe, readers: [notify]}
`

// ownNotificationsManifest — свой манифест службы в форме F21 (а): только
// читатель, без пространства.
const ownNotificationsManifest = `
apiVersion: iam/v1
module: iam
resources: []
notifications: {readers: [notify]}
`

func factCount(ctx context.Context, t *testing.T, pool *pgxpool.Pool, where string, args ...any) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.relation_fact WHERE `+where, args...).Scan(&n))
	return n
}

// TestNTF1F01_FeedReaderFactFollowsTheJournalAndRepeatWritesNothing — первый
// прогон заводит `service:notify reader notification_feed:probe` фактом и одной
// строкой журнала; второй не пишет ни факта, ни строки журнала.
func TestNTF1F01_FeedReaderFactFollowsTheJournalAndRepeatWritesNothing(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres: свойство утверждается прогоном, а не чтением кода")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pgtest.NewDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	m, err := manifest.Load([]byte(notificationsProbeManifest))
	require.NoError(t, err, "проба подаёт манифест, который разбор не принимает — вердикт беспредметен")
	applier := moduleseed.NewApplier(kanamepg.NewModuleSeedWriteRepo(pool))

	journal := func() int {
		var n int
		require.NoError(t, pool.QueryRow(ctx, `
			SELECT count(*) FROM kaname.fga_outbox
			 WHERE payload->>'user' = 'service:notify' AND payload->>'object' = 'notification_feed:probe'`).Scan(&n))
		return n
	}

	first, err := applier.ApplyAll(ctx, []*manifest.Manifest{m})
	require.NoError(t, err)
	t.Logf("первый прогон: %s", first)
	require.Equal(t, 1, factCount(ctx, t, pool,
		`subject = 'service:notify' AND relation = 'reader' AND object_type = 'notification_feed' AND object_id = 'probe'`),
		"факта reader ленты нет: строка применена, а решение о доступе его не увидит")
	require.Equal(t, 1, journal(), "факт без строки журнала — второй производитель факта")
	_, written := first.Totals()
	// Два служебных кортежа: читатель ленты и проекция `sender` записи
	// выдачи пространства, заведённой этим посевом (NTF-1 Р5).
	require.Equal(t, 2, written)
	require.Equal(t, 1, factCount(ctx, t, pool,
		`subject = 'service:probe' AND relation = 'sender' AND object_type = 'notification_namespace' AND object_id = 'probe'`),
		"проекции sender записи выдачи нет")

	second, err := applier.ApplyAll(ctx, []*manifest.Manifest{m})
	require.NoError(t, err)
	t.Logf("второй прогон: %s", second)
	_, written = second.Totals()
	require.Zero(t, written, "повтор посева записал служебный кортеж заново")
	require.Equal(t, 1, journal(), "повтор посева положил вторую строку журнала")

	require.Zero(t, factCount(ctx, t, pool,
		`subject LIKE 'service:%' AND subject <> 'service:notify' AND NOT (subject = 'service:probe' AND relation = 'sender')`),
		"заведён служебный субъект, кроме notify и проекции sender своего модуля")
}

// TestNTF1F21_OwnManifestGrantsOnlyTheKanameFeedReader — свой манифест службы
// заводит ровно `service:notify reader notification_feed:kaname`; субъекта
// `service:kaname` и объекта `notification_namespace:kaname` нет.
func TestNTF1F21_OwnManifestGrantsOnlyTheKanameFeedReader(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pgtest.NewDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	own, err := manifest.Load([]byte(ownNotificationsManifest), manifest.AsAccessService())
	require.NoError(t, err)
	census, err := moduleseed.NewApplier(kanamepg.NewModuleSeedWriteRepo(pool)).Apply(ctx, own, nil)
	require.NoError(t, err)
	t.Logf("перепись: %s", census)

	require.Equal(t, 1, factCount(ctx, t, pool, `subject LIKE 'service:%'`),
		"служебных фактов не ровно один")
	require.Equal(t, 1, factCount(ctx, t, pool,
		`subject = 'service:notify' AND relation = 'reader' AND object_type = 'notification_feed' AND object_id = 'kaname'`))
	require.Zero(t, factCount(ctx, t, pool, `subject = 'service:kaname' OR object_type = 'notification_namespace'`),
		"служба доступа получила служебного принципала либо пространство (MRW-1 Р1)")
}
