// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// module_seed_journal_initiator_integration_test.go — посев модулей пишет
// ресурсный журнал С ИНИЦИАТОРОМ компонента посева на базе, у соединения
// которой инициатора нет (NTF-3, Р2; Д122).
//
// # Почему отдельная база без ролевой настройки
//
// Контейнер проб несёт инициатора посева проб ролевой настройкой
// (`internal/testsupport/journalfixture`), и транзакция, открытая мимо
// открывающего службы, её НАСЛЕДУЕТ: строка журнала ложится с
// `system:kaname-fixture`, и проба зеленеет там, где установка отказывает
// `23502` (стенд kacho, посев модуля `compute`). Здесь каждое соединение пула
// первым оператором снимает инициатора на уровне сессии — так выглядит
// соединение установленной службы, у роли которой настройки нет.
//
// # Пара
//
//   - продуктовый писатель — посев своего манифеста и манифеста модуля
//     проходит, каждая записанная им строка журнала несёт
//     `system:kaname-seed`;
//   - тот же писатель, чья транзакция открыта мимо открывающего (форма до
//     починки: открытие пулом), — отказ базы `23502` по колонке `initiator`.
//
// Один факт между ними — кто открыл транзакцию.
package pg

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/journaltx"
	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleseed"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/servicemanifest"
)

// seedInitiatorProbeManifest — манифест модуля: личность, выдача и вступление
// в живую группу, то есть все журналируемые таблицы, которые посев пишет.
const seedInitiatorProbeManifest = `
apiVersion: iam/v1
module: compute
resources: []
seed:
  serviceAccounts:
    - name: kacho-compute
      account: system
      description: "Module SA: kacho-compute"
  accessBindings:
    - subjects:
        - {type: serviceAccount, name: kacho-compute}
      grantedRelation: system_viewer
      scopeType: iam.cluster
      scopeId: cluster_root
      target: allInScope
  joins:
    - serviceAccount: {account: system, name: kacho-compute}
      group: {account: system, name: module-relation-writers}
      why: "проба инициатора посева"
`

// seedInitiator — инициатор компонента посева службы.
const seedInitiator = "system:kaname-seed"

// poolWithoutInitiator — пул, у каждого соединения которого инициатора журнала
// на уровне сессии нет: ролевая настройка контейнера проб перекрыта пустым
// значением, как у соединения установленной службы.
func poolWithoutInitiator(ctx context.Context, t *testing.T) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(pgtest.NewDB(t))
	require.NoError(t, err)
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, `SELECT set_config($1, '', false)`, journaltx.SettingInitiator)
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	// Предпосылка: соединение пула инициатора НЕ несёт. Без неё пара ниже
	// утверждала бы о ролевой настройке контейнера, а не о писателе.
	var setting string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT coalesce(current_setting($1, true), '')`, journaltx.SettingInitiator).Scan(&setting))
	require.Emptyf(t, setting, "соединение пула несёт инициатора %q — проба не о писателе", setting)
	return pool
}

func seedInitiatorManifests(t *testing.T) (own *manifest.Manifest, delivered []*manifest.Manifest) {
	t.Helper()
	own, err := servicemanifest.Load()
	require.NoError(t, err, "встроенный манифест службы не разобран — вердикт беспредметен")
	m, err := manifest.Load([]byte(seedInitiatorProbeManifest))
	require.NoError(t, err, "манифест пробы не разобран — вердикт беспредметен")
	return own, []*manifest.Manifest{m}
}

func journalHighWater(ctx context.Context, t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	var id int64
	require.NoError(t, pool.QueryRow(ctx, `SELECT coalesce(max(sequence_no), 0) FROM kaname.resource_journal`).Scan(&id))
	return id
}

// TestModuleSeedJournalRowsCarryTheSeedInitiator — посев на базе без
// инициатора соединения проходит, и каждая его строка журнала несёт
// инициатора компонента посева.
func TestModuleSeedJournalRowsCarryTheSeedInitiator(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres: инициатора строки журнала выставляет база")
	}
	ctx := context.Background()
	pool := poolWithoutInitiator(ctx, t)
	own, delivered := seedInitiatorManifests(t)
	before := journalHighWater(ctx, t, pool)

	census, err := moduleseed.NewApplier(NewModuleSeedWriteRepo(pool)).Apply(ctx, own, delivered)
	require.NoErrorf(t, err, "посев модулей на базе без инициатора соединения отвергнут: %v", err)
	t.Logf("перепись посева: %s", census)

	rows, err := pool.Query(ctx, `
		SELECT coalesce(initiator, '<NULL>'), count(*)
		  FROM kaname.resource_journal WHERE sequence_no > $1
		 GROUP BY 1 ORDER BY 1`, before)
	require.NoError(t, err)
	byInitiator := map[string]int{}
	total := 0
	for rows.Next() {
		var who string
		var n int
		require.NoError(t, rows.Scan(&who, &n))
		byInitiator[who] = n
		total += n
	}
	require.NoError(t, rows.Err())
	t.Logf("строк журнала посева %d · по инициатору %v", total, byInitiator)

	// Положительный контроль: ноль строк зеленел бы на посеве, не писавшем журнал.
	require.NotZero(t, total, "посев не записал ни одной строки журнала — утверждать нечего")
	require.Equalf(t, map[string]int{seedInitiator: total}, byInitiator,
		"строки журнала посева несут не инициатора компонента посева %q", seedInitiator)
}

// bypassSeedRunner — писатель посева, чья транзакция открыта пулом мимо
// открывающего службы: форма, которой посев открывал транзакцию до починки.
type bypassSeedRunner struct{ pool *pgxpool.Pool }

func (r bypassSeedRunner) RunInWriteTx(ctx context.Context, fn func(context.Context, moduleseed.Writer) error) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := fn(ctx, moduleSeedWriter{tx: tx}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// TestModuleSeedBypassingTheJournalOpenerIsRefusedByTheDatabase — инъекция:
// тот же посев, транзакция открыта мимо открывающего, — отказ `23502` по
// колонке инициатора, и ни одной строки журнала.
func TestModuleSeedBypassingTheJournalOpenerIsRefusedByTheDatabase(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres: инициатора строки журнала выставляет база")
	}
	ctx := context.Background()
	pool := poolWithoutInitiator(ctx, t)
	own, delivered := seedInitiatorManifests(t)
	before := journalHighWater(ctx, t, pool)

	_, err := moduleseed.NewApplier(bypassSeedRunner{pool: pool}).Apply(ctx, own, delivered)
	require.Error(t, err, "посев мимо открывающего принят: строка журнала без инициатора легла бы на стенде")
	var pgErr *pgconn.PgError
	require.Truef(t, errors.As(err, &pgErr), "отказ не от базы: %v", err)
	require.Equalf(t, "23502", pgErr.Code, "отказ базы не тот: %v", err)
	require.Equalf(t, "initiator", pgErr.ColumnName, "отказ по чужой колонке: %v", err)
	require.Equal(t, before, journalHighWater(ctx, t, pool), "отказавший посев оставил строки журнала")
}
