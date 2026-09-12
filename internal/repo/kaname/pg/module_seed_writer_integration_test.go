// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// module_seed_writer_integration_test.go — свойства применителя посева, которые
// нельзя утверждать иначе как прогоном против живой Postgres (#2452).
//
// # Почему именно эти три
//
// Применитель зовётся НА КАЖДОМ СТАРТЕ службы. Значит его отказ — отказ пуска, а
// его повтор — обычное течение жизни, а не край. Отсюда три свойства, и каждое
// стоит своей пробы:
//
//  1. ПОВТОР НИЧЕГО НЕ ПИШЕТ. Применитель, кладущий строку заново на каждом
//     старте, наблюдаемо исправен: перепись растёт, состояние нет. Заметить это
//     можно только числом записанного во ВТОРОМ прогоне.
//  2. ССЫЛКА, КОТОРОЙ НЕТ, — ОТКАЗ, А НЕ ПРОПУСК. Вставка, чей резолв не дал
//     строки, прошла бы нулём затронутых строк и выглядела бы применённой; это
//     ровно тот класс, из-за которого заведена эта задача.
//  3. ПРЯМОЙ ФАКТ СКЛАДЫВАЕТСЯ ИЗ ЖУРНАЛА. Применитель пишет журнал, а факт
//     производит триггер. Утверждать «журнал записан» значило бы утверждать о
//     вызове, а не о свойстве: решение о доступе принимает факт.
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

// seedProbeManifest — манифест модуля, объявляющий посев всех форм, которые
// применитель умеет: личность, вступление в ЧУЖУЮ группу и выдачу отношением.
//
// Модуль назван `vpc`, потому что имя судится закрытым набором платформы: имя
// вне его отвергнет разбор, и проба краснела бы на форме документа вместо
// предмета. Группа взята ЖИВАЯ — та, что уже лежит в базе: вступают в чужую
// группу, а не в свою, и заводить её посевом модуля запрещает валидатор
// связности.
const seedProbeManifest = `
apiVersion: iam/v1
module: vpc
resources: []
seed:
  serviceAccounts:
    - name: kacho-vpc
      account: kacho-system
      description: "Module SA: kacho-vpc (SEC-C least-priv)"
  accessBindings:
    - subjects:
        - {type: serviceAccount, name: kacho-vpc}
      grantedRelation: system_viewer
      scopeType: iam.cluster
      scopeId: cluster_root
      target: allInScope
  joins:
    - serviceAccount: {account: kacho-system, name: kacho-vpc}
      group: {account: kacho-system, name: module-quota-readers}
      why: "проба применителя посева"
`

// TestModuleSeedApplierIsIdempotent — второй прогон не пишет ничего.
func TestModuleSeedApplierIsIdempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres: свойство утверждается прогоном, а не чтением кода")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pgtest.NewDB(t))
	require.NoError(t, err)
	// Закрытие С ПРЕДЕЛОМ: отложенное закрытие ждёт возврата ВСЕХ соединений, а
	// проба, упавшая внутри открытой транзакции, своё уже не вернёт — тогда
	// «не выполнилось» приходит к читателю под видом красного, и вердикта нет ни
	// у одной пробы пакета.
	pgtest.ClosePoolAtEnd(t, pool)

	m, err := manifest.Load([]byte(seedProbeManifest))
	require.NoError(t, err, "проба подаёт манифест, который разбор не принимает — вердикт беспредметен")

	applier := moduleseed.NewApplier(kanamepg.NewModuleSeedWriteRepo(pool))

	first, err := applier.ApplyAll(ctx, []*manifest.Manifest{m})
	require.NoError(t, err)
	declaredFirst, writtenFirst := first.Totals()
	t.Logf("первый прогон: %s", first)

	// Положительный контроль: без него «второй прогон записал ноль» зеленело бы
	// на применителе, который не пишет НИКОГДА.
	require.NotZero(t, declaredFirst, "манифест пробы не объявил ни одной строки — утверждать нечего")
	require.Equal(t, declaredFirst, writtenFirst,
		"первый прогон записал %d из %d объявленных — предпосылка повтора не создана",
		writtenFirst, declaredFirst)

	second, err := applier.ApplyAll(ctx, []*manifest.Manifest{m})
	require.NoError(t, err)
	declaredSecond, writtenSecond := second.Totals()
	t.Logf("второй прогон: %s", second)

	require.Equal(t, declaredFirst, declaredSecond,
		"второй прогон увидел другое ОБЪЯВЛЕНИЕ — сравниваются разные предметы")
	require.Zerof(t, writtenSecond,
		"повтор записал %d строк(и): применитель кладёт заново на каждом старте, "+
			"и снаружи это неотличимо от исправной работы", writtenSecond)
}

// TestModuleSeedApplierRefusesAnUnresolvableReference — ссылка, которой нет,
// даёт ОТКАЗ, а не тихий пропуск.
func TestModuleSeedApplierRefusesAnUnresolvableReference(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pgtest.NewDB(t))
	require.NoError(t, err)
	// Закрытие С ПРЕДЕЛОМ: отложенное закрытие ждёт возврата ВСЕХ соединений, а
	// проба, упавшая внутри открытой транзакции, своё уже не вернёт — тогда
	// «не выполнилось» приходит к читателю под видом красного, и вердикта нет ни
	// у одной пробы пакета.
	pgtest.ClosePoolAtEnd(t, pool)

	// Один факт против положительного близнеца выше: группа названа именем,
	// которого в базе нет. Всё остальное — то же самое.
	broken := `
apiVersion: iam/v1
module: vpc
resources: []
seed:
  serviceAccounts:
    - name: kacho-vpc
      account: kacho-system
      description: "Module SA: kacho-vpc (SEC-C least-priv)"
  joins:
    - serviceAccount: {account: kacho-system, name: kacho-vpc}
      group: {account: kacho-system, name: group-that-does-not-exist}
      why: "проба отказа применителя посева"
`
	m, err := manifest.Load([]byte(broken))
	require.NoError(t, err, "разбор обязан принять документ: предмет пробы — ПРИМЕНЕНИЕ, а не форма")

	applier := moduleseed.NewApplier(kanamepg.NewModuleSeedWriteRepo(pool))
	_, err = applier.ApplyAll(ctx, []*manifest.Manifest{m})
	require.Error(t, err, "нерезолвящаяся группа принята молча — строка не доехала, а применитель отчитался успехом")
	require.Contains(t, err.Error(), "group-that-does-not-exist",
		"отказ не называет ПАРУ, которой нет: оператор пойдёт искать причину в манифесте")

	// Транзакция на модуль: отказ на вступлении уносит и личность.
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.service_accounts WHERE name = 'kacho-vpc'`).Scan(&n))
	require.Zerof(t, n,
		"личность осталась при отказавшем вступлении (%d): посев модуля обязан лечь целиком либо не лечь вовсе", n)
}

// TestModuleSeedApplierFactFollowsTheJournal — прямой факт отношения появляется
// вместе с журналом, а не вместо него.
func TestModuleSeedApplierFactFollowsTheJournal(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pgtest.NewDB(t))
	require.NoError(t, err)
	// Закрытие С ПРЕДЕЛОМ: отложенное закрытие ждёт возврата ВСЕХ соединений, а
	// проба, упавшая внутри открытой транзакции, своё уже не вернёт — тогда
	// «не выполнилось» приходит к читателю под видом красного, и вердикта нет ни
	// у одной пробы пакета.
	pgtest.ClosePoolAtEnd(t, pool)

	m, err := manifest.Load([]byte(seedProbeManifest))
	require.NoError(t, err)

	applier := moduleseed.NewApplier(kanamepg.NewModuleSeedWriteRepo(pool))
	_, err = applier.ApplyAll(ctx, []*manifest.Manifest{m})
	require.NoError(t, err)

	var saID string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT id FROM kaname.service_accounts WHERE name = 'kacho-vpc'`).Scan(&saID))
	subject := "service_account:" + saID

	var viewerFacts, memberFacts int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kaname.relation_fact
		 WHERE subject = $1 AND object_type = 'cluster' AND relation = 'system_viewer'`,
		subject).Scan(&viewerFacts))
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kaname.relation_fact
		 WHERE subject = $1 AND object_type = 'group' AND relation = 'member'`,
		subject).Scan(&memberFacts))

	t.Logf("перепись: прямых фактов у %s — чтение внутренней поверхности %d · членство %d",
		subject, viewerFacts, memberFacts)

	require.Equalf(t, 1, viewerFacts,
		"прямого факта чтения внутренней поверхности нет (%d): выдача записана, а решение о "+
			"доступе принимает факт — модуль остался бы без права при исправной на вид строке",
		viewerFacts)
	require.Equalf(t, 1, memberFacts,
		"прямого факта членства нет (%d): членство записано, а вопрос о нём задаётся факту", memberFacts)
}
