// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// module_sa_dead_roles_integration_test.go — гейт на снятие МЁРТВЫХ объявлений
// ШЕСТИ служебных учёток модулей, и — отдельным утверждением — на сохранность
// того, чем эти учётки реально работают.
//
// # Что снято и почему это не изменило ни одного доступа
//
// Шесть ролей — `module.{api_gateway,compute,nlb,registry,storage,vpc}_sa` —
// объявляли правила, НИ ОДНО из имён которых закрытая таблица типов не несёт:
// `iam.projects` (таблица несёт `iam.project`), `vpc.subnets` (`vpc.subnet`),
// `vpc.security_groups` (`vpc.securityGroup`), `vpc.addresses` (`vpc.address`),
// `compute.zones` (топология вообще ушла в geo). Разрешимое множество у каждой
// из шести — ПУСТОЕ. Материализация спрашивает таблицу, не получает типа и не
// эмитит ни одного кортежа («a typo'd type never grants», reconcile/tuples.go).
//
// # Чем эти учётки работают на самом деле
//
// Три пути, ни один не идёт через роль, и каждый замерен отдельно:
//
//  1. ЗАПИСЬ в хранилище отношений — кортеж `fga_writer@iam_fgaproxy:system`,
//     посеянный НАПРЯМУЮ в fga_outbox (0009 — vpc/compute/nlb, 0044 — реестр,
//     0057 — хранилище). Заголовок 0044 говорит это прямым текстом: «owner-tuple
//     writes are authorized by the fga_writer ReBAC tuple, not by a role
//     permission».
//  2. ЧТЕНИЕ внутреннего листенера — кортеж `system_viewer@cluster:cluster_kacho_root`
//     (0014 — шлюз/vpc/compute), на котором гейтит `authzguard.SystemViewerFloor`.
//     Тоже прямой посев в fga_outbox, не роль.
//  3. МЕЖСЕРВИСНЫЙ вызов от имени тенанта — субъектом проверки выступает НЕ
//     служебная учётка, а ИНИЦИАТОР запроса: все шесть оборачивают исходящий
//     контекст в `auth.PropagateOutgoing`. Комментарий vpc-клиента говорит это
//     прямо: без проброса «peer увидит анонимный/системный вызов, вернёт
//     NOT_FOUND». То есть право на `ProjectService.Get` предъявляет тенант, а не
//     модуль, и объявление `iam.projects.*.get` в роли не участвует.
//
// Сверх того, привязки шести ролей вставлены посевом СЫРЫМ SQL, минуя
// `buildBindingTuples`, — поэтому за всю жизнь они не эмитили ни одного кортежа
// даже иерархического.
//
// # Почему снята РОЛЬ целиком, а не только её правила
//
// Ловушка измерена пробой (access_binding/tuples_module_sa_branch_test.go):
// `buildBindingTuples` ветвится на `len(role.Rules) > 0`. Роль С правилами
// эмитит только иерархический указатель; роль БЕЗ правил уходит в легаси-ветку и
// садится отношением на якорь области привязки. Якорь здесь — КЛАСТЕР, а на
// кластере `mapClusterRelations` сводит и `admin`, и `editor` в прямое
// `system_admin`. Снять правила у `module.compute_sa`, оставив её строки прав,
// значило бы выдать служебной учётке compute АДМИНИСТРАТОРА ОБЛАКА; пяти
// остальным — `system_viewer@cluster`, которого у nlb, реестра и хранилища нет.
// Поэтому уходят вместе правила, права, привязка и роль.
//
// # Что НЕ снято
//
// Учётки (`service_accounts`) и оба кластерных кортежа. Это личность и
// действующие права; их сохранность держит второе утверждение файла, чтобы
// следующая уборка не приняла их за остаток снятых объявлений.
package pg_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/fga_outbox"
)

// retiredModuleSA — шесть снятых объявлений: имя службы (для детерминированного
// sva-id) и имя роли. Ось перечислена клетками: утверждение на одной роли
// доказало бы существование класса, но не его распределение по шести.
var retiredModuleSA = []struct {
	svc  string // 'sva' || substr(md5('kacho-<svc>'), 1, 17)
	role string // 'rol' || substr(md5('<role>'), 1, 17)
}{
	{"api-gateway", "module.api_gateway_sa"},
	{"compute", "module.compute_sa"},
	{"nlb", "module.nlb_sa"},
	{"registry", "module.registry_sa"},
	{"storage", "module.storage_sa"},
	{"vpc", "module.vpc_sa"},
}

// TestModuleSARoles_RetiredAndGrantNothing — ни одна из шести служебных учёток
// не достижима материализующим селектором, а тот же путь запроса на ЖИВОМ
// принципале отвечает «да».
//
// Отрицание в одиночку зеленеет сильнее всего именно тогда, когда сломано всё:
// пустая база, разъехавшийся запрос, непосеянные селекторы — каждое дало бы
// «ноль» даром. Поэтому положительный контроль идёт ТЕМ ЖЕ путём запроса и
// обязан быть непустым.
func TestModuleSARoles_RetiredAndGrantNothing(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()

	// Селекторы системных ролей проецируются самолечащим посевом (в проде — на
	// загрузке). Зовём его явно, иначе «ноль селекторов» был бы получен из того,
	// что их не проецировал никто, а не из снятия ролей.
	require.NoError(t, bootSeedRuleSides(ctx, pool))

	// ── Перепись ДО вердикта: «ноль находок» обязано быть отличимо от «ноль
	// прочитанного».
	totalRoles := scalarInt(t, ctx, pool, `SELECT count(*) FROM kacho_iam.roles`)
	totalSelectors := scalarInt(t, ctx, pool, `SELECT count(*) FROM kacho_iam.role_rule_selectors`)
	t.Logf("осмотрено: ролей=%d, строк селекторов=%d, снимаемых объявлений=%d",
		totalRoles, totalSelectors, len(retiredModuleSA))
	require.NotZero(t, totalRoles, "предпосылка гейта нарушена: в посеве нет ни одной роли")
	require.NotZero(t, totalSelectors,
		"предпосылка гейта нарушена: селекторы не спроецированы — «ноль у учёток» был бы получен даром")

	for _, m := range retiredModuleSA {
		t.Run(m.role, func(t *testing.T) {
			sva := scalarString(t, ctx, pool, fmt.Sprintf(`'sva' || substr(md5('kacho-%s'), 1, 17)`, m.svc))
			rol := scalarString(t, ctx, pool, fmt.Sprintf(`'rol' || substr(md5('%s'), 1, 17)`, m.role))

			require.Zero(t, scalarInt(t, ctx, pool,
				`SELECT count(*) FROM kacho_iam.roles WHERE id = $1`, rol),
				"роль %s обязана быть снята: её правила не разрешаются закрытой таблицей типов "+
					"и не материализуют ни одного кортежа", m.role)
			require.Zero(t, scalarInt(t, ctx, pool,
				`SELECT count(*) FROM kacho_iam.access_bindings WHERE role_id = $1`, rol),
				"привязка на снятую роль %s не может остаться: снятая роль не может оставаться выданной", m.role)
			require.Zero(t, scalarInt(t, ctx, pool,
				`SELECT count(*) FROM kacho_iam.role_rule_selectors WHERE role_id = $1`, rol),
				"селекторы снятой роли %s обязаны уйти вместе с ней", m.role)

			resolvable, declared := resolvableTypesReachableBySubject(t, ctx, pool, sva)
			require.Empty(t, declared,
				"служебная учётка kacho-%s не должна достигать ни одного объявленного типа: объявлено %v",
				m.svc, declared)
			require.Empty(t, resolvable,
				"служебная учётка kacho-%s не должна достигать ни одного РАЗРЕШИМОГО типа: разрешимо %v",
				m.svc, resolvable)
		})
	}

	// ── Положительный контроль тем же путём: живой принципал свои объекты видит.
	liveSubject := seedLivePrincipalBoundToResolvableRole(t, ctx, pool)
	liveResolvable, liveDeclared := resolvableTypesReachableBySubject(t, ctx, pool, liveSubject)
	require.NotEmpty(t, liveDeclared,
		"контроль: живой принципал не достиг ни одного объявленного типа — путь запроса не измеряет "+
			"свойство, и «ноль у шести учёток» получен даром")
	require.NotEmpty(t, liveResolvable,
		"контроль: живой принципал не достиг ни одного РАЗРЕШИМОГО типа — предикат разрешимости "+
			"не различает, и «ноль у шести учёток» получен даром")
	t.Logf("контроль: живой принципал %s достигает разрешимых типов %v", liveSubject, liveResolvable)
}

// TestModuleSACapabilitiesSurviveRetirement — то, чем шесть учёток РАБОТАЮТ,
// остаётся на месте: их личность и оба кластерных кортежа.
//
// Утверждение стоит рядом со снятием мёртвого именно потому, что оба предмета
// выглядят одинаково «остатками SEC-C»: без этого замка следующая уборка снимет
// живое, опираясь на ту же историю происхождения. Оно обязано быть зелёным и ДО
// правки, и ПОСЛЕ — это и есть «что учётка могла до, то может и после».
func TestModuleSACapabilitiesSurviveRetirement(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()

	// Личность — у всех шести.
	for _, m := range retiredModuleSA {
		sva := scalarString(t, ctx, pool, fmt.Sprintf(`'sva' || substr(md5('kacho-%s'), 1, 17)`, m.svc))
		require.Equal(t, 1, scalarInt(t, ctx, pool,
			`SELECT count(*) FROM kacho_iam.service_accounts WHERE id = $1`, sva),
			"учётка kacho-%s — личность модуля на внутреннем периметре; снятие мёртвого "+
				"объявления её не касается", m.svc)
	}

	// Право ЗАПИСИ в хранилище отношений — ровно у пяти, кто его имел (у шлюза
	// его не было и не появляется).
	fgaWriters := []string{"vpc", "compute", "nlb", "registry", "storage"}
	for _, svc := range fgaWriters {
		require.Equal(t, 1, countClusterTuple(t, ctx, pool, svc, "fga_writer", "iam_fgaproxy:system"),
			"кортеж fga_writer учётки kacho-%s обязан ОСТАТЬСЯ: им авторизована запись "+
				"owner-кортежей (заголовок 0044 говорит это прямо), и роль тут ни при чём", svc)
	}
	require.Zero(t, countClusterTuple(t, ctx, pool, "api-gateway", "fga_writer", "iam_fgaproxy:system"),
		"зеркальная клетка: у шлюза права записи не было — снятие роли не должно его ПОЯВИТЬ")

	// Право ЧТЕНИЯ внутреннего листенера — ровно у трёх, кто его имел.
	systemViewers := []string{"api-gateway", "vpc", "compute"}
	for _, svc := range systemViewers {
		require.Equal(t, 1, countClusterTuple(t, ctx, pool, svc, "system_viewer", "cluster:cluster_kacho_root"),
			"кортеж system_viewer@cluster учётки kacho-%s обязан ОСТАТЬСЯ: на нём гейтит "+
				"authzguard.SystemViewerFloor READ-RPC внутреннего листенера", svc)
	}
	// Зеркальная половина той же оси — и она же замок на ловушку: если правка
	// когда-нибудь снимет у этих трёх правила, оставив права, легаси-ветка
	// выдаст им system_viewer@cluster, которого у них нет.
	for _, svc := range []string{"nlb", "registry", "storage"} {
		require.Zero(t, countClusterTuple(t, ctx, pool, svc, "system_viewer", "cluster:cluster_kacho_root"),
			"у учётки kacho-%s кластерного читательского отношения НЕТ, и снятие мёртвого "+
				"объявления не смеет его выдать: ровно это сделала бы правка, снимающая "+
				"правила и оставляющая строки прав", svc)
	}
}

// countClusterTuple считает посеянные в fga_outbox кортежи одной учётки по паре
// (отношение, объект). Один путь запроса на обе половины оси — иначе «ноль»
// зеркальной клетки был бы получен из опечатки.
func countClusterTuple(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	svc, relation, object string) int {
	t.Helper()
	return scalarInt(t, ctx, pool,
		fmt.Sprintf(`SELECT count(*) FROM kacho_iam.fga_outbox
		              WHERE event_type = 'fga.tuple.write'
		                AND `+fga_outbox.RelationPredicate("payload", "$1")+`
		                AND payload->>'object'   = $2
		                AND payload->>'user'     = 'service_account:' ||
		                    ('sva' || substr(md5('kacho-%s'), 1, 17))`, svc),
		relation, object)
}
