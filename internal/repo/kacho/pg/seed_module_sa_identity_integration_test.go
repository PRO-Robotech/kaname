// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// seed_module_sa_identity_integration_test.go — module ServiceAccount identity seed.
//
// Verifies the state the seed migration (0009) and its successors leave behind
// for the least-privilege module ServiceAccount identities:
//   - 4 module SAs of the original five (deterministic sva-id, system account) —
//     the network operator's identity was retired by migration 0081 together with
//     everything granted to it, its role and binding having gone in 0076;
//   - no backing role and no AccessBinding for any of them (0076 + 0077);
//   - FGA relation-tuples `<sva>#fga_writer@iam_fgaproxy:system` in fga_outbox
//     for vpc/compute/nlb only (api-gateway has none);
//   - immutable system role; idempotent ON CONFLICT re-apply.
//
// The permission strings the backing roles once carried are deliberately NOT
// pinned here any more: pinning the contents of a retired role would demand its
// return, and returning it rules-less would land a cluster-anchored relation the
// module never had.
//
// Skipped under `go test -short`.
package pg_test

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"sort"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho-iam/internal/testsupport/iampgtest"
)

// svaID derives the deterministic ServiceAccount id for a module svc-name
// (`'sva' || substr(md5('kacho-<svc>'), 1, 17)`), matching the seed migration.
func svaID(svc string) string {
	sum := md5.Sum([]byte("kacho-" + svc))
	return "sva" + hex.EncodeToString(sum[:])[:17]
}

// roleName maps a module svc-name to its backing-role name. Role names obey the
// system-role CHECK `^[a-z][-a-z0-9]*(\.[a-z][a-z0-9_]*){0,2}$` (post-dot
// segment allows underscore, NOT dash), so dashes in svc become underscores.
func roleName(svc string) string {
	switch svc {
	case "vpc":
		return "module.vpc_sa"
	case "compute":
		return "module.compute_sa"
	case "nlb":
		return "module.nlb_sa"
	case "vpc-operator":
		return "module.vpc_operator_sa"
	case "api-gateway":
		return "module.api_gateway_sa"
	case "registry":
		return "module.registry_sa"
	case "storage":
		return "module.storage_sa"
	default:
		// Не «правдоподобное» имя по шаблону: `module.`+svc даёт `module.registry`
		// там, где посев завёл `module.registry_sa`, и утверждение о такой роли
		// зеленеет всегда — считает строки id, которого не существует. Неизвестное
		// имя обязано быть видно как неизвестное.
		return "module.UNKNOWN_SVC_" + svc
	}
}

// rolID derives the deterministic backing-role id for a module
// (`'rol' || substr(md5(<role-name>), 1, 17)`), matching the seed migration.
func rolID(svc string) string {
	sum := md5.Sum([]byte(roleName(svc)))
	return "rol" + hex.EncodeToString(sum[:])[:17]
}

// TestSeedModuleSA_B01_ModuleIdentitiesCreated — ось по всем пяти учёткам
// исходного посева 0009: четыре обязаны БЫТЬ, пятая — сетевого оператора —
// обязана ОТСУТСТВОВАТЬ (снята 0081).
//
// Ось перечисляет и снятую клетку, а не молча укорачивается: перечень, из
// которого имя просто исчезло, не отличить от перечня, где о нём забыли, — и
// возвращение строки прошло бы мимо этой пробы.
func TestSeedModuleSA_B01_ModuleIdentitiesCreated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	wantSvcs := []string{"vpc", "compute", "nlb", "api-gateway"}
	for _, svc := range wantSvcs {
		var id, name, accountID string
		err := pool.QueryRow(ctx,
			`SELECT id, name, account_id FROM kacho_iam.service_accounts WHERE id = $1`,
			svaID(svc)).Scan(&id, &name, &accountID)
		require.NoError(t, err, "module SA %q must exist with deterministic id %s", svc, svaID(svc))
		require.Equal(t, "kacho-"+svc, name, "SA name segment is canonical kacho-<svc>")
		require.NotEmpty(t, accountID, "SA must be attached to the seeded system account (account_id NOT NULL)")
	}

	var retired int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.service_accounts WHERE id = $1`,
		svaID("vpc-operator")).Scan(&retired))
	require.Zero(t, retired,
		"учётка сетевого оператора обязана отсутствовать (0081): модуля в дереве нет и чарта, "+
			"выпускающего её сертификат, тоже — предъявить её некому")
}

// TestSeedModuleSA_B02_ComputeRoleRetiredWriteCapabilityKept — у compute снята
// backing-роль и осталось то, чем он работает.
//
// Прежняя редакция пинила СЕМЬ строк прав этой роли «дословно по исходному
// каталогу». Роль снята миграцией 0077: все четыре пары её правил
// (`vpc.subnets`, `vpc.security_groups`, `vpc.addresses`, `iam.projects`)
// закрытая таблица типов не несёт, разрешимое множество пусто, материализация не
// эмитила ни одного кортежа. Пиновать состав снятой роли значило бы требовать её
// возвращения — а возвращение рулесс-строкой выдало бы compute
// system_admin@cluster (см. tuples_module_sa_branch_test.go).
//
// Право ЗАПИСИ, которым compute действительно пользуется, — кортеж fga_writer, и
// он остаётся: это положительная половина пары, без неё «ноль» выше был бы
// получен из пустой базы.
func TestSeedModuleSA_B02_ComputeRoleRetiredWriteCapabilityKept(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	requireRoleRetired(t, ctx, pool, "compute")
	requireFGAWriterTuple(t, ctx, pool, svaID("compute"), true)
}

// TestSeedModuleSA_B03_VpcRoleRetiredWriteCapabilityKept — то же для vpc. Его
// роль называла ещё и `compute.zones`, ресурс, который вместе со всей топологией
// размещения ушёл в geo, — то есть пара не разрешалась дважды.
func TestSeedModuleSA_B03_VpcRoleRetiredWriteCapabilityKept(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	requireRoleRetired(t, ctx, pool, "vpc")
	requireFGAWriterTuple(t, ctx, pool, svaID("vpc"), true)
}

// TestSeedModuleSA_B04_NlbRoleRetiredIdentityAndWriteKept — то же для nlb, плюс
// прежнее утверждение об имени учётки: оно про ЛИЧНОСТЬ, снятие роли его не
// касается.
func TestSeedModuleSA_B04_NlbRoleRetiredIdentityAndWriteKept(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	requireRoleRetired(t, ctx, pool, "nlb")
	requireFGAWriterTuple(t, ctx, pool, svaID("nlb"), true)

	// SA name segment canonical kacho-nlb (not legacy kacho-loadbalancer).
	var name string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT name FROM kacho_iam.service_accounts WHERE id = $1`, svaID("nlb")).Scan(&name))
	require.Equal(t, "kacho-nlb", name)
}

// requireRoleRetired — роль модуля снята вместе с привязкой, а его ЛИЧНОСТЬ на
// месте. Личность проверяется тем же вызовом намеренно: «ноль ролей» из пустой
// базы неотличим от «ноль ролей» по существу, и положительная клетка рядом
// закрывает эту неотличимость.
func requireRoleRetired(t *testing.T, ctx context.Context, pool *pgxpool.Pool, svc string) {
	t.Helper()
	var roleCnt int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.roles WHERE id = $1`, rolID(svc)).Scan(&roleCnt))
	require.Zerof(t, roleCnt,
		"backing-роль %s обязана быть снята (0077): её правила не разрешаются закрытой "+
			"таблицей типов и не материализуют ни одного кортежа", roleName(svc))

	var bindCnt int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.access_bindings WHERE role_id = $1`, rolID(svc)).Scan(&bindCnt))
	require.Zerof(t, bindCnt, "снятая роль %s не может оставаться выданной", roleName(svc))

	var name string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT name FROM kacho_iam.service_accounts WHERE id = $1`, svaID(svc)).Scan(&name))
	require.Equalf(t, "kacho-"+svc, name,
		"учётка kacho-%s — личность модуля на внутреннем периметре; снятие выдачи её не касается", svc)
}

// TestSeedModuleSA_B05_OperatorFullyRetired — у сетевого оператора не остаётся
// НИЧЕГО: ни роли, ни привязки, ни личности.
//
// Прежняя редакция этого места утверждала обратное — «учётка остаётся, она
// личность на внутреннем периметре, а не право». Это верно ровно до тех пор,
// пока личность кто-то может предъявить. Предъявить её некому: каталога модуля в
// дереве нет, репозитория нет, чарт, выпускающий сертификат с её SPIFFE-именем,
// не существует. Строка в таблице принципалов, за которой нет предъявителя, —
// не личность, а место, куда выдача приезжает без чьего-либо решения.
//
// Положительный контроль — рядом: api-gateway остаётся личностью БЕЗ права
// записи. Без него «ноль у оператора» зеленел бы и на выкошенном посеве.
func TestSeedModuleSA_B05_OperatorFullyRetired(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	// Роль снята — вместе с правами, правилами и привязкой (0076).
	var roleCnt int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.roles WHERE id = $1`, rolID("vpc-operator")).Scan(&roleCnt))
	require.Zero(t, roleCnt,
		"backing-роль оператора сети обязана быть снята: её правила не разрешаются закрытой "+
			"таблицей типов и не материализуют ни одного кортежа")

	var bindCnt int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.access_bindings WHERE subject_id = $1`,
		svaID("vpc-operator")).Scan(&bindCnt))
	require.Zero(t, bindCnt, "снятая роль не может оставаться выданной оператору")

	// Личность снята (0081).
	var saCnt int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.service_accounts WHERE id = $1`,
		svaID("vpc-operator")).Scan(&saCnt))
	require.Zero(t, saCnt,
		"учётка оператора обязана быть снята: за ней нет предъявителя, а строка принципала "+
			"переживает компонент и принимает на себя следующую выдачу")

	// Положительный контроль: api-gateway — живая личность, и у неё по-прежнему
	// нет права записи в модель. «Ноль у оператора» получен не из пустого посева.
	var gatewayName string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT name FROM kacho_iam.service_accounts WHERE id = $1`,
		svaID("api-gateway")).Scan(&gatewayName))
	require.Equal(t, "kacho-api-gateway", gatewayName,
		"контроль: учётка парадной двери обязана остаться — снимается ОДИН субъект, а не класс")
	requireFGAWriterTuple(t, ctx, pool, svaID("api-gateway"), false)
}

func TestSeedModuleSA_B06_AccessBindingScopeAndIdempotency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	// НИ ОДНА служебная учётка модуля больше не несёт выдачи В ФОРМЕ РОЛИ: все семь
	// backing-ролей сняты (0076 — оператор сети, 0077 — остальные шесть). Прежняя
	// редакция пинила «ровно одна привязка на модуль» для четырёх из них; после
	// снятия это утверждение требовало бы возвращения снятого.
	//
	// Перечень — ОСЬ по всем семи учёткам, а не по тем, что остались: клетка,
	// выпавшая из перечня, перестала бы проверяться молча. Оператор сети в оси
	// сохранён НАМЕРЕННО, хотя его учётки больше нет (0081): клетка ловит именно
	// тот случай, ради которого её стоило бы удалить, — воскрешённую учётку с
	// привязкой.
	allModuleSAs := []string{"vpc", "compute", "nlb", "vpc-operator", "api-gateway", "registry", "storage"}

	// ЧТО ИМЕННО ЗАПРЕЩЕНО — форма РОЛИ, а не «строка на поверхности выдач».
	//
	// Прежняя редакция считала строки БЕЗ различения формы, и это было точным
	// выражением предмета ровно до тех пор, пока форма у выдачи была ОДНА.
	// Работа #893/#895 завела вторую (`granted_relation` ВЗАМЕН `role_id`,
	// взаимоисключающе по access_bindings_grant_form_ck) и перенесла на
	// поверхность выдач встроенный доступ, который раньше лежал прямым фактом
	// посева. Встроенный `system_viewer@cluster` учёток шлюза, vpc и compute
	// заведён миграцией 0014 и НАМЕРЕННО сохранён — он не backing-роль и никогда
	// ею не был; изменилось только то, что теперь его ВИДНО.
	//
	// Поэтому предикат сужается до `role_id IS NOT NULL`: воскрешение снятого
	// объявления — это возвращение РОЛИ, и только оно. Считать любую строку
	// значило бы требовать, чтобы встроенный доступ снова стал невидимым.
	requireNoRoleFormGrant := func(t *testing.T, when string) {
		t.Helper()
		for _, svc := range allModuleSAs {
			var count int
			require.NoError(t, pool.QueryRow(ctx,
				`SELECT count(*) FROM kacho_iam.access_bindings
				  WHERE subject_id = $1 AND role_id IS NOT NULL`,
				svaID(svc)).Scan(&count))
			require.Zerof(t, count,
				"служебная учётка kacho-%s обязана остаться без выдачи в форме РОЛИ (%s): "+
					"её backing-роль снята (0076/0077)", svc, when)
		}
	}
	requireNoRoleFormGrant(t, "после миграций")

	// Положительный контроль НА НОВУЮ ФОРМУ. Без него сужение предиката молча
	// сняло бы с оси покрытие того самого, ради чего она сужена: «ноль ролей»
	// зеленело бы и на дереве, где встроенный доступ не доехал до поверхности
	// выдач вовсе — то есть на возвращении прежнего дефекта.
	//
	// Ось идёт по ВСЕМ семи учёткам, а не по трём несущим: клетка, выпавшая из
	// перечня, перестала бы проверяться молча.
	builtInRelationGrant := map[string]bool{"api-gateway": true, "vpc": true, "compute": true}
	for _, svc := range allModuleSAs {
		var relCnt int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM kacho_iam.access_bindings
			  WHERE subject_id = $1
			    AND role_id IS NULL
			    AND granted_relation = 'system_viewer'
			    AND resource_type = 'cluster'
			    AND is_system`,
			svaID(svc)).Scan(&relCnt))
		if builtInRelationGrant[svc] {
			require.Equalf(t, 1, relCnt,
				"встроенный system_viewer@cluster учётки kacho-%s (миграция 0014) обязан быть ВИДЕН "+
					"на поверхности выдач в форме отношения: иначе доступ есть, а перечисление "+
					"выдач о нём молчит — предмет #893/#895", svc)
			continue
		}
		require.Zerof(t, relCnt,
			"у kacho-%s встроенного system_viewer@cluster нет и не было — выдача в форме отношения "+
				"здесь означала бы доступ, которого никто не заводил", svc)
	}

	// Положительный контроль: привязки в базе ЕСТЬ — «ноль у модулей» получен не
	// из пустой таблицы. Посев заводит кластерные выдачи бутстрап-учётке.
	var totalBindings int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.access_bindings`).Scan(&totalBindings))
	require.NotZero(t, totalBindings,
		"контроль: в посеве нет НИ ОДНОЙ привязки — «ноль у служебных учёток» получен даром")

	// Второй контроль — на ВЫВОД id: тем же выражением, что даёт нули выше, роль
	// из посева обязана находиться. Без него опечатка в выводе id давала бы ноль
	// на каждой клетке и читалась бы как «всё снято».
	var liveRoleCnt int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.roles WHERE id = 'rol' || substr(md5('vpc.subnet.view'), 1, 17)`).
		Scan(&liveRoleCnt))
	require.Equal(t, 1, liveRoleCnt,
		"контроль: посеянная роль vpc.subnet.view не найдена тем же выводом id — «ноль» у снятых "+
			"ролей получен из опечатки, а не из снятия")

	// Повтор посева — путь ВОСКРЕШЕНИЯ снятого объявления, и он обязан быть
	// закрыт: тело посева больше не содержит ни одной роли и ни одной привязки,
	// поэтому повторный прогон не возвращает ничего. Отдельно проверяется, что
	// повтор идемпотентен и по тому, что в нём ОСТАЛОСЬ (учётки).
	reapplySeed(t, ctx, pool)
	requireNoRoleFormGrant(t, "после повторного посева")
	for _, svc := range allModuleSAs {
		var roleCnt int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM kacho_iam.roles WHERE id = $1`, rolID(svc)).Scan(&roleCnt))
		require.Zerof(t, roleCnt, "повторный посев не должен воскрешать снятую backing-роль %s", roleName(svc))

		// Учётка сетевого оператора снята (0081), и повторный посев обязан её НЕ
		// воскрешать: тело посева её больше не содержит. Клетка стоит рядом с
		// остальными и ждёт ноль там, где они ждут единицу, — именно этой парой
		// проверяется, что путь повторного посева не возвращает снятое.
		wantSA := 1
		if svc == "vpc-operator" {
			wantSA = 0
		}
		var saCnt int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM kacho_iam.service_accounts WHERE id = $1`, svaID(svc)).Scan(&saCnt))
		require.Equalf(t, wantSA, saCnt,
			"повторный посев не должен ни удвоить, ни потерять, ни воскресить учётку kacho-%s", svc)
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func readRolePermissions(t *testing.T, ctx context.Context, pool *pgxpool.Pool, roleID string) []string {
	t.Helper()
	var raw string
	err := pool.QueryRow(ctx,
		`SELECT permissions::text FROM kacho_iam.roles WHERE id = $1`, roleID).Scan(&raw)
	require.NoError(t, err, "backing role %s must exist", roleID)
	var perms []string
	require.NoError(t, json.Unmarshal([]byte(raw), &perms))
	sort.Strings(perms)
	return perms
}

func requireFGAWriterTuple(t *testing.T, ctx context.Context, pool *pgxpool.Pool, sva string, want bool) {
	t.Helper()
	var count int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.fga_outbox
		  WHERE event_type='fga.tuple.write'
		    AND payload->>'user'     = $1
		    AND payload->>'relation' = 'fga_writer'
		    AND payload->>'object'   = 'iam_fgaproxy:system'`,
		"service_account:"+sva).Scan(&count))
	if want {
		require.GreaterOrEqual(t, count, 1, "fga_writer tuple must be seeded for %s", sva)
	} else {
		require.Equal(t, 0, count, "no fga_writer tuple must be seeded for %s", sva)
	}
}

// reapplySeed re-executes the seed body (idempotency assertion). It calls
// the exported SeedModuleSAIdentity helper so the test never hand-copies SQL.
func reapplySeed(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	require.NoError(t, pg.SeedModuleSAIdentity(ctx, pool))
}
