// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// seed_module_sa_identity_integration_test.go — module ServiceAccount identity seed.
//
// Verifies the seed migration (0009) that provisions least-privilege
// module ServiceAccount identities in the ReBAC model:
//   - 5 module SAs (deterministic sva-id, system account, cluster scope);
//   - a backing RBAC-v2 role with the exact 4-segment permission set
//     (byte-for-byte from permission_catalog.json) for FOUR of them — the
//     vpc-operator's was retired by migration 0076;
//   - an AccessBinding (subject=service_account, role, cluster-scope) for those
//     same four;
//   - FGA relation-tuples `<sva>#fga_writer@iam_fgaproxy:system` in fga_outbox
//     for vpc/compute/nlb only (vpc-operator / api-gateway have none);
//   - immutable system role; idempotent ON CONFLICT re-apply.
//
// Source-of-truth permission strings (permission_catalog.json):
//
//	compute     vpc.subnets.*.get, vpc.security_groups.*.get,
//	            vpc.addresses.*.get/create/delete/update, iam.projects.*.get
//	vpc         compute.zones.*.get, iam.projects.*.get
//	nlb         vpc.subnets.*.get, iam.projects.*.get
//	vpc-operator (none — role retired by 0076; identity kept, no grant)
//	api-gateway (none — identity-only)
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

	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
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

func TestSeedModuleSA_B01_AllFiveModuleSAsCreated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, pg.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	wantSvcs := []string{"vpc", "compute", "nlb", "vpc-operator", "api-gateway"}
	for _, svc := range wantSvcs {
		var id, name, accountID string
		err := pool.QueryRow(ctx,
			`SELECT id, name, account_id FROM kacho_iam.service_accounts WHERE id = $1`,
			svaID(svc)).Scan(&id, &name, &accountID)
		require.NoError(t, err, "module SA %q must exist with deterministic id %s", svc, svaID(svc))
		require.Equal(t, "kacho-"+svc, name, "SA name segment is canonical kacho-<svc>")
		require.NotEmpty(t, accountID, "SA must be attached to the seeded system account (account_id NOT NULL)")
	}
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
	pool, err := coredb.NewPool(ctx, pg.NewTestPostgres(t))
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
	pool, err := coredb.NewPool(ctx, pg.NewTestPostgres(t))
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
	pool, err := coredb.NewPool(ctx, pg.NewTestPostgres(t))
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

// TestSeedModuleSA_B05_OperatorRoleRetiredIdentityKept — у оператора сети
// остаётся ЛИЧНОСТЬ и не остаётся выдачи.
//
// Прежняя редакция пинила ЧЕТЫРЕ строки прав его backing-роли как «набор из
// исходного каталога». Роль снята миграцией 0076: ни одно из четырёх имён
// закрытая таблица типов не несёт, поэтому пообъектно она не материализовала
// ничего, а каскад, ради которого веер задумывался, из модели удалён. Пиновать
// состав снятой роли значило бы требовать её возвращения.
//
// Учётка при этом остаётся: она — личность оператора на внутреннем периметре, а
// не право. Как и прежде, у неё нет кортежа fga_writer (read-only sync ничего не
// регистрирует).
func TestSeedModuleSA_B05_OperatorRoleRetiredIdentityKept(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, pg.NewTestPostgres(t))
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

	// Личность остаётся — контроль в положительную сторону: «ноль» выше получен
	// не из того, что учётки нет вовсе.
	var name string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT name FROM kacho_iam.service_accounts WHERE id = $1`,
		svaID("vpc-operator")).Scan(&name))
	require.Equal(t, "kacho-vpc-operator", name,
		"учётка оператора — его личность на внутреннем периметре; снятие выдачи её не касается")

	// No fga_writer tuple for operator (read-only sync, registers nothing).
	requireFGAWriterTuple(t, ctx, pool, svaID("vpc-operator"), false)
	// api-gateway also has no fga_writer tuple.
	requireFGAWriterTuple(t, ctx, pool, svaID("api-gateway"), false)
}

func TestSeedModuleSA_B06_AccessBindingScopeAndIdempotency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, pg.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	// НИ ОДНА служебная учётка модуля больше не несёт привязки: все семь
	// backing-ролей сняты (0076 — оператор сети, 0077 — остальные шесть). Прежняя
	// редакция пинила «ровно одна привязка на модуль» для четырёх из них; после
	// снятия это утверждение требовало бы возвращения снятого.
	//
	// Перечень — ОСЬ по всем семи учёткам, а не по тем, что остались: клетка,
	// выпавшая из перечня, перестала бы проверяться молча.
	allModuleSAs := []string{"vpc", "compute", "nlb", "vpc-operator", "api-gateway", "registry", "storage"}
	requireAllUnbound := func(t *testing.T, when string) {
		t.Helper()
		for _, svc := range allModuleSAs {
			var count int
			require.NoError(t, pool.QueryRow(ctx,
				`SELECT count(*) FROM kacho_iam.access_bindings WHERE subject_id = $1`,
				svaID(svc)).Scan(&count))
			require.Zerof(t, count,
				"служебная учётка kacho-%s обязана остаться без привязки (%s): её backing-роль снята", svc, when)
		}
	}
	requireAllUnbound(t, "после миграций")

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
	requireAllUnbound(t, "после повторного посева")
	for _, svc := range allModuleSAs {
		var roleCnt int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM kacho_iam.roles WHERE id = $1`, rolID(svc)).Scan(&roleCnt))
		require.Zerof(t, roleCnt, "повторный посев не должен воскрешать снятую backing-роль %s", roleName(svc))

		var saCnt int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM kacho_iam.service_accounts WHERE id = $1`, svaID(svc)).Scan(&saCnt))
		require.Equalf(t, 1, saCnt, "повторный посев не должен ни удвоить, ни потерять учётку kacho-%s", svc)
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
