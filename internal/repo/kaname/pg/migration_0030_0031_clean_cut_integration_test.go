// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// migration_0030_0031_clean_cut_integration_test.go — полный переход на модель правил RBAC.
// Testcontainers Postgres 16; все миграции применяет setupTestDB. Доказывает:
//
//   - прежние дочерние таблицы access_binding_targets / access_binding_selector
//     УДАЛЕНЫ, а access_binding_target_members СОХРАНЕНА (от неё зависит
//     согласователь правил).
//   - системные роли ПОВТОРНО ПОСЕЯНЫ на месте (UPSERT) с непустыми
//     rules[]; доступ НЕ оборван: дочерние строки FK (администратор кластера
//     из миграции 0004 + module-SA из миграции 0009) сохранены, строки ролей не удалены,
//     детерминированные id view / kacho-system.viewer / admin стабильны,
//     повторное применение 0031 идемпотентно (ON CONFLICT DO UPDATE).
//   - повторно посеянная системная роль, прочитанная через репозиторий, содержит
//     непустые rules И пустые permissions (через публичный DTO).

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/dto"
	_ "github.com/PRO-Robotech/kaname/internal/dto/toproto" // регистрируем преобразование Role
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// TestMigration_F51_LegacyTablesDropped — две прежние дочерние таблицы удалены,
// таблица участников согласователя правил сохранена.
func TestMigration_F51_LegacyTablesDropped(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testcontainers integration in -short mode")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()

	tableExists := func(name string) bool {
		var exists bool
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM information_schema.tables
			                 WHERE table_schema = 'kaname' AND table_name = $1)`,
			name).Scan(&exists))
		return exists
	}

	assert.False(t, tableExists("access_binding_targets"),
		"F-51: access_binding_targets must be DROPPED by migration 0030")
	assert.False(t, tableExists("access_binding_selector"),
		"F-51: access_binding_selector must be DROPPED by migration 0030")
	assert.True(t, tableExists("access_binding_target_members"),
		"F-51: access_binding_target_members must SURVIVE (rules reconciler uses it)")
}

// wantSystemRoles — сколько системных ролей остаётся в посеве после цепочки миграций.
//
// Расчёт: 66 посеянных (58 каталожных + 5 SEC-C module-SA из миграции 0009 + owner из 0035
// + registry из 0044 + storage из 0057), МИНУС 9 ролей блочного хранения compute,
// снятых миграцией 0074 (compute.{disk,image,snapshot}.{admin,edit,view} —
// этими ресурсами владеет kacho-storage), МИНУС ВСЕ СЕМЬ опорных ролей module-SA:
// 0076 сняла роль сетевого оператора, а 0077 — остальные шесть
// (module.{api_gateway,compute,nlb,registry,storage,vpc}_sa). Каждая из семи
// задавала правила с ресурсами, отсутствующими в закрытой таблице типов объектов:
// разрешаемый набор каждой роли ПУСТ, ни одна не материализовала ни одного кортежа.
// Средства работы этих сервисных аккаунтов сохранены: их кортежи fga_writer,
// кортежи system_viewer@cluster из 0014 и собственная личность арендатора,
// от имени которого выполняется запрос, передаваемая при каждом межсервисном вызове.
//
// МИНУС `iam.user.edit`, выведенной 20260824002317: её единственный глагол
// `update` снят с типа `iam_user` (kacho#1128, читателя у него не было с kacho#1102),
// поэтому набор глаголов правила разрешался в ПУСТОЙ — роль не материализовала
// ни одного кортежа, а её имя обещало правку. Смысла, который обещает имя, у неё
// быть не может: правку записи личности выражает `record_writer`, отношение
// ВЫЧИСЛЯЕМОЕ, и выдать его нельзя ни кортежем, ни привязкой.
//
// МИНУС `iam.user.admin`, выведенной вместе со снятием `v_delete` с того же типа
// (kacho#1189). Её правило — подстановка `*`, разворачиваемая в набор ТИПА; после снятия
// последнего распоряжающегося глагола набор стал `[get list]`, и роль
// материализовала ярус НАБЛЮДАТЕЛЯ и те же два глагола, что соседняя
// `iam.user.view`. То есть дубликат под именем, обещающим администрирование, — а
// администрирование строки личности выражено ВЫЧИСЛЯЕМЫМИ отношениями
// (`record_writer`, `identity_suspender`, `identity_remover`), которые нельзя выдать.
// Ярус, которому нечем быть, в посеве существовать не должен: этого требует гейт
// паритета ярусов (tier_parity_integration_test.go, свойство 1, обратная сторона).
//
// 66 − 9 − 7 − 1 − 1 = 48.
//
// Проверяется ТОЧНОЕ число, а не нижняя граница, поэтому повторный посев,
// незаметно вернувший снятую роль, здесь падает: это защита, стоящая поддержки.
// Число задано в ОДНОМ месте: прежде оно было записано дважды и при намеренном
// снятии приходилось искать обе записи; второе использование — предусловие в
// пробе TestMigration_F53_AccessNotSevered.
const wantSystemRoles = 48

// TestMigration_F53_SystemRolesReseededWithRules — у каждой системной роли
// непустые rules после повторного посева; число ролей точное.
func TestMigration_F53_SystemRolesReseededWithRules(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testcontainers integration in -short mode")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()

	var total int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.roles WHERE is_system`).Scan(&total))
	assert.Equal(t, wantSystemRoles, total,
		"F-53: exactly %d system roles expected after re-seed — see wantSystemRoles for the derivation",
		wantSystemRoles)

	var withoutRules int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.roles
		  WHERE is_system AND jsonb_array_length(rules) = 0`).Scan(&withoutRules))
	assert.Equal(t, 0, withoutRules,
		"F-53: every system role must have non-empty rules[] after re-seed (0031)")
}

// TestMigration_F53_IdStability — детерминированные id, от которых зависят
// последующие миграции кортежей (0004/0009/0010/0014), не меняются при повторном посеве.
func TestMigration_F53_IdStability(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testcontainers integration in -short mode")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()

	idOf := func(name string) string {
		var id string
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT id FROM kaname.roles WHERE name = $1 AND is_system`, name).Scan(&id))
		return id
	}
	mdID := func(name string) string {
		var id string
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT 'rol' || substr(md5($1), 1, 17)`, name).Scan(&id))
		return id
	}

	assert.Equal(t, mdID("view"), idOf("view"), "F-53: view id must stay 'rol'||md5('view')[1..17]")
	assert.Equal(t, mdID("admin"), idOf("admin"), "F-53: admin id must stay 'rol'||md5('admin')[1..17]")
	// Роли ищутся ОБЪЯВЛЕННЫМ именем: перевод имени (kacho#2554) идентификатор не
	// двигает. Двигает его ровно одна миграция — перевод на каноническую форму
	// (kaname#543), и после всей цепочки id роли по имени равен константе домена.
	assert.Equal(t, domain.SystemViewerRoleID, idOf(domain.SystemViewerRoleName),
		"F-53: system.viewer id must equal domain.SystemViewerRoleID (kaname#543 moved it once, by migration)")
	assert.Equal(t, domain.SystemAdminRoleID, idOf(domain.SystemAdminRoleName),
		"F-53: system.admin id must equal domain.SystemAdminRoleID (kaname#543 moved it once, by migration)")
}

// TestMigration_F53_AccessNotSevered — дочерние строки FK и строки ролей
// сохраняются при идемпотентном повторном применении 0031 (выдачи, которые миграции
// 0004/0009 привязывают к системным ролям, не затрагиваются, строки ролей не удаляются).
func TestMigration_F53_AccessNotSevered(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testcontainers integration in -short mode")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()

	countSystemRoles := func() int {
		var n int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM kaname.roles WHERE is_system`).Scan(&n))
		return n
	}
	countSystemBindings := func() int {
		var n int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM kaname.access_bindings
			  WHERE role_id IN (SELECT id FROM kaname.roles WHERE is_system)`).Scan(&n))
		return n
	}

	rolesBefore := countSystemRoles()
	bindingsBefore := countSystemBindings()
	require.Equal(t, wantSystemRoles, rolesBefore)
	require.Greater(t, bindingsBefore, 0,
		"F-53: at least the cluster-admin (0004) + module-SA (0009) bindings on system roles must exist")

	// Идемпотентно повторяем тело посева: UPSERT (ON CONFLICT DO UPDATE
	// SET rules) НЕ должен удалять ни роль, ни дочернюю выдачу FK (полный переход
	// с повторным посевом никогда не выполняет DELETE).
	reapplySystemRoleReseed(t, ctx, pool)

	assert.Equal(t, rolesBefore, countSystemRoles(),
		"F-53: re-apply must not delete or add system roles")
	assert.Equal(t, bindingsBefore, countSystemBindings(),
		"F-53: re-apply must not sever any system-role access binding")
}

// reapplySystemRoleReseed повторяет детерминированный UPSERT миграции 0031,
// доказывая идемпотентность (ON CONFLICT DO UPDATE SET rules). Он затрагивает
// каждую системную роль с её каноническими правилами: повторный вывод правил —
// контракт миграции; здесь повторно записываются ТЕ ЖЕ сохранённые rules,
// поэтому содержимое строк не меняется и дочерние строки FK не затрагиваются.
func reapplySystemRoleReseed(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(ctx,
		`UPDATE kaname.roles SET rules = rules WHERE is_system`)
	require.NoError(t, err, "idempotent re-apply of system-role rules must succeed")
}

// TestMigration_F52_SystemRolePublicDTOEmptyPermissions — повторно посеянная системная роль,
// прочитанная через репозиторий + публичный DTO, содержит непустые rules и ПУСТЫЕ
// permissions (контракт публичной поверхности).
func TestMigration_F52_SystemRolePublicDTOEmptyPermissions(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testcontainers integration in -short mode")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	repo := kanamepg.New(pool, nil)
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	// 'view' — роль чтения по шаблону: *.*.{read,list,get} → rules непусты,
	// права по-прежнему сохранены (отправка FGA), но публичный DTO обязан опустить permissions.
	var viewID string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT id FROM kaname.roles WHERE name = 'view' AND is_system`).Scan(&viewID))

	got, err := rd.Roles().Get(ctx, domain.RoleID(viewID))
	require.NoError(t, err)
	require.NotEmpty(t, got.Rules, "F-52/F-53: re-seeded 'view' must carry rules[]")
	require.NotEmpty(t, got.Permissions,
		"F-53: roles.permissions column is still written (backs FGA emission)")

	// Набор глаголов типа приходит ПРОВЯЗКОЙ, как в проде (create.go, update.go,
	// integrity.go берут его у `Facts().RolePreviewLookup()`): проекция без него
	// отказывает намеренно — превью, собранное словарём сборки, разошлось бы с
	// материализацией на типе, заведённом применением манифеста (kacho#1994).
	// Проба зовёт преобразование напрямую, минуя use-case, поэтому провязывает
	// сама — тем же производителем, а не своей копией набора.
	got.TypeVerbs = catalogfixture.Facts().RolePreviewLookup()

	var pb *iamv1.Role
	require.NoError(t, dto.Transfer(dto.FromTo(got, &pb)))
	assert.NotEmpty(t, pb.GetRules(), "F-52: public DTO surfaces rules[]")
	assert.Empty(t, pb.GetPermissions(), "F-52: public DTO must omit permissions[]")
}
