// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// migration_0005_integration_test.go — инварианты грамматики прав RBAC v2 и
// области выдачи (`access_bindings.scope`).
//
// # Имя файла историческое, и это сказано здесь, а не подразумевается
//
// Файл заводился под миграцию `0005_rbac_v2_grammar_and_scope.sql` и шагал по
// ЛЕСТНИЦЕ версий: поднять базу до 4, посеять состояние «до», применить пятую,
// сверить состояние «после». Свод 171 миграции iam в одну первичную снял
// лестницу целиком — файлов в каталоге ровно один (предикат:
// `ls services/iam/internal/migrations/*.sql | wc -l` → 1), и никакого «до
// пятой» больше не существует.
//
// Переименовать файл нельзя тем же заходом, что его правит, поэтому имя
// оставлено, а предмет назван здесь. Исторические номера сценариев (S3.1…S3.11)
// сохранены в шапках проб — по ним находится то, что искали.
//
// # Разбор по ПРЕДМЕТУ: шесть проб перенесены, четыре сняты
//
// Проба снимается, только когда умер её ПРЕДМЕТ, а не когда умерла лестница, по
// которой она к нему шла. Разложение — замером, по каждой:
//
//	S3.1  повышение legacy 3-сегментной записи до 4-сегментной НА МЕСТЕ
//	      — СНЯТА: предмет есть ШАГ. Записи, которую повышать, в схеме не
//	      существует: проверка отвергает трёхсегментную форму при вставке.
//	S3.2  четырёхсегментная запись проходит
//	      — ПЕРЕНЕСЕНА (вторая половина пробы; первая была про то же повышение).
//	S3.3  негодная запись отвергается 23514
//	      — ПЕРЕНЕСЕНА: грамматику держит `roles_permissions_valid`, живая.
//	S3.4  `*.*.*.*` проходит
//	      — ПЕРЕНЕСЕНА.
//	S3.5  область выдачи выводится из типа ресурса
//	      — ПЕРЕНЕСЕНА, и производитель НАЗВАН ДРУГОЙ: значение то же, но ставит
//	      его теперь не обратное заполнение шага, а триггер
//	      `access_bindings_scope_default_trg` — единственный производитель этого
//	      значения в сведённой схеме.
//	S3.6  область вне (1,2,3) отвергается; опущенная выводится
//	      — ПЕРЕНЕСЕНА.
//	S3.7  повторный прогон шага не двоит строк
//	      — СНЯТА: шага нет, повторять нечего.
//	S3.8  таблицы `_pre_rbac_v2_*` несут состояние «до»
//	      — СНЯТА: таблицы сняты сводом (предикат: `grep -c _pre_rbac_v2` по
//	      своду → 0). Утверждать о них значило бы утверждать о несуществующем.
//	S3.10 негодных записей в посеянных ролях не остаётся
//	      — ПЕРЕНЕСЕНА: посев ролей живой и вырос с 12 строк до 48.
//	S3.11 шаг прерывается на неповышаемой строке, откат сохраняет её
//	      — СНЯТА: предмет есть ПРЕРЫВАНИЕ ШАГА.
//
// Ослабления ни в одной перенесённой пробе нет: утверждения те же, изменилось
// то, ЧЕМ поднимается база — не лестницей, а сведённой схемой целиком.
package pg_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
	coredb "github.com/PRO-Robotech/kacho/pkg/db"
)

// ЗДЕСЬ ЛЕЖАЛИ ДВА ПОМОЩНИКА ЛЕСТНИЦЫ ВЕРСИЙ — startPostgresUpTo и applyOneMore.
//
// Оба писались под цепочку из 171 миграции: первый останавливался НЕ ДОХОДЯ до
// последней, чтобы вызывающий посеял состояние «до», второй шагал ровно один
// раз. Свод оставил одну миграцию, и лестницы не стало: `to` любой величины
// даёт всю схему целиком, а шагать после неё некуда.
//
// Их оставляли ради проб соседних миграций (0010, 0014, 0081), правившихся
// своим изменением. Те пробы сняты вместе со своим предметом — снятой личностью
// сетевого оператора (см. retired_operator_identity_integration_test.go), —
// и вызывающих у помощников не осталось НИ ОДНОГО.
//
// Мёртвый помощник хуже отсутствующего: он выглядит рабочим, и следующий,
// кому понадобится «состояние до», позовёт его и получит состояние ПОСЛЕ, не
// узнав об этом ничем. Конечное состояние даёт setupTestDB.

// ─────────────────────────────────────────────────────────────────────────────
// Фикстура

// rbacFixture — приведённая база с минимальной обвязкой: кластер, аккаунт,
// пользователь, проект и одна кластерная роль, на которую можно сослаться.
type rbacFixture struct {
	pool   *pgxpool.Pool
	roleID string
}

// newRbacFixture сеет обвязку ОДНОЙ транзакцией: связь аккаунта с владельцем и
// пользователя с аккаунтом взаимна, и её внешние ключи отложены — построчная
// автофиксация проверяла бы их на каждом операторе и отвергла бы любой порядок
// вставки.
func newRbacFixture(t *testing.T, ctx context.Context, suffix string) *rbacFixture {
	t.Helper()

	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	roleID := "rol0000000000000" + suffix

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	exec := func(sql string, args ...any) {
		t.Helper()
		_, xerr := tx.Exec(ctx, sql, args...)
		require.NoError(t, xerr, sql)
	}
	exec(`INSERT INTO kacho_iam.clusters (id, name) VALUES ('cluster_kacho_root', 'kacho')
	      ON CONFLICT DO NOTHING`)
	exec(`INSERT INTO kacho_iam.accounts (id, name, owner_user_id)
	      VALUES ($1, $2, $3)`, "acc-"+suffix, "probe-"+suffix, "usr-"+suffix)
	exec(`INSERT INTO kacho_iam.users (id, external_id, email, account_id)
	      VALUES ($1, $2, $3, $4)`,
		"usr-"+suffix, "ext-"+suffix, "usr-"+suffix+"@kacho.local", "acc-"+suffix)
	exec(`INSERT INTO kacho_iam.projects (id, account_id, name)
	      VALUES ($1, $2, $3)`, "prj-"+suffix, "acc-"+suffix, "home")
	// Роль КЛАСТЕРНОГО яруса: на неё ссылаются выдачи всех областей, тогда как
	// роль проекта ограничена своей. Имя обязано пройти roles_system_name_check.
	exec(`INSERT INTO kacho_iam.roles (id, name, permissions, cluster_id)
	      VALUES ($1, $2, '["compute.instance.*.get"]'::jsonb, 'cluster_kacho_root')`,
		roleID, "kacho.probe"+suffix)
	require.NoError(t, tx.Commit(ctx))

	return &rbacFixture{pool: pool, roleID: roleID}
}

// insertRole — вставка роли кластерного яруса с названным набором прав.
// Возвращает ошибку как есть: грамматику судят пробы, а не помощник.
func (f *rbacFixture) insertRole(ctx context.Context, id, name, perms string) error {
	_, err := f.pool.Exec(ctx, `
		INSERT INTO kacho_iam.roles (id, name, permissions, cluster_id)
		VALUES ($1, $2, $3::jsonb, 'cluster_kacho_root')`, id, name, perms)
	return err
}

// ─────────────────────────────────────────────────────────────────────────────
// Грамматика прав (перенесено: S3.2, S3.3, S3.4, S3.10)

// TestRbacV2Grammar_FourSegmentPermissionIsAccepted — S3.2, вторая половина.
//
// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ для отрицания ниже: без него «негодная запись
// отвергнута» было бы неотличимо от «в эту таблицу не вставляется ничего».
func TestRbacV2Grammar_FourSegmentPermissionIsAccepted(t *testing.T) {
	if testing.Short() {
		t.Skip("requires docker")
	}
	ctx := context.Background()
	f := newRbacFixture(t, ctx, "g4a")

	require.NoError(t, f.insertRole(ctx, "rol0000000000000g4ab", "kacho.probeg4ab",
		`["compute.instance.inst-abc.update","vpc.network.*.create"]`),
		"четырёхсегментная запись обязана приниматься — и именованным ресурсом, и подстановкой")

	var raw string
	require.NoError(t, f.pool.QueryRow(ctx,
		`SELECT permissions::text FROM kacho_iam.roles WHERE id=$1`,
		"rol0000000000000g4ab").Scan(&raw))
	require.Contains(t, raw, `"compute.instance.inst-abc.update"`)
	require.Contains(t, raw, `"vpc.network.*.create"`)
}

// TestRbacV2Grammar_MalformedPermissionIsRejected — S3.3.
//
// Утверждается ПАРА: код SQLSTATE и имя проверки. Одного кода мало — 23514
// приходит от любой проверки таблицы, и проба зеленела бы, отвергнись строка по
// совершенно другой причине.
func TestRbacV2Grammar_MalformedPermissionIsRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("requires docker")
	}
	ctx := context.Background()
	f := newRbacFixture(t, ctx, "g4b")

	bad := []struct{ why, perms string }{
		{"пустой сегмент", `["compute.instance.bad..verb"]`},
		{"три сегмента — форма до RBAC v2", `["compute.instance.read"]`},
		{"пять сегментов", `["compute.instance.inst-A.read.extra"]`},
		{"пустой сегмент ресурса", `["compute..*.read"]`},
		{"заглавные в модуле", `["UPPER.instance.*.read"]`},
	}
	for i, c := range bad {
		id := fmt.Sprintf("rol0000000000000g4b%d", i)
		err := f.insertRole(ctx, id, fmt.Sprintf("kacho.probeg4b%d", i), c.perms)
		require.Error(t, err, "%s: %s обязано отвергаться", c.why, c.perms)

		pgErr := unwrapPgErr(err)
		require.NotNil(t, pgErr, "%s: ожидалась ошибка уровня СУБД, получено %v", c.why, err)
		require.Equal(t, "23514", pgErr.Code, "%s: ожидалось нарушение проверки", c.why)
		require.Contains(t, pgErr.ConstraintName, "permissions",
			"%s: нарушение обязано называть проверку ПРАВ, иначе строка отвергнута по "+
				"другой причине и о грамматике проба не утверждает ничего", c.why)
	}
}

// TestRbacV2Grammar_WildcardOnlyIsAccepted — S3.4.
func TestRbacV2Grammar_WildcardOnlyIsAccepted(t *testing.T) {
	if testing.Short() {
		t.Skip("requires docker")
	}
	ctx := context.Background()
	f := newRbacFixture(t, ctx, "g4c")

	require.NoError(t, f.insertRole(ctx, "rol0000000000000g4cw", "kacho.probeg4cw", `["*.*.*.*"]`),
		"подстановка во всех четырёх сегментах законна: это и есть форма роли «может всё»")
}

// TestRbacV2Grammar_SeededRolesAreAllFourSegment — S3.10.
//
// Предмет не в конкретной роли, а в ПОСЕВЕ целиком: строка, разошедшаяся с
// грамматикой, не отвергается ничем при чтении и всплывает отказом вердикта у
// арендатора.
//
// Перепись печатается ВСЕГДА: «негодных ноль» обязано быть отличимо от «прочитано
// ноль» — на пустой таблице отрицание выполняется тождественно.
func TestRbacV2Grammar_SeededRolesAreAllFourSegment(t *testing.T) {
	if testing.Short() {
		t.Skip("requires docker")
	}
	ctx := context.Background()
	f := newRbacFixture(t, ctx, "g4d")

	var total, withPerms int
	require.NoError(t, f.pool.QueryRow(ctx,
		`SELECT count(*), count(*) FILTER (WHERE jsonb_array_length(permissions) > 0)
		   FROM kacho_iam.roles`).Scan(&total, &withPerms))
	t.Logf("осмотрено ролей: %d, из них с непустым набором прав: %d", total, withPerms)
	require.Positive(t, withPerms,
		"ролей с непустым набором прав ноль — обход пуст, и вердикт беспредметен: "+
			"утверждение «негодных нет» выполнялось бы тождественно")

	var leftCount int
	require.NoError(t, f.pool.QueryRow(ctx, `
		SELECT count(*) FROM kacho_iam.roles
		WHERE EXISTS (
			SELECT 1 FROM jsonb_array_elements_text(permissions) p
			WHERE array_length(string_to_array(p, '.'), 1) <> 4
			   OR p ~ '^\.|\.\.|\.$'
			   OR p !~ '^(\*|[a-zA-Z][a-zA-Z0-9_-]*)\.(\*|[a-zA-Z][a-zA-Z0-9_-]*)\.(\*|[a-zA-Z0-9_-]+)\.(\*|[a-z][a-zA-Z0-9_-]*)$'
		)
	`).Scan(&leftCount))
	require.Equal(t, 0, leftCount, "каждая посеянная роль обязана нести строго четырёхсегментные права")
}

// ─────────────────────────────────────────────────────────────────────────────
// Область выдачи (перенесено: S3.5, S3.6)

// insertBinding — выдача с ЯВНО названной областью либо без неё (scope < 0).
func (f *rbacFixture) insertBinding(ctx context.Context, id, resType, resID, subject string, scope int) error {
	if scope < 0 {
		_, err := f.pool.Exec(ctx, `
			INSERT INTO kacho_iam.access_bindings
			    (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
			VALUES ($1, 'user', $2, $3, $4, $5, 'ACTIVE')`,
			id, subject, f.roleID, resType, resID)
		return err
	}
	_, err := f.pool.Exec(ctx, `
		INSERT INTO kacho_iam.access_bindings
		    (id, subject_type, subject_id, role_id, resource_type, resource_id, status, scope)
		VALUES ($1, 'user', $2, $3, $4, $5, 'ACTIVE', $6)`,
		id, subject, f.roleID, resType, resID, scope)
	return err
}

// TestAccessBindingScope_DerivedFromResourceType — S3.5.
//
// # Предмет тот же, ПРОИЗВОДИТЕЛЬ другой — и это сказано, а не умолчано
//
// Прежде значение ставило обратное заполнение шага миграции; в сведённой схеме
// единственный его производитель — триггер `access_bindings_scope_default_trg`.
// Утверждаемая таблица «тип ресурса → область» не изменилась ни в одной строке,
// поэтому проба перенесена, а не заведена заново.
//
// Ветвь `ELSE 3` покрыта НЕСКОЛЬКИМИ типами намеренно: один тип не отличил бы
// «умолчание работает» от «этот тип назван поимённо».
func TestAccessBindingScope_DerivedFromResourceType(t *testing.T) {
	if testing.Short() {
		t.Skip("requires docker")
	}
	ctx := context.Background()
	f := newRbacFixture(t, ctx, "sc1")
	subject := "usr-sc1"

	cases := []struct {
		id, resType, resID string
		want               int
	}{
		{"acb0000000000000clst1", "cluster", "cluster_kacho_root", 1},
		{"acb0000000000000acct1", "account", "acc-sc1", 2},
		{"acb0000000000000proj1", "project", "prj-sc1", 3},
		{"acb0000000000000vpcn1", "vpc_network", "enp00000000000000n001", 3},
		{"acb0000000000000inst1", "compute_instance", "epd00000000000000i001", 3},
		{"acb0000000000000user1", "user", "usr00000000000000u001", 3},
		{"acb0000000000000role1", "iam_role", "rol00000000000000r001", 3},
	}
	for _, c := range cases {
		require.NoError(t, f.insertBinding(ctx, c.id, c.resType, c.resID, subject, -1),
			"выдача на тип %s обязана вставляться без названной области", c.resType)
	}
	for _, c := range cases {
		var got int
		require.NoError(t, f.pool.QueryRow(ctx,
			`SELECT scope FROM kacho_iam.access_bindings WHERE id=$1`, c.id).Scan(&got))
		require.Equal(t, c.want, got, "тип ресурса %s обязан давать область %d", c.resType, c.want)
	}
}

// TestAccessBindingScope_OutOfRangeIsRejectedAndOmittedIsDerived — S3.6.
//
// Две стороны в ОДНОЙ пробе намеренно: отрицание («четвёрка отвергнута») без
// парного положительного («опущенная выводится») зеленело бы и на схеме, куда
// выдача не вставляется вовсе.
func TestAccessBindingScope_OutOfRangeIsRejectedAndOmittedIsDerived(t *testing.T) {
	if testing.Short() {
		t.Skip("requires docker")
	}
	ctx := context.Background()
	f := newRbacFixture(t, ctx, "sc2")
	subject := "usr-sc2"

	err := f.insertBinding(ctx, "acb0000000000000bad01", "account", "acc-sc2", subject, 4)
	require.Error(t, err, "область вне (1,2,3) обязана отвергаться")
	pgErr := unwrapPgErr(err)
	require.NotNil(t, pgErr, "ожидалась ошибка уровня СУБД, получено %v", err)
	require.Equal(t, "23514", pgErr.Code)
	require.Contains(t, pgErr.ConstraintName, "scope_ck",
		"нарушение обязано называть проверку ОБЛАСТИ: иначе строка отвергнута по другой "+
			"причине и об области проба не утверждает ничего")

	// Опущенная область: колонка объявлена NOT NULL и умолчания не имеет —
	// значение ставит триггер. Вставка без области обязана проходить, иначе
	// вызывающие, не знающие о колонке, перестали бы работать.
	require.NoError(t, f.insertBinding(ctx,
		"acb0000000000000ok001", "cluster", "cluster_kacho_root", subject, -1),
		"триггер обязан вывести область из типа ресурса")
	var derived int
	require.NoError(t, f.pool.QueryRow(ctx,
		`SELECT scope FROM kacho_iam.access_bindings WHERE id='acb0000000000000ok001'`).Scan(&derived))
	require.Equal(t, 1, derived, "тип ресурса cluster даёт область 1")
}

// unwrapPgErr — peel pgconn.PgError out of wrap chain.
func unwrapPgErr(err error) *pgconn.PgError {
	for e := err; e != nil; {
		pgErr, ok := e.(*pgconn.PgError)
		if ok {
			return pgErr
		}
		un, ok := e.(interface{ Unwrap() error })
		if !ok {
			return nil
		}
		e = un.Unwrap()
	}
	return nil
}
