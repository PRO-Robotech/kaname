// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// binding_subject_scope_carrier_integration_test.go — СОГЛАСОВАННОСТЬ
// ПЕРЕНЕСЁННЫХ КОЛОНОК ОБЛАСТИ ДЕРЖИТ БАЗА, А НЕ КОД (R7-1-12, ban #10).
//
// # Что здесь утверждается и почему этого не было видно ниоткуда
//
// Строка субъекта выдачи несёт копию области своей выдачи — ради того, чтобы
// оба предиката вердикта («этот субъект» и «эта область») стояли на одном
// отношении и сужались одним индексом. Перенос значения ставит вопрос, на
// который приёмка требует ответа механизмом, а не обещанием: чем расхождение
// копии с оригиналом сделано НЕВОЗМОЖНЫМ.
//
// Ответ — двумя конструкциями миграции 732001, и каждая закрывает свою половину:
//
//	составной внешний ключ  — солгать нельзя: строка с чужой областью не
//	                          ссылается ни на что и отвергается;
//	триггер заполнения      — не называть область можно: её берут у родителя,
//	                          поэтому ни один писатель не меняется.
//
// # Почему косвенной опоры недостаточно
//
// Соблазнительно считать, что механизм доказан самим прогоном: не сработай
// триггер, `SET NOT NULL` в миграции уронил бы её, а солги вставка — упал бы
// внешний ключ. Это неверно, и неверно молча: такой довод не отличает «механизм
// работает» от «этот путь ни разу не проходили». Проба обязана ПРОЙТИ путь.
//
// # Четвёртый исход назван, но НЕ создан пробой
//
// Каскад правки области у родителя сегодня недостижим: ни один путь записи в
// дереве область выдачи не меняет. Проба это НАЗЫВАЕТ и проверяет каскад прямым
// оператором — то есть свидетельствует об оборонительной мере, а не выдаёт
// несуществующий путь продукта за существующий.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
)

// scopeCarrierFixture — минимальная обвязка: аккаунт, пользователь, проекты,
// роль и одна выдача с её строкой субъекта.
type scopeCarrierFixture struct {
	pool *pgxpool.Pool
}

func newScopeCarrierFixture(t *testing.T, ctx context.Context) *scopeCarrierFixture {
	t.Helper()
	pool, err := pgxpool.New(ctx, pgtest.NewDB(t))
	require.NoError(t, err)
	// Закрытие пула С ПРЕДЕЛОМ: голое pool.Close ждёт занятые соединения без
	// срока, и проба, уронившая транзакцию, вешает прогон вместо того чтобы
	// покраснеть.
	pgtest.ClosePoolAtEnd(t, pool)

	// Обвязка сеется ОДНОЙ транзакцией: связь аккаунта с владельцем и
	// пользователя с аккаунтом взаимна, и её внешние ключи ОТЛОЖЕНЫ — то есть
	// проверяются на фиксации. Построчная автофиксация проверяла бы их на каждом
	// операторе и отвергла бы любой порядок вставки.
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	exec := func(sql string, args ...any) {
		t.Helper()
		_, err := tx.Exec(ctx, sql, args...)
		require.NoError(t, err, sql)
	}
	exec(`INSERT INTO kacho_iam.clusters (id, name) VALUES ('cluster_kacho_root', 'kacho')
	      ON CONFLICT DO NOTHING`)
	exec(`INSERT INTO kacho_iam.accounts (id, name, owner_user_id) VALUES ('acc-1', 'carrier', 'usr-1')`)
	// ДВА пользователя, и второй здесь не для полноты. Строка субъекта проходит
	// ещё и стража существования субъекта (0049); назови проба несуществующего,
	// отказ пришёл бы ОТ НЕГО, и «чужая область отвергнута» стало бы зелёным,
	// не сказав об области ничего.
	exec(`INSERT INTO kacho_iam.users (id, external_id, email, account_id)
	      VALUES ('usr-1', 'ext-1', 'usr-1@kacho.local', 'acc-1'),
	             ('usr-2', 'ext-2', 'usr-2@kacho.local', 'acc-1')`)
	exec(`INSERT INTO kacho_iam.projects (id, account_id, name)
	      VALUES ('prj-home', 'acc-1', 'home'), ('prj-other', 'acc-1', 'other')`)
	// Пустой набор разрешений законен только при непустых правилах — так велит
	// проверка схемы, и фикстура ей подчиняется, а не обходит её.
	exec(`INSERT INTO kacho_iam.roles (id, name, permissions, rules, cluster_id)
	      VALUES ('rol-1', 'probe.carrier', '[]'::jsonb,
	              jsonb_build_array(jsonb_build_object(
	                  'module', 'probe', 'resources', jsonb_build_array('*'),
	                  'verbs',  jsonb_build_array('get'))),
	              'cluster_kacho_root')`)
	exec(`INSERT INTO kacho_iam.access_bindings
	        (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
	      VALUES ('acb-1', 'user', 'usr-1', 'rol-1', 'project', 'prj-home', 'ACTIVE')`)
	require.NoError(t, tx.Commit(ctx))
	return &scopeCarrierFixture{pool: pool}
}

func (f *scopeCarrierFixture) scopeOf(t *testing.T, ctx context.Context, binding, subject string) (string, string) {
	t.Helper()
	var rt, ri string
	err := f.pool.QueryRow(ctx,
		`SELECT resource_type, resource_id FROM kacho_iam.access_binding_subjects
		  WHERE binding_id = $1 AND subject_type = 'user' AND subject_id = $2`,
		binding, subject).Scan(&rt, &ri)
	require.NoError(t, err)
	return rt, ri
}

// TestBindingSubjectScopeCarrier_LyingIsUnrepresentable — исход (а).
//
// Строка субъекта, называющая область, отличную от области своей выдачи, не
// ссылается ни на что и отвергается ВНЕШНИМ КЛЮЧОМ. Это и есть «расхождение
// невыразимо»: не «поймано проверкой», а не имеет представления в схеме.
func TestBindingSubjectScopeCarrier_LyingIsUnrepresentable(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	ctx := context.Background()
	f := newScopeCarrierFixture(t, ctx)

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ ПЕРВЫМ: та же вставка с ВЕРНОЙ областью проходит.
	// Без него отказ ниже был бы неотличим от «вставка сюда не проходит вовсе».
	_, err := f.pool.Exec(ctx,
		`INSERT INTO kacho_iam.access_binding_subjects
		   (binding_id, subject_type, subject_id, resource_type, resource_id)
		 VALUES ('acb-1', 'user', 'usr-1', 'project', 'prj-home')`)
	require.NoError(t, err, "вставка с ВЕРНОЙ областью обязана проходить: иначе отказ ниже "+
		"ничего не доказывает — он был бы отказом на любой вставке")

	_, err = f.pool.Exec(ctx,
		`INSERT INTO kacho_iam.access_binding_subjects
		   (binding_id, subject_type, subject_id, resource_type, resource_id)
		 VALUES ('acb-1', 'user', 'usr-2', 'project', 'prj-other')`)
	require.Error(t, err, "строка субъекта с ЧУЖОЙ областью принята: значит согласованность "+
		"держится не базой, и её обязан был бы держать код — то есть software check-then-act")
	require.Equal(t, "access_binding_subjects_scope_fk", constraintOf(t, err),
		"отказ пришёл не от составного внешнего ключа области, а от чего-то другого — "+
			"значит про область он ничего не утверждает: %v", err)
	t.Logf("(а) чужая область отвергнута составным внешним ключом: %s", firstLineOfErr(err))
}

// TestBindingSubjectScopeCarrier_ScopeIsTakenFromTheParent — исход (б).
//
// Писатель строки субъекта область не называет и называть не обязан: она
// свойство выдачи, а не субъекта. Ровно поэтому ни один существующий писатель
// не менялся — и это утверждается, а не предполагается.
func TestBindingSubjectScopeCarrier_ScopeIsTakenFromTheParent(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	ctx := context.Background()
	f := newScopeCarrierFixture(t, ctx)

	_, err := f.pool.Exec(ctx,
		`INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id)
		 VALUES ('acb-1', 'user', 'usr-1')`)
	require.NoError(t, err, "вставка без области отвергнута: писателю пришлось бы знать область, "+
		"то есть менялся бы каждый писатель строки субъекта")

	rt, ri := f.scopeOf(t, ctx, "acb-1", "usr-1")
	require.Equal(t, "project", rt)
	require.Equal(t, "prj-home", ri)
	t.Logf("(б) область взята у родителя: %s/%s", rt, ri)
}

// TestBindingSubjectScopeCarrier_MissingParentIsRefusedByName — исход (в).
//
// Пустой носитель не проглатывается: строка без области выпала бы из вердикта
// молча, и право перестало бы действовать без единого признака. Отказ обязан
// НАЗЫВАТЬ объявленное имя ограничения — по нему маппер ошибок и различает
// причину.
func TestBindingSubjectScopeCarrier_MissingParentIsRefusedByName(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	ctx := context.Background()
	f := newScopeCarrierFixture(t, ctx)

	_, err := f.pool.Exec(ctx,
		`INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id)
		 VALUES ('acb-нет-такой', 'user', 'usr-1')`)
	require.Error(t, err, "строка субъекта несуществующей выдачи принята — она осталась бы "+
		"без области и выпала бы из вердикта молча")
	// Имя ограничения читается из СТРУКТУРНОГО поля ответа, а не из текста
	// сообщения: по нему маппер ошибок и различает причину, а текст —
	// человеческая проза, которую он не разбирает.
	require.Equal(t, "access_binding_subjects_scope_fk", constraintOf(t, err),
		"отказ не несёт объявленного имени ограничения в структурном поле: %v", err)
	t.Logf("(в) отсутствующий родитель отвергнут с именем ограничения: %s", firstLineOfErr(err))
}

// TestBindingSubjectScopeCarrier_ParentScopeUpdateCascades — исход (г).
//
// # ЭТОТ ПУТЬ В ПРОДУКТЕ СЕГОДНЯ НЕ СУЩЕСТВУЕТ, и проба это НАЗЫВАЕТ
//
// Перенос выдачи между областями ни одним путём записи не делается: ни один
// `UPDATE kacho_iam.access_bindings` области не трогает. Значит `ON UPDATE
// CASCADE` — мера ОБОРОНИТЕЛЬНАЯ: она бесплатна, она верна, и она непроверяема
// вызовом продукта, потому что вызывать нечего.
//
// Проба поэтому бьёт по базе ПРЯМЫМ оператором и утверждает ровно то, что
// утверждать вправе: если такой путь когда-нибудь заведут, копия поедет за
// оригиналом САМА. Создавать путь ради зелёной пробы было бы хуже молчания —
// это выдало бы оборонительную меру за действующую поверхность продукта.
func TestBindingSubjectScopeCarrier_ParentScopeUpdateCascades(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	ctx := context.Background()
	f := newScopeCarrierFixture(t, ctx)

	_, err := f.pool.Exec(ctx,
		`INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id)
		 VALUES ('acb-1', 'user', 'usr-1')`)
	require.NoError(t, err)

	// ПРЕДПОСЫЛКА, названная числом: путей продукта, меняющих область выдачи,
	// ноль. Проба свидетельствует об обороне, а не о поверхности.
	t.Log("предпосылка: путь «перенос выдачи между областями» в дереве отсутствует — " +
		"каскад здесь проверяется прямым оператором к базе, а не вызовом продукта")

	_, err = f.pool.Exec(ctx,
		`UPDATE kacho_iam.access_bindings SET resource_id = 'prj-other' WHERE id = 'acb-1'`)
	require.NoError(t, err, "правка области у родителя отвергнута: значит копия удерживает "+
		"родителя, а не следует за ним")

	rt, ri := f.scopeOf(t, ctx, "acb-1", "usr-1")
	require.Equal(t, "project", rt)
	require.Equal(t, "prj-other", ri,
		"копия осталась на прежней области: каскад правки не доехал, и две стороны разошлись")
	t.Logf("(г) каскад доехал: копия стала %s/%s вслед за родителем", rt, ri)
}

// constraintOf — имя ограничения из СТРУКТУРНОГО поля ответа Postgres.
func constraintOf(t *testing.T, err error) string {
	t.Helper()
	var pg *pgconn.PgError
	if !errors.As(err, &pg) {
		t.Fatalf("ошибка не от Postgres, имя ограничения читать неоткуда: %v", err)
	}
	return pg.ConstraintName
}

func firstLineOfErr(err error) string {
	s := err.Error()
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
