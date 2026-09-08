// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// expand_access_form_integration_test.go — разворот выдачи в конкретных
// принципалов НА ФОРМЕ, а не на внешнем движке отношений.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ БЫЛО РАНЬШЕ И ЧТО ИЗ ЭТОГО ПЕРЕЖИЛО СНЯТИЕ ДВИЖКА
//
// Прежняя редакция поднимала настоящий внешний движок, писала в него кортежи
// руками и спрашивала его же. Движка нет — но ПРЕДМЕТ пробы им не был: предмет
// в том, что выдача, адресованная ГРУППЕ, разворачивается в людей, а сама группа
// принципалом не становится, и что развернуть чужой объект нельзя.
//
// Оба вопроса теперь отвечает та же база, что хранит выдачу: форма
// (`repo/kaname/pg/relverdict`) под дверью решения (`internal/authzcascade`). Она
// же подставляется в оба порта use-case'а — перечисление принципалов и вопрос о
// праве вызывающего, — поэтому проба спрашивает ровно тот источник, который
// спрашивает боевая посадка (`cmd/kaname/wiring.go`).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ИНТЕГРАЦИОННАЯ, А НЕ ЮНИТ С ПОДСТАВНЫМ ПЕРЕЧИСЛИТЕЛЕМ
//
// Юнит с подставным перечислителем в этом пакете УЖЕ есть
// (`expand_access_test.go`): он моделирует контракт порта — «граф уже пройден» —
// и проверяет проекцию: дедупликацию, усечение, форму ошибки. Он по построению
// не может сказать, разворачивает ли членство САМ ИСТОЧНИК: подставной
// перечислитель возвращает то, что в него положили.
//
// Здесь предмет обратный — именно проход графа: право лежит на группе, спрашивают
// про людей, и между ними членство. Подставной источник сделал бы это утверждение
// вакуумным.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
)

// formDoor поднимает дверь решения над НАСТОЯЩЕЙ базой пробы.
//
// Возвращается один и тот же экземпляр на оба порта — перечисление принципалов и
// вопрос о праве вызывающего, — потому что в корне композиции он тоже один.
// Разные значения здесь дали бы пробу, в которой гейт и разворот отвечают из
// разных состояний, а такого состояния в проде не бывает.
func formDoor(t *testing.T) (*authzcascade.Client, *pgxpool.Pool) {
	t.Helper()
	if testing.Short() {
		t.Skip("нужен Postgres: пропуск в -short")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pgtest.NewDB(t))
	require.NoError(t, err, "пул")
	// Закрытие С ПРЕДЕЛОМ, а не «когда-нибудь»: `pgxpool.Pool.Close` ждёт возврата
	// ВСЕХ выданных соединений, а проба, упавшая внутри открытой транзакции,
	// соединение не вернёт — отложенное закрытие встало бы ждать писателя,
	// которого уже нет, пакет упёрся бы в предел прогона и напечатал `FAIL`.
	// Тогда «не выполнилось» приходит к читателю под видом красного, и вердикта
	// нет НИ У ОДНОЙ пробы пакета, включая прошедшие.
	pgtest.ClosePoolAtEnd(t, pool)
	return authzcascade.Wrap(relverdict.NewAsker(pool)), pool
}

// seedExpandFixture кладёт арендную обвязку, группу с двумя людьми и выдачу.
//
// Сеется НАСТОЯЩИМИ строками, а не обходом внешних ключей: фикстура, снимающая
// ограничения ради удобства, доказывала бы работу разворота на данных, которых
// в проде не бывает.
func seedExpandFixture(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	// ВЕСЬ посев — ОДНОЙ транзакцией, и это не оформление. Ссылка круговая: у
	// аккаунта есть владелец-пользователь, у пользователя — аккаунт. Разрешает её
	// отложенный внешний ключ (`accounts_owner_fk … DEFERRABLE INITIALLY
	// DEFERRED`), а откладывание действует до КОММИТА. Посев по одному оператору в
	// автокоммите проверяет ключ на каждом из них и отвергает первый же — то есть
	// фикстура не собирается вовсе.
	tx, err := pool.Begin(ctx)
	require.NoError(t, err, "транзакция посева")
	defer func() { _ = tx.Rollback(ctx) }()
	run := func(sql string, args ...any) {
		t.Helper()
		_, err := tx.Exec(ctx, sql, args...)
		require.NoErrorf(t, err, "посев (%s)", sql)
	}
	// Имена проходят `accounts_name_check` / `projects_name_check` /
	// `groups_name_check` (единственная форма имени дерева): подчёркивание в ИМЕНИ
	// отвергается схемой, в идентификаторе — нет.
	run(`INSERT INTO kaname.accounts (id, name, owner_user_id)
	     VALUES ('acc_A', 'home-account', 'usr_owner'), ('acc_B', 'foreign-account', 'usr_owner')
	     ON CONFLICT DO NOTHING`)
	for _, u := range []string{"usr_owner", "usr_auditor", "usr_m1", "usr_m2", "usr_secret_b"} {
		run(`INSERT INTO kaname.users (id, external_id, email, account_id)
		     VALUES ($1, $1, $1 || '@kacho.local', 'acc_A') ON CONFLICT DO NOTHING`, u)
	}
	run(`INSERT INTO kaname.groups (id, account_id, name) VALUES ('grp_team', 'acc_A', 'team-group')
	     ON CONFLICT DO NOTHING`)
	run(`INSERT INTO kaname.group_members (group_id, member_type, member_id)
	     VALUES ('grp_team', 'user', 'usr_m1'), ('grp_team', 'user', 'usr_m2')
	     ON CONFLICT DO NOTHING`)

	// Выдача группе — в КАНОНИЧЕСКОЙ форме субъекта, той самой, какую производит
	// продукт: хвост отношения раскрывает членство на стороне модели. Голая форма
	// `group:<id>` тоже законна, но она адресует саму группу как получателя, а
	// предмет здесь — люди внутри неё.
	run(`INSERT INTO kaname.relation_fact (object_type, object_id, relation, subject)
	     VALUES ('account', 'acc_A', 'viewer', 'group:grp_team#member')`)
	// Право вызывающего администрировать СВОЙ объект — и только его.
	run(`INSERT INTO kaname.relation_fact (object_type, object_id, relation, subject)
	     VALUES ('account', 'acc_A', 'admin', 'user:usr_auditor')`)
	// На чужом аккаунте лежит НАСТОЯЩАЯ выдача: без неё отказ ниже был бы
	// неотличим от «там всё равно никого нет», и утечка не имела бы чего утекать.
	run(`INSERT INTO kaname.relation_fact (object_type, object_id, relation, subject)
	     VALUES ('account', 'acc_B', 'viewer', 'user:usr_secret_b')`)
	require.NoError(t, tx.Commit(ctx), "коммит посева: форма читает СВОЕЙ транзакцией и "+
		"незакоммиченного не увидит — проба зеленела бы на пустоте")
}

func auditorCtx() context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{ID: "usr_auditor", Type: "user"})
}

// Выдача, адресованная группе, разворачивается в людей; сама группа принципалом
// не становится.
func TestExpandAccess_GroupGrantResolvesToItsMembers_OnTheForm(t *testing.T) {
	door, pool := formDoor(t)
	ctx := context.Background()
	seedExpandFixture(t, ctx, pool)

	// repo не провязан намеренно: право вызывающего резолвится ЧЕРЕЗ ФОРМУ
	// (делегированный администратор), а не через владельца аккаунта в БД. Так
	// проверяется именно тот путь, который остался единственным для объектов без
	// владельца в схеме.
	uc := NewExpandAccessUseCase(door).WithGrantAuthority(nil, door, nil)

	principals, truncated, err := uc.Execute(auditorCtx(), "account", "acc_A", "viewer", 0)
	require.NoError(t, err)
	assert.False(t, truncated,
		"форма отвечает страницами с курсором — усечения, о котором нельзя спросить дальше, у неё не бывает")

	ids := map[string]struct{}{}
	for _, p := range principals {
		ids[string(p.ID)] = struct{}{}
		assert.NotContains(t, string(p.ID), "grp_",
			"группа названа принципалом: разворот вернул адресата выдачи вместо тех, у кого доступ")
	}
	assert.Contains(t, ids, "usr_m1",
		"член группы не назван — право, выданное каноническим путём, не находится, и выглядит это как честное «прав нет»")
	assert.Contains(t, ids, "usr_m2",
		"назван один член из двух — разворот останавливается на первом, а отзывать пошли бы не всех")
}

// Развернуть ЧУЖОЙ объект нельзя, и отказ не отдаёт ничего из него.
//
// Отрицание стоит в паре с положительным контролем выше по телу: без него
// «отказано» было бы неотличимо от «разворот не работает вовсе».
func TestExpandAccess_ForeignObjectIsDeniedAndLeaksNothing_OnTheForm(t *testing.T) {
	door, pool := formDoor(t)
	ctx := context.Background()
	seedExpandFixture(t, ctx, pool)

	uc := NewExpandAccessUseCase(door).WithGrantAuthority(nil, door, nil)

	// Положительный контроль: на СВОЁМ объекте тот же вызывающий проходит.
	_, _, err := uc.Execute(auditorCtx(), "account", "acc_A", "viewer", 0)
	require.NoError(t, err, "вызывающий держит admin на acc_A — разворот обязан пройти")

	principals, _, err := uc.Execute(auditorCtx(), "account", "acc_B", "viewer", 0)
	require.Error(t, err, "разворот чужого объекта обязан быть отказан")
	assert.Equal(t, codes.PermissionDenied, status.Code(err),
		"отказ в праве администрировать объект — PERMISSION_DENIED")
	assert.Empty(t, principals,
		"вместе с отказом ушёл состав чужой выдачи — отказ, отдающий предмет вопроса, защищает только на вид")
}
