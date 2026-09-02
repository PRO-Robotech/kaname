// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package user

// identity_tuples_removed_test.go — стадия S2 перехода IAM-ID-1 (задача
// kacho#472), сценарий IAM-ID-1-61: кортежи личности снимаются вместе со строкой.
//
// # Предмет
//
// Создание человека ПИШЕТ кортежи его объекта личности — самокортеж
// (`iam_user:<u> # subject @ user:<u>`, тот самый «прочитать себя») и указатель
// принадлежности (`iam_user:<u> # account @ account:<A>`), от которого сегодня
// выводится административный уровень. Снятие строки не удаляло НИ ОДНОГО из них:
// путь удаления снимал строку и писал событие аудита, и всё.
//
// Асимметрия «пишем на создании, не снимаем на удалении» оставляет в модели прав
// утверждения о человеке, которого больше нет. Это не косметика: указатель
// принадлежности — источник вывода уровня, и он переживает своего носителя.
//
// # Почему проб ДВЕ, и почему одной мало
//
// Приёмка требует утверждать ОТСУТСТВИЕ кортежей в модели, а не факт вызова
// снятия. Причина конкретная: намерение можно эмитировать в форме, которую
// принимающая сторона не примет либо примет как no-op, — и проба «снятие
// вызвано» останется зелёной ровно на этом дефекте (data-integrity.md
// §«Межсервисное намерение» — тест обязан утверждать контракт ПРИНИМАЮЩЕЙ
// стороны).
//
// Поэтому:
//
//   - TestIntegration_IdentityTuplesAreRemovedFromTheModel — ИСХОД: настоящая
//     база iam, кортежи пишутся в форме СОЗДАНИЯ, снимаются списком УДАЛЕНИЯ, и
//     СОСТОЯНИЕ опрашивается о результате. Два разных производителя формы по обе
//     стороны — если они разойдутся, снятие станет no-op и проба покраснеет;
//   - TestDeleteUser_EmitsIdentityTupleDeletesInTx — МЕСТО: намерение уходит в
//     ТОЙ ЖЕ транзакции, что и снятие строки, а не «потом» и не best-effort.
//
// Ни одна из двух другую не заменяет: первая не видит транзакции, вторая не
// видит движка.

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// identityTuplesOfCreation — форма, которую пишет путь СОЗДАНИЯ
// (`bootstrapTuples`), суженная до кортежей, чей ОБЪЕКТ есть объект личности.
// Выписана здесь намеренно, а не взята из прод-функции: сравнивать список
// удаления с ним самим значило бы записать тождество синтаксисом утверждения.
// Прочие кортежи создания (владение аккаунтом, админ проекта, указатели
// кластера) объектом личности не являются и со снятием человека не уходят —
// аккаунт и проект переживают его.
func identityTuplesOfCreation(userID, accountID string) []clients.RelationTuple {
	return []clients.RelationTuple{
		{User: fmt.Sprintf("user:%s", userID), Relation: "subject", Object: fmt.Sprintf("iam_user:%s", userID)},
		{User: fmt.Sprintf("account:%s", accountID), Relation: "account", Object: fmt.Sprintf("iam_user:%s", userID)},
	}
}

func toClientTuples(in []service.RelationTuple) []clients.RelationTuple {
	out := make([]clients.RelationTuple, 0, len(in))
	for _, t := range in {
		out = append(out, clients.RelationTuple{User: t.User, Relation: t.Relation, Object: t.Object})
	}
	return out
}

// journalWrite кладёт строку намерения ЗАПИСИ и утверждает, что проекция её
// приняла. Утверждение несущее: без него «кортеж есть» было бы неотличимо от
// «фикстура ничего не посеяла».
func journalWrite(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tp clients.RelationTuple) {
	t.Helper()
	_, err := pool.Exec(ctx, `
		INSERT INTO kacho_iam.fga_outbox (event_type, payload, created_at)
		VALUES ('fga.tuple.write',
		        jsonb_build_object('user', $1::text, 'relation', $2::text, 'object', $3::text),
		        now())`, tp.User, tp.Relation, tp.Object)
	require.NoErrorf(t, err, "журнал: запись %+v", tp)
}

// journalDelete кладёт строку намерения СНЯТИЯ — ровно ту форму, которую эмитит
// путь удаления. Отказ проекции здесь и есть «принимающая сторона формы не
// приняла»: намерение, которого она не принимает, неотличимо от неэмитированного.
func journalDelete(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tuples []clients.RelationTuple) {
	t.Helper()
	for _, tp := range tuples {
		_, err := pool.Exec(ctx, `
			INSERT INTO kacho_iam.fga_outbox (event_type, payload, created_at)
			VALUES ('fga.tuple.delete',
			        jsonb_build_object('user', $1::text, 'relation', $2::text, 'object', $3::text),
			        now())`, tp.User, tp.Relation, tp.Object)
		require.NoErrorf(t, err,
			"проекция обязана ПРИНЯТЬ форму снятия %+v: намерение, которого принимающая "+
				"сторона не принимает, не отличимо от неэмитированного", tp)
	}
}

// factHeld — держится ли этот прямой факт состоянием прямо сейчас.
func factHeld(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tp clients.RelationTuple) bool {
	t.Helper()
	objectType, objectID, ok := strings.Cut(tp.Object, ":")
	require.Truef(t, ok, "объект %q не разбирается как «тип:идентификатор»", tp.Object)
	var n int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*)::int FROM kacho_iam.relation_fact
		 WHERE object_type = $1 AND object_id = $2 AND relation = $3 AND subject = $4`,
		objectType, objectID, tp.Relation, tp.User).Scan(&n))
	return n > 0
}

func TestIntegration_IdentityTuplesAreRemovedFromTheModel(t *testing.T) {
	if testing.Short() {
		t.Skip("нужна живая база (-short)")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pgtest.NewDB(t))
	require.NoError(t, err, "пул")
	t.Cleanup(pool.Close)

	const (
		userID    = "usr000000000000tupl1"
		accountID = "acc000000000000tupl1"
	)

	// ── форма СОЗДАНИЯ: кортежи объекта личности лежат в состоянии ───────────
	created := identityTuplesOfCreation(userID, accountID)
	for _, tp := range created {
		journalWrite(t, ctx, pool, tp)
	}

	// Положительный контроль. Без него «кортежей нет» было бы истинно и на
	// пустом состоянии, то есть утверждение ниже не значило бы ничего.
	for _, tp := range created {
		require.Truef(t, factHeld(t, ctx, pool, tp),
			"ПРЕДПОСЫЛКА: кортеж %+v обязан лежать в состоянии до снятия", tp)
	}

	// ── снятие: применяем ровно тот список, который эмитит путь удаления ─────
	deletes := identityTuplesForRemoval(domain.UserID(userID), accountID)
	require.NotEmpty(t, deletes,
		"список снятия пуст — тогда удаление ничего не снимает, а проба ниже зеленеет вхолостую")
	journalDelete(t, ctx, pool, toClientTuples(deletes))

	// ── исход: кортежей больше нет ───────────────────────────────────────────
	require.False(t, factHeld(t, ctx, pool, clients.RelationTuple{
		User: "user:" + userID, Relation: "subject", Object: "iam_user:" + userID}),
		"самокортеж снятого человека обязан исчезнуть из модели — иначе о человеке, "+
			"которого нет, продолжают утверждать")

	require.False(t, factHeld(t, ctx, pool, clients.RelationTuple{
		User: "account:" + accountID, Relation: "account", Object: "iam_user:" + userID}),
		"указатель принадлежности обязан исчезнуть: от него выводится административный "+
			"уровень, и переживать своего носителя он не вправе")

	// ── повторное снятие идемпотентно ────────────────────────────────────────
	// Дренаж доставляет как минимум однажды, поэтому повтор — штатный путь, а не
	// исключительный.
	journalDelete(t, ctx, pool, toClientTuples(deletes))
	for _, tp := range created {
		require.Falsef(t, factHeld(t, ctx, pool, tp),
			"повторное снятие уже снятого обязано быть безобидным: дренаж at-least-once, "+
				"и вторая доставка не должна ни воскрешать кортеж %+v, ни отравлять строку", tp)
	}
}

// TestDeleteUser_EmitsIdentityTupleDeletesInTx — намерение уходит В ТОЙ ЖЕ
// транзакции, что и снятие строки.
//
// Проба выше утверждает, что форма снятия принимается движком; эта — что
// намерение вообще будет доставлено. Post-commit best-effort здесь не годится:
// процесс, умерший между фиксацией и вызовом, оставил бы в модели прав
// утверждения о человеке, которого уже нет, и заметить это было бы нечем.
//
// `doDelete` зовётся напрямую — это тело транзакции, и оно синхронно; идти
// через асинхронную операцию значило бы утверждать про расписание, а не про
// порядок.
func TestDeleteUser_EmitsIdentityTupleDeletesInTx(t *testing.T) {
	repo := newFakeUsrRepo(delAccID)
	uc := NewDeleteUserUseCase(repo, newFakeUsrOps())

	_, err := uc.doDelete(context.Background(), delUserID, "actor-"+delUserID, delAccID)
	require.NoError(t, err)

	require.Equal(t, []string{"delete-row", "emit-delete", "commit"}, repo.sequence(),
		"порядок внутри транзакции: строка снята → намерение эмитировано → и только "+
			"потом фиксация. Намерение ПОСЛЕ фиксации — это уже не транзакция")

	require.ElementsMatch(t, identityTuplesForRemoval(delUserID, delAccID), repo.deletedTuples(),
		"снимаются ровно кортежи объекта личности — не меньше (иначе утверждение "+
			"переживает человека) и не больше (иначе снятие человека рушит аккаунт)")
}

// TestDeleteUser_AccountLess_EmitsNoAccountTuple — у строки без аккаунта
// указателя принадлежности нет, и выдумывать его снятие нечем.
//
// Отрицание в паре с положительным контролем: самокортеж обязан сниматься и
// здесь, иначе «кортежа аккаунта нет» было бы зелено и при полностью
// отсутствующей эмиссии.
func TestDeleteUser_AccountLess_EmitsNoAccountTuple(t *testing.T) {
	repo := newFakeUsrRepo("")
	uc := NewDeleteUserUseCase(repo, newFakeUsrOps())

	_, err := uc.doDelete(context.Background(), delUserID, "actor-"+delUserID, "")
	require.NoError(t, err)

	got := repo.deletedTuples()
	require.Len(t, got, 1,
		"ровно один кортеж — самокортеж; аккаунта у строки нет")
	require.Equal(t, "iam_user:"+delUserID, got[0].Object)
	require.Equal(t, "subject", got[0].Relation,
		"положительный контроль: самокортеж снимается и у строки без аккаунта")
	for _, tp := range got {
		require.NotContains(t, tp.User, "account:",
			"кортеж, адресующий аккаунт, которого никто не называл, эмитировать нельзя")
	}
}
