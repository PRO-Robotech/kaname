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
//   - TestIntegration_IdentityTuplesAreRemovedFromTheModel — ИСХОД: настоящий
//     движок прав, кортежи пишутся в форме СОЗДАНИЯ, снимаются списком УДАЛЕНИЯ,
//     и движок опрашивается о результате. Два разных производителя формы по обе
//     стороны — если они разойдутся, снятие станет no-op и проба покраснеет;
//   - TestDeleteUser_EmitsIdentityTupleDeletesInTx — МЕСТО: намерение уходит в
//     ТОЙ ЖЕ транзакции, что и снятие строки, а не «потом» и не best-effort.
//
// Ни одна из двух другую не заменяет: первая не видит транзакции, вторая не
// видит движка.

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
	"github.com/PRO-Robotech/kacho/services/iam/internal/testsupport/fgatest"
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

func TestIntegration_IdentityTuplesAreRemovedFromTheModel(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	h := fgatest.New(t)

	const (
		userID    = "usr00000000000tupl1"
		accountID = "acc00000000000tupl1"
	)

	// ── форма СОЗДАНИЯ: кортежи объекта личности лежат в движке ──────────────
	for _, tp := range identityTuplesOfCreation(userID, accountID) {
		h.Write(t, tp.User, tp.Relation, tp.Object)
	}

	// Положительный контроль. Без него «кортежей нет» было бы истинно и на
	// пустом хранилище, то есть утверждение ниже не значило бы ничего.
	selfOK, err := h.Client.Check(ctx, "user:"+userID, "subject", "iam_user:"+userID)
	require.NoError(t, err)
	require.True(t, selfOK, "ПРЕДПОСЫЛКА: самокортеж обязан лежать в движке до снятия")

	// ── снятие: применяем ровно тот список, который эмитит путь удаления ─────
	deletes := identityTuplesForRemoval(domain.UserID(userID), accountID)
	require.NotEmpty(t, deletes,
		"список снятия пуст — тогда удаление ничего не снимает, а проба ниже зеленеет вхолостую")
	require.NoError(t, h.Client.DeleteTuples(ctx, toClientTuples(deletes)),
		"движок обязан ПРИНЯТЬ форму снятия: намерение, которого принимающая сторона "+
			"не принимает, не отличимо от неэмитированного")

	// ── исход: кортежей больше нет ───────────────────────────────────────────
	selfOK, err = h.Client.Check(ctx, "user:"+userID, "subject", "iam_user:"+userID)
	require.NoError(t, err)
	require.False(t, selfOK,
		"самокортеж снятого человека обязан исчезнуть из модели — иначе о человеке, "+
			"которого нет, продолжают утверждать")

	acctOK, err := h.Client.Check(ctx, "account:"+accountID, "account", "iam_user:"+userID)
	require.NoError(t, err)
	require.False(t, acctOK,
		"указатель принадлежности обязан исчезнуть: от него выводится административный "+
			"уровень, и переживать своего носителя он не вправе")

	// ── повторное снятие идемпотентно ────────────────────────────────────────
	// Дренаж доставляет как минимум однажды, поэтому повтор — штатный путь, а не
	// исключительный.
	require.NoError(t, h.Client.DeleteTuples(ctx, toClientTuples(deletes)),
		"повторное снятие уже снятого обязано быть безобидным: дренаж at-least-once, "+
			"и вторая доставка не должна отравлять строку")
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
