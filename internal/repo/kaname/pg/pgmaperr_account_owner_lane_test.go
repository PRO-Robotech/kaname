// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// pgmaperr_account_owner_lane_test.go — `accounts_owner_fk` несёт ОБЕ стороны
// пары сентинелов, а не одну.
//
// ПРЕДМЕТ (#2048). Ветвь отвечала «User %s not found» + `ErrReferenceMissing`
// при ЛЮБОМ исходе. Ограничение объявлено `ON DELETE RESTRICT`, то есть
// срабатывает и на снятии человека, ВЛАДЕЮЩЕГО аккаунтом, — а это состояние
// «ещё ссылаются», противоположное «ссылки нет». Человек, которого только что
// вернул `ListUsers`, получал утверждение о собственном отсутствии.
//
// Пара сентинелов заведена специально ради этого различения, и её собственный
// комментарий это говорит (`internal/errors/errors.go`): `ErrReferenceMissing` —
// «referenced resource missing», `ErrReferenceInUse` — «resource still
// referenced». Четыре соседних ограничения в той же функции ветвятся правильно;
// у этого ветви не было вовсе.
//
// ПОЧЕМУ УТВЕРЖДАЕТСЯ ТЕКСТ, А НЕ ТОЛЬКО КОД. Обе стороны пары вложены в
// `ErrFailedPrecondition`, поэтому код отказа у них ОДИН и различить их кодом
// нельзя by construction. Различает сообщение, а тон сообщений — часть
// контракта (`api-conventions.md` §Error-format). Проба, утверждающая только
// код, зеленела бы на дефекте дословно.

import (
	stderrors "errors"
	"strings"
	"testing"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// ownerLaneRefusal — текст стороны «ещё ссылаются». Держится здесь дословно,
// потому что его же обещает шапка use-case снятия человека
// (`internal/apps/kaname/api/user/delete.go`), и до #2048 у этого обещания не
// было производителя нигде в дереве: единственным вхождением строки был сам
// комментарий.
const ownerLaneRefusal = "owns accounts and cannot be deleted"

func TestAccountOwnerFK_CarriesBothSidesOfThePair(t *testing.T) {
	const userID = "usr0000000000000ownr"

	t.Run("сторона ссылающихся — человек владеет аккаунтом", func(t *testing.T) {
		// Подсказку `User.Delete` ставит сам репозиторий на своём операторе
		// снятия (`user_repo.go`), поэтому полоса не выдумана пробой.
		err := wrapPgErr(mkPgErr("23503", "accounts_owner_fk"), "User.Delete", userID)

		if !stderrors.Is(err, iamerr.ErrReferenceInUse) {
			t.Fatalf("признак = %v; ожидался ErrReferenceInUse (ресурс ещё ссылается)", err)
		}
		if !stderrors.Is(err, iamerr.ErrFailedPrecondition) {
			t.Fatalf("отказ перестал быть отказом предусловия: %v", err)
		}
		text := iamerr.StripSentinel(err)
		if !strings.Contains(text, ownerLaneRefusal) {
			t.Fatalf("текст не называет блокер: %q, ожидалось вхождение %q", text, ownerLaneRefusal)
		}
		if strings.Contains(text, "not found") {
			t.Fatalf("отказ утверждает ОТСУТСТВИЕ существующего человека: %q", text)
		}
		if !strings.Contains(text, userID) {
			t.Errorf("текст не называет человека, о котором отказ: %q", text)
		}
		assertNoLeak(t, text)
	})

	t.Run("сторона ссылки — такого человека нет", func(t *testing.T) {
		// Положительный контроль: путь `Account.Create` со ссылкой на
		// несуществующего владельца обязан сохранить прежний контракт-тон. Без
		// него отрицание выше зеленело бы на ветви, потерявшей обе стороны и
		// отвечающей «ещё ссылаются» всегда.
		err := wrapPgErr(mkPgErr("23503", "accounts_owner_fk"), "", userID)

		if !stderrors.Is(err, iamerr.ErrReferenceMissing) {
			t.Fatalf("признак = %v; ожидался ErrReferenceMissing (ссылаемого нет)", err)
		}
		if !stderrors.Is(err, iamerr.ErrFailedPrecondition) {
			t.Fatalf("отказ перестал быть отказом предусловия: %v", err)
		}
		text := iamerr.StripSentinel(err)
		want := "User " + userID + " not found"
		if text != want {
			t.Fatalf("контракт-тон стороны ссылки изменился: %q, ожидалось %q", text, want)
		}
		assertNoLeak(t, text)
	})

	t.Run("две стороны дают РАЗНЫЕ тексты", func(t *testing.T) {
		inUse := iamerr.StripSentinel(
			wrapPgErr(mkPgErr("23503", "accounts_owner_fk"), "User.Delete", userID))
		missing := iamerr.StripSentinel(
			wrapPgErr(mkPgErr("23503", "accounts_owner_fk"), "", userID))
		if inUse == missing {
			t.Fatalf("обе стороны отвечают одним текстом %q — различения нет", inUse)
		}
		t.Logf("перепись: сторон пары осмотрено 2 · текстов различных 2 · подсказок полосы 2 (User.Delete, «»)")
	})
}

// TestAccountOwnerFK_ADeleteOfAnotherResourceKeepsTheReferenceSide — законный
// близнец: подсказка снятия, но ЧУЖОГО ресурса. Полоса «ещё ссылаются» у этого
// ограничения принадлежит снятию ЧЕЛОВЕКА; вставка аккаунта из-под любого
// другого глагола обязана остаться стороной ссылки.
//
// Без этого утверждения починка вида «всякая подсказка снятия ⇒ ещё ссылаются»
// прошла бы незамеченной, а она неверна: `accounts_owner_fk` нарушается снятием
// ровно одной строки — пользователя.
func TestAccountOwnerFK_ADeleteOfAnotherResourceKeepsTheReferenceSide(t *testing.T) {
	const userID = "usr0000000000000ownr"
	err := wrapPgErr(mkPgErr("23503", "accounts_owner_fk"), "Group.Delete", userID)

	if !stderrors.Is(err, iamerr.ErrReferenceMissing) {
		t.Fatalf("чужой глагол снятия сменил полосу: %v", err)
	}
	if text := iamerr.StripSentinel(err); text != "User "+userID+" not found" {
		t.Fatalf("чужой глагол снятия сменил текст: %q", text)
	}
}

// ── ГДЕ ключ срабатывает: на ОПЕРАТОРЕ, а не на коммите ─────────────────────
//
// Ключ объявлен `DEFERRABLE INITIALLY DEFERRED`, и соседняя интеграционная
// проба (`account_owner_fk_commit_integration_test.go`) показывает отложенность
// на стороне ВСТАВКИ: аккаунт с несуществующим владельцем срывает коммит.
// Отсюда напрашивается вывод, что и снятие владельца сорвётся на коммите, — и
// он НЕВЕРЕН.
//
// Перемерено прогоном (`user_delete_owns_account_integration_test.go`): отказ
// приходит из САМОГО оператора снятия, с подсказкой `User.Delete`, которую
// репозиторий ставит рядом. Причина в Postgres: `ON DELETE RESTRICT` проверяется
// НЕМЕДЛЕННО и откладыванию не подлежит — этим он и отличается от `NO ACTION`,
// который откладывается. Отложенность ключа относится к стороне вставки.
//
// Записано здесь, потому что посылка «раз ключ отложен, значит отложены обе его
// стороны» правдоподобна, и по ней я успел завести подсказку коммита, у которой
// нет и не может быть входа. Опровергла её проба, а не чтение.
