// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// own_gate_wiring_guard_test.go — отказ в старте, исполненный в ОБЕ стороны.
//
// Страж существует потому, что потеря куска провязки ТИХАЯ: служба поднимется,
// станет Ready и не ответит ни на один вопрос о доступе — а снаружи это выглядит
// исправной службой. Ничто другое в процессе об этом не скажет.
//
// Страж, которого никто не может исполнить, — это страж, про который никто не
// знает, работает ли он. Поэтому здесь утверждаются обе стороны: полная провязка
// проходит, а недостающий кусок даёт жалобу, КОТОРАЯ НАЗЫВАЕТ недостающее. Текст
// жалобы проверяется намеренно — это то, что видит оператор, когда стенд не
// поднимается, и отказ, не сказавший что чинить, исполнить нельзя (текст отказа
// оператору выведен из-под запрета на operational-детали, `security.md`).
//
// ─────────────────────────────────────────────────────────────────────────────
// УСЛОВИЕ ЗДЕСЬ ОДНО, А БЫЛО ЧЕТЫРЕ — И ЭТО НЕ ОСЛАБЛЕНИЕ
//
// Три снятых условия были условиями ЧУЖОГО транспорта: второй шанс поверх
// доехавших очередью кортежей, страничное чтение структурных фактов и
// предъявление решения сравнителю форм. Ни у одного из трёх больше нет ПРЕДМЕТА —
// решение принимает реляционная форма своей базой, и то, чем её дополняли, она
// читает первым же вопросом. Проба, продолжавшая их утверждать, утверждала бы о
// несуществующем.
//
// Оставшееся условие — что двери есть чем отвечать: дверь без формы возвращает
// ОШИБКУ на каждый вопрос (`authzcascade.ErrFormNotWired`), а не отказ.
package main

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/authzcascade"
)

// askerNeverAsked — форма, которую страж НЕ спрашивает.
//
// Страж выясняет ровно одно: ЕСТЬ ли у двери чем отвечать. Ни одной строки здесь
// не читается, поэтому дублёр не отвечает «да» — он отвечает ОШИБКОЙ на любой
// вопрос. Дублёр, молча возвращающий «разрешено», был бы снисходительнее
// настоящего и сделал бы невидимым как раз тот случай, ради которого страж
// заведён: обращение к форме там, где обращения быть не должно, прошло бы молча.
type askerNeverAsked struct{ t *testing.T }

func (a askerNeverAsked) fail(method string) error {
	a.t.Helper()
	a.t.Fatalf("страж провязки спросил форму (%s) — он обязан лишь установить, что она ЕСТЬ", method)
	return nil
}

func (a askerNeverAsked) Allowed(context.Context, string, string, string, string, map[string]any) (bool, error) {
	return false, a.fail("Allowed")
}

func (a askerNeverAsked) AllowedMany(context.Context, string, string, []string, string, map[string]any) ([]bool, error) {
	return nil, a.fail("AllowedMany")
}

func (a askerNeverAsked) SubjectsPage(context.Context, string, string, string, string, int) ([]string, string, error) {
	return nil, "", a.fail("SubjectsPage")
}

func (a askerNeverAsked) Sources(context.Context, string, string, string) ([]string, error) {
	return nil, a.fail("Sources")
}

// DirectRelationsMany — страничная диагностика. Страж провязки её тоже не зовёт:
// его предмет — существование формы, а не её ответы.
func (a askerNeverAsked) DirectRelationsMany(context.Context, string, string, []string, int) (
	map[string][]string, error) {
	return nil, a.fail("DirectRelationsMany")
}

func (a askerNeverAsked) DirectRelations(context.Context, string, string, string, int) ([]string, error) {
	return nil, a.fail("DirectRelations")
}

func TestOwnGateWiringGuard(t *testing.T) {
	// Положительная сторона: то, что собирает композиционный корень
	// (`authzcascade.Wrap(<форма>)`), обязано удовлетворять СВОЕМУ ЖЕ стражу.
	// Иначе страж либо неверен, либо недостижим, а снаружи эти два состояния
	// выглядят одинаково.
	require.Empty(t,
		ownGateWiringComplaint(authzcascade.Wrap(askerNeverAsked{t})),
		"провязка, которую строит композиционный корень, обязана проходить свой же страж")

	// Отрицательная сторона: формы нет — КАЖДЫЙ вопрос о доступе вернул бы
	// ошибку, а служба была бы Ready. Отказ обязан состояться И НАЗВАТЬ предмет.
	complaint := ownGateWiringComplaint(authzcascade.Wrap(nil))
	require.NotEmpty(t, complaint,
		"дверь без формы обязана быть отвергнута: служба поднялась бы, не решая ничего")
	for _, want := range []string{"источник вердикта о доступе не провязан", "ошибку, а не ответ"} {
		require.Contains(t, complaint, want,
			"отказ обязан назвать оператору, ЧТО не провязано и чем это грозит; "+
				"отказ, не сказавший что чинить, исполнить нельзя")
	}

	// Дверь, которой нет вовсе, — тот же исход, а не паника: страж читается ДО
	// того, как что-либо собрано, и обязан пережить вход, который в боевой
	// посадке не встречается.
	require.NotEmpty(t, ownGateWiringComplaint(nil),
		"отсутствующая дверь обязана давать жалобу, а не падение стража")

	// Жалоба — рантайм-диагностика ОПЕРАТОРУ, а не текст для арендатора: она
	// называет ручку, которую надо починить, и не несёт ни строки подключения,
	// ни имени субъекта.
	require.False(t, strings.Contains(complaint, "://"),
		"жалоба не несёт строку подключения — оператор чинит настройку, а не читает её значение")
}
