// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession_test

// recovery_refusal_work_test.go — НЕРАЗЛИЧИМОСТЬ ПОЛОС ОТКАЗА ЗАВЕРШЕНИЯ ПО
// РАБОТЕ (Ф5 Р7, §8 инвариант 4 — половина «время»; абзац Р5 о неразличимости
// на завершении: «адреса нет» и «код не тот» исполняют один и тот же оператор и
// один отказ; задача PRO-Robotech/kaname#305).
//
// Проб времени у полосы завершения нет: Ф5-20…22 меряют запрос кода. Поэтому
// равенство держится здесь тем, что время производит, — рядом обращений к
// портам хранилища: каждое обращение есть обход базы, и полоса, делающая до
// отказа на обход больше, отвечает дольше.

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// TestRecovery_WrongCodeRefusalDoesTheSameStoreWorkForNobodyAndForSomeone —
// до единого отказа полоса «адрес есть, код не тот» делает ТУ ЖЕ работу
// хранилища, что полоса «адреса нет»: тот же ряд обращений тех же видов в том же
// числе и порядке.
//
// Отличающий факт у каждой полосы «адрес есть» против полосы «адреса нет» —
// один: адрес есть. Вариантов «адрес есть» три — без второго фактора, с
// заведённым вторым фактором, заблокирована: ни один из них не вправе менять
// работу до отказа, потому что до применения кода полоса не знает, годен ли он.
//
// Положительный контроль журнала — полоса выдачи (верный код): она читает
// заведённые способы входа, и журнал обязан это чтение видеть. Без контроля
// «ряды равны» было бы сказано и о журнале, не видящем чтения способов вовсе.
func TestRecovery_WrongCodeRefusalDoesTheSameStoreWorkForNobodyAndForSomeone(t *testing.T) {
	h := newHarness(t, nil)
	const wrongCode = "AAAAA-AAAAA"

	plain := h.person(t, "usr-rrw0", "rrw0@example.invalid", "old-password-rrw", true)
	factor := h.person(t, "usr-rrw1", "rrw1@example.invalid", "old-password-rrw", true)
	material, err := domain.NewLoginVerifier("seeded-second-factor-rrw")
	require.NoError(t, err)
	h.store.factors[factor.ID] = map[domain.LoginMethodKind]*domain.LoginMethod{
		domain.LoginMethodTOTP: {UserID: factor.ID, Kind: domain.LoginMethodTOTP, Verifier: material,
			State: domain.LoginMethodStateActive, CreatedAt: ucBase},
	}
	locked := h.person(t, "usr-rrw2", "rrw2@example.invalid", "old-password-rrw", true)
	control := h.person(t, "usr-rrw3", "rrw3@example.invalid", "old-password-rrw", true)
	for _, u := range []domain.User{plain, factor, locked, control} {
		h.request(t, string(u.Email))
	}
	locked.InviteStatus = domain.InviteStatusBlocked
	h.store.users[locked.ID] = locked

	// Ряд одной полосы: журнал вынимается до и после, источник у каждой полосы
	// свой — ось источника в замер оси адреса не вмешивается.
	lane := func(email, code, source string) ([]storeOp, error) {
		h.journal.take()
		_, err := h.completeFrom(email, code, "brand-new-password-rrw", source)
		return h.journal.take(), err
	}

	// Положительный контроль — ПЕРВЫМ: без него равенство рядов ниже сказано и о
	// журнале, слепом к чтению способов входа.
	issued, err := lane(string(control.Email), h.letterOf(t, control.ID), "203.0.113.164")
	require.NoError(t, err, "контроль: верный код — выдача (Ф5-03)")
	require.True(t, readsLoginMethods(issued),
		"контроль: полоса выдачи решает счёт по адресу и читает заведённые способы — журнал этого чтения не "+
			"увидел, и равенство рядов ниже было бы сказано о журнале, слепом к нему; ряд: %v", issued)

	nobody, errNobody := lane("nobody-rrw@example.invalid", wrongCode, "203.0.113.160")
	require.ErrorIs(t, errNobody, humansession.ErrAuthenticationFailed, "Дано: «адреса нет» — один отказ")
	require.True(t, hasOp(nobody, "writer", "ConsumeRecoveryCode"),
		"Дано: оператор применения исполняется и у полосы «адреса нет» (Р5); ряд: %v", nobody)
	// Чтение способов входа «о пустой личности» законной симметричной формой НЕ
	// является: адаптер базы такого чтения не исполняет вовсе — пустой человек
	// отвергается аргументом без обхода базы (`getLoginMethod`), — и равенство
	// обращений к порту здесь не было бы равенством работы базы. Законная форма
	// одна: чтение после точки решения.
	require.False(t, readsLoginMethods(nobody),
		"у полосы «адреса нет» личности нет, и читать способы входа не о ком — чтение о пустой личности адаптер "+
			"отвергает без обхода базы, так что равный ряд обращений не дал бы равной работы; ряд: %v", nobody)

	someone := []struct {
		label, email, source string
	}{
		{"адрес есть, без второго фактора", string(plain.Email), "203.0.113.161"},
		{"адрес есть, второй фактор заведён", string(factor.Email), "203.0.113.162"},
		{"адрес есть, заблокирована", string(locked.Email), "203.0.113.163"},
	}
	for _, s := range someone {
		got, err := lane(s.email, wrongCode, s.source)
		require.ErrorIs(t, err, humansession.ErrAuthenticationFailed, "%s: код не тот — один отказ", s.label)
		require.True(t, errors.Is(err, errNobody) && err.Error() == errNobody.Error(),
			"%s: отказ тот же, что у «адреса нет»", s.label)
		require.Equal(t, nobody, got,
			"%s: до единого отказа полоса делает ИНУЮ работу хранилища, чем «адреса нет» — разница в работе "+
				"есть разница во времени ответа, и она называет, существует ли адрес (Р7, §8 инв. 4)\n"+
				"  «адреса нет» (%d обращений): %v\n  %s (%d обращений): %v",
			s.label, len(nobody), nobody, s.label, len(got), got)
		t.Logf("%s: обращений до отказа %d — равно «адреса нет»", s.label, len(got))
	}
	t.Logf("перепись: полос отказа сверено %d против «адреса нет» (%d обращений: %v); полоса выдачи — %d обращений",
		len(someone), len(nobody), nobody, len(issued))
}

func hasOp(ops []storeOp, port, name string) bool {
	for _, op := range ops {
		if op.Port == port && op.Name == name {
			return true
		}
	}
	return false
}

func readsLoginMethods(ops []storeOp) bool {
	for _, op := range ops {
		if op.LoginMethodRead {
			return true
		}
	}
	return false
}
