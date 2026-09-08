// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// keywrap_rotation_test.go — смена ключа обёртки (задача #1065).
//
// Предмет проб — не «принимает несколько ключей», а два свойства, из которых
// смена ключа и состоит: обёртка, сделанная ПРЕЖНИМ ключом, снимается, пока
// прежний ключ ещё назван, — и НОВАЯ обёртка делается ПЕРВЫМ, а не любым из
// названных. Без второго «список» означал бы «шифруем чем попало», и вывод
// прежнего ключа из списка не приближался бы никогда.
package keywrap_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/keywrap"
)

// TestUnwrapOpensWhatAPreviousWrappingKeyWrapped — записанное прежним ключом
// читается, пока прежний ключ назван в списке.
func TestUnwrapOpensWhatAPreviousWrappingKeyWrapped(t *testing.T) {
	previous, current, stranger := key(1), key(2), key(3)
	plain := []byte("-----BEGIN PRIVATE KEY-----\nmaterial\n-----END PRIVATE KEY-----\n")

	before, err := keywrap.New(previous)
	if err != nil {
		t.Fatalf("построение обёртки на прежнем ключе: %v", err)
	}
	wrapped, err := before.Wrap(plain)
	if err != nil {
		t.Fatalf("обёртка прежним ключом: %v", err)
	}

	// Смена ключа: новый встаёт ПЕРВЫМ, прежний остаётся для чтения.
	after, err := keywrap.New(current, previous)
	if err != nil {
		t.Fatalf("построение обёртки на списке: %v", err)
	}
	got, err := after.Unwrap(wrapped)
	if err != nil {
		t.Fatalf("записанное прежним ключом не открылось после смены: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("развёрнутое не равно исходному")
	}

	// ОТРИЦАНИЕ ПЕРВОЕ: список без прежнего ключа НЕ открывает. Без него
	// утверждение выше зелено на обёртке, открывающей что угодно.
	onlyCurrent, err := keywrap.New(current)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if _, err := onlyCurrent.Unwrap(wrapped); !errors.Is(err, keywrap.ErrUnwrap) {
		t.Fatalf("обёртка снялась списком, в котором прежнего ключа нет (ошибка %v)", err)
	}

	// ОТРИЦАНИЕ ВТОРОЕ: посторонний ключ не открывает и в списке. Список — это
	// перечень названных ключей, а не ослабление проверки подлинности.
	strangers, err := keywrap.New(stranger, key(4))
	if err != nil {
		t.Fatalf("%v", err)
	}
	if _, err := strangers.Unwrap(wrapped); !errors.Is(err, keywrap.ErrUnwrap) {
		t.Fatalf("обёртка снялась чужим списком (ошибка %v)", err)
	}
}

// TestNewWrappingIsDoneByTheFirstKeyOfTheList — новая обёртка делается ПЕРВЫМ
// ключом списка.
//
// Свойство несущее, а не оформление: если бы обёртку делал произвольный ключ
// списка, хранилище никогда не переходило бы на новый ключ целиком, и прежний
// нельзя было бы вывести ни в какой момент.
func TestNewWrappingIsDoneByTheFirstKeyOfTheList(t *testing.T) {
	previous, current := key(1), key(2)
	plain := []byte("material")

	after, err := keywrap.New(current, previous)
	if err != nil {
		t.Fatalf("%v", err)
	}
	wrapped, err := after.Wrap(plain)
	if err != nil {
		t.Fatalf("%v", err)
	}

	onlyCurrent, err := keywrap.New(current)
	if err != nil {
		t.Fatalf("%v", err)
	}
	got, err := onlyCurrent.Unwrap(wrapped)
	if err != nil {
		t.Fatalf("новая обёртка не снимается первым ключом списка: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("развёрнутое не равно исходному")
	}

	onlyPrevious, err := keywrap.New(previous)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if _, err := onlyPrevious.Unwrap(wrapped); !errors.Is(err, keywrap.ErrUnwrap) {
		t.Fatalf("новая обёртка снялась ПРЕЖНИМ ключом — оборачивает не первый")
	}
}

// TestNewRefusesAnEmptyKeyList — пустой список ОТВЕРГАЕТСЯ.
//
// Пустой перечень означает «не сужаем», а не «запрещаем»: обёртка без ключей
// не смогла бы открыть ничего, а построенная — выглядела бы собранной.
func TestNewRefusesAnEmptyKeyList(t *testing.T) {
	if _, err := keywrap.New(); err == nil {
		t.Fatalf("обёртка построена без единого ключа")
	}
	var none [][]byte
	if _, err := keywrap.New(none...); err == nil {
		t.Fatalf("обёртка построена на пустом списке")
	}
	// Положительный контроль: один ключ — законный список из одного.
	if _, err := keywrap.New(key(1)); err != nil {
		t.Fatalf("одиночный ключ отвергнут: %v", err)
	}
}

// TestNewRefusesABadKeyAtAnyPositionOfTheList — негодный ключ отвергается на
// ЛЮБОЙ позиции, и отказ называет позицию.
//
// Проверка только первого означала бы, что ошибка в хвосте списка становится
// рабочим режимом: обёртка собирается, а прежний ключ на деле не назван.
func TestNewRefusesABadKeyAtAnyPositionOfTheList(t *testing.T) {
	short := bytes.Repeat([]byte{9}, keywrap.KeySize-1)

	for name, keys := range map[string][][]byte{
		"негоден первый":  {short, key(1)},
		"негоден второй":  {key(1), short},
		"негоден третий":  {key(1), key(2), short},
		"пустой в хвосте": {key(1), nil},
	} {
		_, err := keywrap.New(keys...)
		if err == nil {
			t.Fatalf("%s: список с негодным ключом принят", name)
		}
		// Позиция называется: без неё оператор со списком из трёх значений
		// не знает, какое из них чинить.
		if !strings.Contains(err.Error(), "#") {
			t.Fatalf("%s: отказ не называет позицию: %v", name, err)
		}
	}

	// Положительный контроль — список годных ключей принимается. Без него
	// отрицания выше зелены на обёртке, не принимающей ничего.
	if _, err := keywrap.New(key(1), key(2), key(3)); err != nil {
		t.Fatalf("список годных ключей отвергнут: %v", err)
	}
}

// TestKeyCountReportsHowManyKeysWereDeclared — число названных ключей
// наблюдаемо.
//
// Оно печатается при старте, потому что «список вырос до шести» иначе
// невидимо, а вывод прежних ключей — работа, которую кто-то должен начать.
func TestKeyCountReportsHowManyKeysWereDeclared(t *testing.T) {
	for want, keys := range map[int][][]byte{
		1: {key(1)},
		2: {key(1), key(2)},
		3: {key(1), key(2), key(3)},
	} {
		w, err := keywrap.New(keys...)
		if err != nil {
			t.Fatalf("%v", err)
		}
		if got := w.KeyCount(); got != want {
			t.Fatalf("названо ключей %d, обёртка сообщает %d", want, got)
		}
	}
}
