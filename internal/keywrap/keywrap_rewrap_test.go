// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// keywrap_rewrap_test.go — переобёртка под первый ключ перечня (kaname#259 п.3).
//
// Смена ключа перечнем даёт замещение, но не вывод: прежний ключ открывает
// записанное им, пока хоть одно значение им обёрнуто. Переобёртка и есть путь
// вывода — и её свойства здесь проверяются по сторонам: значение, обёрнутое
// прежним ключом, после переобёртки открывается ОДНИМ первым ключом и НЕ
// открывается одним прежним; значение, уже обёрнутое первым, не трогается;
// значение, которого не открывает ни один ключ перечня, не «переобёртывается»
// в новое — это отказ, а не исход.
package keywrap_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/keywrap"
)

// TestRewrapMovesAPreviousWrappingOntoTheFirstKey — значение, обёрнутое
// прежним ключом, переобёртывается первым: открывается перечнем из одного
// первого ключа тем же материалом и не открывается перечнем из одного прежнего.
func TestRewrapMovesAPreviousWrappingOntoTheFirstKey(t *testing.T) {
	previous, current := key(1), key(2)
	plain := []byte("totp secret material")

	before, err := keywrap.New(previous)
	if err != nil {
		t.Fatalf("%v", err)
	}
	wrapped, err := before.Wrap(plain)
	if err != nil {
		t.Fatalf("%v", err)
	}

	ring, err := keywrap.New(current, previous)
	if err != nil {
		t.Fatalf("%v", err)
	}
	moved, alreadyFirst, err := ring.Rewrap(wrapped)
	if err != nil {
		t.Fatalf("переобёртка значения прежнего ключа отказала: %v", err)
	}
	if alreadyFirst {
		t.Fatalf("значение прежнего ключа названо уже обёрнутым первым")
	}

	onlyCurrent, err := keywrap.New(current)
	if err != nil {
		t.Fatalf("%v", err)
	}
	got, err := onlyCurrent.Unwrap(moved)
	if err != nil {
		t.Fatalf("переобёрнутое не открывается одним первым ключом: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("переобёртка изменила материал")
	}

	// Прежний ключ после переобёртки не читает ничего: только так его и можно
	// снять из перечня.
	onlyPrevious, err := keywrap.New(previous)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if _, err := onlyPrevious.Unwrap(moved); !errors.Is(err, keywrap.ErrUnwrap) {
		t.Fatalf("переобёрнутое открылось прежним ключом (ошибка %v)", err)
	}
}

// TestRewrapLeavesAFirstKeyWrappingAlone — законный близнец: значение, уже
// обёрнутое первым ключом, переобёртки не требует, и новой обёртки не
// порождается — писать нечего, повтор прохода ничего не меняет.
func TestRewrapLeavesAFirstKeyWrappingAlone(t *testing.T) {
	previous, current := key(1), key(2)
	ring, err := keywrap.New(current, previous)
	if err != nil {
		t.Fatalf("%v", err)
	}
	wrapped, err := ring.Wrap([]byte("material"))
	if err != nil {
		t.Fatalf("%v", err)
	}
	moved, alreadyFirst, err := ring.Rewrap(wrapped)
	if err != nil {
		t.Fatalf("значение первого ключа отказало при переобёртке: %v", err)
	}
	if !alreadyFirst {
		t.Fatalf("значение первого ключа не опознано как уже обёрнутое им")
	}
	if moved != nil {
		t.Fatalf("для значения первого ключа порождена новая обёртка")
	}
}

// TestRewrapRefusesWhatNoKeyOfTheListOpens — значение, которого не открывает
// ни один ключ перечня, — отказ тем же словом, что у снятия обёртки: новой
// обёртки из него не получить, и «переобёрнуто» было бы ложью. Короче
// вектора инициализации — отказ формы.
func TestRewrapRefusesWhatNoKeyOfTheListOpens(t *testing.T) {
	stranger, err := keywrap.New(key(3))
	if err != nil {
		t.Fatalf("%v", err)
	}
	foreign, err := stranger.Wrap([]byte("material"))
	if err != nil {
		t.Fatalf("%v", err)
	}
	ring, err := keywrap.New(key(2), key(1))
	if err != nil {
		t.Fatalf("%v", err)
	}
	if moved, _, err := ring.Rewrap(foreign); !errors.Is(err, keywrap.ErrUnwrap) || moved != nil {
		t.Fatalf("чужое значение переобёрнуто (ошибка %v)", err)
	}
	if _, _, err := ring.Rewrap([]byte{1, 2, 3}); !errors.Is(err, keywrap.ErrNotWrapped) {
		t.Fatalf("значение короче вектора инициализации не отвергнуто формой (ошибка %v)", err)
	}
}
