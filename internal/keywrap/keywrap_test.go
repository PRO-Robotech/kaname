// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// keywrap_test.go — обёртка приватной половины подписного ключа.
//
// Предмет проб — не «шифрует», а три свойства, без которых обёртка выглядит
// исправной и ею не является: она снимается ТЕМ ЖЕ ключом и никаким другим;
// подменённое значение не разворачивается в мусор, который потом сойдёт за
// ключ; и две обёртки одного и того же материала не совпадают.
package keywrap_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/keywrap"
)

func key(b byte) []byte { return bytes.Repeat([]byte{b}, keywrap.KeySize) }

func TestWrapUnwrapRoundTrip(t *testing.T) {
	w, err := keywrap.New(key(1))
	if err != nil {
		t.Fatalf("построение обёртки: %v", err)
	}
	plain := []byte("-----BEGIN PRIVATE KEY-----\nmaterial\n-----END PRIVATE KEY-----\n")
	wrapped, err := w.Wrap(plain)
	if err != nil {
		t.Fatalf("обёртка: %v", err)
	}

	// Обёрнутое не совпадает с исходным — иначе «обёртка» была бы копией.
	if bytes.Contains(wrapped, plain) {
		t.Fatalf("обёрнутое значение содержит исходный материал дословно")
	}

	got, err := w.Unwrap(wrapped)
	if err != nil {
		t.Fatalf("снятие обёртки: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("развёрнутое не равно исходному")
	}
}

func TestUnwrapRefusesAnotherKeyAndTamperedValue(t *testing.T) {
	mine, err := keywrap.New(key(1))
	if err != nil {
		t.Fatalf("%v", err)
	}
	other, err := keywrap.New(key(2))
	if err != nil {
		t.Fatalf("%v", err)
	}
	wrapped, err := mine.Wrap([]byte("material"))
	if err != nil {
		t.Fatalf("%v", err)
	}

	// ДРУГОЙ ключ обёртку не снимает.
	if _, err := other.Unwrap(wrapped); !errors.Is(err, keywrap.ErrUnwrap) {
		t.Fatalf("обёртка снялась чужим ключом (ошибка %v)", err)
	}

	// Подменённое значение не разворачивается ВООБЩЕ, а не разворачивается в
	// мусор: мусор, принятый за ключ, подписал бы токены, которые не проверит
	// никто, и узналось бы это у клиента.
	tampered := append([]byte(nil), wrapped...)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := mine.Unwrap(tampered); !errors.Is(err, keywrap.ErrUnwrap) {
		t.Fatalf("подменённое значение развернулось (ошибка %v)", err)
	}

	// Значение, которое обёрткой не является вовсе, отличимо от подменённого:
	// первое — negodный вход, второе — признак подмены, и путать их в журнале
	// значило бы прятать второе под первым.
	if _, err := mine.Unwrap([]byte{1, 2, 3}); !errors.Is(err, keywrap.ErrNotWrapped) {
		t.Fatalf("слишком короткое значение не опознано как «не обёртка»: %v", err)
	}

	// Положительный контроль — СВОИМ ключом обёртка по-прежнему снимается.
	// Без него все отрицания выше зелены на обёртке, не снимающейся никогда.
	if _, err := mine.Unwrap(wrapped); err != nil {
		t.Fatalf("своя обёртка не снялась: %v", err)
	}
}

func TestWrapIsNotDeterministic(t *testing.T) {
	w, err := keywrap.New(key(1))
	if err != nil {
		t.Fatalf("%v", err)
	}
	plain := []byte("material")
	a, err := w.Wrap(plain)
	if err != nil {
		t.Fatalf("%v", err)
	}
	b, err := w.Wrap(plain)
	if err != nil {
		t.Fatalf("%v", err)
	}
	// Две обёртки одного материала совпадать не должны: совпадение означало бы,
	// что по хранимому значению видно, одинаковы ли два ключа.
	if bytes.Equal(a, b) {
		t.Fatalf("две обёртки одного материала совпали")
	}
	// …и обе снимаются — иначе различие достигалось бы порчей.
	for _, wrapped := range [][]byte{a, b} {
		got, uerr := w.Unwrap(wrapped)
		if uerr != nil || !bytes.Equal(got, plain) {
			t.Fatalf("обёртка не снялась: %v", uerr)
		}
	}
}

func TestNewRefusesAKeyOfTheWrongSize(t *testing.T) {
	for name, k := range map[string][]byte{
		"пусто":         nil,
		"короче нормы":  bytes.Repeat([]byte{1}, keywrap.KeySize-1),
		"длиннее нормы": bytes.Repeat([]byte{1}, keywrap.KeySize+1),
	} {
		// Ключ негодного размера — ОТКАЗ, а не усечение и не растяжение:
		// «привели к нужной длине» означает, что ошибка настройки становится
		// рабочим режимом, и обнаруживается это никогда.
		if _, err := keywrap.New(k); err == nil {
			t.Fatalf("%s: ключ негодного размера принят", name)
		}
	}
	if _, err := keywrap.New(key(1)); err != nil {
		t.Fatalf("ключ объявленного размера отвергнут: %v", err)
	}
}

func TestWrapRefusesNothing(t *testing.T) {
	w, err := keywrap.New(key(1))
	if err != nil {
		t.Fatalf("%v", err)
	}
	// Пустой материал — отказ: обёртка пустоты выглядит как обёртка ключа и
	// разворачивается в ключ нулевой длины, который потом «не подписывает».
	if _, err := w.Wrap(nil); err == nil {
		t.Fatalf("обёрнута пустота")
	}
	if _, err := w.Wrap([]byte{}); err == nil {
		t.Fatalf("обёрнута пустота")
	}
	if _, err := w.Wrap([]byte("x")); err != nil {
		t.Fatalf("непустой материал отвергнут: %v", err)
	}
}
