// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package authzmodel

// install_test.go — установка модели процесса (#1969, §2 п. 7-8).
//
// ПРОБЫ ЖИВУТ ВНУТРИ ПАКЕТА НАМЕРЕННО. Предмет — состояние процесса
// («установлено», «прочитано»), и внешняя проба его не восстановит: она не
// вправе вернуть замок в исходное между случаями, а `go test` даёт ей один
// процесс на весь файл. Изнутри состояние сбрасывается явно — и это сказано
// здесь, чтобы следующий не переносил пробы наружу «для чистоты».

import (
	"errors"
	"strings"
	"testing"
)

// resetProcessModel возвращает пакет к состоянию «модель не читалась».
//
// Единственный писатель этих признаков в пробах: три копии сброса разошлись бы
// с четвёртой молча — на признаке, о котором одна из них не знает.
func resetProcessModel(t *testing.T) {
	t.Helper()
	sharedMu.Lock()
	defer sharedMu.Unlock()
	shared, sharedErr, installed, wasRead = nil, nil, false, false
}

// probeModel — заведомо ДРУГАЯ модель: свой тип субъекта и свой тип объекта,
// ни одного имени канона. Так «установка применилась» отличимо от «модель и так
// это объявляла».
const probeModel = "type probe_subject\n\ntype probe_only\n  relations\n    define admin: [probe_subject]\n"

// Установка ДО первого чтения меняет модель процесса.
func TestInstallBeforeFirstReadReplacesTheProcessModel(t *testing.T) {
	resetProcessModel(t)
	t.Cleanup(func() { resetProcessModel(t) })

	if err := Install(probeModel); err != nil {
		t.Fatalf("установка до первого чтения отвергнута: %v", err)
	}
	p, err := Shared()
	if err != nil {
		t.Fatalf("чтение установленной модели: %v", err)
	}
	if !p.DeclaresType("probe_only") {
		t.Fatal("модель процесса не несёт установленного типа — установка не применилась")
	}
	// ЗЕРКАЛО: канонический тип из модели ушёл. Без него утверждение выше
	// зеленело бы на модели, объявляющей ВСЁ.
	if p.DeclaresType("vpc_network") {
		t.Fatal("модель процесса несёт и канонический тип — установка не заменила, а дополнила")
	}
}

// Установка ПОСЛЕ первого чтения — ОШИБКА, а не тихая замена.
func TestInstallAfterFirstReadIsAnError(t *testing.T) {
	resetProcessModel(t)
	t.Cleanup(func() { resetProcessModel(t) })

	before, err := Shared()
	if err != nil {
		t.Fatalf("первое чтение: %v", err)
	}
	if !before.DeclaresType("vpc_network") {
		t.Fatal("вшитая модель не несёт vpc_network — предпосылка отпала")
	}

	ierr := Install(probeModel)
	if !errors.Is(ierr, ErrModelAlreadyRead) {
		t.Fatalf("установка после чтения дала %v, ожидалась ErrModelAlreadyRead", ierr)
	}
	// Модель НЕ подменена: отказ обязан быть ещё и бездейственным.
	after, _ := Shared()
	if after != before {
		t.Fatal("отказ установки всё же подменил модель — «ошибка» без содержания")
	}
	if after.DeclaresType("probe_only") {
		t.Fatal("отвергнутая установка доехала до модели процесса")
	}
}

// Вторая установка — ОШИБКА, отличимая от первой по основанию.
func TestSecondInstallIsRefusedWithItsOwnReason(t *testing.T) {
	resetProcessModel(t)
	t.Cleanup(func() { resetProcessModel(t) })

	if err := Install(probeModel); err != nil {
		t.Fatalf("первая установка: %v", err)
	}
	err := Install(probeModel)
	if !errors.Is(err, ErrModelAlreadyInstalled) {
		t.Fatalf("вторая установка дала %v, ожидалась ErrModelAlreadyInstalled", err)
	}
	// РАЗЛИЧИМОСТЬ ДВУХ ОТКАЗОВ: без неё «уже прочитана» и «уже установлена»
	// отвечали бы одинаково, и оператор искал бы причину не там.
	if errors.Is(err, ErrModelAlreadyRead) {
		t.Fatal("вторая установка названа чтением — два разных основания слились в одно")
	}
}

// Неразбираемый текст установкой НЕ становится: отказ, а не пустая модель.
func TestInstallRefusesAnUnparsableText(t *testing.T) {
	resetProcessModel(t)
	t.Cleanup(func() { resetProcessModel(t) })

	err := Install("type broken\n  relations\n    define admin: [nosuchtype]\n")
	if err == nil {
		t.Fatal("неразбираемый текст установлен — пустая модель отвечала бы «нет» на всякий вопрос")
	}
	if !strings.Contains(err.Error(), "установка модели процесса") {
		t.Fatalf("отказ не назвал предмета: %v", err)
	}
	// Отказ бездейственен: модель процесса осталась вшитой.
	p, serr := Shared()
	if serr != nil || !p.DeclaresType("vpc_network") {
		t.Fatalf("после отвергнутой установки модель процесса не вшитая: err=%v", serr)
	}
}
