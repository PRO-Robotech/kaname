// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// door_packages_test.go — перечень каталогов контракта, которые читает перепись,
// обязан совпадать с картой ДВЕРИ по ПРОВЕРКЕ, а не по шапке.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Перепись объявляет собственную посылку: «перечень обязан совпадать с пакетами
// карты прав двери». Пока это стояло прозой, оба места разошлись молча — дверь
// сняла пакет учёта и переименовала пакет операции, перепись осталась при старых
// координатах и не читала НИ ОДНОГО каталога сверх собственного контракта.
//
// Совпадение проверяется здесь, и проверяется по ПАКЕТУ, а не по каталогу: имя
// каталога выбирает тот, кто раскладывал дерево, а имя пакета объявляет сам
// контракт — то есть та величина, которой оперирует дверь.

package publicauthzcensus_test

import (
	"os"
	"sort"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/publicauthzcensus"
	"github.com/PRO-Robotech/kaname/internal/treeposture"
)

// TestCensusReadsExactlyThePackagesTheDoorHolds — перечни совпадают в ОБЕ
// стороны: пакет двери без каталога переписи оставляет его RPC неосмотренными,
// каталог переписи без пакета двери судит то, чего дверь не обслуживает.
func TestCensusReadsExactlyThePackagesTheDoorHolds(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	// Корень берётся напрямую у резолва, а не через обёртку пробы: предмет этой
	// проверки — сама способность переписи прочитать дерево, и пропуск здесь
	// сделал бы её вакуумной.
	root, err := treeposture.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не установлен: %v", err)
	}

	want := append([]string(nil), authzguard.OwnDoorProtoPackages()...)
	sort.Strings(want)
	if len(want) == 0 {
		t.Fatalf("карта двери не объявила ни одного пакета — сверять нечего, и молчание было бы сказано ни о чём")
	}

	got, err := publicauthzcensus.ContractPackages(root)
	if err != nil {
		t.Fatalf("каталоги контракта переписи не установлены: %v", err)
	}
	sort.Strings(got)

	t.Logf("перепись: пакетов карты двери %d · пакетов, читаемых переписью, %d", len(want), len(got))

	if len(got) != len(want) {
		t.Fatalf("перечни разошлись: дверь держит %v, перепись читает %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("перечни разошлись: дверь держит %v, перепись читает %v", want, got)
		}
	}
}

// TestCensusWalksTheWholeContractOfThisTree — обход переписи не пуст и доходит
// до вердикта: «ноль находок» обязано быть отличимо от «ноль прочитанного».
func TestCensusWalksTheWholeContractOfThisTree(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	root, err := treeposture.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	c, err := publicauthzcensus.Collect(root)
	if err != nil {
		t.Fatalf("перепись не состоялась: %v", err)
	}
	if c.ProtoFiles == 0 || c.Inspected == 0 {
		t.Fatalf("обход пуст: файлов контракта %d, публичных RPC осмотрено %d", c.ProtoFiles, c.Inspected)
	}
	t.Logf("перепись: файлов контракта %d · RPC объявлено %d · публичных осмотрено %d",
		c.ProtoFiles, c.RPCsDeclared, c.Inspected)
}
