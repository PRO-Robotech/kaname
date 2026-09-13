// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// quota_authority_retired_test.go — ГЕЙТ КЛАССА: авторитета величин в дереве
// службы доступа нет (задача продукта `PRO-Robotech/kacho#2117`, приёмка
// `KAN-QUOTA-1` S4, сценарии `KAN-Q4-08`, `KAN-Q4-14`).
//
// Предмет, выбор осей, довод против предиката по слову `limit` и поимённый
// перечень законного остатка — в шапке `quota_authority_retired.go`; здесь они
// не пересказываются, чтобы два места об одном предмете не разошлись.
//
// Способность гейта упасть и смолчать доказана инъекцией —
// `quota_authority_retired_injection_test.go`.
package check_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// TestLimitAuthorityIsGoneFromTheTree — авторитет величин не назван ни прод-кодом,
// ни контрактом, ни моделью прав.
//
// Что делать, если гейт сработал, — исходов ТРИ, четвёртого нет:
//
//  1. имя вернулось вместе с кодом → снять код: модуль ушёл решением владельца
//     2026-09-06, и возврат его частями есть тот же модуль под другим именем;
//  2. имя принадлежит ОСТАВШЕМУСЯ предмету (потолок из посадки, арендаторское
//     чтение своего потолка, предел скорости приёма) → назвать его в перечне
//     законного остатка, а не расширять образец: перечень сопоставляется по
//     равенству имени, и расширение по подстроке ослепило бы ось целиком;
//  3. предмет вернулся в продукт решением владельца → снять гейт ВМЕСТЕ с его
//     инъекцией и этой шапкой, одним изменением. Проверка, чей предмет вернулся,
//     молчит так же, как исправная.
func TestLimitAuthorityIsGoneFromTheTree(t *testing.T) {
	t.Parallel()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	root, err := platformtree.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не найден: %v", err)
	}

	tracked, err := treecorpus.Under(root)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав дерева берётся у индекса git: %v", err)
	}

	corpus := map[string]string{}
	for _, abs := range tracked {
		rel, rerr := filepath.Rel(root, abs)
		if rerr != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: путь %s: %v", abs, rerr)
		}
		slashed := filepath.ToSlash(rel)
		if !judgedByAuthorityResidue(slashed) {
			continue
		}
		raw, berr := os.ReadFile(abs) // #nosec G304 -- путь из индекса git ЭТОГО дерева
		if berr != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: чтение %s: %v", slashed, berr)
		}
		corpus[slashed] = string(raw)
	}

	census, findings := check.JudgeAuthorityResidue(corpus)
	t.Logf("%s; находок %d", census, len(findings))

	// ПРЕДПОСЫЛКИ — до вердикта. Пустой обход даёт ноль находок при любом
	// состоянии дерева: это «не выполнилось», а не «чисто».
	if census.GoFiles == 0 || census.Contracts == 0 || census.Models == 0 {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: обход пуст по одной из осей — "+
			"прод-файлов %d, контрактов %d, моделей %d; ноль находок здесь есть "+
			"вердикт об обходе, а не о дереве", census.GoFiles, census.Contracts, census.Models)
	}
	if census.Kept == 0 {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: законный остаток прочитан НОЛЬ раз — " +
			"разбор не дошёл до файлов, где он живёт (словарь посадки, арендаторское " +
			"чтение своего потолка). Его ноль находок ничего не значит")
	}
	if len(census.Unparsed) != 0 {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ по %d файлам — парсер их не принял, и "+
			"о них не известно НИЧЕГО: %s", len(census.Unparsed), strings.Join(census.Unparsed, ", "))
	}

	if len(findings) == 0 {
		return
	}
	var b strings.Builder
	for _, f := range findings {
		b.WriteString("\n  " + f.String())
	}
	t.Fatalf("авторитет величин назван деревом службы доступа в %d местах — "+
		"модуль выпилен решением владельца 2026-09-06 и возврату частями не "+
		"подлежит:%s", len(findings), b.String())
}

// judgedByAuthorityResidue — что разбор читает, а что не его предмет.
//
// Контракты СЛУЖБЫ, а не всякий `.proto` в дереве: `proto/kacho/` и
// `proto/corelib/` — копии чужих контрактов, и судить их отсюда значило бы
// краснеть на чужом продукте.
func judgedByAuthorityResidue(rel string) bool {
	switch {
	case strings.HasSuffix(rel, ".go"):
		return !strings.HasSuffix(rel, "_test.go")
	case strings.HasSuffix(rel, ".proto"):
		return strings.HasPrefix(rel, "proto/kaname/")
	case strings.HasSuffix(rel, ".fga"):
		return true
	default:
		return false
	}
}
