// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// catalog_gate_comment_injection_test.go — ДОКАЗАТЕЛЬСТВО, что соседний гейт
// умеет и краснеть, и молчать.
//
// По каждой оси — обе стороны: возвращённый дефект обязан краснить и НАЗЫВАТЬ
// оба отношения (то, что стоит в тексте, и то, что энфорсит каталог); законный
// близнец той же формы обязан молчать.
//
// Отдельная ось — та, ради которой утверждение отмечено: проза, называющая
// отношение и тип в том же написании, но БЕЗ отметки, читаться не должна. Без
// неё гейт краснел бы на комментарии, который объясняет сам дефект.
package authzmap_test

import (
	"strings"
	"testing"
)

// catalogGateInjectionEntries — каталог в объёме, достаточном для утверждений
// ниже. Синтетика здесь законна: судится РАЗБОР отметки, а не содержимое
// каталога дерева (его читает сам гейт, и его перепись он печатает).
var catalogGateInjectionEntries = []catalogGateEntry{
	{
		FQN:         "kaname.cloud.iam.v1.UserTokenService/Issue",
		RequiredRel: "token_issuer",
		ScopeExtractor: &struct {
			ObjectType string `json:"object_type"`
		}{ObjectType: "iam_user"},
	},
}

func TestCatalogGateCommentInjection_TreeCarriesAJudgeableMark(t *testing.T) {
	// Контроль предпосылки: без отметки в дереве все утверждения ниже вакуумны.
	marks, filesRead := walkIAMProductionGoFiles(t)
	if filesRead == 0 || len(marks) == 0 {
		t.Fatalf("обход дал файлов %d, отметок %d — предмет доказательства отсутствует",
			filesRead, len(marks))
	}
	if f := judgeCatalogGateMarks(readCatalogGateEntries(t), marks); len(f) != 0 {
		t.Fatalf("дерево объявлено расходящимся с каталогом: %v", f)
	}
	t.Logf("перепись: файлов %d · отметок %d", filesRead, len(marks))
}

func TestCatalogGateCommentInjection_TheOriginalWrongRelationIsFound(t *testing.T) {
	// ДЕФЕКТ, ВОЗВРАЩЁННЫЙ ДОСЛОВНО: отметка называет отношение, которое стояло
	// в комментарии до починки (#1258).
	broken := collectCatalogGateMarks("handler.go",
		"// ГЕЙТ КАТАЛОГА kaname.cloud.iam.v1.UserTokenService/Issue: v_update@iam_user\n")
	if len(broken) != 1 {
		t.Fatalf("отметка не разобрана: %v", broken)
	}
	findings := judgeCatalogGateMarks(catalogGateInjectionEntries, broken)
	joined := strings.Join(findings, " | ")
	if len(findings) == 0 {
		t.Fatal("подменённое отношение не найдено — гейт не сверяет отметку с каталогом")
	}
	for _, want := range []string{"v_update", "token_issuer"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("находка не называет %q — читателю нечем починить текст: %s", want, joined)
		}
	}

	// ЗАКОННЫЙ БЛИЗНЕЦ той же формы: верное отношение обязано молчать.
	ok := collectCatalogGateMarks("handler.go",
		"// ГЕЙТ КАТАЛОГА kaname.cloud.iam.v1.UserTokenService/Issue: token_issuer@iam_user\n")
	if f := judgeCatalogGateMarks(catalogGateInjectionEntries, ok); len(f) != 0 {
		t.Fatalf("верная отметка объявлена находкой — гейт ловит форму, а не существо: %v", f)
	}
}

func TestCatalogGateCommentInjection_WrongObjectTypeIsFound(t *testing.T) {
	// ДЕФЕКТ: отношение верное, тип объекта — нет. Область гейта берётся именно
	// с типа, поэтому половина утверждения так же лжива, как целое.
	broken := collectCatalogGateMarks("handler.go",
		"// ГЕЙТ КАТАЛОГА kaname.cloud.iam.v1.UserTokenService/Issue: token_issuer@account\n")
	joined := strings.Join(judgeCatalogGateMarks(catalogGateInjectionEntries, broken), " | ")
	if !strings.Contains(joined, "account") || !strings.Contains(joined, "iam_user") {
		t.Fatalf("подменённый тип объекта не найден: %q", joined)
	}
}

func TestCatalogGateCommentInjection_UnknownMethodIsFound(t *testing.T) {
	// ДЕФЕКТ: отметка пережила метод, которого в каталоге нет.
	broken := collectCatalogGateMarks("handler.go",
		"// ГЕЙТ КАТАЛОГА kaname.cloud.iam.v1.UserTokenService/Mint: token_issuer@iam_user\n")
	joined := strings.Join(judgeCatalogGateMarks(catalogGateInjectionEntries, broken), " | ")
	if !strings.Contains(joined, "Mint") {
		t.Fatalf("отметка на несуществующем методе не найдена: %q", joined)
	}
}

func TestCatalogGateCommentInjection_ProseIsNotReadAsAMark(t *testing.T) {
	// ОСЬ, РАДИ КОТОРОЙ УТВЕРЖДЕНИЕ ОТМЕЧЕНО: разбор дефекта называет прежнее
	// отношение рядом с фактическим. Сплошной предикат краснел бы на нём — то
	// есть на собственном объяснении.
	prose := "// Здесь стояло `v_update@iam_user`, и это было неверно: каталог гейтит\n" +
		"// выпуск отношением `token_issuer` на `iam_user`.\n"
	if marks := collectCatalogGateMarks("handler.go", prose); len(marks) != 0 {
		t.Fatalf("проза прочитана как утверждение (%d отметок) — гейт краснел бы на "+
			"объяснении самого дефекта", len(marks))
	}

	// ЗАКОННЫЙ БЛИЗНЕЦ той же формы: та же пара С ОТМЕТКОЙ обязана читаться,
	// иначе молчание выше означало бы мёртвый детектор, а не разборчивость.
	marked := prose + "// ГЕЙТ КАТАЛОГА kaname.cloud.iam.v1.UserTokenService/Issue: v_update@iam_user\n"
	marks := collectCatalogGateMarks("handler.go", marked)
	if len(marks) != 1 {
		t.Fatalf("отметка рядом с прозой не разобрана: %d", len(marks))
	}
	if f := judgeCatalogGateMarks(catalogGateInjectionEntries, marks); len(f) == 0 {
		t.Fatal("отмеченная ложь рядом с прозой не найдена — детектор отметки мёртв")
	}
}
