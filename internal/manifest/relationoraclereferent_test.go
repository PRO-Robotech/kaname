// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest_test

// relationoraclereferent_test.go — модель ВНОСИТСЯ вызывающим, и обе полосы
// названы (задача продукта #2002, сценарий `IAM-MB-1-17` приёмки
// `model-composes-at-boot-from-delivered-manifests.md`).
//
// # Что здесь доказывается
//
// Пара проб отличается ОДНИМ фактом — внесён оракул или нет, — и вход у них
// побайтово один. Дельта в один факт обязательна: инъекция, меняющая два факта
// сразу, не говорит, какой из них дал исход (`change-graph.md` §6).
//
// # Почему полос ДВЕ, а не одна строгая
//
// Полоса без оракула — не послабление, а ЕДИНСТВЕННО возможное поведение на
// пути старта: модель там ещё собирается из этих же манифестов, и спрашивать её
// значит спрашивать у ответа. Полоса с оракулом — оснастка дерева, где канон
// авторитетен, потому что тип уже в нём.
//
// Без второй полосы первая читалась бы как «загрузчик перестал проверять».

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/manifest"
)

// grantOfRelationCanonDoesNotDeclare — выдача отношением, которого канон у
// `iam.cluster` не объявляет. Вход ОДИН на обе полосы пары.
func grantOfRelationCanonDoesNotDeclare() []byte {
	return seedWithBinding(`    - subjects:
        - {type: serviceAccount, name: kacho-vpc}
      grantedRelation: no_such_relation_at_all
      scopeType: iam.cluster
      scopeId: cluster_kacho_root
      target: allInScope
`)
}

// TestRelationGrantJudgedOnlyWhenTheModelIsSupplied — пара полос на одном входе.
func TestRelationGrantJudgedOnlyWhenTheModelIsSupplied(t *testing.T) {
	doc := grantOfRelationCanonDoesNotDeclare()

	// ── полоса 1: оракул ВНЕСЁН — связность судится, отношения нет, отказ ─────
	if _, err := manifest.Load(doc, canonOracle(t)); err == nil {
		t.Fatal("оракул внесён, а выдача отношением, которого модель не объявляет, " +
			"прошла — суждение о связности не состоялось")
	}

	// ── полоса 2: оракул НЕ внесён — тот же вход проходит ────────────────────
	//
	// Отличие от полосы 1 — РОВНО ОДНО: опция не передана.
	m, err := manifest.Load(doc)
	if err != nil {
		t.Fatalf("без внесённой модели загрузчик обязан судить ФОРМУ, а не существование "+
			"отношения: разбор доставки на старте идёт именно так, и отказ здесь сделал бы "+
			"композицию неисполнимой; получено: %v", err)
	}

	// ── и это НЕ молчание: перепись называет обе величины ────────────────────
	//
	// Ноль суждённых, напечатанный без числа прочитанных, читался бы как
	// «сверили и не нашли расхождений».
	census := m.Linkage()
	if census.RelationGrantsRead != 1 {
		t.Fatalf("перепись обязана СЧИТАТЬ выдачи отношением, прочитано %d из 1",
			census.RelationGrantsRead)
	}
	if census.RelationGrantsJudged != 0 {
		t.Fatalf("модель не внесена — суждённых обязано быть 0, получено %d",
			census.RelationGrantsJudged)
	}
	if !strings.Contains(census.String(), "выдач отношением суждено 0 из 1") {
		t.Fatalf("перепись обязана печатать ОБЕ величины рядом, получено: %s", census.String())
	}

	// ── и обратная сторона переписи: с оракулом суждённых столько же, сколько
	// прочитанных ────────────────────────────────────────────────────────────
	//
	// Без этого «суждено 0 из 1» было бы неотличимо от переписи, которая не
	// умеет считать суждённые вовсе.
	ok := mustLoadGrantOK(t, seedWithBinding(`    - subjects:
        - {type: serviceAccount, name: kacho-vpc}
      grantedRelation: system_viewer
      scopeType: iam.cluster
      scopeId: cluster_kacho_root
      target: allInScope
`), "законная выдача отношением при внесённой модели")
	if got := ok.Linkage(); got.RelationGrantsJudged != 1 || got.RelationGrantsRead != 1 {
		t.Fatalf("с внесённой моделью перепись обязана дать «суждено 1 из 1», получено: %s",
			got.String())
	}
}
