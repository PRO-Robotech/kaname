// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package manifestoracle_test

// manifestoracle_test.go — переходник отвечает НИЧЕМ там, где ответа нет
// (задача продукта #2002).
//
// # Почему это отдельная проба, а не «и так видно»
//
// Предмет здесь — ловушка типизированного nil. Интерфейс, несущий нулевое
// ЗНАЧЕНИЕ, сам по себе `nil` НЕ равен, поэтому вызывающий, проверивший его
// обычным `== nil`, получил бы «объявление есть» ровно там, где его нет, — и
// пошёл бы спрашивать у пустоты. Ошибка не видна ни в диффе, ни в сборке: обе
// формы возврата компилируются и выглядят одинаково.

import (
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmodel"
	"github.com/PRO-Robotech/kacho/services/iam/internal/manifestoracle"
)

// TestNilPlansGiveNilOracle — переходник поверх пустоты НЕ заводится.
//
// Оракул, отвечающий «не объявляет» на всякий вопрос, отверг бы КАЖДУЮ законную
// выдачу отношением и был бы неотличим от строгой модели, которой просто нет.
func TestNilPlansGiveNilOracle(t *testing.T) {
	if o := manifestoracle.FromPlans(nil); o != nil {
		t.Fatalf("переходник поверх отсутствующей модели не есть nil (%T) — "+
			"вызывающий принял бы его за внесённую модель и получил бы отказ "+
			"на каждой законной выдаче", o)
	}
}

// TestUndeclaredRelationYieldsNilDeclaration — «не объявляет» отвечает НИЧЕМ, а
// не нулевым объявлением; и рядом положительный контроль.
func TestUndeclaredRelationYieldsNilDeclaration(t *testing.T) {
	plans, err := authzmodel.New(authzmodel.DSL)
	if err != nil {
		t.Fatalf("канон образа не разобран: %v", err)
	}
	oracle := manifestoracle.FromPlans(plans)
	if oracle == nil {
		t.Fatal("предпосылка не создана: переходник поверх разобранного канона обязан быть")
	}

	// ── отрицание ────────────────────────────────────────────────────────────
	decl, declared := oracle.RelationDeclaration("iam.cluster", "no_such_relation_at_all")
	if declared {
		t.Fatal("предпосылка не создана: канон обязан НЕ объявлять выдуманное отношение")
	}
	if decl != nil {
		t.Fatalf("необъявленное отношение вернуло НЕнулевое объявление (%T) — "+
			"ловушка типизированного nil: проверка `== nil` у вызывающего солгала бы", decl)
	}

	// ── положительный контроль: объявленное отвечает ЧЕМ-ТО ──────────────────
	//
	// Без него «всегда nil» было бы неотличимо от исправного переходника.
	got, ok := oracle.RelationDeclaration("cluster", "system_viewer")
	if !ok || got == nil {
		t.Fatalf("объявленное отношение обязано отдавать объявление, получено ok=%v decl=%v",
			ok, got)
	}
	if !got.IsDirect() {
		t.Fatal("cluster.system_viewer объявлено каноном ПРЯМЫМ — переходник обязан это передать")
	}
	if len(got.AcceptedKinds()) == 0 {
		t.Fatal("перечень принимаемых видов пуст — текст отказа не смог бы назвать, что канон принимает")
	}
	if !got.AcceptsKind("serviceAccount") {
		t.Fatalf("канон принимает служебную запись на cluster.system_viewer, переходник ответил иначе; "+
			"принимаемое: %v", got.AcceptedKinds())
	}

	// ── перечень отношений типа — для ТЕКСТА отказа ──────────────────────────
	if len(oracle.TypeRelations("cluster")) == 0 {
		t.Fatal("перечень отношений типа пуст — автор, ошибшийся в имени, не увидел бы объявленных")
	}
	if len(oracle.TypeRelations("no_such_type_at_all")) != 0 {
		t.Fatal("у незнакомого типа перечень отношений обязан быть пуст")
	}
}
