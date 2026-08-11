// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package internal_iam

// check_shadow_wiring_test.go — живой Check СПРАШИВАЕТ форму E и НЕ меняет от
// этого своего ответа.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЭТИХ ДВУХ УТВЕРЖДЕНИЙ НУЖНО ИМЕННО ДВА
//
// «Спрашивает» без «не меняет» допускает провязку, которая однажды начнёт
// влиять на вердикт — и это заметят по чужому доступу. «Не меняет» без
// «спрашивает» удовлетворяется провязкой, которой нет вовсе: ответ тот же
// потому, что сравнения не было. Порознь каждое утверждение зеленеет на
// дефекте, который ловит другое.

import (
	"context"
	"testing"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// stubAuthz — движок с заданным вердиктом.
type stubAuthz struct{ allow bool }

func (s stubAuthz) CheckRelation(context.Context, service.CheckRelationRequest) (*service.CheckResult, error) {
	return &service.CheckResult{Allowed: s.allow}, nil
}

// recordingComparator запоминает, о чём его спросили.
type recordingComparator struct {
	calls    int
	engine   bool
	relation string
	objTyp   string
	objID    string
}

func (r *recordingComparator) Compare(_ context.Context, engineAllowed bool, _, objectType, objectID, relation string, _ map[string]any) {
	r.calls++
	r.engine = engineAllowed
	r.objTyp, r.objID, r.relation = objectType, objectID, relation
}

func TestCheck_AsksTheShadowFormAndKeepsItsOwnAnswer(t *testing.T) {
	for _, engineAllows := range []bool{true, false} {
		rec := &recordingComparator{}
		h := (&Handler{authz: stubAuthz{allow: engineAllows}}).WithShadowVerdict(rec)

		resp, err := h.Check(context.Background(), &iamv1.CheckRequest{
			SubjectId: "user:usr-1",
			Relation:  "v_get",
			Object:    "vpc_network:net-1",
		})
		if err != nil {
			t.Fatalf("Check: %v", err)
		}

		// (1) СПРАШИВАЕТ — иначе «расхождений нет» означало бы «сравнений не было».
		if rec.calls != 1 {
			t.Fatalf("форма E спрошена %d раз, ожидался 1 — провязка, которой нет, "+
				"удовлетворяет утверждению «ответ не изменился» даром", rec.calls)
		}
		// Вопрос задаётся ТОТ ЖЕ, что ушёл движку, — отношением модели, без
		// перевода. Приставку снимает компилятор плана и только там, где
		// источником служит роль: снять её раньше значило бы спросить форму E о
		// другом предмете и записать расхождение между двумя разными вопросами.
		if rec.relation != "v_get" || rec.objTyp != "vpc_network" || rec.objID != "net-1" {
			t.Errorf("форме E задан не тот вопрос: тип=%q id=%q отношение=%q",
				rec.objTyp, rec.objID, rec.relation)
		}
		if rec.engine != engineAllows {
			t.Errorf("сравнению передан не тот вердикт движка: %v", rec.engine)
		}

		// (2) НЕ МЕНЯЕТ — ответ ровно тот, что дал движок.
		if resp.GetAllowed() != engineAllows {
			t.Errorf("ответ изменился теневым сравнением: %v вместо %v — исход формы E "+
				"не вправе влиять на вердикт, пока отвечает движок",
				resp.GetAllowed(), engineAllows)
		}
	}
}

// Непонятая форма объекта — форму E НЕ спрашиваем.
//
// Спросить наугад значило бы задать вопрос о несуществующем объекте, получить
// честное «нет» и записать расхождение там, где его нет.
func TestCheck_DoesNotAskTheShadowFormOnAnUnparsableObject(t *testing.T) {
	rec := &recordingComparator{}
	h := (&Handler{authz: stubAuthz{allow: true}}).WithShadowVerdict(rec)

	if _, err := h.Check(context.Background(), &iamv1.CheckRequest{
		SubjectId: "user:usr-1",
		Relation:  "v_get",
		Object:    "net-1-без-типа",
	}); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if rec.calls != 0 {
		t.Fatalf("форма E спрошена о неразобранном объекте — её честное «нет» стало бы " +
			"расхождением, которого нет")
	}
}
