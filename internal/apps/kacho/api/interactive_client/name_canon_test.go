// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package interactiveclient

// name_canon_test.go — канон имени на пути создания InteractiveClient (#1279,
// канон #715).

import (
	"context"
	"testing"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
)

// createNamed прогоняет создание с заданным именем и возвращает ресурс, каким
// его увидит арендатор в ответе операции.
func createNamed(t *testing.T, name string) *iamv1.InteractiveClient {
	t.Helper()
	uc := NewCreateUseCase(&fakeRepo{}, &failingProvider{}, &fakeOps{},
		[]string{"https://api.example"}, nil)

	req := createReq()
	req.Name = name
	op, err := uc.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("создание с именем %q обязано пройти проверку формы: %v", name, err)
	}
	if op.GetResponse() == nil {
		t.Fatalf("ответ операции обязан нести созданный ресурс")
	}
	var got iamv1.InteractiveClient
	if uerr := op.GetResponse().UnmarshalTo(&got); uerr != nil {
		t.Fatalf("ответ операции не разбирается: %v", uerr)
	}
	return &got
}

// TestCreateInteractiveClient_EmptyName_WritesIdDerivedDefault — пустое имя до
// записи не доживает: его заменяет имя, производное от идентификатора.
//
// Имя интерактивного клиента уникально на ВЕСЬ кластер
// (`interactive_clients_name_uk`), поэтому умолчание обязано быть производным
// от идентификатора: он глобально уникален by construction, и второе безымянное
// создание не столкнётся с первым БЕЗ проверки-перед-вставкой (запрет #10).
func TestCreateInteractiveClient_EmptyName_WritesIdDerivedDefault(t *testing.T) {
	got := createNamed(t, "")
	if got.GetName() == "" {
		t.Error("строка ресурса не может нести пустое имя")
	}
	if got.GetName() != got.GetId() {
		t.Errorf("умолчание — сам идентификатор (pkg/validate.NameOrDefault): имя %q, id %q",
			got.GetName(), got.GetId())
	}
}

// TestCreateInteractiveClient_TwoEmptyNames_DistinctNames — два безымянных
// создания получают разные имена.
func TestCreateInteractiveClient_TwoEmptyNames_DistinctNames(t *testing.T) {
	first := createNamed(t, "")
	second := createNamed(t, "")
	if first.GetName() == second.GetName() {
		t.Errorf("два безымянных создания получили одно имя %q — "+
			"кластер-уникальность имени отвергла бы второе", first.GetName())
	}
}

// TestCreateInteractiveClient_CanonNames_Accepted — положительный контроль на
// осях, где прежняя форма iam была УЖЕ канона.
func TestCreateInteractiveClient_CanonNames_Accepted(t *testing.T) {
	for _, tc := range []struct{ label, value string }{
		{"цифра первым символом", "9lives"},
		{"один символ", "a"},
		{"обычное имя", "console-a"},
	} {
		t.Run(tc.label, func(t *testing.T) {
			got := createNamed(t, tc.value)
			if got.GetName() != tc.value {
				t.Errorf("присланное имя обязано сохраниться как есть: ждали %q, получили %q",
					tc.value, got.GetName())
			}
		})
	}
}
