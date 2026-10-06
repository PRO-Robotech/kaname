// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// admission_526_test.go — текст отказа положения называет ШАГ, который его
// снимает (приёмка `docs/engineering/acceptance/access-beyond-login-needs-a-verified-address.md`,
// редакция 5 и далее, Р3, EV-14; задача PRO-Robotech/kaname#526).
//
// Значение здесь — ЛИТЕРАЛ приёмки, а не константа пакета: предмет пробы и
// есть то, что константа несёт одобренный текст побайтово. Проба, читающая
// ожидаемое из той же константы, зеленела бы на любом её значении.
package admission_test

import (
	"strings"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/admission"
)

// approvedR3Text — текст Р3 приёмки, побайтово (регистр, пробелы, двоеточие и
// скобки — часть значения).
const approvedR3Text = "email address is not verified: confirm it with the code from the letter (POST /iam/v1/auth/verify-email/confirm)"

// Test526_EmailNotVerifiedRefusalNamesTheConfirmationStep — значение отказа на
// слушателях gRPC: код, текст Р3 дословно, ровно один `ErrorInfo` с прежним
// признаком; распознаватель отказа узнаёт ровно это значение.
func Test526_EmailNotVerifiedRefusalNamesTheConfirmationStep(t *testing.T) {
	t.Parallel()
	if admission.TextNotVerified != approvedR3Text {
		t.Fatalf("текст отказа положения — не текст Р3:\n  есть  %q\n  ждали %q", admission.TextNotVerified, approvedR3Text)
	}

	err := admission.RefusalStatus()
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("отказ положения обязан быть статусом gRPC: %v", err)
	}
	if st.Code() != codes.PermissionDenied {
		t.Fatalf("код отказа: есть %s, ждали PermissionDenied", st.Code())
	}
	if st.Message() != approvedR3Text {
		t.Fatalf("текст на проводе: есть %q, ждали %q", st.Message(), approvedR3Text)
	}
	var reasons []string
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok {
			reasons = append(reasons, info.GetReason())
		}
	}
	if len(reasons) != 1 || reasons[0] != admission.ReasonNotVerified {
		t.Fatalf("признак отказа: есть %v, ждали ровно [%s]", reasons, admission.ReasonNotVerified)
	}
	if !admission.IsRefusal(err) {
		t.Fatalf("распознаватель не узнал собственное значение отказа")
	}
}

// Test526_EmailNotVerifiedStepIsTheConfirmationPath — путь, который текст
// называет шагом (после `POST ` до `)`), есть путь глагола подтверждения. Пустой
// вырез — отказ пробы, а не зелёное (EV-14 (в)).
func Test526_EmailNotVerifiedStepIsTheConfirmationPath(t *testing.T) {
	t.Parallel()
	path := stepPath(admission.TextNotVerified)
	t.Logf("вырезанный путь шага: %q", path)
	if path == "" {
		t.Fatalf("текст отказа %q не называет шага: выреза между %q и %q нет", admission.TextNotVerified, "POST ", ")")
	}
	if path != "/iam/v1/auth/verify-email/confirm" {
		t.Fatalf("шаг отказа — не глагол подтверждения: %q", path)
	}
}

// Test526_EmailNotVerifiedRecogniserRefusesTheOldText — законный близнец
// распознавателя: значение с прежним текстом (без шага) отказом положения больше
// не считается, а значение с текстом Р3 — считается.
func Test526_EmailNotVerifiedRecogniserRefusesTheOldText(t *testing.T) {
	t.Parallel()
	mk := func(text string) error {
		st, err := status.New(codes.PermissionDenied, text).
			WithDetails(&errdetails.ErrorInfo{Reason: admission.ReasonNotVerified})
		if err != nil {
			t.Fatalf("сборка статуса: %v", err)
		}
		return st.Err()
	}
	if admission.IsRefusal(mk("email address is not verified")) {
		t.Fatalf("прежний текст без шага узнан как отказ положения")
	}
	if !admission.IsRefusal(mk(approvedR3Text)) {
		t.Fatalf("текст Р3 не узнан как отказ положения")
	}
}

// stepPath — путь между `POST ` и `)`; пусто, если выреза нет.
func stepPath(text string) string {
	_, after, ok := strings.Cut(text, "POST ")
	if !ok {
		return ""
	}
	path, _, ok := strings.Cut(after, ")")
	if !ok {
		return ""
	}
	return path
}
