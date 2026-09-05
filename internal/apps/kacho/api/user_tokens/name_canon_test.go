// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user_tokens

// name_canon_test.go — канон имени на пути выпуска user-token (#1279,
// канон #715).
//
// Имя токена было ЕДИНСТВЕННЫМ в iam, где пустая строка доживала до записи:
// доменный тип пропускал её особой веткой. Пустое имя — не «имя, которого
// нет», а ресурс, который не ищется, не отличается в списке и показывается
// прочерком; канон заменяет его именем, производным от идентификатора.

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// issueTokenNamed выпускает токен с заданным именем и возвращает строку,
// которую получил писатель, — то есть то, что доживает до записи.
func issueTokenNamed(t *testing.T, name string) domain.UserOAuthClient {
	t.Helper()
	repo := &stubUserClientRepo{}
	ops := &stubOpsRepo{}
	uc := NewIssueUserTokenUseCase(repo, &stubTx{}, ops)

	_, err := uc.Execute(context.Background(), IssueInput{
		UserID:          "usr00000000000000001",
		CreatedByUserID: "usr00000000000000001",
		Name:            name,
	})
	if err != nil {
		t.Fatalf("выпуск с именем %q обязан пройти проверку формы: %v", name, err)
	}
	waitForOp(t, ops)
	if ops.lastErr != nil {
		t.Fatalf("выпуск с именем %q обязан пройти: %v", name, ops.lastErr)
	}
	return repo.inserted
}

// TestIssueUserToken_EmptyName_WritesIdDerivedDefault — пустое имя до записи не
// доживает.
func TestIssueUserToken_EmptyName_WritesIdDerivedDefault(t *testing.T) {
	got := issueTokenNamed(t, "")
	if got.Name == "" {
		t.Error("строка ресурса не может нести пустое имя")
	}
	if string(got.Name) != string(got.ID) {
		t.Errorf("умолчание — сам идентификатор (pkg/validate.NameOrDefault): имя %q, id %q",
			got.Name, got.ID)
	}
}

// TestIssueUserToken_CanonNames_Accepted — положительный контроль на осях, где
// прежняя форма iam была УЖЕ канона; заодно доказывает, что присланное имя
// подстановка не трогает.
func TestIssueUserToken_CanonNames_Accepted(t *testing.T) {
	for _, tc := range []struct{ label, value string }{
		{"цифра первым символом", "9lives"},
		{"один символ", "a"},
		{"обычное имя", "laptop-token"},
	} {
		t.Run(tc.label, func(t *testing.T) {
			got := issueTokenNamed(t, tc.value)
			if string(got.Name) != tc.value {
				t.Errorf("присланное имя обязано сохраниться как есть: ждали %q, получили %q",
					tc.value, got.Name)
			}
		})
	}
}

// TestIssueUserToken_MalformedName_Rejected — отрицание в паре с положительным
// контролем выше: подстановка умолчания не отменяет проверки формы.
func TestIssueUserToken_MalformedName_Rejected(t *testing.T) {
	for _, tc := range []struct{ label, value string }{
		{"заглавные буквы", "Bad-Name"},
		{"подчёркивание", "bad_name"},
		{"дефис последним символом", "trail-"},
	} {
		t.Run(tc.label, func(t *testing.T) {
			repo := &stubUserClientRepo{}
			ops := &stubOpsRepo{}
			uc := NewIssueUserTokenUseCase(repo, &stubTx{}, ops)
			_, err := uc.Execute(context.Background(), IssueInput{
				UserID:          "usr00000000000000001",
				CreatedByUserID: "usr00000000000000001",
				Name:            tc.value,
			})
			if err == nil {
				t.Errorf("негодное имя %q (%s) принято", tc.value, tc.label)
			}
		})
	}
}
