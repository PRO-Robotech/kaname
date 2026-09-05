// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package sa_keys

// name_canon_test.go — канон имени на пути выпуска SA-key (#1279, канон #715).

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// issueSAKeyNamed выпускает ключ с заданным именем и возвращает строку, которую
// получил писатель, — то есть то, что доживает до записи.
func issueSAKeyNamed(t *testing.T, name string) domain.ServiceAccountOAuthClient {
	t.Helper()
	repo := &stubSAClientRepo{}
	ops := &stubOpsRepo{}
	uc := NewIssueSAKeyUseCase(repo, &stubTx{}, &stubHydra{}, ops)

	_, err := uc.Execute(context.Background(), IssueInput{
		ServiceAccountID: "sva00000000000000001",
		CreatedByUserID:  "usr00000000000000001",
		Name:             name,
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

// TestIssueSAKey_EmptyName_WritesIdDerivedDefault — пустое имя до записи не
// доживает.
func TestIssueSAKey_EmptyName_WritesIdDerivedDefault(t *testing.T) {
	got := issueSAKeyNamed(t, "")
	if got.Name == "" {
		t.Error("строка ресурса не может нести пустое имя")
	}
	if string(got.Name) != string(got.ID) {
		t.Errorf("умолчание — сам идентификатор (pkg/validate.NameOrDefault): имя %q, id %q",
			got.Name, got.ID)
	}
}

// TestIssueSAKey_CanonNames_Accepted — положительный контроль на осях, где
// прежняя форма iam была УЖЕ канона.
func TestIssueSAKey_CanonNames_Accepted(t *testing.T) {
	for _, tc := range []struct{ label, value string }{
		{"цифра первым символом", "9lives"},
		{"один символ", "a"},
		{"обычное имя", "prod-ci-key"},
	} {
		t.Run(tc.label, func(t *testing.T) {
			got := issueSAKeyNamed(t, tc.value)
			if string(got.Name) != tc.value {
				t.Errorf("присланное имя обязано сохраниться как есть: ждали %q, получили %q",
					tc.value, got.Name)
			}
		})
	}
}

// TestIssueSAKey_MalformedName_Rejected — отрицание в паре с положительным
// контролем выше.
func TestIssueSAKey_MalformedName_Rejected(t *testing.T) {
	for _, tc := range []struct{ label, value string }{
		{"заглавные буквы", "Bad-Name"},
		{"подчёркивание", "bad_name"},
		{"дефис последним символом", "trail-"},
	} {
		t.Run(tc.label, func(t *testing.T) {
			uc := NewIssueSAKeyUseCase(&stubSAClientRepo{}, &stubTx{}, &stubHydra{}, &stubOpsRepo{})
			_, err := uc.Execute(context.Background(), IssueInput{
				ServiceAccountID: "sva00000000000000001",
				CreatedByUserID:  "usr00000000000000001",
				Name:             tc.value,
			})
			if err == nil {
				t.Errorf("негодное имя %q (%s) принято", tc.value, tc.label)
			}
		})
	}
}
