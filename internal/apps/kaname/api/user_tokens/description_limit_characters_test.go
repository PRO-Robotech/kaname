// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// description_limit_characters_test.go — предел описания пользовательского
// токена считается в ЗНАКАХ, как у доменного типа и у ограничения схемы
// (kaname#864).
//
// Вход судил предел функцией `len()` — в байтах — до доменного типа: описание
// из 200 кириллических знаков (400 байт) получало отказ, который ни домен, ни
// база не дали бы. Проба идёт по обеим сторонам предела и по обеим единицам:
// 256 знаков принимаются, 257 отвергаются ТЕКСТОМ ДОМЕНА — то есть суждение
// взято у доменного типа, а не выписано вторым местом.
package user_tokens

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/momentclock"
)

func TestIssueDescriptionLimitIsCountedInCharacters(t *testing.T) {
	refusal := domain.Description(strings.Repeat("ж", domain.DescriptionMax+1)).Validate()
	if refusal == nil {
		t.Fatal("предпосылка: доменный тип обязан отвергать 257 знаков")
	}
	cases := []struct {
		name   string
		desc   string
		accept bool
	}{
		{"200 кириллических знаков (400 байт)", strings.Repeat("ж", 200), true},
		{"256 кириллических знаков — граница", strings.Repeat("ж", domain.DescriptionMax), true},
		{"256 латинских знаков — граница", strings.Repeat("a", domain.DescriptionMax), true},
		{"257 кириллических знаков", strings.Repeat("ж", domain.DescriptionMax+1), false},
		{"257 латинских знаков", strings.Repeat("a", domain.DescriptionMax+1), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			uc := NewIssueUserTokenUseCase(&stubUserClientRepo{}, &stubTx{}, &stubOpsRepo{}).
				WithIssuanceClock(momentclock.Func(time.Now)).WithOwnIssuance()
			_, err := uc.Execute(context.Background(), IssueInput{
				UserID:          "usr00000000000000001",
				CreatedByUserID: "usr00000000000000001",
				Description:     tc.desc,
				TTLSeconds:      7776000,
			})
			if tc.accept {
				if err != nil {
					t.Fatalf("описание %d знаков (%d байт) отвергнуто: %v", len([]rune(tc.desc)), len(tc.desc), err)
				}
				return
			}
			if grpcstatus.Code(err) != codes.InvalidArgument {
				t.Fatalf("code = %v (err=%v), want InvalidArgument", grpcstatus.Code(err), err)
			}
			if got := grpcstatus.Convert(err).Message(); got != refusal.Error() {
				t.Fatalf("текст отказа = %q, want текст домена %q", got, refusal.Error())
			}
		})
	}
}
