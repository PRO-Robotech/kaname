// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user_tokens

// issuance_clock_refusal_test.go — источник момента выдачи не ответил либо не
// подан: выдача отказывает закрыто фиксированным текстом, строка удостоверения
// не пишется, часов процесса взамен нет (задача kaname#589). Журнал называет
// шаг и класс, не текст причины.

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/revocationpolicy"
	"github.com/PRO-Robotech/kaname/internal/testsupport/momentclock"
)

func TestIssue_UnansweredOrUnwiredIssuanceClockIsAClosedRefusal(t *testing.T) {
	sources := map[string]revocationpolicy.Clock{
		"источник не ответил": momentclock.Failing{Err: errors.New("dial tcp 10.42.7.3:5432 (user=kaname)")},
		"источник не подан":   nil,
	}
	kinds := map[string]domain.CredentialKind{"SECRET": domain.CredentialKindSecret, "KEYPAIR": domain.CredentialKindKeypair}
	for sname, clock := range sources {
		for kname, kind := range kinds {
			t.Run(sname+" · "+kname, func(t *testing.T) {
				var logBuf bytes.Buffer
				repo := &stubUserClientRepo{}
				ops := &stubOpsRepo{}
				uc := NewIssueUserTokenUseCase(repo, &stubTx{}, ops).WithIssuanceClock(clock).WithOwnIssuance().
					WithLogger(slog.New(slog.NewTextHandler(&logBuf, nil)))
				op, err := uc.Execute(context.Background(), IssueInput{
					UserID: "usr00000000000000001", CreatedByUserID: "usr00000000000000001",
					CredentialKind: kind, TTLSeconds: 3600,
				})
				var code codes.Code
				var msg string
				switch {
				case err != nil:
					st := status.Convert(err)
					code, msg = st.Code(), st.Message()
				default:
					require.NotNil(t, op)
					if kind == domain.CredentialKindKeypair {
						waitForOp(t, ops)
						require.NotNil(t, ops.lastErr, "Operation несёт отказ")
						code, msg = codes.Code(ops.lastErr.GetCode()), ops.lastErr.GetMessage()
					} else {
						require.NotNil(t, op.Error, "Operation несёт отказ")
						code, msg = codes.Code(op.Error.GetCode()), op.Error.GetMessage()
					}
				}
				require.Equal(t, codes.Unavailable, code)
				require.Equal(t, shared.MomentUnavailableMessage, msg, "текст фиксирован и не несёт причины")
				require.Empty(t, repo.inserted.ID, "строка удостоверения не записана")
				logged := logBuf.String()
				require.Contains(t, logged, "step=issuance-moment")
				require.NotContains(t, logged, "10.42.7.3")
				require.NotContains(t, logged, "user=kaname")
			})
		}
	}
}
