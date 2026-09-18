// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// second_factor_remove_integration_test.go — СНЯТИЕ второго фактора на настоящей
// базе: ответ `remove` несёт `backupCodesRemaining: 0` ВСЕГДА, в обеих ветках
// (запасной код и код по времени), согласовано с состоянием (`GET` → «не
// заведён»).
//
// Приёмка `docs/engineering/acceptance/second-factor-totp-and-recovery-codes.md`
// ред. 10, Р4 (исключение для `remove`), Ф12-28, Ф12-45 «а»; решение диспетчера
// по kaname#275 (делегирование владельца 2026-09-18).
//
// # Почему настоящая база, а не дублёр
//
// Остаток набора считает `settle` над строкой набора ПОД ЗАМКОМ
// (`LockLookupSet` → `MatchSet` → `ConsumeLookupElement`), а согласованность с
// `GET` — над той же строкой ПОСЛЕ `RemoveSecondFactor`, одной транзакцией.
// Дублёр отдал бы объявленный остаток и не показал бы, что набор снят: предмет
// пробы — исход над базой, а не проброс значения.
//
// # Красный до фикса (kaname#275)
//
// На нынешнем коде снятие ЗАПАСНЫМ кодом отдаёт остаток уже снятого набора
// (`st.remaining` = 9 на посеве полного набора), а снятие кодом ПО ВРЕМЕНИ поля
// не несёт вовсе (`st.consumed` ложно) — обе подпробы падают до фикса.
//
// Run: `go test ./internal/handler/loginlanehttp/ -run F12_28_Remove -count=1`
// (Docker). Skipped under -short.
package loginlanehttp_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
	"github.com/PRO-Robotech/kaname/internal/totpverify"
)

// TestLaneIntegration_F12_28_RemoveAlwaysReportsZeroBackupCodesRemaining —
// Ф12-28, Р4 ред. 10 (kaname#275): после успешного `remove` любым годным кодом
// фактор снят, набора запасных кодов нет — ответ несёт `backupCodesRemaining: 0`
// ВСЕГДА, и согласуется с состоянием (`GET` → «не заведён»).
//
// Две подпробы — две ветки сверки кода, и обе обязаны дать 0:
//   - запасной код: до фикса ответ нёс остаток снятого набора (9);
//   - код по времени: до фикса поля в ответе не было вовсе.
func TestLaneIntegration_F12_28_RemoveAlwaysReportsZeroBackupCodesRemaining(t *testing.T) {
	for _, tc := range []struct {
		name string
		// factor — предъявление снятия из заведённого материала (секрет, набор,
		// принятая подтверждением ступень).
		factor func(t *testing.T, secret totpverify.Secret, codes []string, accepted int64) humansession.SecondFactorPresentation
	}{
		{
			name: "lookup_secret: снятие запасным кодом",
			factor: func(_ *testing.T, _ totpverify.Secret, codes []string, _ int64) humansession.SecondFactorPresentation {
				return humansession.SecondFactorPresentation{Method: assurance.MethodLookupSecret, Code: codes[0]}
			},
		},
		{
			name: "totp: снятие кодом по времени",
			factor: func(t *testing.T, secret totpverify.Secret, _ []string, accepted int64) humansession.SecondFactorPresentation {
				return humansession.SecondFactorPresentation{Method: assurance.MethodTOTP, Code: laneTOTP(t, secret, accepted+1)}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newSessionLane(t)
			secret, codes, accepted := h.enrolledSecondFactor(t)

			remove, err := humansession.NewRemoveSecondFactorUseCase(h.secondFactor)
			require.NoError(t, err)
			status, err := humansession.NewSecondFactorStatusUseCase(h.secondFactor)
			require.NoError(t, err)

			// Дано (проверяется ДО предмета): у личности заведён фактор с набором.
			s := h.login(t, integrationPassword)
			bearer := domain.PresentedSessionBearer(s.bearer.Value)
			given, err := status.Execute(h.ctx, humansession.StatusInput{Bearer: bearer})
			require.NoError(t, err)
			require.True(t, given.TOTPEnrolled, "Дано: у личности заведён второй фактор")
			require.NotNil(t, given.BackupCodes, "Дано: у заведённого фактора есть набор запасных кодов")
			require.Equal(t, passwordverify.BackupCodeCount, given.BackupCodes.Total, "Дано: полный набор")
			require.Equal(t, passwordverify.BackupCodeCount, given.BackupCodes.Remaining, "Дано: ни один код не потреблён")

			// Когда: снятие годным кодом ветки tc.
			out, err := remove.Execute(h.ctx, humansession.RemoveSecondFactorInput{
				Bearer: bearer, Factor: tc.factor(t, secret, codes, accepted),
				Source: fwd()[loginlanehttp.HeaderForwardedFor],
			})
			require.NoError(t, err, "снятие годным кодом проходит")

			// Тогда: ответ несёт остаток 0 ВСЕГДА — фактор снят, набора нет.
			require.NotNil(t, out.BackupCodesRemaining, "ответ remove несёт backupCodesRemaining всегда (Р4 ред. 10)")
			require.Equal(t, 0, *out.BackupCodesRemaining,
				"снятие убрало фактор — набора нет, остаток 0 в обеих ветках (Р4, Ф12-28, kaname#275)")

			// Согласовано с состоянием: `GET` того же человека — «не заведён».
			after, err := status.Execute(h.ctx, humansession.StatusInput{Bearer: out.Bearer})
			require.NoError(t, err)
			require.False(t, after.TOTPEnrolled, "GET после снятия — «не заведён»")
			require.Nil(t, after.BackupCodes, "GET после снятия — набора нет")
		})
	}
}
