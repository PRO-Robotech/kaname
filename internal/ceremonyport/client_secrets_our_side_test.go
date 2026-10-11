// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package ceremonyport_test

// client_secrets_our_side_test.go — негодное хранимое значение секрета клиента
// растит клетку «наша сторона» ряда проверяющего (kaname#692).
//
// Правило отказов нашей стороны читает ряд проверяющего; сверка секрета
// клиента попадает под него ровно постольку, поскольку идёт через тот же
// наблюдаемый проверяющий. Здесь это держится исходом. Законный близнец —
// неверный секрет при читаемом значении: клетка «наша сторона» не растёт.

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/corelib/oauthceremony"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

func TestClientSecrets_UnreadableStoredValueCountsOurSideAtTheVerifier(t *testing.T) {
	rig := newSecretsRig(t)
	ctx := context.Background()
	ours := passwordverify.OutcomeFormatNotInRegistry
	require.True(t, ours.IsOurError(), "предпосылка: исход пробы — наша сторона")

	verdict, err := rig.port.VerifyClientSecret(ctx, testClientID, oauthceremony.NewPresentedSecret(wrongClientSecret))
	require.NoError(t, err)
	require.Equal(t, oauthceremony.SecretMismatched, verdict)
	require.Zero(t, rig.outcomes.count(ours), "неверный секрет — сторона клиента")

	unreadable, err := domain.NewLoginVerifier("$unknown-format$v=1$c29tZQ$Ym9keQ")
	require.NoError(t, err)
	rig.store.verifiers[testClientID] = unreadable
	_, err = rig.port.VerifyClientSecret(ctx, testClientID, oauthceremony.NewPresentedSecret(rightClientSecret))
	require.Error(t, err, "негодное хранимое значение — отказ операции, а не вердикт")
	require.Equal(t, 1, rig.outcomes.count(ours),
		"сверка секрета клиента прошла мимо наблюдаемого проверяющего — правило отказов о ней молчит")
}
