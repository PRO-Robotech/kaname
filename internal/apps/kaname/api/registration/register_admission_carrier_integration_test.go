// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// register_admission_carrier_integration_test.go — A197-02: носитель окна темпа
// пишется в момент чеканки личности регистрацией, и писатель регистрации его не
// передаёт (приёмка `docs/engineering/acceptance/admission-rate-carrier-is-fixed-at-registration.md`,
// Р1; задача PRO-Robotech/kaname#197).
package registration_test

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registration"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// TestA197_02_CarrierIsWrittenWhenTheIdentityIsMinted — A197-02.
func TestA197_02_CarrierIsWrittenWhenTheIdentityIsMinted(t *testing.T) {
	h := newHarness(t)
	_, err := kanamepg.NewOwnCeilingRepo(h.pool).ApplyAdmissionRate(h.ctx, 0, time.Hour)
	require.NoError(t, err)

	email := "Reg-C-" + strings.ToUpper(freshEmail("a197-02")[4:])
	out, err := h.register(t, h.useCase(t, h.store), email)
	require.NoError(t, err, "A197-02: первая регистрация носителя проходит при потолке 0")
	h.assertAllThree(t, email, out)
	require.Equal(t, 1, h.obs.count(registration.OutcomeIssued))

	want := strings.ToLower(email)
	var carrier string
	require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT admission_carrier FROM kaname.users WHERE id = $1`, string(out.View.User.ID)).Scan(&carrier),
		"A197-02: носитель строки человека")
	require.Equal(t, want, carrier, "A197-02: носитель — адрес в нижнем регистре в момент чеканки")
	var windows int
	require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT count(*) FROM kaname.identity_admission_windows WHERE kind = 'iam.account' AND carrier_id = $1`, want).Scan(&windows))
	require.Equal(t, 1, windows, "A197-02: окно заведено с этим носителем")
}
