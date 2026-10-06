// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// address_verification_a197_integration_test.go — A197-04: носитель окна темпа
// приглашённого — адрес на момент активации приглашения подтверждением адреса
// (приёмка `docs/engineering/acceptance/admission-rate-carrier-is-fixed-at-registration.md`,
// Р1; задача PRO-Robotech/kaname#197). «Дано» — сцена EV-72 этого стенда.
package loginlanehttp_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// TestA197_04_InviteeCarrierIsTheAddressAtActivation — A197-04 и близнец
// (потолок 2 вместо 1).
func TestA197_04_InviteeCarrierIsTheAddressAtActivation(t *testing.T) {
	for _, tc := range []struct {
		name, tag string
		ceiling   int64
		admit     bool
	}{
		{"потолок 1 — отказ рубежом темпа", "neg", 1, false},
		{"близнец: потолок 2 — заведение проходит, счётчик 2", "pos", 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newAVLane(t)
			h.requireVerbs(t, "A197-04")
			inv, acc, prj := h.inviter(t)
			iv := h.invite(t, inv, acc, prj, freshAddress("inv-e-"+tc.tag), 7*24*time.Hour)
			s := h.registerInvitee(t, iv)
			r := h.confirm(t, s, h.latestCode(t, "A197-04", iv.user))
			require.Equal(t, http.StatusOK, r.status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): активация подтверждением (EV-72): %s", r.body)
			st, _, _ := h.inviteState(t, iv)
			require.Equal(t, "ACTIVE", st, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): приглашение активировано")

			carrier := strings.ToLower(iv.email)
			var admitted int
			require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT admitted FROM kaname.identity_admission_windows WHERE kind = 'iam.account' AND carrier_id = $1`, carrier).Scan(&admitted),
				"A197-04: окно носителя %q после активации", carrier)
			require.Equal(t, 1, admitted, "A197-04: личный аккаунт активации сосчитан")

			_, err := kanamepg.NewOwnCeilingRepo(h.pool).ApplyAdmissionRate(h.ctx, tc.ceiling, time.Hour)
			require.NoError(t, err)
			moved := "inv-f-" + strings.ToLower(ids.NewID("tst")[3:9]) + "@example.invalid"
			_, err = h.pool.Exec(h.ctx, `UPDATE kaname.users SET email = $2 WHERE id = $1`, string(iv.user), moved)
			require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): посев смены адреса")

			_, err = h.pool.Exec(h.ctx, `INSERT INTO kaname.accounts (id, name, owner_user_id, labels) VALUES ($1, $2, $3, '{}'::jsonb)`,
				ids.NewID(domain.PrefixAccount), "a197-04-"+strings.ToLower(string(iv.user)[4:12]), string(iv.user))
			var got string
			require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT admission_carrier FROM kaname.users WHERE id = $1`, string(iv.user)).Scan(&got),
				"A197-04: носитель человека")
			require.Equal(t, carrier, got, "A197-04: носитель — адрес на момент активации")
			require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT admitted FROM kaname.identity_admission_windows WHERE kind = 'iam.account' AND carrier_id = $1`, carrier).Scan(&admitted))
			if tc.admit {
				require.NoError(t, err, "A197-04 близнец: заведение при потолке 2")
				require.Equal(t, 2, admitted, "A197-04 близнец: счётчик окна %q — 2", carrier)
				return
			}
			require.Error(t, err, "A197-04: смена адреса открыла окно — второе заведение прошло")
			var pgErr *pgconn.PgError
			require.ErrorAs(t, err, &pgErr)
			require.Equal(t, "KQ004", pgErr.Code, "A197-04: отказ рубежом темпа")
			require.Equal(t, 1, admitted)
		})
	}
}
