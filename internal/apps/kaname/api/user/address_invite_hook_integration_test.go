// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// address_invite_hook_integration_test.go — EV-74 приёмки
// `access-beyond-login-needs-a-verified-address.md` (kaname#456, Р11 п. 5) и
// условие аудита поверхности о пути хука поставщика: строка приглашения без
// отметки нашей полосы этим путём не активируется, путь не доходит до
// заведения личных ресурсов, а исход — названный отказ, а не «уже активна» и не
// «срок истёк». Близнец — та же строка с отметкой: активирована.
package user

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

func TestEV74_ProviderHookDoesNotActivateAnUnverifiedInvite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	for _, verified := range []bool{false, true} {
		ctx := context.Background()
		pool, err := coredb.NewPool(ctx, dsnWithSchema(t))
		require.NoError(t, err)
		pgtest.ClosePoolAtEnd(t, pool)
		repo := kanamepg.New(pool, nil)

		// Распорядитель и его аккаунт.
		inviter, acc := domain.UserID(ids.NewID(domain.PrefixUser)), domain.AccountID(ids.NewID(domain.PrefixAccount))
		tx, err := pool.Begin(ctx)
		require.NoError(t, err)
		_, err = tx.Exec(ctx, `INSERT INTO kaname.accounts (id, name, owner_user_id) VALUES ($1, 'ev74-acc', $2)`, string(acc), string(inviter))
		require.NoError(t, err)
		_, err = tx.Exec(ctx, `INSERT INTO kaname.users (id, account_id, external_id, email, display_name, invite_status, email_verified_at)
			VALUES ($1, $2, 'ext-ev74-inviter', 'ev74-inviter@example.test', 'Inviter', 'ACTIVE', now())`, string(inviter), string(acc))
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))

		// Приглашение адреса V.
		const email = "ev74-invitee@example.test"
		w, err := repo.Writer(ctx)
		require.NoError(t, err)
		row, _, err := w.UsersW().InsertPending(ctx, domain.User{
			ID: domain.UserID(ids.NewID(domain.PrefixUser)), AccountID: acc, Email: email, DisplayName: "invitee",
			InviteStatus: domain.InviteStatusPending, InvitedBy: inviter,
		}, time.Now().Add(7*24*time.Hour))
		require.NoError(t, err)
		require.NoError(t, w.Commit(ctx))
		if verified {
			_, err = pool.Exec(ctx, `UPDATE kaname.users SET email_verified_at = now() WHERE id = $1`, string(row.ID))
			require.NoError(t, err)
		}

		count := func(q string, args ...any) int {
			var n int
			require.NoError(t, pool.QueryRow(ctx, q, args...).Scan(&n))
			return n
		}
		usersBefore := count(`SELECT count(*) FROM kaname.users`)
		accountsBefore := count(`SELECT count(*) FROM kaname.accounts`)
		bindingsBefore := count(`SELECT count(*) FROM kaname.access_bindings`)

		obs := &recordingActivationObserver{}
		uc := NewUpsertFromIdentityUseCase(repo, nil).WithActivationObserver(obs)
		_, upErr := uc.doUpsert(ctx, activationCandidateID, UpsertFromIdentityInput{
			ExternalID: "kratos-ev74-subject", Email: email, DisplayName: "Invitee",
		}, "system")

		var status, membership string
		require.NoError(t, pool.QueryRow(ctx, `SELECT invite_status FROM kaname.users WHERE id = $1`, string(row.ID)).Scan(&status))
		require.NoError(t, pool.QueryRow(ctx, `SELECT state FROM kaname.memberships WHERE user_id = $1 AND account_id = $2`,
			string(row.ID), string(acc)).Scan(&membership))
		if verified {
			require.NoError(t, upErr, "EV-74 близнец: строка с отметкой активируется")
			require.Equal(t, "ACTIVE", status, "EV-74 близнец: активирована")
			continue
		}
		require.Equal(t, "PENDING", status, "EV-74: inviteStatus остаётся PENDING")
		require.Equal(t, "PENDING", membership, "EV-74: Membership.state остаётся PENDING")
		require.Error(t, upErr, "EV-74: исход пути хука — названный отказ, а не успех")
		require.Zero(t, obs.count(activationOutcomeAlreadyActive), "EV-74: отказ не читается как «уже активна»")
		require.Zero(t, obs.count(activationOutcomeExpired), "EV-74: отказ не читается как «срок истёк»")
		require.Equal(t, usersBefore, count(`SELECT count(*) FROM kaname.users`), "EV-74: новых строк людей ноль")
		require.Equal(t, accountsBefore, count(`SELECT count(*) FROM kaname.accounts`), "EV-74: новых аккаунтов ноль")
		require.Equal(t, bindingsBefore, count(`SELECT count(*) FROM kaname.access_bindings`), "EV-74: новых выдач ноль")
		require.Zero(t, count(`SELECT count(*) FROM kaname.fga_outbox WHERE payload::text LIKE '%' || $1 || '%'`, string(row.ID)),
			"EV-74: намерений материализации об этой строке ноль")
	}
}
