// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// basic_credential_address_integration_test.go — EV-66 приёмки
// `access-beyond-login-needs-a-verified-address.md` (kaname#456, Р5): базовый
// секрет человека с неподтверждённым адресом не принимается ни резолвом, ни
// перепросом живости открытого соединения (заказ консольной пары: перепрос
// судит ту же отметку, что резолв); причина — своя клетка `owner-unverified`,
// а снаружи отказ побайтно равен отказу удостоверению, которого нет.
package pg_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/PRO-Robotech/corelib/credsecret"

	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// TestEV66_BasicCredentialOfTheUnverifiedIsRefused — EV-66.
func TestEV66_BasicCredentialOfTheUnverifiedIsRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	f := newAssertionFixture(t)
	authority := newBasicAuthority(t, f.pool)
	h := internaliam.NewHandler(internaliam.NewLookupSubjectUseCase(nil), nil).WithBasicCredentialResolver(authority)
	const id = "uoc_addr0000000000001"
	presented := f.mintUserSecret(t, id)
	stranger, _, err := credsecret.Mint(basicLaneStrangerID)
	require.NoError(t, err)
	ref := basicResolve(t, ctx, h, stranger)

	setMark := func(verified bool) {
		t.Helper()
		if verified {
			_, err = f.pool.Exec(ctx, `UPDATE kaname.users SET email_verified_at = $2 WHERE id = $1`, f.user, time.Now().UTC())
		} else {
			_, err = f.pool.Exec(ctx, `UPDATE kaname.users SET email_verified_at = NULL WHERE id = $1`, f.user)
		}
		require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): посев отметки")
	}

	setMark(true)
	require.Equal(t, codes.OK, basicResolve(t, ctx, h, presented).code, "EV-66 (б): подтверждённому — принят")
	require.Equal(t, codes.OK, basicLive(t, ctx, h, id).code, "EV-66 (б): перепрос живости — жив")

	setMark(false)
	_, aerr := authority.ResolveBasic(ctx, presented)
	require.Truef(t, errors.Is(aerr, domain.ErrBasicCredentialRefused), "EV-66 (а): резолв — единый отказ: %v", aerr)
	reason, _ := domain.BasicCredentialRefusalReasonOf(aerr)
	require.Equal(t, domain.BasicCredentialRefusalReason("owner-unverified"), reason, "EV-66 (а): причина owner-unverified")
	got := basicResolve(t, ctx, h, presented)
	require.Equal(t, codes.Unauthenticated, got.code, "EV-66 (а): UNAUTHENTICATED")
	require.Equal(t, ref.wire, got.wire, "EV-66 (а): снаружи побайтно тот же отказ, что удостоверению, которого нет")
	lerr := authority.CheckBasicLive(ctx, id)
	require.Truef(t, errors.Is(lerr, domain.ErrBasicCredentialRefused), "EV-66 (а): перепрос живости — единый отказ: %v", lerr)
	lreason, _ := domain.BasicCredentialRefusalReasonOf(lerr)
	require.Equal(t, domain.BasicCredentialRefusalReason("owner-unverified"), lreason, "EV-66 (а): перепрос — причина owner-unverified")
}
