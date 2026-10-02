// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// basic_credential_refusal_reason_integration_test.go — у каждого отказа полосы
// базового секрета есть своя причина, и она рождается у НАСТОЯЩЕГО авторитета
// (задача kaname#379).
//
// # Что здесь утверждается
//
// На одной базе и одном человеке, над теми же строками: отсечка отзыва-всех,
// «строки нет», «секрет не тот» и «строка не наша» дают каждая свою причину у
// авторитета и свою клетку переписи у глагола, собранного над ним, — при том
// что снаружи все они побайтно равны отказу удостоверению, которого нет.
//
// # Чем проба защищена от собственной снисходительности
//
//   - положительный контроль в том же прогоне: живой секрет проходит, иначе
//     «все отказы различны» неотличимо от полосы, отвергающей всё подряд;
//   - отсечка стоит РОВНО в момент выдачи отзываемого секрета (граница
//     включительна), а живой секрет выдан позже неё — отказ по отсечке не
//     растворяется в «удостоверения нет»;
//   - неверный секрет — настоящая предъявляемая строка того же удостоверения с
//     другой секретной частью: контрольная сумма сходится, форма годна, база
//     спрошена;
//   - перепись выводится из исполненного: сколько входов подано, сколько
//     клеток сдвинулось.
package pg_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/PRO-Robotech/corelib/credsecret"

	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// TestBasicLane_EachRefusalCarriesItsOwnReasonAndItsOwnCell — причина у
// авторитета и клетка у глагола, на каждом входе, над настоящими строками.
func TestBasicLane_EachRefusalCarriesItsOwnReasonAndItsOwnCell(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	f := newAssertionFixture(t)
	authority := newBasicAuthority(t, f.pool)
	h := internaliam.NewHandler(internaliam.NewLookupSubjectUseCase(nil), nil).
		WithBasicCredentialResolver(authority)

	const (
		revokedID = "uoc_rsnr0000000000001"
		liveID    = "uoc_rsnr0000000000002"
		foreignID = "xyz_rsnr0000000000003"
	)
	// Отзываемый секрет выдан первым; отсечка — ровно в момент его выдачи.
	revoked := f.mintUserSecret(t, revokedID)
	cutoff := userClientIssuedAt(t, f, revokedID)
	_, err := f.pool.Exec(ctx, `
INSERT INTO kaname.user_token_revocations (user_id, revoke_before) VALUES ($1, $2)
ON CONFLICT (user_id) DO UPDATE SET revoke_before = EXCLUDED.revoke_before`, f.user, cutoff)
	require.NoError(t, err)

	// Живой секрет выдан ПОСЛЕ отсечки — отсечка его не касается.
	live := f.mintUserSecret(t, liveID)
	require.Truef(t, userClientIssuedAt(t, f, liveID).After(cutoff),
		"предпосылка: живой секрет выдан позже отсечки")

	// Та же форма, то же удостоверение, другая секретная часть.
	wrong, _, err := credsecret.Mint(liveID)
	require.NoError(t, err)
	stranger, _, err := credsecret.Mint(basicLaneStrangerID)
	require.NoError(t, err)
	foreign, _, err := credsecret.Mint(foreignID)
	require.NoError(t, err)

	// Положительный контроль — до всякого отказа.
	require.Equal(t, codes.OK, basicResolve(t, ctx, h, live).code, "контроль: живой секрет не резолвится")
	require.Equal(t, codes.OK, basicLive(t, ctx, h, liveID).code, "контроль: живой секрет не жив")

	// Эталон снаружи — отказ удостоверению, которого нет.
	ref := basicResolve(t, ctx, h, stranger)
	require.Equal(t, codes.Unauthenticated, ref.code)

	type input struct {
		name  string
		verb  internaliam.BasicCredentialVerb
		value string // предъявленная строка для резолва, идентификатор для живости
		want  domain.BasicCredentialRefusalReason
	}
	inputs := []input{
		{"резолв: отсечка владельца", internaliam.BasicCredentialResolve, revoked, domain.BasicRefusalOwnerRevoked},
		{"резолв: строки нет", internaliam.BasicCredentialResolve, stranger, domain.BasicRefusalNotFound},
		{"резолв: секрет не тот", internaliam.BasicCredentialResolve, wrong, domain.BasicRefusalSecretMismatch},
		{"резолв: вид не наш", internaliam.BasicCredentialResolve, foreign, domain.BasicRefusalMalformed},
		{"резолв: форма негодна", internaliam.BasicCredentialResolve, credsecret.Mark + "garbage", domain.BasicRefusalMalformed},
		{"живость: отсечка владельца", internaliam.BasicCredentialLiveness, revokedID, domain.BasicRefusalOwnerRevoked},
		{"живость: строки нет", internaliam.BasicCredentialLiveness, basicLaneStrangerID, domain.BasicRefusalNotFound},
		{"живость: вид не наш", internaliam.BasicCredentialLiveness, foreignID, domain.BasicRefusalMalformed},
	}

	var ran int
	for _, in := range inputs {
		// (1) Причина у авторитета — та, что названа, и отказ остаётся единым.
		var aerr error
		if in.verb == internaliam.BasicCredentialResolve {
			_, aerr = authority.ResolveBasic(ctx, in.value)
		} else {
			aerr = authority.CheckBasicLive(ctx, in.value)
		}
		require.Truef(t, errors.Is(aerr, domain.ErrBasicCredentialRefused),
			"%s: авторитет ответил не единым отказом: %v", in.name, aerr)
		require.Equalf(t, domain.ErrBasicCredentialRefused.Error(), aerr.Error(),
			"%s: текст отказа авторитета отличается от единого", in.name)
		reason, named := domain.BasicCredentialRefusalReasonOf(aerr)
		require.Truef(t, named, "%s: авторитет отказал, не назвав причины", in.name)
		require.Equalf(t, in.want, reason, "%s: причина не та", in.name)

		// (2) Клетка у глагола и отказ снаружи.
		before := h.BasicCredentialOutcomes()
		var got basicAnswer
		if in.verb == internaliam.BasicCredentialResolve {
			got = basicResolve(t, ctx, h, in.value)
		} else {
			got = basicLive(t, ctx, h, in.value)
		}
		require.Equalf(t, ref.wire, got.wire, "%s: отказ снаружи различим", in.name)
		after := h.BasicCredentialOutcomes()
		cell := internaliam.BasicCredentialCell{Verb: in.verb, Outcome: internaliam.BasicCredentialOutcome(in.want)}
		require.Equalf(t, before[cell]+1, after[cell], "%s: отказ не лёг в свою клетку %v", in.name, cell)
		for c, v := range after {
			if c != cell {
				require.Equalf(t, before[c], v, "%s: сдвинулась чужая клетка %v", in.name, c)
			}
		}
		ran++
	}
	t.Logf("перепись: входов подано %d · исполнено до конца, каждый своей клеткой, %d", len(inputs), ran)
	require.Equal(t, len(inputs), ran)
}
