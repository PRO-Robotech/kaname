// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_keys_test

// credential_revoke_outcomes_test.go — исход отзыва несуществующего у трёх видов
// удостоверений (приёмка `docs/engineering/acceptance/credential-verbs-refusal-outcomes.md`,
// задача kaname#522).
//
//   - CVR-09: сторона ключа доступа — образец, НЕ меняется. Повторный отзыв
//     отвергается тем же синхронным `NOT_FOUND`, что отзыв никогда не
//     существовавшего. Проба зелена до правки и после.
//   - CVR-10: сличение видов. У трёх глаголов отзыва на идентификаторе годной
//     формы без строки совпадают синхронность (операции нет), код, набор
//     деталей и форма текста `<Resource> <id> not found`; различаются только
//     имя ресурса и эхо идентификатора.
//
// Сличение живёт здесь, а не в пакете одного из видов: оно о ТРЁХ глаголах, и
// каждый собирается своим настоящим конструктором через свои экспортированные
// порты — дублёры ниже отвечают «строки нет» тем же исходом, что хранилище.

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/sa_keys"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user_tokens"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify/webauthntest"
)

// TestAccessKey_CVR09_RepeatRevokeIsTheAbsentRefusal — CVR-09; близнец —
// Ф7-25 (первый отзыв того же ключа проходит), отличие в одном факте: ключ уже
// снят.
func TestAccessKey_CVR09_RepeatRevokeIsTheAbsentRefusal(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	first := webauthntest.New(t, webauthntest.AlgES256)
	second := webauthntest.New(t, webauthntest.AlgES256)
	k1 := h.mustRegister(alice, first)
	h.mustRegister(alice, second)

	// Близнец Ф7-25: первый отзыв — успех.
	op, err := h.revoke(alice, string(k1.ID))
	require.NoError(t, err)
	require.Nil(t, op.Error)

	// Повторный отзыв.
	_, errRepeat := h.revoke(alice, string(k1.ID))
	st := requireCode(t, errRepeat, codes.NotFound)
	require.Equal(t, fmt.Sprintf("AccessKey %s not found", k1.ID), st.Message())

	// Побайтово равен отказу по никогда не существовавшему идентификатору
	// годной формы (Ф7-27) после замены идентификатора.
	const never = "ak-0000000000000000z"
	_, errNever := h.revoke(alice, never)
	requireCode(t, errNever, codes.NotFound)
	require.Equal(t,
		strings.ReplaceAll(errNever.Error(), never, "X"),
		strings.ReplaceAll(errRepeat.Error(), string(k1.ID), "X"),
		"повторный отзыв и отзыв несуществующего обязаны быть одним отказом")

	// Второй ключ на месте и предъявляется; события снятия — ровно одно.
	_, err = h.assertWith(alice, second, webauthntest.AssertionOptions{})
	require.NoError(t, err)
	require.Equal(t, 1, h.store.keyCount(alice))
}

// revokeRefusal — наблюдаемое об отказе одного вида.
type revokeRefusal struct {
	resource  string
	id        string
	sync      bool
	opCreated bool
	err       error
}

// shape — отпечаток отказа после вычёркивания эха идентификатора и имени
// ресурса: код, набор деталей, форма текста.
func (r revokeRefusal) shape() string {
	st := status.Convert(r.err)
	var kinds []string
	for _, d := range st.Details() {
		kinds = append(kinds, fmt.Sprintf("%T", d))
	}
	msg := strings.Replace(st.Message(), r.id, "<id>", 1)
	msg = strings.Replace(msg, r.resource, "<Resource>", 1)
	return fmt.Sprintf("sync=%v opCreated=%v code=%v details=%v msg=%q", r.sync, r.opCreated, st.Code(), kinds, msg)
}

// TestCredentialRevoke_CVR10_ThreeKindsShareOneRefusalForm — CVR-10; близнецы —
// CVR-02, CVR-06, CVR-09.
func TestCredentialRevoke_CVR10_ThreeKindsShareOneRefusalForm(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// ── AccessKey — образец.
	h := newHarness(t)
	const akID = "ak-0000000000000000z"
	_, akErr := h.revoke(alice, akID)
	ak := revokeRefusal{resource: "AccessKey", id: akID, sync: akErr != nil, err: akErr}

	// ── UserToken: субъект существует, удостоверения годной формы нет.
	const utID = "uoc00000000000000404"
	utOps := newFakeOps()
	utOp, utErr := user_tokens.NewRevokeUserTokenUseCase(absentUserTokens{}, noTx{}, utOps).
		Execute(ctx, user_tokens.RevokeInput{UserID: alice, TokenID: utID})
	ut := revokeRefusal{resource: "UserToken", id: utID, sync: utErr != nil, opCreated: utOps.count() > 0, err: utErr}
	if utErr == nil {
		ut.err = opOutcome(t, utOps, utOp.ID)
	}

	// ── SAKey: учётка существует, ключа годной формы нет.
	const skID = "soc00000000000000404"
	skOps := newFakeOps()
	skOp, skErr := sa_keys.NewRevokeSAKeyUseCase(absentSAKeys{}, noTx{}, skOps).
		Execute(ctx, sa_keys.RevokeInput{ServiceAccountID: "sva00000000000000001", KeyID: skID})
	sk := revokeRefusal{resource: "SAKey", id: skID, sync: skErr != nil, opCreated: skOps.count() > 0, err: skErr}
	if skErr == nil {
		sk.err = opOutcome(t, skOps, skOp.ID)
	}

	// Образец обязан быть тем, что объявлено, — иначе сличение с ним ничего не
	// говорит (положительный контроль сличения).
	want := `sync=true opCreated=false code=NotFound details=[] msg="<Resource> <id> not found"`
	require.Equal(t, want, ak.shape(), "образец (ключ доступа) не тот, что объявлен приёмкой")
	for _, r := range []revokeRefusal{ut, sk} {
		if got := r.shape(); got != ak.shape() {
			t.Errorf("CVR-10: %s — отпечаток отказа %s, у ключа доступа %s", r.resource, got, ak.shape())
		}
	}
}

// opOutcome — исход операции, сведённый к ошибке: успех операции — не отказ,
// и отпечаток его покажет как код OK.
func opOutcome(t *testing.T, ops *fakeOps, id string) error {
	t.Helper()
	op := ops.await(t, id)
	if op.Error != nil {
		return status.ErrorProto(op.Error)
	}
	return status.Error(codes.OK, "операция завершилась успехом")
}

func (f *fakeOps) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.ops)
}

// noTx — транзакция дублёров: дублёры SQL не исполняют.
type noTx struct{}

func (noTx) Begin(context.Context) (service.Tx, error) { return noTx{}, nil }
func (noTx) Commit(context.Context) error                { return nil }
func (noTx) Rollback(context.Context) error              { return nil }

// absentUserTokens — хранилище, у которого строки нет: субъект существует,
// удостоверения у него нет. Отвечает тем же исходом, что настоящее хранилище
// на отсутствующей строке: чтение — «нет», снятие — found=false.
type absentUserTokens struct{}

func (absentUserTokens) Insert(_ context.Context, _ service.Tx, c domain.UserOAuthClient) (domain.UserOAuthClient, error) {
	return c, nil
}
func (absentUserTokens) ExistsOwnedByID(context.Context, domain.UserID, domain.UserOAuthClientID) (bool, error) {
	return false, nil
}
func (absentUserTokens) DeleteOwnedByID(context.Context, service.Tx, domain.UserID, domain.UserOAuthClientID) (domain.UserOAuthClient, bool, error) {
	return domain.UserOAuthClient{}, false, nil
}
func (absentUserTokens) List(context.Context, domain.UserID, string, int32) ([]domain.UserOAuthClient, string, error) {
	return nil, "", nil
}
func (absentUserTokens) AccountForUser(context.Context, domain.UserID) (domain.AccountID, bool, error) {
	return "acc00000000000000001", true, nil
}

// absentSAKeys — то же для ключей служебной учётки.
type absentSAKeys struct{}

func (absentSAKeys) Insert(_ context.Context, _ service.Tx, c domain.ServiceAccountOAuthClient) (domain.ServiceAccountOAuthClient, error) {
	return c, nil
}
func (absentSAKeys) ExistsOwnedByID(context.Context, domain.ServiceAccountID, domain.SAOAuthClientID) (bool, error) {
	return false, nil
}
func (absentSAKeys) DeleteOwnedByID(context.Context, service.Tx, domain.ServiceAccountID, domain.SAOAuthClientID) (domain.ServiceAccountOAuthClient, bool, error) {
	return domain.ServiceAccountOAuthClient{}, false, nil
}
func (absentSAKeys) List(context.Context, domain.ServiceAccountID, string, int32) ([]domain.ServiceAccountOAuthClient, string, error) {
	return nil, "", nil
}
func (absentSAKeys) AccountForServiceAccount(context.Context, domain.ServiceAccountID) (domain.AccountID, bool, error) {
	return "acc00000000000000001", true, nil
}
func (absentSAKeys) OwnerUserForServiceAccount(context.Context, domain.ServiceAccountID) (domain.UserID, error) {
	return "usr00000000000000001", nil
}
