// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// usecase_quota_refusal_test.go — отказ учёта доезжает до вызывающего ПАРОЙ
// «код + признак» (задача #1191, приёмка сценарий CRED-CAP-19).
//
// Предмет: у этого глагола свой преобразователь ошибок, и о полосе учёта он не
// знал. Неопознанный признак уходит в фиксированный INTERNAL — вызывающий видит
// поломку платформы там, где платформа сработала как задумано, и не узнаёт ни
// носителя, ни предела, ни вида.
//
// Утверждается ПАРА, а не код: клиент различает полосы машинно, по признаку
// `google.rpc.ErrorInfo`. Код без признака не отличает «поднять предел» от
// «завести предел» — а действия администратора у них разные.

package user_tokens

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

func quotaRefusalReason(t *testing.T, err error) (codes.Code, string, string) {
	t.Helper()
	st, ok := status.FromError(err)
	require.True(t, ok, "ответ обязан быть gRPC-статусом")
	for _, d := range st.Details() {
		if info, is := d.(*errdetails.ErrorInfo); is {
			return st.Code(), info.GetReason(), st.Message()
		}
	}
	return st.Code(), "", st.Message()
}

func TestQuotaRefusalReachesTheCallerAsACodeAndAReason(t *testing.T) {
	t.Parallel()

	const full = "iam.user usr00000000000000001 has reached its limit of 10 iam.user.credential"
	code, reason, msg := quotaRefusalReason(t, mapPGErr(iamerr.Wrapf(iamerr.ErrQuotaExceeded, "%s", full)))
	require.Equal(t, codes.ResourceExhausted, code,
		"место кончилось, а вызывающий получил другой код: край отдаст не 429, и клиент "+
			"прочитает исчерпание как поломку платформы")
	require.Equal(t, "QUOTA_EXCEEDED", reason,
		"признак полосы не приклеен: клиенту придётся разбирать прозу, чтобы понять, "+
			"поднимать предел или заводить его")
	require.Contains(t, msg, "has reached its limit of 10",
		"текст единственного производителя отказа обязан доезжать ДОСЛОВНО — он и есть контракт")

	const none = "iam.user usr00000000000000001 has no ceiling stated for iam.user.credential"
	code, reason, _ = quotaRefusalReason(t, mapPGErr(iamerr.Wrapf(iamerr.ErrQuotaNotProvisioned, "%s", none)))
	require.Equal(t, codes.FailedPrecondition, code,
		"«предел не назван» — не исчерпание: ввод арендатора корректен, не выполнено "+
			"предусловие ПЛАТФОРМЫ, и обвинять вызывающего нельзя")
	require.Equal(t, "QUOTA_NOT_PROVISIONED", reason)
}

// Отрицание в паре с положительным: ошибка НЕ из полосы учёта признака не
// получает и в 429 не превращается.
func TestANonQuotaErrorDoesNotBecomeARefusal(t *testing.T) {
	t.Parallel()

	code, reason, _ := quotaRefusalReason(t, mapPGErr(iamerr.Wrapf(iamerr.ErrNotFound, "nothing here")))
	require.Equal(t, codes.NotFound, code)
	require.Empty(t, reason, "признак полосы учёта приклеен к ошибке, которая к учёту не относится")
}
