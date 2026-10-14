// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// register_whoami_integration_test.go — Ф4-26 уровнем I (приёмка
// `registration-and-its-three-consequences.md`, §10а п. 1; kaname#256): снимок
// «кто я» сразу после регистрации с улицы называет личный аккаунт — ровно одну
// запись, и её роли содержат `owner`.
//
// Снимок читается настоящим хранилищем той же базы под принципалом
// зарегистрированного, без ожидания чего-либо: он не опирается на
// материализацию прав (Р2, Р8). Сквозное наблюдение — маршрут края, его
// держатель — стенд платформы под `own` (§10а п. 2).
//
// Отрицательная сторона этой полосы — Ф4-11 и Ф4-25 (регистрация, отказавшая,
// сессии и снимка не выдаёт), а не вызов без сессии.
package registration_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/authorize"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

func TestRegisterIntegration_F4_26_WhoAmINamesThePersonalAccount(t *testing.T) {
	h := newHarness(t)
	email := freshEmail("f4-26")
	out, err := h.register(t, h.useCase(t, h.store), email)
	require.NoError(t, err)
	h.assertAllThree(t, email, out)

	var personal string
	require.NoError(t, h.pool.QueryRow(h.ctx,
		`SELECT a.id FROM accounts a WHERE a.owner_user_id = $1`, string(out.View.User.ID)).Scan(&personal),
		"ПРЕДПОСЫЛКА: регистрация завела личный аккаунт (Ф4-05)")

	ctx := operations.WithPrincipal(h.ctx, operations.Principal{Type: "user", ID: string(out.View.User.ID)})
	res, err := authorize.NewWhoAmIUseCase(h.repo, nil).Execute(ctx)
	require.NoError(t, err)

	require.Equal(t, out.View.User.ID, res.UserID, "userId снимка равен user.id ответа регистрации")
	require.Len(t, res.Accounts, 1, "у человека с улицы — ровно одна запись снимка: личный аккаунт")
	require.Equal(t, domain.AccountID(personal), res.Accounts[0].AccountID,
		"запись снимка — личный аккаунт, заведённый этой регистрацией")
	require.Contains(t, res.Accounts[0].Roles, "owner", "владение названо ролью owner")
}
