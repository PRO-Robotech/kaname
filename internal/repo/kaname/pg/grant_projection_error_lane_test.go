// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// Неверный отпечаток или версия в хранилище — дефект службы, не ввода клиента.
// Проверяем публичный результат настоящего переводчика, включая отсутствие
// сырого отказа драйвера и содержимого строки в цепочке ошибок.
func TestGrantProjection_ServiceChecksHaveOpaqueInternalErrors(t *testing.T) {
	cvCaptureLog(t)
	for _, check := range []struct{ table, constraint string }{
		{"role_create_binding_rule", "role_create_binding_rule_fp_check"},
		{"role_bind_role_rule", "role_bind_role_rule_fp_check"},
		{"access_bindings", "access_bindings_grant_capability_version_check"},
	} {
		t.Run(check.constraint, func(t *testing.T) {
			err := mapErr(cvCheckPgErr(check.constraint, check.table), "", "")
			require.ErrorIs(t, err, iamerr.ErrInternal)
			require.NotErrorIs(t, err, iamerr.ErrInvalidArg)
			require.Equal(t, iamerr.ErrInternal.Error(), err.Error())
			var pgErr *pgconn.PgError
			require.False(t, errors.As(err, &pgErr))
		})
	}
}
