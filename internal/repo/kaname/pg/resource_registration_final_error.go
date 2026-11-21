// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"errors"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/jackc/pgx/v5/pgconn"
)

// Только закрытый результат финальной проверки полномочий получает публичный
// отказ. Общие ошибки SQL ACL и ошибки источников сохраняют исходную причину.
func (s *resourceRegistrationStage) finalAuthorityError(err error) error {
	var pgerr *pgconn.PgError
	if s == nil || !errors.As(err, &pgerr) || pgerr.Code != "42501" || pgerr.ConstraintName != "resource_registration_authority_denied" {
		return err
	}
	denied := authzguard.PermissionDenied()
	if s.registration != nil {
		return s.registration.accountRefusal(denied)
	}
	return denied
}
