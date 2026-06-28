// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

import (
	"time"

	"go.uber.org/multierr"
)

// Project — child Account-а («folder» в YC-стилистике, но без промежуточного
// Cloud). Уникальное имя per-Account (DB UNIQUE projects_account_name_unique).
//
// FK: account_id → accounts(id) ON DELETE RESTRICT.
// account_id — hard-immutable после Create (Update его reject'ит).
type Project struct {
	ID          ProjectID
	AccountID   AccountID
	Name        ProjectName
	Description Description
	Labels      Labels
	CreatedAt   time.Time
}

func (p Project) Validate() error {
	var errs error
	errs = multierr.Append(errs, p.Name.Validate())
	errs = multierr.Append(errs, p.Description.Validate())
	errs = multierr.Append(errs, p.Labels.Validate())
	if p.AccountID == "" {
		errs = multierr.Append(errs, ErrEmpty)
	}
	return errs
}
