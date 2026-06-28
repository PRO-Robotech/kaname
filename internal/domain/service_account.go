// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

import (
	"time"

	"go.uber.org/multierr"
)

// ServiceAccount — Account-scoped (account_id FK ON DELETE RESTRICT).
// : добавлены `project_id` (optional, FK projects RESTRICT)
// и `enabled` (default true). Migration 0011.
type ServiceAccount struct {
	ID          ServiceAccountID
	AccountID   AccountID
	ProjectID   ProjectID // nullable —
	Name        SvcAccountName
	Description Description
	Enabled     bool //  (default true)
	CreatedAt   time.Time
	// Labels — tenant-facing метки. Делают ServiceAccount label-selectable
	// наравне с account/project (ARM_LABELS-грант на iam.serviceAccount → v_list
	// по `labels @> matchLabels`; List фильтрует viewer ∪ v_list).
	Labels Labels
}

func (s ServiceAccount) Validate() error {
	var errs error
	errs = multierr.Append(errs, s.Name.Validate())
	errs = multierr.Append(errs, s.Description.Validate())
	errs = multierr.Append(errs, s.Labels.Validate())
	if s.AccountID == "" {
		errs = multierr.Append(errs, ErrEmpty)
	}
	return errs
}
