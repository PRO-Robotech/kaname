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

// MayAuthenticate reports whether this service account is allowed to obtain a
// token or a fresh credential. It is the single predicate every issuance path
// asks, the machine counterpart of InviteStatus.MayAuthenticate for users — so
// that no path can re-derive its own answer and quietly disagree with the rest.
//
// It reads a field, which means it is only as truthful as the query that
// populated the struct: `enabled` is a bool, false in every zero value, so a
// read that does not select the column makes this method answer "no" for every
// account in existence. Callers therefore judge a row they actually read, and
// the reads that feed them are pinned by their own tests.
func (s ServiceAccount) MayAuthenticate() bool { return s.Enabled }

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
