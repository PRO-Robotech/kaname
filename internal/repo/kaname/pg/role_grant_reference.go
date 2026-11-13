// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	rolerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/role"
)

func (w *roleWriter) LockGrantOwnerAccount(ctx context.Context, r domain.Role) (domain.AccountID, error) {
	if r.IsSystem {
		return "", nil
	}
	var account domain.AccountID
	if r.ProjectID != "" {
		err := w.tx.QueryRow(ctx, `SELECT account_id FROM kaname.projects WHERE id=$1 FOR SHARE`, r.ProjectID).Scan(&account)
		return account, err
	}
	err := w.tx.QueryRow(ctx, `SELECT id FROM kaname.accounts WHERE id=$1 FOR SHARE`, r.AccountID).Scan(&account)
	return account, err
}
func (w *roleWriter) LockGrantReference(ctx context.Context, id domain.RoleID) (rolerepo.GrantReference, error) {
	var out rolerepo.GrantReference
	// Замок до чтения правил и lifecycle: снятие/перенос не проходит между ними.
	if err := w.tx.QueryRow(ctx, `SELECT live FROM kaname.roles WHERE id=$1 FOR SHARE`, id).Scan(&out.Live); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return out, iamerr.Wrapf(iamerr.ErrNotFound, "Role reference not found")
		}
		return out, err
	}
	r, err := w.Get(ctx, id)
	if err != nil {
		return out, err
	}
	out.Role = r
	out.AccountID, err = w.LockGrantOwnerAccount(ctx, r)
	return out, err
}

var _ rolerepo.GrantReferenceReader = (*roleWriter)(nil)

// kaname#1034: кэш Facts не заменяет удержание live authoring axis в этой TX.
func (w *roleWriter) LockGrantAuthoringAxes(ctx context.Context, caps []domain.GrantCapabilityRule) error {
	needed := map[domain.GrantCapabilityKind]bool{}
	for _, c := range caps {
		needed[c.Kind] = true
	}
	for _, axis := range []struct {
		kind           domain.GrantCapabilityKind
		resource, verb string
	}{
		{domain.GrantCapabilityCreateBinding, "accessBinding", "create"},
		{domain.GrantCapabilityBindRole, "role", "bind"},
	} {
		if !needed[axis.kind] {
			continue
		}
		var live bool
		err := w.tx.QueryRow(ctx, `SELECT live FROM kaname.catalog_verb WHERE module='iam' AND resource=$1 AND verb=$2 AND NOT per_object AND container_parent IS NULL AND container_relation IS NULL FOR SHARE`, axis.resource, axis.verb).Scan(&live)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && !live) {
			return iamerr.Wrapf(iamerr.ErrFailedPrecondition, "Grant authoring axis unavailable")
		}
		if err != nil {
			return err
		}
	}
	return nil
}
