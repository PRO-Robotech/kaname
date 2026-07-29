// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package service_account — CQRS port-iface'ы для kacho_iam.service_accounts.
package service_account

import (
	"context"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

type ReaderIface interface {
	Get(ctx context.Context, id domain.ServiceAccountID) (domain.ServiceAccount, error)
	List(ctx context.Context, filter ListFilter) ([]domain.ServiceAccount, string, error)
}

type WriterIface interface {
	Insert(ctx context.Context, sa domain.ServiceAccount) (domain.ServiceAccount, error)
	Update(ctx context.Context, sa domain.ServiceAccount, updateMask []string) (domain.ServiceAccount, error)
	Delete(ctx context.Context, id domain.ServiceAccountID) error

	// SetEnabled writes `service_accounts.enabled` — whether this service
	// account may authenticate at all.
	//
	// Separate from Update on purpose. Update carries a field mask, an EMPTY mask
	// means full replacement by convention, and a proto3 bool cannot say "not
	// sent" — so had `enabled` been made a maskable field, omitting it would have
	// disabled the account. That design was declined rather than repaired; the
	// state deciding whether a machine identity still works must not be reachable
	// by forgetting something.
	//
	// The argument is the STATE, not a transition: setting the state an account
	// is already in succeeds and reports it. A retry of a disable is a disable.
	//
	// Missing row → iamerr.ErrNotFound ("ServiceAccount <id> not found").
	SetEnabled(ctx context.Context, id domain.ServiceAccountID, enabled bool) (domain.ServiceAccount, error)
}

type ListFilter struct {
	PageSize  int32
	PageToken string
	Filter    string
	AccountID domain.AccountID
}
