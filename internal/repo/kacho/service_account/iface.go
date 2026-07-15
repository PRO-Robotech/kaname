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
}

type ListFilter struct {
	PageSize  int32
	PageToken string
	Filter    string
	AccountID domain.AccountID
}
