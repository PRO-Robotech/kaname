// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package project — CQRS port-iface'ы для kacho_iam.projects.
package project

import (
	"context"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

type ReaderIface interface {
	Get(ctx context.Context, id domain.ProjectID) (domain.Project, error)
	List(ctx context.Context, filter ListFilter) ([]domain.Project, string, error)
	// CountByAccount — для AccountService.Delete sync precheck.
	CountByAccount(ctx context.Context, accountID domain.AccountID) (int64, error)
}

type WriterIface interface {
	Insert(ctx context.Context, p domain.Project) (domain.Project, error)
	Update(ctx context.Context, p domain.Project, updateMask []string) (domain.Project, error)
	Delete(ctx context.Context, id domain.ProjectID) error
}

type ListFilter struct {
	PageSize  int32
	PageToken string
	Filter    string
	// AccountID — для List в scope'е Account (`/iam/v1/projects?accountId=...`).
	AccountID domain.AccountID
}
