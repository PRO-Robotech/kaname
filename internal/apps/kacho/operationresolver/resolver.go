// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package operationresolver implements the IAM operations.Resolver: given the
// metadata of an orphaned operation (a row left done=false because the worker
// process died mid-flight), it determines the terminal outcome by reading the
// committed reality of the resource. The reconciler engine lives in corelib; this
// resolver knows the IAM metadata types and resource tables.
package operationresolver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/dto"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	kachorepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho"
)

// kind — семантика операции для разрешения orphan'а по существованию ресурса.
type kind int

const (
	kindCreate kind = iota
	kindUpdate
	kindDelete
)

// Resolver реализует operations.Resolver поверх IAM-репозитория.
type Resolver struct {
	repo kachorepo.Repository
	log  *slog.Logger
}

// Option — функциональная опция Resolver.
type Option func(*Resolver)

// WithLogger подключает структурированный логгер.
func WithLogger(l *slog.Logger) Option {
	return func(r *Resolver) {
		if l != nil {
			r.log = l
		}
	}
}

// New конструирует Resolver.
func New(repo kachorepo.Repository, opts ...Option) *Resolver {
	r := &Resolver{repo: repo, log: slog.Default()}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Resolve определяет терминальный исход осиротевшей операции по типу ее метаданных
// и committed-реальности ресурса. Неизвестный тип метаданных → Skip (строка
// остается done=false, не наша операция в этом прогоне).
func (r *Resolver) Resolve(ctx context.Context, op operations.Operation) (operations.ResolverResult, error) {
	if op.Metadata == nil {
		return skip(), nil
	}
	msg, err := op.Metadata.UnmarshalNew()
	if err != nil {
		r.log.Warn("operation resolver: undecodable metadata, skipping orphan",
			"op", op.ID, "type_url", op.Metadata.TypeUrl, "err", err)
		return skip(), nil
	}

	rd, err := r.repo.Reader(ctx)
	if err != nil {
		return operations.ResolverResult{}, fmt.Errorf("operationresolver: open reader: %w", err)
	}
	defer func() { _ = rd.Rollback(ctx) }()

	switch m := msg.(type) {
	case *iamv1.CreateAccountMetadata:
		return resolveExistence(ctx, kindCreate, m.GetAccountId(), rd.Accounts().Get, marshalAccount)
	case *iamv1.UpdateAccountMetadata:
		return resolveExistence(ctx, kindUpdate, m.GetAccountId(), rd.Accounts().Get, marshalAccount)
	case *iamv1.DeleteAccountMetadata:
		return resolveExistence(ctx, kindDelete, m.GetAccountId(), rd.Accounts().Get, marshalAccount)

	case *iamv1.CreateProjectMetadata:
		return resolveExistence(ctx, kindCreate, m.GetProjectId(), rd.Projects().Get, marshalProject)
	case *iamv1.UpdateProjectMetadata:
		return resolveExistence(ctx, kindUpdate, m.GetProjectId(), rd.Projects().Get, marshalProject)
	case *iamv1.DeleteProjectMetadata:
		return resolveExistence(ctx, kindDelete, m.GetProjectId(), rd.Projects().Get, marshalProject)

	case *iamv1.UpdateUserMetadata:
		return resolveExistence(ctx, kindUpdate, m.GetUserId(), rd.Users().Get, marshalUser)

	case *iamv1.CreateServiceAccountMetadata:
		return resolveExistence(ctx, kindCreate, m.GetServiceAccountId(), rd.ServiceAccounts().Get, marshalServiceAccount)
	case *iamv1.UpdateServiceAccountMetadata:
		return resolveExistence(ctx, kindUpdate, m.GetServiceAccountId(), rd.ServiceAccounts().Get, marshalServiceAccount)
	case *iamv1.DeleteServiceAccountMetadata:
		return resolveExistence(ctx, kindDelete, m.GetServiceAccountId(), rd.ServiceAccounts().Get, marshalServiceAccount)

	case *iamv1.CreateGroupMetadata:
		return resolveExistence(ctx, kindCreate, m.GetGroupId(), rd.Groups().Get, marshalGroup)
	case *iamv1.UpdateGroupMetadata:
		return resolveExistence(ctx, kindUpdate, m.GetGroupId(), rd.Groups().Get, marshalGroup)
	case *iamv1.DeleteGroupMetadata:
		return resolveExistence(ctx, kindDelete, m.GetGroupId(), rd.Groups().Get, marshalGroup)

	case *iamv1.CreateRoleMetadata:
		return resolveExistence(ctx, kindCreate, m.GetRoleId(), rd.Roles().Get, marshalRole)
	case *iamv1.UpdateRoleMetadata:
		return resolveExistence(ctx, kindUpdate, m.GetRoleId(), rd.Roles().Get, marshalRole)
	case *iamv1.DeleteRoleMetadata:
		return resolveExistence(ctx, kindDelete, m.GetRoleId(), rd.Roles().Get, marshalRole)

	case *iamv1.CreateAccessBindingMetadata:
		return resolveExistence(ctx, kindCreate, m.GetAccessBindingId(), rd.AccessBindings().Get, marshalAccessBinding)
	case *iamv1.UpdateAccessBindingMetadata:
		return resolveExistence(ctx, kindUpdate, m.GetAccessBindingId(), rd.AccessBindings().Get, marshalAccessBinding)
	case *iamv1.DeleteAccessBindingMetadata:
		return resolveExistence(ctx, kindDelete, m.GetAccessBindingId(), rd.AccessBindings().Get, marshalAccessBinding)
	case *iamv1.RevokeAccessBindingMetadata:
		// Soft-revoke RETAINS the row (status→REVOKED), so it resolves like an
		// Update (resource present after the op → response = the REVOKED binding),
		// NOT like Delete (which resolves to absence).
		return resolveExistence(ctx, kindUpdate, m.GetAccessBindingId(), rd.AccessBindings().Get, marshalAccessBinding)

	default:
		// Condition / прочие типы метаданных — не разрешаются этим resolver'ом.
		return skip(), nil
	}
}

// resolveExistence — общая логика «существование ресурса → терминальный исход».
// get читает ресурс (iamerr.ErrNotFound → отсутствует); toAny упаковывает текущий
// ресурс в Operation.response для Done на Create/Update. ID ~string покрывает
// доменные newtypes (AccountID/RoleID/...): идентификатор из метаданных приходит
// строкой и конвертируется в типизированный id.
func resolveExistence[ID ~string, T any](
	ctx context.Context,
	k kind,
	idStr string,
	get func(context.Context, ID) (T, error),
	toAny func(T) (*anypb.Any, error),
) (operations.ResolverResult, error) {
	rec, err := get(ctx, ID(idStr))
	present := false
	switch {
	case err == nil:
		present = true
	case errors.Is(err, iamerr.ErrNotFound):
		present = false
	default:
		// transient read-ошибка → движок инкрементит reconcile_errors, пропускает.
		return operations.ResolverResult{}, fmt.Errorf("operationresolver: get %q: %w", idStr, err)
	}

	if k == kindDelete {
		if present {
			return interrupted(), nil
		}
		return done(nil), nil // Empty-семантика: ресурс удален, как и просили
	}
	// Create / Update: ресурс должен присутствовать.
	if !present {
		return interrupted(), nil
	}
	resp, err := toAny(rec)
	if err != nil {
		return operations.ResolverResult{}, fmt.Errorf("operationresolver: marshal %q: %w", idStr, err)
	}
	return done(resp), nil
}

func skip() operations.ResolverResult {
	return operations.ResolverResult{Outcome: operations.OutcomeSkip}
}

func done(resp *anypb.Any) operations.ResolverResult {
	return operations.ResolverResult{Outcome: operations.OutcomeDone, Response: resp}
}

func interrupted() operations.ResolverResult {
	return operations.ResolverResult{Outcome: operations.OutcomeInterrupted}
}

// ---- domain → Any маршалеры (через DTO-реестр) ----

func marshalAccount(a domain.Account) (*anypb.Any, error) {
	var dst *iamv1.Account
	if err := dto.Transfer(dto.FromTo(a, &dst)); err != nil {
		return nil, err
	}
	return anypb.New(dst)
}

func marshalProject(p domain.Project) (*anypb.Any, error) {
	var dst *iamv1.Project
	if err := dto.Transfer(dto.FromTo(p, &dst)); err != nil {
		return nil, err
	}
	return anypb.New(dst)
}

func marshalUser(u domain.User) (*anypb.Any, error) {
	var dst *iamv1.User
	if err := dto.Transfer(dto.FromTo(u, &dst)); err != nil {
		return nil, err
	}
	return anypb.New(dst)
}

func marshalServiceAccount(s domain.ServiceAccount) (*anypb.Any, error) {
	var dst *iamv1.ServiceAccount
	if err := dto.Transfer(dto.FromTo(s, &dst)); err != nil {
		return nil, err
	}
	return anypb.New(dst)
}

func marshalGroup(g domain.Group) (*anypb.Any, error) {
	var dst *iamv1.Group
	if err := dto.Transfer(dto.FromTo(g, &dst)); err != nil {
		return nil, err
	}
	return anypb.New(dst)
}

func marshalRole(r domain.Role) (*anypb.Any, error) {
	var dst *iamv1.Role
	if err := dto.Transfer(dto.FromTo(r, &dst)); err != nil {
		return nil, err
	}
	return anypb.New(dst)
}

func marshalAccessBinding(ab domain.AccessBinding) (*anypb.Any, error) {
	var dst *iamv1.AccessBinding
	if err := dto.Transfer(dto.FromTo(ab, &dst)); err != nil {
		return nil, err
	}
	return anypb.New(dst)
}
