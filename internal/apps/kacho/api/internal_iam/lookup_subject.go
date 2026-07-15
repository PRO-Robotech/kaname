// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package internal_iam — LookupSubjectUseCase
// (gRPC-direct only from api-gateway auth-interceptor).
//
// Oneof key: external_id (OIDC `sub`, Ory) | id (`usr...` / `sva...`) | email.
// Возвращает либо User, либо ServiceAccount (oneof subject).
package internal_iam

import (
	"context"
	stderrors "errors"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	kachorepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho"
)

// Repo — узкий port-iface, чтобы не тащить весь Repository в этот use-case.
type Repo = kachorepo.Repository

// LookupSubjectUseCase резолвит внешний OIDC subject (`sub` claim, Ory) в локальный
// kacho subject (User mirror или ServiceAccount). gRPC-direct only — НЕ
// регистрируется в restmux api-gateway (запрет #6 + loop-prevention).
type LookupSubjectUseCase struct {
	repo Repo
}

func NewLookupSubjectUseCase(r Repo) *LookupSubjectUseCase {
	return &LookupSubjectUseCase{repo: r}
}

// Execute резолвит subject по одному из oneof-ключей.
func (uc *LookupSubjectUseCase) Execute(ctx context.Context, req *iamv1.LookupSubjectRequest) (*iamv1.LookupSubjectResponse, error) {
	switch k := req.GetKey().(type) {
	case *iamv1.LookupSubjectRequest_ExternalId:
		return uc.byExternalID(ctx, k.ExternalId)
	case *iamv1.LookupSubjectRequest_Id:
		return uc.byID(ctx, k.Id)
	case *iamv1.LookupSubjectRequest_Email:
		return uc.byEmail(ctx, k.Email)
	default:
		return nil, status.Error(codes.InvalidArgument, "key oneof required: external_id | id | email")
	}
}

func (uc *LookupSubjectUseCase) byExternalID(ctx context.Context, ext string) (*iamv1.LookupSubjectResponse, error) {
	if ext == "" {
		return nil, status.Error(codes.InvalidArgument, "external_id required")
	}
	rd, err := uc.repo.Reader(ctx)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "repo reader")
	}
	defer func() { _ = rd.Rollback(ctx) }()

	u, err := rd.Users().GetByExternalID(ctx, domain.ExternalSubject(ext))
	if err == nil {
		return responseUser(u)
	}
	if !stderrors.Is(err, iamerr.ErrNotFound) {
		return nil, status.Error(codes.Internal, "user lookup")
	}
	// Future: ServiceAccount external_id (Ory Hydra client identity) — отложен
	// на SA-key-flow follow-up. Текущий behaviour: NOT_FOUND.
	return nil, status.Errorf(codes.NotFound, "subject not found by external_id=%s", ext)
}

func (uc *LookupSubjectUseCase) byID(ctx context.Context, id string) (*iamv1.LookupSubjectResponse, error) {
	if id == "" {
		return nil, status.Error(codes.InvalidArgument, "id required")
	}
	rd, err := uc.repo.Reader(ctx)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "repo reader")
	}
	defer func() { _ = rd.Rollback(ctx) }()

	switch {
	case strings.HasPrefix(id, domain.PrefixUser):
		u, err := rd.Users().Get(ctx, domain.UserID(id))
		if err != nil {
			if stderrors.Is(err, iamerr.ErrNotFound) {
				return nil, status.Errorf(codes.NotFound, "User %s not found", id)
			}
			return nil, status.Error(codes.Internal, "user get")
		}
		return responseUser(u)
	case strings.HasPrefix(id, domain.PrefixServiceAccount):
		sa, err := rd.ServiceAccounts().Get(ctx, domain.ServiceAccountID(id))
		if err != nil {
			if stderrors.Is(err, iamerr.ErrNotFound) {
				return nil, status.Errorf(codes.NotFound, "ServiceAccount %s not found", id)
			}
			return nil, status.Error(codes.Internal, "service account get")
		}
		return responseServiceAccount(sa)
	}
	return nil, status.Errorf(codes.InvalidArgument, "unknown id prefix: %s", id)
}

func (uc *LookupSubjectUseCase) byEmail(ctx context.Context, email string) (*iamv1.LookupSubjectResponse, error) {
	if email == "" {
		return nil, status.Error(codes.InvalidArgument, "email required")
	}
	rd, err := uc.repo.Reader(ctx)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "repo reader")
	}
	defer func() { _ = rd.Rollback(ctx) }()

	u, err := rd.Users().GetByEmail(ctx, domain.Email(email))
	if err == nil {
		return responseUser(u)
	}
	if stderrors.Is(err, iamerr.ErrNotFound) {
		return nil, status.Errorf(codes.NotFound, "subject not found by email=%s", email)
	}
	return nil, status.Error(codes.Internal, "user lookup by email")
}

func responseUser(u domain.User) (*iamv1.LookupSubjectResponse, error) {
	pb := &iamv1.User{
		Id:          string(u.ID),
		ExternalId:  string(u.ExternalID),
		Email:       string(u.Email),
		DisplayName: string(u.DisplayName),
	}
	return &iamv1.LookupSubjectResponse{
		Subject: &iamv1.LookupSubjectResponse_User{User: pb},
	}, nil
}

func responseServiceAccount(sa domain.ServiceAccount) (*iamv1.LookupSubjectResponse, error) {
	pb := &iamv1.ServiceAccount{
		Id:          string(sa.ID),
		AccountId:   string(sa.AccountID),
		Name:        string(sa.Name),
		Description: string(sa.Description),
	}
	return &iamv1.LookupSubjectResponse{
		Subject: &iamv1.LookupSubjectResponse_ServiceAccount{ServiceAccount: pb},
	}, nil
}
