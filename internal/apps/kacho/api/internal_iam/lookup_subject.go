// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package internal_iam — LookupSubjectUseCase
// (зовётся auth-интерсептором api-gateway gRPC-direct; см. handler.go про то,
// почему это loop-prevention, а не отсутствие REST-маршрута).
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

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
	kachorepo "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho"
)

// Repo — узкий port-iface, чтобы не тащить весь Repository в этот use-case.
type Repo = kachorepo.Repository

// LookupSubjectUseCase резолвит внешний OIDC subject (`sub` claim, Ory) в локальный
// kacho subject (User mirror или ServiceAccount). Internal-only (запрет #6):
// на внешний endpoint не выходит, но REST-маршрут на ВНУТРЕННЕМ mux api-gateway у
// него есть — см. handler.go.
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

// identityStates — состояния, в которых личность вообще может найтись по
// внешнему идентификатору. PENDING-строка external_id не несёт (DB-CHECK
// users_invite_status_consistency), поэтому этими двумя набор исчерпан.
var identityStates = []domain.InviteStatus{domain.InviteStatusActive, domain.InviteStatusBlocked}

func (uc *LookupSubjectUseCase) byExternalID(ctx context.Context, ext string) (*iamv1.LookupSubjectResponse, error) {
	if ext == "" {
		return nil, status.Error(codes.InvalidArgument, "external_id required")
	}
	rd, err := uc.repo.Reader(ctx)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "repo reader")
	}
	defer func() { _ = rd.Rollback(ctx) }()

	// Строки читаются КАК ЕСТЬ и судятся по состоянию — не «дай действующие».
	//
	// Фильтр отвечал пустым множеством на заблокированную личность, а пустое
	// множество на этом пути край читает как «личности не существует» и идёт
	// заводить её заново. То есть отказ выдавал себя за приглашение
	// провизионировать — ровно того, кому запрещено. Отличить «нет такой» от
	// «есть, но нельзя» вызывающий обязан, и обязан получить это от владельца
	// личности, а не выводить сам.
	rows, err := rd.Users().FindByExternalIDInStatuses(ctx, domain.ExternalSubject(ext), identityStates)
	if err != nil {
		return nil, status.Error(codes.Internal, "user lookup")
	}
	// Строки упорядочены по created_at ASC — каноническая личность та же, что
	// резолвят остальные пути (UpsertFromIdentity.resolveUserID).
	for _, u := range rows {
		if u.InviteStatus.MayAuthenticate() {
			return responseUser(u)
		}
	}
	if len(rows) > 0 {
		return nil, status.Errorf(codes.FailedPrecondition, "identity %s is blocked", ext)
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
		// Чтение по идентификатору состояние не фильтрует — значит судить его
		// обязан этот код. Иначе одна и та же личность резолвится по-разному
		// в зависимости от того, каким ключом её спросили.
		if !u.InviteStatus.MayAuthenticate() {
			return nil, status.Errorf(codes.FailedPrecondition, "User %s %s", id, userStateReason(u.InviteStatus))
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
		if !sa.MayAuthenticate() {
			return nil, status.Errorf(codes.FailedPrecondition, "ServiceAccount %s is disabled", id)
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

	// Каноническая строка адреса — старейшая действующая (тот же выбор, что у
	// ветки по внешнему идентификатору и у посева администратора).
	actives, err := rd.Users().FindActiveByEmail(ctx, domain.Email(email))
	if err != nil {
		return nil, status.Error(codes.Internal, "user lookup by email")
	}
	if len(actives) > 0 {
		return responseUser(actives[0])
	}
	// Действующих нет. Это либо «адрес никому не принадлежит», либо «строка
	// есть, но аутентификация ей запрещена» — два разных ответа.
	u, err := rd.Users().GetByEmail(ctx, domain.Email(email))
	if err == nil {
		return nil, status.Errorf(codes.FailedPrecondition, "identity %s %s", email, userStateReason(u.InviteStatus))
	}
	if stderrors.Is(err, iamerr.ErrNotFound) {
		return nil, status.Errorf(codes.NotFound, "subject not found by email=%s", email)
	}
	return nil, status.Error(codes.Internal, "user lookup by email")
}

// userStateReason — причина отказа словами, точная для конкретного состояния.
//
// PENDING — приглашение, которое ещё никто не подтвердил: такая строка не несёт
// внешнего идентификатора, и подтвердит его тот, кто первым войдёт по этому
// адресу почты. Назвать это «заблокирован» значило бы отправить администратора
// снимать запрет, которого нет.
func userStateReason(st domain.InviteStatus) string {
	if st == domain.InviteStatusBlocked {
		return "is blocked"
	}
	return "is not active"
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
