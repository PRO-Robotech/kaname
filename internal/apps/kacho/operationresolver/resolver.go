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
	"github.com/PRO-Robotech/kacho/services/iam/internal/catalog"
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
	// cat — ЖИВЫЕ строки каталога: набор глаголов типа для превью роли (#1994).
	//
	// Нужен здесь по той же причине, что и на пути чтения: осиротевшая операция
	// над ролью доводится до терминального исхода ЭТИМ кодом, и её ответ несёт то
	// же превью, что вернул бы `Get`. Собрать его другим источником значило бы
	// отдать арендатору два разных ответа об одной роли.
	cat catalog.Source
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
//
// Каталожный факт приходит ОБЯЗАТЕЛЬНЫМ параметром: роль без набора глаголов
// проекция отвергает, и опция позволила бы забыть провязку — исход был бы виден
// только тогда, когда осиротевшая операция над ролью впервые дойдёт до резолва.
func New(repo kachorepo.Repository, cat catalog.Source, opts ...Option) *Resolver {
	r := &Resolver{repo: repo, cat: cat, log: slog.Default()}
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
	case *iamv1.BlockUserMetadata:
		// Block/Unblock RETAIN the membership row and change its state, so both
		// resolve like an Update (resource present afterwards → response = the
		// user), never like a Delete. Without these two cases an ORPHANED block —
		// the worker died between minting the Operation and committing — falls to
		// the default arm, is skipped forever, and the Operation stays `done=false`
		// while being re-claimed on every sweep. The administrator who suspended
		// someone during an incident would be left polling an answer that never
		// comes.
		return resolveExistence(ctx, kindUpdate, m.GetUserId(), rd.Users().Get, marshalUser)
	case *iamv1.UnblockUserMetadata:
		return resolveExistence(ctx, kindUpdate, m.GetUserId(), rd.Users().Get, marshalUser)

	case *iamv1.CreateServiceAccountMetadata:
		return resolveExistence(ctx, kindCreate, m.GetServiceAccountId(), rd.ServiceAccounts().Get, marshalServiceAccount)
	case *iamv1.UpdateServiceAccountMetadata:
		return resolveExistence(ctx, kindUpdate, m.GetServiceAccountId(), rd.ServiceAccounts().Get, marshalServiceAccount)
	case *iamv1.DeleteServiceAccountMetadata:
		return resolveExistence(ctx, kindDelete, m.GetServiceAccountId(), rd.ServiceAccounts().Get, marshalServiceAccount)
	case *iamv1.DisableServiceAccountMetadata:
		// Disable/Enable RETAIN the row and change its state, so both resolve like
		// an Update (resource present afterwards → response = the service account),
		// never like a Delete. Without these two cases an ORPHANED disable — the
		// worker died between minting the Operation and committing — falls to the
		// default arm, is skipped forever, and the Operation stays `done=false`
		// while being re-claimed on every sweep. The operator who pulled a machine
		// identity during an incident would be left polling an answer that never
		// comes.
		return resolveExistence(ctx, kindUpdate, m.GetServiceAccountId(), rd.ServiceAccounts().Get, marshalServiceAccount)
	case *iamv1.EnableServiceAccountMetadata:
		return resolveExistence(ctx, kindUpdate, m.GetServiceAccountId(), rd.ServiceAccounts().Get, marshalServiceAccount)

	case *iamv1.CreateGroupMetadata:
		return resolveExistence(ctx, kindCreate, m.GetGroupId(), rd.Groups().Get, marshalGroup)
	case *iamv1.UpdateGroupMetadata:
		return resolveExistence(ctx, kindUpdate, m.GetGroupId(), rd.Groups().Get, marshalGroup)
	case *iamv1.DeleteGroupMetadata:
		return resolveExistence(ctx, kindDelete, m.GetGroupId(), rd.Groups().Get, marshalGroup)

	case *iamv1.CreateRoleMetadata:
		return resolveExistence(ctx, kindCreate, m.GetRoleId(), rd.Roles().Get, r.marshalRole)
	case *iamv1.UpdateRoleMetadata:
		return resolveExistence(ctx, kindUpdate, m.GetRoleId(), rd.Roles().Get, r.marshalRole)
	case *iamv1.DeleteRoleMetadata:
		return resolveExistence(ctx, kindDelete, m.GetRoleId(), rd.Roles().Get, r.marshalRole)

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

	case *iamv1.RemoveUserFromAccountMetadata:
		// Исключение человека из аккаунта (#1127). Разрешается по ОТСУТСТВИЮ
		// членства — той самой строки, которую операция и снимает.
		//
		// Общий `resolveExistence` здесь не годится, и это не оформительская
		// разница: он ищет ресурс по ОДНОМУ идентификатору, а членство есть ПАРА
		// (человек, аккаунт). Спросить по строке личности значило бы ответить про
		// другой аккаунт: `users.account_id` называет один аккаунт человека из
		// многих. Поэтому вопрос задаётся паре, и отвечает на него
		// `MembershipExists`.
		//
		// Семантика та же, что у `kindDelete`: членства нет — операция состоялась
		// (`Empty`); членство есть — не состоялась, и строка объявляется
		// прерванной, а не пропускается: иначе вызывающий поллил бы ответ, которого
		// не будет.
		exists, mErr := rd.Users().MembershipExists(ctx,
			domain.UserID(m.GetUserId()), domain.AccountID(m.GetAccountId()))
		if mErr != nil {
			return operations.ResolverResult{}, fmt.Errorf(
				"operationresolver: membership %q in %q: %w", m.GetUserId(), m.GetAccountId(), mErr)
		}
		if exists {
			return interrupted(), nil
		}
		return done(nil), nil

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

// marshalRole — проекция роли для терминального ответа операции.
//
// Метод, а не свободная функция: набор глаголов типа берётся у ЖИВОГО каталога
// резолвера, а не у словаря, порождённого сборкой (#1994).
func (r *Resolver) marshalRole(role domain.Role) (*anypb.Any, error) {
	if r.cat == nil {
		return nil, fmt.Errorf("operationresolver: каталожный факт не провязан — " +
			"превью роли собрать нечем (kacho#1994)")
	}
	role.TypeVerbs = r.cat.Facts().RolePreviewLookup()
	var dst *iamv1.Role
	if err := dto.Transfer(dto.FromTo(role, &dst)); err != nil {
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
