// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// system_class_gates.go — ворота выдачи системному классу (приёмка
// anonymous-and-authenticated-are-subject-classes.md, Р4 и Р5; kaname#829).
//
// # Место в порядке Create — несущее
//
// Ворота стоят ПОСЛЕ права выдавать (`requireGrantAuthority`) и после
// структурных ворот (назначаемость роли, покрытие типа), но ДО правила
// кластера (`validateGlobalAllSelector`) и до заведения операции:
//
//   - после права — потому что отказ ворот называет роль и вид цели; тот, кто
//     выдавать не вправе, обязан получить прежний отказ в праве и ничего не
//     узнать о роли (SC-20, SC-28; разбор CE-19 (а));
//   - после структурных и до правила кластера — ворота класса СУЖАЮТ, а не
//     расширяют: ни одна их ветвь не пропускает выдачу мимо назначаемости роли
//     и правила кластера (CE-19 (б)). Классовой ветви «на кластере — разрешить»
//     нет: единственная классовая выдача на кластере — системная, её заводит
//     миграция, а не этот глагол (CE-19 (в)).
//
// Каждый отказ синхронен: операции, которая отвергнется, не заводится.

import (
	"context"
	stderrors "errors"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_keys"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/refusaldomain"
)

// ClassGrantFreshness — окно свежести человеческой сессии выдающего классу
// (Р5, SC-25): не старше 15 минут от последнего предъявления. Величина —
// часть контракта глагола (её называет приёмка и держат сценарии 14 и 16
// минут), а не ручка развёртывания.
const ClassGrantFreshness = 15 * time.Minute

// Тексты отказа вида цели (SC-24, SC-19) — контракт тона, дословно приёмочные.
const (
	textAnonymousAllInScope     = "Illegal argument target: a grant to system class anonymous names its objects (allInScope is not accepted)"
	textAuthenticatedAllInScope = "Illegal argument target: a grant to system class authenticated outside the cluster names its objects (allInScope is not accepted)"
)

// validateSystemClassGates — ворота выдачи, среди субъектов которой есть
// системный класс. У выдачи без класса не делают ничего.
func (u *CreateAccessBindingUseCase) validateSystemClassGates(ctx context.Context, b domain.AccessBinding) error {
	if !domain.HasSystemClass(b.Subjects) {
		return nil
	}
	if err := systemClassTargetGate(b); err != nil {
		return err
	}
	if err := u.systemClassRoleGate(ctx, b); err != nil {
		return err
	}
	return u.systemClassFreshnessGate(ctx)
}

// systemClassTargetGate — вид цели (Р5).
//
// Будущие объекты области не становятся читаемыми классу сами: `allInScope`
// у `anonymous` отвергается на любом уровне (SC-24), у `authenticated` — вне
// кластера (SC-19). Пустая цель хранится как вся область и судится так же.
func systemClassTargetGate(b domain.AccessBinding) error {
	wholeScope := b.Target.AllInScope || b.Target.IsEmpty()
	if !wholeScope {
		return nil
	}
	for _, s := range b.Subjects {
		if !s.IsSystemClass() {
			continue
		}
		switch s.ID {
		case domain.ClassAnonymous:
			return shared.InvalidArg("target", textAnonymousAllInScope)
		case domain.ClassAuthenticated:
			if b.ResourceType != "cluster" {
				return shared.InvalidArg("target", textAuthenticatedAllInScope)
			}
		}
	}
	return nil
}

// systemClassRoleGate — роль только читает (Р4, SC-21).
//
// Синхронный ответ; последнее слово — у записи: страж базы
// (`kaname.access_binding_subject_class_reads_only`) судит правила роли под
// замком её строки, так что правка роли, прошедшая между этим чтением и
// вставкой выдачи, мимо не проходит (разбор CE-17).
func (u *CreateAccessBindingUseCase) systemClassRoleGate(ctx context.Context, b domain.AccessBinding) error {
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()
	role, err := rd.Roles().Get(ctx, b.RoleID)
	if err != nil {
		if stderrors.Is(err, iamerr.ErrNotFound) {
			return status.Errorf(codes.FailedPrecondition, "Role %s not found", b.RoleID)
		}
		return shared.MapRepoErr(err)
	}
	if !role.GrantsReadsOnly() {
		return status.Error(codes.FailedPrecondition, domain.RoleNotReadOnlyForClassText(b.RoleID))
	}
	return nil
}

// systemClassFreshnessGate — окно свежести человеческой сессии выдающего
// (Р5, SC-25).
//
// Окно — у человека: у сервисной учётки сессии нет, и окна у неё нет тоже
// (SC-27). Живой сессии нет вовсе — отказ, а не пропуск: человеческий запрос
// без живой сессии не доказывает свежести ничем.
func (u *CreateAccessBindingUseCase) systemClassFreshnessGate(ctx context.Context) error {
	p := operations.PrincipalFromContext(ctx)
	if p.Type != string(domain.SubjectTypeUser) {
		return nil
	}
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()
	at, found, err := rd.AccessBindings().GrantorLastPresentedAt(ctx, domain.UserID(p.ID))
	if err != nil {
		return shared.MapRepoErr(err)
	}
	if !found || time.Since(at) > ClassGrantFreshness {
		return sessionNotFresh()
	}
	return nil
}

// sessionNotFresh — отказ окна свежести той же формы, что у заведения ключа
// доступа (SC-25): PERMISSION_DENIED, признак SESSION_NOT_FRESH и следующий
// шаг в тексте.
func sessionNotFresh() error {
	st := status.New(codes.PermissionDenied, access_keys.TextSessionNotFresh)
	info := &errdetails.ErrorInfo{
		Reason: access_keys.ReasonSessionNotFresh,
		Domain: refusaldomain.For(refusaldomain.ServiceIAM),
	}
	if with, err := st.WithDetails(info); err == nil {
		return with.Err()
	}
	return st.Err()
}
