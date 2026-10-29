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
//     нет: выдачу классу `authenticated` на всю область кластера судят те же
//     правила ствола, что выдачу человеку (Д4). Роль с правилом-якорем
//     отвергает правило кластера (SC-28), а системная роль модуля с именами или
//     метками его проходит (близнец SC-81 приёмки, редакция 17) — такой путь
//     закрывают только ворота модуля с ключом S7 (ниже).
//
// # Ворота модуля (S7, kaname#950)
//
// Модуль, объявивший ключ оболочки `classGrantsOnlyOnContainers`, принимает
// выдачу классу, достающую до его типов, только на объявленном контейнере
// публичного чтения (Р11). Они стоят после ворот вида цели, роли и вложенных
// правил и до правила кластера: тот, кто выдавать не вправе, о ключе не узнаёт
// (SC-78 «И»), а роль с правилом-якорем над необъявленным типом получает на
// кластере отказ S7, а не правила кластера (SC-81 «И»).
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
	role, err := u.systemClassRoleGate(ctx, b)
	if err != nil {
		return err
	}
	if err := u.systemClassNestedRuleGate(ctx, b, role); err != nil {
		return err
	}
	if err := u.systemClassModuleGate(ctx, b, role); err != nil {
		return err
	}
	if err := u.systemClassContainerGate(ctx, b, role); err != nil {
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
func (u *CreateAccessBindingUseCase) systemClassRoleGate(ctx context.Context, b domain.AccessBinding) (domain.Role, error) {
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return domain.Role{}, shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()
	role, err := rd.Roles().Get(ctx, b.RoleID)
	if err != nil {
		if stderrors.Is(err, iamerr.ErrNotFound) {
			return domain.Role{}, status.Errorf(codes.FailedPrecondition, "Role %s not found", b.RoleID)
		}
		return domain.Role{}, shared.MapRepoErr(err)
	}
	if !role.GrantsReadsOnly() {
		return domain.Role{}, status.Error(codes.FailedPrecondition, domain.RoleNotReadOnlyForClassText(b.RoleID))
	}
	return role, nil
}

// systemClassModuleGate — модуль решает публичность своих объектов сам (S7,
// kaname#950; Р11 приёмки, редакция 17).
//
// Модуль, объявивший ключ `classGrantsOnlyOnContainers`, принимает выдачу
// классу, достающую до его типов, только на объявленном контейнере публичного
// чтения. Ветвь — по виду цели:
//   - объекты: отвергается цель, хотя бы один объект которой имеет тип модуля с
//     ключом, не объявленный контейнером (SC-78); цель — объявленный
//     контейнер — проходит (исключение Р11 п. 3, SC-79);
//   - вся область: отвергается роль, хотя бы одно правило которой (верхнего
//     уровня либо вложенное, любым селектором, с подстановкой `*`; у роли без
//     правил — её права) покрывает такой тип (SC-81). Живая только у класса
//     `authenticated` на кластере: прочие сочетания отвергли ворота вида цели.
//
// Источник «ключ объявлен» и «тип объявлен» — живой каталог из доставленных
// манифестов, одним чтением на выдачу; модуля с ключом нет — ворота молчат,
// поведение прежнее (Р11 п. 6). Поштучную публикацию владельцем
// (`RegisterResource`) эти ворота не судят: она идёт не глаголом создания
// выдачи (SC-78 «И»).
func (u *CreateAccessBindingUseCase) systemClassModuleGate(ctx context.Context, b domain.AccessBinding, role domain.Role) error {
	wholeScope := b.Target.AllInScope || b.Target.IsEmpty()
	if !wholeScope && len(b.Target.Resources) == 0 {
		return nil
	}
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()
	keyed, err := rd.AccessBindings().ClassGrantsKeyedModules(ctx)
	if err != nil {
		return shared.MapRepoErr(err)
	}
	if len(keyed) == 0 {
		return nil
	}
	var (
		text    string
		refused bool
	)
	if wholeScope {
		text, refused = domain.ClassGrantWholeScopeRefusal(keyed, b.RoleID, role)
	} else {
		text, refused = domain.ClassGrantObjectsRefusal(keyed, b.Target)
	}
	if refused {
		return status.Error(codes.FailedPrecondition, text)
	}
	return nil
}

// systemClassContainerGate — цель выдачи классу ролью, покрывающей тип-ребёнок,
// обязана быть объявленным контейнером публичного чтения (SC-65, kaname#856).
// «Покрывающей» — правилом верхнего уровня над ребёнком либо вложенным правилом
// под правилом над типом цели (`PublicReadContainer.CoveredChild`, kaname#874).
//
// Сфера отказа узкая и названа приёмкой: только выдача классу, только роль,
// чьё правило покрывает тип-ребёнок типа цели, и только цель, тип которой не
// объявлен. Роль, покрывающая лишь тип самой цели (SC-01: `rol-read` на
// `vpc.network`), проходит как сегодня; человеку отказа нет вовсе — эти ворота
// зовутся только у выдачи с классом.
//
// Без ворот такая выдача принималась бы и не давала потомкам НИЧЕГО (кортеж
// `public_reader` пишется только на объявленном контейнере), и выдающий узнал бы
// об этом лишь по отказу чтения. Источник «тип объявлен» — живой каталог из
// доставленных манифестов, а не литерал с именем модуля.
func (u *CreateAccessBindingUseCase) systemClassContainerGate(ctx context.Context, b domain.AccessBinding, role domain.Role) error {
	if len(b.Target.Resources) == 0 || len(role.Rules) == 0 {
		return nil
	}
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()
	judged := map[string]bool{}
	for _, ref := range b.Target.Resources {
		if judged[ref.Type] {
			continue
		}
		judged[ref.Type] = true
		c, err := rd.AccessBindings().PublicReadContainer(ctx, ref.Type)
		if err != nil {
			return shared.MapRepoErr(err)
		}
		if c.Declared {
			continue
		}
		if child, covers := c.CoveredChild(role.Rules); covers {
			return status.Error(codes.FailedPrecondition, domain.UndeclaredContainerText(ref.Type, b.RoleID, child))
		}
	}
	return nil
}

// systemClassNestedRuleGate — роль с вложенными правилами классу выдаётся,
// только если КАЖДОЕ вложенное правило открывает детей так, как их открывает
// `public_reader` (kaname#874, приёмка
// `nested-rule-reaches-descendants-of-a-named-container.md`, Р5, ND-05):
// контейнер объявлен, тип вложенного — его прямой ребёнок, ровно `get` и
// `list`, без сужения. Иначе выдача принималась бы и давала классу меньше (или
// иначе), чем называет роль, и выдающий узнал бы об этом лишь по отказу чтения.
//
// Судятся ВСЕ вложенные правила роли, а не только стоящие под типом цели: роль,
// выданная классу, — обещание о каждом своём правиле. Источник «объявлен» и
// «прямой ребёнок» — живой каталог из доставленных манифестов.
func (u *CreateAccessBindingUseCase) systemClassNestedRuleGate(ctx context.Context, b domain.AccessBinding, role domain.Role) error {
	if !role.Rules.HasChildren() {
		return nil
	}
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()
	containers := map[string]domain.PublicReadContainer{}
	for _, r := range role.Rules {
		owner := r.OwnerType()
		if len(r.Children) == 0 || owner == "" {
			continue
		}
		if _, judged := containers[owner]; judged {
			continue
		}
		c, err := rd.AccessBindings().PublicReadContainer(ctx, owner)
		if err != nil {
			return shared.MapRepoErr(err)
		}
		containers[owner] = c
	}
	if text, refused := domain.ClassNestedRuleRefusal(b.RoleID, role.Rules, containers); refused {
		return status.Error(codes.FailedPrecondition, text)
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
