// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// delegated_grant.go — четвёртый путь права выдавать: делегированный (задача
// PRO-Robotech/kaname#986, Р2 приёмки
// docs/engineering/acceptance/delegated-grants-stay-within-the-delegation.md).
//
// # Почему отдельная функция, а не ветвь requireGrantAuthority
//
// `requireGrantAuthority` и `grantAuthorityBeyondClusterAdmin` зовут десять мест
// в проде: кроме выдачи, отзыва и удаления — чтения, перечни, `ExpandAccess` и
// `ListByRole`. Делегат не держит ни одного отношения модели, и путь, встроенный
// в общую функцию, открыл бы ему каждое из этих мест (условие CE-03 разбора
// классов). Поэтому делегированный путь — ЭТА функция, и зовут её ровно три
// места: `CreateAccessBindingUseCase.Execute`, отзыв и удаление выдачи
// (`removalAuthority`). Спрашивается она только после отказа прежних путей:
// учётка, держащая право выдавать сама, выдаёт прежним путём и ссылки на
// делегирование не ставит (GD-62 b).

import (
	"context"
	stderrors "errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// DelegatedGrantPath — провязка делегированного пути права выдавать: хранилище
// (делегирования, принадлежность субъектов, регистрация объектов) и дверь
// решения (право делегирующего, Д3). Незаданный путь — выключенный путь:
// отказ, а не всеразрешение.
type DelegatedGrantPath struct {
	repo      Repo
	relations clients.RelationStore
}

// NewDelegatedGrantPath — делегированный путь над хранилищем и дверью решения
// службы (те же экземпляры, что у глаголов выдачи).
func NewDelegatedGrantPath(repo Repo, relations clients.RelationStore) *DelegatedGrantPath {
	return &DelegatedGrantPath{repo: repo, relations: relations}
}

// delegatedGrantAuthority — делегированный путь права выдавать.
//
// Для ВЫДАЧИ (`removal = false`) верно должно быть ВСЁ (Р2): у вызывающего —
// действующее делегирование на аккаунт области; область — этот аккаунт или
// проект в нём; роль ∈ ролей; цель — названные объекты, тип каждого ∈ типов, и
// каждый зарегистрирован в проекте этого аккаунта (Д7); тип каждого субъекта ∈
// типов субъекта, субъект принадлежит аккаунту (Д6), системный класс — только
// `anonymous` (Д5), субъект — не делегат и не группа с делегатом в составе
// (Д4); делегирующий держит право
// выдавать на аккаунте сейчас (Д3). Отдаёт id делегирования — ссылку выдачи.
//
// Для ОТЗЫВА и УДАЛЕНИЯ (`removal = true`) — выдача несёт ссылку на действующее
// делегирование, делегат которого — вызывающий. Права делегирующего на отзыве не
// спрашиваются: отзыв сужает доступ (GD-31).
//
// Иначе — `PERMISSION_DENIED` `permission denied`, побайтово тот же отказ, что у
// вызывающего без права. Неполадка хранилища или двери — её код, а не отказ.
//
// Читающая транзакция закрывается ДО вопроса о праве делегирующего: вопрос
// берёт соединения того же пула (читатель хранилища и хранилище отношений), и
// путь, держащий одно соединение в ожидании другого, при числе одновременных
// выдач не меньше свободных соединений останавливает пул целиком (находка
// ревью SD-986-C1).
func delegatedGrantAuthority(ctx context.Context, p *DelegatedGrantPath, b domain.AccessBinding, removal bool) (domain.GrantDelegationID, error) {
	if p == nil || p.repo == nil {
		return "", authzguard.PermissionDenied()
	}
	caller := operations.PrincipalFromContext(ctx)
	if t, ok := domain.SubjectTypeOfPrincipal(caller.Type); !ok || t != domain.SubjectTypeServiceAccount || caller.ID == "" {
		return "", authzguard.PermissionDenied()
	}
	d, err := readDelegatedGrant(ctx, p.repo, b, caller, removal)
	if err != nil || removal {
		return d.ID, err
	}
	if err := delegatorStillHoldsAuthority(ctx, p, d); err != nil {
		return "", err
	}
	return d.ID, nil
}

// readDelegatedGrant — всё, что делегированный путь читает из хранилища, одной
// читающей транзакцией, закрытой к возврату. Для выдачи — делегирование
// вызывающего, прошедшее оси, цель и субъектов; для отзыва и удаления —
// делегирование, на которое ссылается выдача.
func readDelegatedGrant(ctx context.Context, repo Repo, b domain.AccessBinding, caller operations.Principal, removal bool) (domain.GrantDelegation, error) {
	rd, err := repo.Reader(ctx)
	if err != nil {
		return domain.GrantDelegation{}, shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()

	if removal {
		return removalByDelegate(ctx, rd, b, caller)
	}

	account, err := delegationAccountOfScope(ctx, rd, b)
	if err != nil {
		return domain.GrantDelegation{}, err
	}
	d, err := rd.AccessBindings().GrantDelegations().ActiveFor(ctx, account, domain.ServiceAccountID(caller.ID))
	if err != nil {
		return domain.GrantDelegation{}, denyOnNotFound(err)
	}
	if !d.AllowsRole(b.RoleID) || b.GrantedRelation != "" {
		return domain.GrantDelegation{}, authzguard.PermissionDenied()
	}
	if err := delegatedTargetWithin(ctx, rd, d, b.Target); err != nil {
		return domain.GrantDelegation{}, err
	}
	for _, s := range b.Subjects {
		if err := delegatedSubjectWithin(ctx, rd, d, s); err != nil {
			return domain.GrantDelegation{}, err
		}
	}
	return d, nil
}

// removalByDelegate — отзыв и удаление выдачи делегатом: только выдача,
// несущая ссылку на действующее делегирование, делегат которого — вызывающий
// (пара «вид, идентификатор», условие CE-22).
func removalByDelegate(ctx context.Context, rd Reader, b domain.AccessBinding, caller operations.Principal) (domain.GrantDelegation, error) {
	if b.DelegationID == "" {
		return domain.GrantDelegation{}, authzguard.PermissionDenied()
	}
	d, err := rd.AccessBindings().GrantDelegations().Get(ctx, b.DelegationID)
	if err != nil {
		return domain.GrantDelegation{}, denyOnNotFound(err)
	}
	if !d.Active() || !d.IsDelegate(caller.Type, caller.ID) {
		return domain.GrantDelegation{}, authzguard.PermissionDenied()
	}
	return d, nil
}

// delegationAccountOfScope — аккаунт области выдачи: сам аккаунт либо аккаунт
// проекта. Область кластера и прочие делегированным путём не выдаются.
func delegationAccountOfScope(ctx context.Context, rd Reader, b domain.AccessBinding) (domain.AccountID, error) {
	switch b.ResourceType {
	case "account":
		return domain.AccountID(b.ResourceID), nil
	case "project":
		proj, err := rd.Projects().Get(ctx, domain.ProjectID(b.ResourceID))
		if err != nil {
			return "", denyOnNotFound(err)
		}
		return proj.AccountID, nil
	default:
		return "", authzguard.PermissionDenied()
	}
}

// delegatedTargetWithin — цель выдачи делегатом: только названные объекты (не
// вся область), тип каждого — в типах делегирования, каждый зарегистрирован и
// его проект лежит в аккаунте делегирования (Д7). Проверяется КАЖДЫЙ объект.
func delegatedTargetWithin(ctx context.Context, rd Reader, d domain.GrantDelegation, t domain.AccessTarget) error {
	if t.AllInScope || len(t.Resources) == 0 {
		return authzguard.PermissionDenied()
	}
	for _, ref := range t.Resources {
		if !d.AllowsTargetType(ref.Type) {
			return authzguard.PermissionDenied()
		}
		registered, account, err := rd.AccessBindings().GrantDelegations().TargetObjectAccount(ctx, ref)
		if err != nil {
			return shared.MapRepoErr(err)
		}
		if !registered || account != d.AccountID {
			return authzguard.PermissionDenied()
		}
	}
	return nil
}

// delegatedSubjectWithin — субъект выдачи делегатом (Д4–Д6). Выбор по типу
// исчерпывающий, ветвь по умолчанию — отказ. Отсутствие строки — отказ, сбой
// чтения — его код (условие CE-07). Состояние членства сравнивается
// положительно: участник — только `ACTIVE`.
//
// Д4 судится на момент выдачи. Включение делегата в группу ПОСЛЕ выдачи — шаг
// держателя права на группу (`v_update`, `GroupService.AddMember`): он отдаёт
// учётке всё, что выдано группе, как при любом включении; сам делегат себя в
// группу не включает (GD-25 e).
func delegatedSubjectWithin(ctx context.Context, rd Reader, d domain.GrantDelegation, s domain.Subject) error {
	if !d.AllowsSubjectType(s.Type) || d.IsDelegateSubject(s) {
		return authzguard.PermissionDenied()
	}
	switch s.Type {
	case domain.SubjectTypeServiceAccount:
		sa, err := rd.ServiceAccounts().Get(ctx, domain.ServiceAccountID(s.ID))
		if err != nil {
			return denyOnNotFound(err)
		}
		if sa.AccountID != d.AccountID {
			return authzguard.PermissionDenied()
		}
		return nil
	case domain.SubjectTypeGroup:
		g, err := rd.Groups().Get(ctx, domain.GroupID(s.ID))
		if err != nil {
			return denyOnNotFound(err)
		}
		if g.AccountID != d.AccountID {
			return authzguard.PermissionDenied()
		}
		// Д4 по §1 приёмки (делегирование не даёт делегату доступа к данным):
		// право роли, выданное группе, достаётся каждому её члену, поэтому
		// группа, в составе которой делегат, — тот же делегат (находка ревью
		// SEC-986-1). Состав читается одним уровнем: член группы — только
		// человек или учётка (`group_members_type_check`), вложенных групп нет.
		member, err := rd.Groups().IsMember(ctx, g.ID, domain.SubjectTypeServiceAccount, domain.SubjectID(d.DelegateID))
		if err != nil {
			return shared.MapRepoErr(err)
		}
		if member {
			return authzguard.PermissionDenied()
		}
		return nil
	case domain.SubjectTypeUser:
		m, err := rd.Users().Membership(ctx, domain.UserID(s.ID), d.AccountID)
		if err != nil {
			return denyOnNotFound(err)
		}
		if m.State != domain.MembershipStateActive {
			return authzguard.PermissionDenied()
		}
		return nil
	case domain.SubjectTypeSystemClass:
		// Д5: «любой вошедший» шире аккаунта — только `anonymous`.
		if s.ID != domain.ClassAnonymous {
			return authzguard.PermissionDenied()
		}
		return nil
	default:
		return authzguard.PermissionDenied()
	}
}

// delegatorStillHoldsAuthority — Д3: делегирующий держит право выдавать на
// аккаунте В МОМЕНТ выдачи. Вопрос задаётся о субъекте `delegatedBy` теми же
// тремя прежними путями; личность вопроса подменяется в КОНТЕКСТЕ, который не
// покидает эту функцию — ни в аудит, ни в `granted_by_user_id`, ни в
// структурные ворота он не уходит (условие CE-06). Неполадка двери — её код.
func delegatorStillHoldsAuthority(ctx context.Context, p *DelegatedGrantPath, d domain.GrantDelegation) error {
	asDelegator := operations.WithPrincipal(ctx, operations.Principal{Type: d.DelegatedBy.Type, ID: d.DelegatedBy.ID})
	err := requireGrantAuthority(asDelegator, p.repo, p.relations, "account", string(d.AccountID))
	if err == nil {
		return nil
	}
	if code := status.Code(err); code == codes.PermissionDenied || code == codes.NotFound {
		return authzguard.PermissionDenied()
	}
	return err
}

// denyOnNotFound — отсутствие строки на делегированном пути — отказ в праве
// (скрытие существования); прочие ошибки хранилища — отображённым кодом.
func denyOnNotFound(err error) error {
	if stderrors.Is(err, iamerr.ErrNotFound) {
		return authzguard.PermissionDenied()
	}
	return shared.MapRepoErr(err)
}

// isPermissionDenied — исход прежних путей, после которого спрашивается
// делегированный: ТОЛЬКО отказ в праве. Неполадка двери и прочие ошибки
// возвращаются как есть и к делегированному пути не ведут (условие CE-04).
func isPermissionDenied(err error) bool {
	return status.Code(err) == codes.PermissionDenied
}
