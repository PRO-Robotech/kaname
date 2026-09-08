// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// subject_read_authority.go — ОДИН предикат допуска к выдачам названного
// субъекта, общий для обоих чтений, и общая форма сужения их страницы.
//
// # Почему предикат один, а не два согласованных (#1352)
//
// `ListBySubject` и `ListSubjectPrivileges` отвечают на ОДИН вопрос — «какие
// выдачи есть у этого субъекта», — и оба принимают `subject_type` +
// `subject_id` без обязательного аккаунта. Допуск у них разошёлся: первый
// требовал БЫТЬ субъектом, второй допускал ещё и распорядителя домашнего
// аккаунта. Обе полосы были защитимы по отдельности; неверна была их РАЗНИЦА —
// делегированный распорядитель читал выдачи сотрудника своего аккаунта одним
// глаголом и не читал вторым, то есть ответ зависел от выбора глагола, а не от
// прав (`architecture.md` §«Параллельные полосы одного механизма обязаны
// сверяться МЕЖДУ СОБОЙ»).
//
// Выровнять два условия вручную значило бы оставить ДВА написания одной
// политики: они снова разошлись бы молча, и заметить это можно было бы только
// сравнив файлы. Поэтому здесь стоит одно написание, а оба чтения его ЗОВУТ.
//
// # Полосы допуска и что каждая видит (решение владельца по #1352/#1354)
//
//	сам субъект (для субъекта-группы — её участник) → все свои выдачи, БЕЗ сужения
//	владелец аккаунта · делегированный распорядитель → выдачи субъекта ТОЛЬКО в
//	                                                   границах ЭТОГО аккаунта
//	администратор облака                            → всё, БЕЗ сужения
//
// Границы аккаунта держит не условие в Go, а МОДЕЛЬ: страница проходит
// пообъектный вопрос `authzfilter`, привязанный к отношению, которым каталог
// прав гейтит одиночное чтение выдачи. `v_get` на выдаче выводится через
// `super_admin from account`, поэтому распорядитель аккаунта A держит его на
// КАЖДОЙ выдаче, чей родитель — A, без единого прямого кортежа, а на выдаче в
// аккаунте B не держит ниоткуда. То есть сужение снимает ровно чужое, а политика
// остаётся выражена отношением, а не самодельной проверкой (`security.md`
// §«Авторизация живёт в МОДЕЛИ»).
//
// # Почему допуска НЕДОСТАТОЧНО и нужна вторая половина (#1354)
//
// Допуск отвечает на вопрос «вправе ли вызывающий читать про ЭТОГО субъекта» и
// решается по ДОМАШНЕМУ аккаунту субъекта. Но строки ответа называют ОБЛАСТЬ
// каждой выдачи, а области у одного человека бывают в разных аккаунтах: пройдя
// допуск по аккаунту A, распорядитель A получал строки про аккаунты B и C — то
// есть узнавал о существовании арендаторов, к которым отношения не имеет. Это
// тот же класс, что закрыт решением по #1085 (перечень аккаунтов человека,
// отданный распорядителю одного из них), только в другой форме: не членства, а
// области выдач.
//
// # Существование субъекта ПРИДЕРЖИВАЕТСЯ
//
// Идентификатор субъекта называет вызывающий, и всякий идентификатор кластера —
// законная проба. Поэтому ответ «такого субъекта нет» отделяется от ответа «есть,
// но не ваш» ТОЛЬКО для того, кто вправе читать субъекта; предикат возвращает
// исход резолва отдельно от полосы, а решает, показывать ли его, каждое чтение
// само: одно отвечает `NOT_FOUND`, второе — пустой страницей, и оба обязаны
// делать это ПОСЛЕ допуска.

import (
	"context"
	"errors"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// subjectReadLane — полоса, которой вызывающий допущен к чтению выдач субъекта.
//
// Полоса — не украшение отчёта: от неё зависит, сужается ли страница. Вернуть
// один лишь булев допуск значило бы потерять ровно то различие, ради которого
// заведено сужение.
type subjectReadLane uint8

const (
	// subjectReadDenied — вызывающий не допущен ни одной полосой.
	subjectReadDenied subjectReadLane = iota
	// subjectReadSelf — вызывающий и ЕСТЬ субъект (для субъекта-группы — состоит
	// в ней). Ответ не шире того, что ему и так принадлежит.
	subjectReadSelf
	// subjectReadClusterAdmin — верхний ярус супер-доступа (`security.md` §Три
	// уровня супер-доступа): каскадом на всё, в паритете с соседними чтениями.
	subjectReadClusterAdmin
	// subjectReadAccountAdmin — владелец либо делегированный распорядитель
	// ДОМАШНЕГО аккаунта субъекта. Единственная полоса, чья страница сужается.
	subjectReadAccountAdmin
)

// narrowsPage — сужается ли страница этой полосы построчно.
//
// Две полосы проходят несужёнными, и обе названы, а не подразумеваются:
//
//   - собственное чтение — сузить его значило бы опустошить главное употребление
//     обоих глаголов, и опустошить ТИХО, отдав `200` с пустым перечнем: выдачей
//     распоряжается администратор области, а не тот, кому она выдана, поэтому
//     прямого кортежа у субъекта на свою же выдачу обычно нет;
//   - надзор облака — верхний ярус супер-доступа, паритет с Get / ListByScope /
//     ListByAccount / ListByRole / List.
func (l subjectReadLane) narrowsPage() bool { return l == subjectReadAccountAdmin }

// subjectReadDecision — исход допуска ВМЕСТЕ с придержанным существованием.
type subjectReadDecision struct {
	lane subjectReadLane
	// resolved — резолв субъекта: домашний аккаунт, признак существования и
	// СОБСТВЕННЫЙ `NOT_FOUND` владельца, придержанный до тех пор, пока чтение не
	// решит, что вызывающему его можно показать.
	resolved subjectResolution
}

// subjectResolution — outcome of the subject lookup, with the absence answer
// held back. `miss` carries the owning repo's OWN NotFound (contract tone
// "<Resource> <id> not found", never re-composed here — re-composing it is how
// the hide-existence texts drift apart), and it is returned to the caller only
// after authority has been established.
type subjectResolution struct {
	accountID domain.AccountID
	found     bool
	miss      error
}

// subjectReadAuthority — ЕДИНЫЙ предикат допуска обоих чтений.
//
// Порядок шагов держит анти-оракул: существование субъекта резолвится, но
// вердиктом не становится — оно возвращается ОТДЕЛЬНО, а полоса решается раньше.
//
// Три исхода, а не два: полоса (допущен) · `PermissionDenied` (хранилище
// ответило «нет») · иная ошибка (хранилище не ответило). Последняя отказом в
// правах не является и обязана доехать до вызывающего: за сужаемым чтением нет
// пообъектной полосы края, которая сообщила бы о неполадке сама.
func subjectReadAuthority(
	ctx context.Context,
	repo Repo,
	relations clients.RelationStore,
	subjectType domain.SubjectType,
	subjectID domain.SubjectID,
) (subjectReadDecision, error) {
	// 1. Анти-анонимный страж. Запись каталога у обоих чтений —
	// `scope_filtered`, то есть край пропускает всякого аутентифицированного;
	// точная политика авторитетна здесь.
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return subjectReadDecision{}, err
	}

	// 2. Вызывающий обязан быть НАЗЫВАЕМ модели прав, и это отсекается
	// безусловно — до допуска, а не внутри сужения.
	//
	// Две проверки личности спрашивают разное: допуск по владельцу аккаунта
	// сверяет голый идентификатор принципала и о его виде не спрашивает, а
	// сужение строит субъект, который знает лишь человека и служебную учётку. На
	// принципале иного вида они расходятся — допуск проходит, а имени для
	// вопроса нет. Пустой субъект `VisibleSet` не отвергает: он возвращает
	// пустой набор, и страница молча схлопывается в `200` с пустым перечнем —
	// исход, который вызывающий не отличит от отзыва прав. Полосы края, на
	// которую можно было бы откатиться, у этих чтений нет.
	if subject, ok := authzguard.PrincipalSubject(ctx); !ok || subject == "" {
		return subjectReadDecision{}, authzguard.PermissionDenied()
	}

	// 3. Резолв субъекта: даёт домашний аккаунт, нужный полосе распорядителя.
	// Ответ об отсутствии ПРИДЕРЖИВАЕТСЯ — его покажет (или не покажет) чтение.
	res, err := resolveSubjectHome(ctx, repo, subjectType, subjectID)
	if err != nil {
		// Неполадка хранилища — не утверждение о субъекте.
		return subjectReadDecision{}, err
	}

	// 4. Собственное чтение. Для группы «сам субъект» означает «состоит в ней»:
	// членство и есть то, чем группа наделяет человека, поэтому её выдачи ему
	// принадлежат так же, как свои.
	self, err := callerIsSubject(ctx, repo, subjectType, subjectID)
	if err != nil {
		return subjectReadDecision{}, err
	}
	if self {
		return subjectReadDecision{lane: subjectReadSelf, resolved: res}, nil
	}

	// 5. Надзор облака — ОДИН вопрос на запрос, вне какого-либо цикла.
	// E-форма обязательна: за этой ветвью нет пообъектной полосы, которая
	// сообщила бы о неполадке сама. Проглоченный отказ хранилища прав стал бы
	// здесь отказом В ПРАВАХ — тем же ответом, что и настоящий deny, и
	// вызывающий не узнал бы, что повтор осмыслен.
	clusterAdmin, aerr := authzguard.IsClusterAdminE(ctx, relations)
	if aerr != nil {
		return subjectReadDecision{}, authzguard.AuthzBackendUnavailable()
	}
	if clusterAdmin {
		return subjectReadDecision{lane: subjectReadClusterAdmin, resolved: res}, nil
	}

	// 6. Идентификатор, не принадлежащий никому, домашнего аккаунта не имеет,
	// поэтому единственный авторитет над ним — плоский супер-гейт выше, и он
	// только что ответил «нет». Все прочие получают ТОТ ЖЕ ответ, что и на
	// субъекта в чужом аккаунте, — тождество ответов и закрывает оракул.
	if !res.found {
		return subjectReadDecision{lane: subjectReadDenied, resolved: res}, authzguard.PermissionDenied()
	}

	// 7. Распорядитель ДОМАШНЕГО аккаунта субъекта. Единственная полоса, чью
	// страницу сужает пообъектный вопрос.
	ok, aerr := subjectHomeAccountAuthority(ctx, repo, relations, res.accountID)
	if aerr != nil {
		return subjectReadDecision{}, aerr
	}
	if !ok {
		return subjectReadDecision{lane: subjectReadDenied, resolved: res}, authzguard.PermissionDenied()
	}
	return subjectReadDecision{lane: subjectReadAccountAdmin, resolved: res}, nil
}

// callerIsSubject — «вызывающий и есть субъект»: тождество для человека и
// служебной учётки, членство для группы.
//
// Не-член группы здесь ОТКАЗОМ не является: он возвращает `false` и уходит
// дальше по полосам. Иначе распорядитель аккаунта, не состоящий в группе, был бы
// отвергнут раньше, чем его авторитет вообще спросили, — и глагол снова решал бы
// допуск иначе, чем сосед.
//
// Только человек и служебная учётка могут состоять в группе
// (`group_members.member_type` CHECK), поэтому принципал иного вида отвечает
// `false` без обращения к хранилищу.
func callerIsSubject(
	ctx context.Context,
	repo Repo,
	subjectType domain.SubjectType,
	subjectID domain.SubjectID,
) (bool, error) {
	switch subjectType {
	case domain.SubjectTypeUser, domain.SubjectTypeServiceAccount:
		return authzguard.IsSelf(ctx, string(subjectID)), nil
	case domain.SubjectTypeGroup:
		p := operations.PrincipalFromContext(ctx)
		switch p.Type {
		case string(domain.SubjectTypeUser), string(domain.SubjectTypeServiceAccount):
		default:
			return false, nil
		}
		rd, err := repo.Reader(ctx)
		if err != nil {
			return false, shared.MapRepoErr(err)
		}
		defer func() { _ = rd.Rollback(ctx) }()
		isMember, err := rd.Groups().IsMember(ctx, domain.GroupID(subjectID),
			domain.SubjectType(p.Type), domain.SubjectID(p.ID))
		if err != nil {
			return false, shared.MapRepoErr(err)
		}
		return isMember, nil
	default:
		return false, nil
	}
}

// resolveSubjectHome reads the subject (User / ServiceAccount / Group) to return
// its home account_id for the authz check. All reads are within kaname,
// same-schema — NOT a cross-domain edge.
//
// Three outcomes, deliberately distinct: resolved (found, account id); absent
// (found=false, miss holds the mapped NotFound — NOT returned as an error here);
// store failure (err — never a statement about the subject).
func resolveSubjectHome(
	ctx context.Context,
	repo Repo,
	subjectType domain.SubjectType,
	subjectID domain.SubjectID,
) (subjectResolution, error) {
	rd, err := repo.Reader(ctx)
	if err != nil {
		return subjectResolution{}, shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()

	resolved := func(accountID domain.AccountID) (subjectResolution, error) {
		return subjectResolution{accountID: accountID, found: true}, nil
	}
	// classify splits "no such row" (deferred answer) from a real store failure.
	classify := func(gerr error) (subjectResolution, error) {
		if errors.Is(gerr, iamerr.ErrNotFound) {
			return subjectResolution{miss: shared.MapRepoErr(gerr)}, nil
		}
		return subjectResolution{}, shared.MapRepoErr(gerr)
	}

	switch subjectType {
	case domain.SubjectTypeUser:
		usr, gerr := rd.Users().Get(ctx, domain.UserID(subjectID))
		if gerr != nil {
			return classify(gerr)
		}
		return resolved(usr.AccountID)
	case domain.SubjectTypeServiceAccount:
		sa, gerr := rd.ServiceAccounts().Get(ctx, domain.ServiceAccountID(subjectID))
		if gerr != nil {
			return classify(gerr)
		}
		return resolved(sa.AccountID)
	case domain.SubjectTypeGroup:
		// A Group is Account-scoped (groups.account_id FK), so its home account is
		// the gate scope — same policy as User / SA.
		grp, gerr := rd.Groups().Get(ctx, domain.GroupID(subjectID))
		if gerr != nil {
			return classify(gerr)
		}
		return resolved(grp.AccountID)
	default:
		// Unreachable — subject_type is whitelisted by the caller.
		return subjectResolution{}, authzguard.PermissionDenied()
	}
}

// subjectHomeAccountAuthority — вызывающий распоряжается ДОМАШНИМ аккаунтом
// субъекта. Авторитет держится, когда верно ЛИБО:
//   - вызывающий владеет аккаунтом (`owner_user_id` == принципал), ЛИБО
//   - вызывающий держит отношение `admin` на `account:<homeAccountID>`
//     (делегированный распорядитель, не владелец; `fgaHoldsAdminE` несёт
//     короткое замыкание на плоский супер-гейт надзора).
//
// Это читающее зеркало `requireGrantAuthority` на домашнем аккаунте субъекта:
// «кто вправе выдавать» == «кто вправе видеть». Повисший домашний аккаунт — это
// просто «нет пути владельца», а не утверждение о субъекте.
//
// Возвращает `(false, nil)` для «нет авторитета» и `(false, err)` только для
// неполадки хранилища: недоступное хранилище не есть отказ.
func subjectHomeAccountAuthority(
	ctx context.Context,
	repo Repo,
	relations clients.RelationStore,
	accountID domain.AccountID,
) (bool, error) {
	if accountID == "" {
		return false, nil
	}

	rd, err := repo.Reader(ctx)
	if err != nil {
		return false, shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()

	// Path 1 — owner of the home Account.
	acct, gerr := rd.Accounts().Get(ctx, accountID)
	if gerr == nil && acct.OwnerUserID != "" && authzguard.IsSelf(ctx, string(acct.OwnerUserID)) {
		return true, nil
	}
	// A missing account row is treated as "no owner-path" — fall through to the
	// FGA delegated-admin path; ultimately unauthorized if neither holds.
	if gerr != nil && !errors.Is(gerr, iamerr.ErrNotFound) {
		return false, shared.MapRepoErr(gerr)
	}

	// Path 2 — delegated admin: principal holds `admin` on account:<id> in FGA
	// (shared predicate — the single authority gate used by every site).
	//
	// E-форма обязательна: этот путь строит СТРАНИЦУ видимого. Проглотив
	// неполадку хранилища прав, он вернул бы well-formed `200` с молча суженным
	// набором, который вызывающий не отличит от отзыва прав.
	return fgaHoldsAdminE(ctx, relations, "account", string(accountID))
}

// visibleOnNarrowedPage — ОДНА форма сужения на оба чтения.
//
// Непровязанный порт и неотвеченный вопрос — ОТКАЗ, а не несужённая либо молча
// пустая страница. Отдать при этом всё значило бы потерять сужение целиком и
// молча; отдать пустое — сказать «прав нет» там, где мы просто не спросили.
// Полосы края, на которую можно было бы откатиться, у этих чтений нет
// (`scope_filtered`).
func visibleOnNarrowedPage(ctx context.Context, q clients.RelationQueries, ids []string) (map[string]bool, error) {
	visible, wired, err := visibleBindingIDsOnPage(ctx, q, ids)
	if err != nil {
		return nil, err
	}
	if !wired {
		return nil, shared.MapRepoErr(iamerr.ErrUnavailable)
	}
	return visible, nil
}
