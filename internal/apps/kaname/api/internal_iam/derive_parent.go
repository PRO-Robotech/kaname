// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

// derive_parent.go — ПОЛИТИКА ЗАПИСИ МОДУЛЯ И ВЫВОД РОДИТЕЛЯ регистрируемого
// объекта (задача kaname#982, приёмка
// `docs/engineering/acceptance/kaname-derives-the-parent-of-a-registered-object.md`).
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО БЫЛО И ПОЧЕМУ ЭТОГО МАЛО
//
// Регистрация переносила сведения модуля о родителе (`parentProjectId`,
// `parentAccountId`, `parentChain`) в строку зеркала и цепь как присланы, а
// записать модуль мог любое отношение иерархии на объект своего типа. Граница
// проекта и родителя держалась на корректности модуля, а не на kaname.
//
// ─────────────────────────────────────────────────────────────────────────────
// ГДЕ ЭТО СУДИТСЯ И ПОЧЕМУ ЗДЕСЬ
//
// В use-case, в транзакции регистрации, ДО её первого оператора записи (Р1, Р9).
// Обработчик был бы вторым местом: use-case зовут и мимо него (внутренние
// вызывающие, пробы), и закрытие, живущее в обработчике, обходилось бы любым
// таким входом (DP-06). Читаются политика и иерархия в той же транзакции, что
// пишет регистрацию: решение и запись лежат в одном снимке.
//
// Порядок двух отказов несущий (Р9): сперва политика (`PERMISSION_DENIED`), затем
// вывод (`FAILED_PRECONDITION`) — модуль не узнаёт ничего об иерархии kaname
// записью, на которую не вправе (DP-16).
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ЗДЕСЬ НЕТ НАМЕРЕННО
//
// Вывод сверяет и не дописывает (Р7, Р-В1): опущенное поле остаётся пустым,
// опущенное звено в цепь не вставляется. Снятие регистрации и публикация для
// анонимного чтения политикой и выводом не судятся (Р11): снятие сужает доступ и
// обязано оставаться возможным и для кортежа, записанного до политики.

import (
	"context"
	stderrors "errors"
	"fmt"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// registrationScopeReader — узкий порт чтений вывода родителя (Р4, Р5) в
// транзакции регистрации. Реализация — *repo/kaname/pg.RegistrationScopeReader.
//
// ОБЯЗАТЕЛЕН, а не опция: «нет читателя — родителя не выводим» и было признаком
// задачи — регистрация верила модулю.
type registrationScopeReader interface {
	// ProjectAccountTx — аккаунт проекта; ok=false — проекта в kaname нет.
	ProjectAccountTx(ctx context.Context, tx service.Tx, projectID string) (accountID string, ok bool, err error)
	// ContainerScopeTx — записанная область зарегистрированного контейнера.
	ContainerScopeTx(ctx context.Context, tx service.Tx, modelType, id string) (domain.ContainerScope, error)
	// PointerSubjectsTx — субъекты фактов указателя объекта.
	PointerSubjectsTx(ctx context.Context, tx service.Tx, modelType, id string, pointers []string) ([]string, error)
	// BindingRefusesTx — привязка объекта к проекту (kaname#983) отвергает
	// регистрацию с проектом поля project и цепью chain. Тот же предикат базы,
	// которым судят триггеры записи зеркала и цепи.
	BindingRefusesTx(ctx context.Context, tx service.Tx, modelType, id, project string, chain []string) (bool, error)
}

// anchorProjectType — тип опоры-проекта: его иерархию даёт строка проекта, а не
// строка зеркала.
const anchorProjectType = "project"

// admitRegistration судит регистрацию кортежа t со сведениями о родителе row
// политикой записи (Р1) и выводом родителя (Р4–Р6) и возвращает точечное имя
// каталога, которым регистрация ляжет в зеркало.
//
// Тип без живой строки каталога политикой и выводом не судится (Р3): его
// отвергает строка зеркала полем `object`, и отказ по правам на вход, у которого
// вызывающему есть что чинить, был бы худшей диагностикой. Имя для него — тот же
// перевод, что у снятия.
//
// Отказ политики — тот же ответ, что у правила проксируемой записи
// ([proxyWriteRefusal]), один производитель текста. Отказ вывода —
// [iamerr.ParentScopeMismatch]. Оба возвращаются НЕОБЁРНУТЫМИ: переводчик
// узнаёт их по виду, а обёртка дописала бы в ответ имя внутреннего шага.
func (uc *RegisterResourceUseCase) admitRegistration(
	ctx context.Context, tx service.Tx, t tupleIntent, row service.ResourceMirrorRow,
) (string, error) {
	dotted, policy, live, err := uc.catalogTypes.WritePolicyTx(ctx, tx, row.ObjectType)
	if err != nil {
		return "", fmt.Errorf("read write policy: %w", err)
	}
	if !live {
		catalogType, cerr := uc.catalogObjectType(ctx, tx, row.ObjectType)
		if cerr != nil {
			return "", fmt.Errorf("resolve catalog object type: %w", cerr)
		}
		return catalogType, nil
	}
	if err := permanentProjectForm(policy, row); err != nil {
		return "", err
	}
	subjectType, _, _ := strings.Cut(t.subject, ":")
	if !policy.Admits(t.relation, subjectType) {
		return "", proxyWriteRefusal()
	}
	if err := uc.deriveParent(ctx, tx, t, policy, domain.ParentClaim{
		ProjectID: row.ParentProjectID,
		AccountID: row.ParentAccountID,
		Chain:     row.ParentChain,
	}); err != nil {
		return "", uc.preferBindingRefusal(ctx, tx, t, policy, row, err)
	}
	return dotted, nil
}

// permanentProjectForm — форма регистрации типа с неизменным проектом
// (kaname#983, Р2): проект обязан стоять и полем `parentProjectId`, и хотя бы одним
// звеном `project:<id>` цепи — без звена второй носитель проекта, из которого
// решение о доступе берёт область, сверять с привязкой нечем. Поле судится
// первым: при обоих нарушениях отказ называет `parent_project_id`.
func permanentProjectForm(policy domain.WritePolicy, row service.ResourceMirrorRow) error {
	if !policy.PermanentProject {
		return nil
	}
	if row.ParentProjectID == "" {
		return shared.InvalidArg("parent_project_id", fmt.Sprintf(
			"parent_project_id: required for object type %s with a permanent project", policy.ObjectType))
	}
	for _, link := range row.ParentChain {
		if typ, id, ok := strings.Cut(link, ":"); ok && typ == anchorProjectType && id != "" {
			return nil
		}
	}
	return shared.InvalidArg("parent_chain", fmt.Sprintf(
		"parent_chain: must name the project for object type %s with a permanent project", policy.ObjectType))
}

// preferBindingRefusal — порядок двух отказов, когда к регистрации приложимы оба
// (Р10 приёмки kaname#982, §7 строка 4): отказ привязки объекта к проекту
// (kaname#983) возвращается раньше отказа вывода родителя. Привязку судит база
// на уровне записи зеркала и цепи, а вывод стоит до первой записи; поэтому отказ
// вывода не возвращается, пока тем же предикатом базы не установлено, что
// привязка этот запрос пропускает. Второго предиката привязки здесь нет.
//
// derr — отказ вывода; прочие ошибки проходят как есть.
func (uc *RegisterResourceUseCase) preferBindingRefusal(ctx context.Context, tx service.Tx, t tupleIntent,
	policy domain.WritePolicy, row service.ResourceMirrorRow, derr error,
) error {
	if !stderrors.Is(derr, iamerr.ErrParentScopeMismatch) {
		return derr
	}
	_, objID := t.splitObject()
	refuses, err := uc.scopes.BindingRefusesTx(ctx, tx, policy.ObjectType, objID, row.ParentProjectID, row.ParentChain)
	if err != nil {
		return fmt.Errorf("derive parent: judge project binding: %w", err)
	}
	if refuses {
		return iamerr.ObjectBoundToOtherProject(t.object, policy.ObjectType, objID)
	}
	return derr
}

// deriveParent — вывод родителя (Р4) и сверка сведений модуля с ним (Р6).
//
// Опора регистрации указателем — субъект кортежа. Опора записи из `writes` —
// ВЫВЕДЕННЫЙ родитель объекта: субъекты его фактов указателя, а не первое звено
// присланной цепи (DP-17): цепь вправе опускать звенья, и объект с цепью
// `[account:…]` либо с пустой цепью опору всё равно имеет. Фактов указателя
// несколько (перенос под другой контейнер того же проекта, когда прежний
// указатель ещё не снят) — сведения проходят, если согласны хотя бы с одной
// иерархией: каждый такой субъект — родитель, уже выведенный kaname.
//
// Опоры нет либо ни одна иерархия не согласна — отказ Р8; ответ на оба случая
// один (различие было бы оракулом иерархии).
func (uc *RegisterResourceUseCase) deriveParent(
	ctx context.Context, tx service.Tx, t tupleIntent, policy domain.WritePolicy, claim domain.ParentClaim,
) error {
	_, objID := t.splitObject()
	anchors := []string{t.subject}
	if _, isPointer := policy.Pointer(t.relation); !isPointer {
		var err error
		if anchors, err = uc.scopes.PointerSubjectsTx(ctx, tx, policy.ObjectType, objID, policy.PointerNames()); err != nil {
			return fmt.Errorf("derive parent: read pointer facts: %w", err)
		}
	}
	for _, anchor := range anchors {
		h, ok, err := uc.hierarchyOf(ctx, tx, anchor)
		if err != nil {
			return err
		}
		if ok && h.Admits(claim) {
			return nil
		}
	}
	return iamerr.ParentScopeMismatch(t.object, policy.ObjectType, objID)
}

// hierarchyOf — иерархия kaname от опоры anchor (`<тип>:<id>`), Р5. ok=false —
// иерархии нет: проекта в kaname нет либо контейнер не зарегистрирован.
func (uc *RegisterResourceUseCase) hierarchyOf(ctx context.Context, tx service.Tx, anchor string) (domain.ParentHierarchy, bool, error) {
	typ, id, found := strings.Cut(anchor, ":")
	if !found || id == "" {
		return domain.ParentHierarchy{}, false, nil
	}
	if typ == anchorProjectType {
		acc, ok, err := uc.scopes.ProjectAccountTx(ctx, tx, id)
		if err != nil {
			return domain.ParentHierarchy{}, false, fmt.Errorf("derive parent: read project: %w", err)
		}
		if !ok {
			return domain.ParentHierarchy{}, false, nil
		}
		return domain.ProjectHierarchy(id, acc), true, nil
	}
	scope, err := uc.scopes.ContainerScopeTx(ctx, tx, typ, id)
	if err != nil {
		return domain.ParentHierarchy{}, false, fmt.Errorf("derive parent: read container: %w", err)
	}
	if !scope.Registered {
		return domain.ParentHierarchy{}, false, nil
	}
	return domain.ContainerHierarchy(anchor, scope), true, nil
}
