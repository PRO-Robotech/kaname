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
	"sort"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/hierarchy"

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

// registrationParentGraphReader — отдельный bounded port строгого admission.
// Отсутствие реализации закрывает допуск; исторический PointerSubjectsTx не
// используется запасным путём и сохраняет прежние audit/cleanup semantics.
type registrationParentGraphReader interface {
	BoundedPointerSubjectsTx(ctx context.Context, tx service.Tx, modelType, id string, pointers []string) ([]string, error)
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
	ctx context.Context, tx service.Tx, module string, t tupleIntent, row service.ResourceMirrorRow,
) (registrationAdmission, error) {
	dotted, policy, live, err := uc.catalogTypes.WritePolicyTx(ctx, tx, row.ObjectType)
	if err != nil {
		return registrationAdmission{}, fmt.Errorf("read write policy: %w", err)
	}
	if !live {
		catalogType, cerr := uc.catalogObjectType(ctx, tx, row.ObjectType)
		if cerr != nil {
			return registrationAdmission{}, fmt.Errorf("resolve catalog object type: %w", cerr)
		}
		return registrationAdmission{}, shared.InvalidArg("object", fmt.Sprintf("resource type %q is not a live entry of the platform resource catalog", catalogType))
	}
	if err := authorizeCatalogOwner(module, policy.Module); err != nil {
		return registrationAdmission{}, err
	}
	_, id := t.splitObject()
	if err := validateRegistrationShape(module, t.subject, t.relation, policy.ObjectType+":"+id); err != nil {
		return registrationAdmission{}, err
	}
	if err := permanentProjectForm(policy, row); err != nil {
		return registrationAdmission{}, err
	}
	subjectType, _, _ := strings.Cut(t.subject, ":")
	// Сверх прежних трёх отношений разрешён только точный указатель, не writes.
	if !legacyRegistrationRelation(t.relation) {
		pointer, ok := policy.Pointer(t.relation)
		if !ok || pointer.Type != subjectType || !namedPointerSubjectType(subjectType) {
			return registrationAdmission{}, proxyWriteRefusal()
		}
		if _, ok := uc.scopes.(registrationPointerStore); !ok {
			return registrationAdmission{}, proxyWriteRefusal()
		}
	}
	if !policy.Admits(t.relation, subjectType) {
		return registrationAdmission{}, proxyWriteRefusal()
	}
	hierarchies, err := uc.deriveParent(ctx, tx, t, policy, domain.ParentClaim{
		ProjectID: row.ParentProjectID,
		AccountID: row.ParentAccountID,
		Chain:     row.ParentChain,
	})
	if err != nil {
		return registrationAdmission{}, uc.preferBindingRefusal(ctx, tx, t, policy, row, err)
	}
	authorities, err := uc.registrationAuthorities(ctx, tx, hierarchies)
	if err != nil {
		return registrationAdmission{}, uc.preferProjectBindingRefusal(ctx, tx, t, policy.ObjectType, row, err)
	}
	return registrationAdmission{catalogType: dotted, hierarchies: hierarchies, authorities: authorities}, nil
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
	return uc.preferProjectBindingRefusal(ctx, tx, t, policy.ObjectType, row, derr)
}

// preferProjectBindingRefusal сохраняет прежний отказ привязки перед отказом
// вывода либо account authority. Читаем предикат только на отказном пути:
// успешный Register по-прежнему проверяет привязку единственным чтением внутри
// UpsertTx, без повторного вывода иерархии и без записи до account authority.
func (uc *RegisterResourceUseCase) preferProjectBindingRefusal(ctx context.Context, tx service.Tx, t tupleIntent,
	modelType string, row service.ResourceMirrorRow, refusal error,
) error {
	_, objID := t.splitObject()
	refuses, err := uc.scopes.BindingRefusesTx(ctx, tx, modelType, objID, row.ParentProjectID, row.ParentChain)
	if err != nil {
		return fmt.Errorf("derive parent: judge project binding: %w", err)
	}
	if refuses {
		return iamerr.ObjectBoundToOtherProject(t.object, modelType, objID)
	}
	return refusal
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
) (admitted []domain.ParentHierarchy, err error) {
	_, objID := t.splitObject()
	// Сохраняем публичный Р8 для неизвестного/неполного родителя. Чистый port
	// отдельно сохраняет причины для captured runner; ошибки чтения не скрываем.
	defer func() {
		if stderrors.Is(err, domain.ErrParentHierarchyIncomplete) || stderrors.Is(err, domain.ErrParentHierarchyInvalid) {
			admitted = nil
			err = iamerr.ParentScopeMismatch(t.object, policy.ObjectType, objID)
		}
	}()
	if _, ok := uc.scopes.(registrationParentGraphReader); !ok {
		return nil, fmt.Errorf("%w: bounded pointer reader is not configured", domain.ErrParentHierarchyIncomplete)
	}
	budget := new(parentHierarchyReadBudget)
	anchors := []string{t.subject}
	if _, isPointer := policy.Pointer(t.relation); !isPointer {
		var err error
		anchors, err = uc.parentPointerSubjects(ctx, tx, policy.ObjectType, objID, policy, budget)
		if err != nil {
			return nil, err
		}
	}
	graph, err := uc.parentHierarchyGraph(ctx, tx, anchors, budget)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, anchor := range anchors {
		if seen[anchor] {
			continue
		}
		seen[anchor] = true
		hs, err := domain.BuildParentHierarchies(anchor, graph)
		if err != nil {
			return nil, err
		}
		for _, h := range hs {
			if h.Admits(claim) {
				admitted = append(admitted, h)
			}
		}
	}
	if len(admitted) > 0 {
		return admitted, nil
	}
	return nil, iamerr.ParentScopeMismatch(t.object, policy.ObjectType, objID)
}

// Один бюджет охватывает все опоры, страницы указателей и ветви входа.
// Каждый запрос возвращает точечную строку либо страницу с sentinel; ошибки
// источника не превращаются в пустой набор и не оставляют частичный допуск.
type parentHierarchyReadBudget struct{ reads, edges int }

func (b *parentHierarchyReadBudget) read() error {
	b.reads++
	if b.reads > domain.MaxParentHierarchyReads {
		return fmt.Errorf("%w: read budget", domain.ErrParentHierarchyInvalid)
	}
	return nil
}

func (uc *RegisterResourceUseCase) parentPointerSubjects(ctx context.Context, tx service.Tx, typ, id string, policy domain.WritePolicy, budget *parentHierarchyReadBudget) ([]string, error) {
	if policy.ObjectType != typ || len(policy.Pointers) > hierarchy.MaxImmediateParents {
		return nil, fmt.Errorf("%w: pointer policy", domain.ErrParentHierarchyInvalid)
	}
	reader, ok := uc.scopes.(registrationParentGraphReader)
	if !ok {
		return nil, fmt.Errorf("%w: bounded pointer reader is not configured", domain.ErrParentHierarchyIncomplete)
	}
	var out []string
	names, subjects := map[string]bool{}, map[string]bool{}
	for _, pointer := range policy.Pointers {
		if pointer.Name == "" || names[pointer.Name] || !namedPointerSubjectType(pointer.Type) {
			return nil, fmt.Errorf("%w: pointer declaration", domain.ErrParentHierarchyInvalid)
		}
		names[pointer.Name] = true
		if err := budget.read(); err != nil {
			return nil, err
		}
		// Отдельное чтение каждого отношения сохраняет точную пару relation/type.
		// Чтение всех имён сразу потеряло бы эту связь для разных parent types.
		rows, err := reader.BoundedPointerSubjectsTx(ctx, tx, typ, id, []string{pointer.Name})
		if err != nil {
			return nil, fmt.Errorf("derive parent: read pointer facts: %w", err)
		}
		budget.edges += len(rows)
		if len(rows) > hierarchy.MaxImmediateParents || budget.edges > domain.MaxParentHierarchyEdges {
			return nil, fmt.Errorf("%w: pointer row budget", domain.ErrParentHierarchyInvalid)
		}
		for _, ref := range rows {
			parentType, parentID, ok := strings.Cut(ref, ":")
			if !ok || parentType != pointer.Type || parentID == "" {
				return nil, fmt.Errorf("%w: pointer subject %q", domain.ErrParentHierarchyInvalid, ref)
			}
			if !subjects[ref] {
				subjects[ref] = true
				out = append(out, ref)
			}
		}
	}
	if len(out) > hierarchy.MaxImmediateParents {
		return nil, fmt.Errorf("%w: immediate parent budget", domain.ErrParentHierarchyInvalid)
	}
	sort.Strings(out)
	return out, nil
}

// parentHierarchyGraph читает текущие указатели и owning rows той же TX.
// Сохранённый project edge используется ContainerScopeTx только как ceiling;
// он никогда не подменяет непосредственное ребро pointer graph.
func (uc *RegisterResourceUseCase) parentHierarchyGraph(ctx context.Context, tx service.Tx, anchors []string, budget *parentHierarchyReadBudget) (domain.ParentHierarchyGraph, error) {
	type pending struct {
		ref   string
		depth int
	}
	graph := domain.ParentHierarchyGraph{}
	var queue []pending
	queued := map[string]bool{}
	enqueue := func(ref string, depth int) error {
		if queued[ref] {
			return nil
		}
		if len(queued) >= domain.MaxParentHierarchyNodes || depth > hierarchy.MaxStoredParentLinks {
			return fmt.Errorf("%w: graph budget", domain.ErrParentHierarchyInvalid)
		}
		queued[ref] = true
		queue = append(queue, pending{ref, depth})
		return nil
	}
	for _, anchor := range anchors {
		if err := enqueue(anchor, 1); err != nil {
			return nil, err
		}
	}
	for pos := 0; pos < len(queue); pos++ {
		item := queue[pos]
		typ, id, ok := strings.Cut(item.ref, ":")
		if !ok || typ == "" || id == "" || !namedPointerSubjectType(typ) {
			return nil, fmt.Errorf("%w: anchor %q", domain.ErrParentHierarchyInvalid, item.ref)
		}
		node := domain.ParentHierarchyNode{Ref: item.ref}
		if err := budget.read(); err != nil {
			return nil, err
		}
		if typ == anchorProjectType {
			account, found, err := uc.scopes.ProjectAccountTx(ctx, tx, id)
			if err != nil {
				return nil, fmt.Errorf("derive parent: read project: %w", err)
			}
			node.Scope = domain.ContainerScope{Registered: found, ProjectID: id, AccountID: account}
		} else {
			scope, err := uc.scopes.ContainerScopeTx(ctx, tx, typ, id)
			if err != nil {
				return nil, fmt.Errorf("derive parent: read container: %w", err)
			}
			node.Scope = scope
			// DP14 останавливает проецируемую иерархию здесь; saved authority читается
			// отдельно и не может повысить этот ceiling.
			if scope.Registered && scope.ProjectID != "" {
				if err := budget.read(); err != nil {
					return nil, err
				}
				_, policy, live, err := uc.catalogTypes.WritePolicyTx(ctx, tx, typ)
				if err != nil {
					return nil, fmt.Errorf("derive parent: read container policy: %w", err)
				}
				if !live {
					return nil, fmt.Errorf("%w: container policy", domain.ErrParentHierarchyIncomplete)
				}
				node.Parents, err = uc.parentPointerSubjects(ctx, tx, typ, id, policy, budget)
				if err != nil {
					return nil, err
				}
				for _, parent := range node.Parents {
					if err := enqueue(parent, item.depth+1); err != nil {
						return nil, err
					}
				}
			}
		}
		graph[item.ref] = node
	}
	return graph, nil
}

// hierarchyOf сохранён только для исторического audit/cleanup. Снятие и
// аудит отказа не требуют новой живой политики предков. Допуск Register выше
// всегда строит полный граф и не вызывает этот сокращённый helper.
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
