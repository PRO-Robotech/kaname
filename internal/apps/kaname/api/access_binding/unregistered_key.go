// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// unregistered_key.go — снятие регистрации объекта снимает его выдачи
// (задача PRO-Robotech/kaname#963, приёмка
// docs/engineering/acceptance/unregistration-revokes-its-grants.md, редакция 2).
//
// Ключ объекта модуля освобождается: у реестра registry-operator id — его имя, и
// после снятия регистрации тот же ключ может занять другой владелец. Выдача,
// цель которой называла прежний объект, и название в правиле роли к новому
// объекту переходить не вправе (Р2). Поэтому снятие, удалившее строку
// регистрации (Д1), в ТОЙ ЖЕ транзакции:
//
//   - отзывает выдачу, цель которой — только этот ключ: `REVOKED`, причина
//     `RESOURCE_UNREGISTERED`, отозвал не человек; защита от удаления не мешает
//     (Р1 (а), (в)); выпущенные выдачей кортежи снимаются так же, как при отзыве
//     глаголом — строками снятия на весь реестр выпущенного; факт, который держит
//     другая действующая выдача, свёртка журнала оставляет (kaname#919);
//   - сужает выдачу, у которой в цели остаются другие объекты (Р1 (б)); пустой
//     цели не бывает (Д3): опустевшая — отзыв, в цели отозванной остаётся
//     последний снятый ключ;
//   - убирает ключ из `resourceNames` правил ролей и их вложенных правил; правило
//     без имён снимается, роль без правил остаётся и не даёт ничего (Р1 (д), Р6,
//     Р7, Д5); три проекции правил переписываются теми же писателями, что у
//     правки роли;
//   - кладёт строку аудита на каждое изменение (Р5); ленту изменений даёт
//     существующий триггер.
//
// Перерасчёт снятого не воскрешает (Р4): отозванная выдача не материализуется,
// суженная цель и суженные правила — то, что читают и материализатор, и ветвь
// выдач решения о доступе.

import (
	"context"
	"fmt"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	abrepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// Типы событий аудита отзыва по снятию регистрации (Р5). Словарь
// `audit_outbox.event_type` — регулярное выражение, а не перечень; образец —
// `iam.access_binding.orphan_scope_revoked`.
const (
	AuditEventResourceUnregisteredRevoked  abrepo.AuditEventType = "iam.access_binding.resource_unregistered_revoked"
	AuditEventResourceUnregisteredNarrowed abrepo.AuditEventType = "iam.access_binding.resource_unregistered_narrowed"
	AuditEventRoleResourceUnregistered                           = "iam.role.resource_unregistered_narrowed"
)

// UnregisteredKeyStore — узкий порт хранилища отзыва; операторы идут в
// транзакции снятия. Реализация — *repo/kaname/pg.UnregisteredKeyStore.
type UnregisteredKeyStore interface {
	WriterOn(tx service.Tx) Writer
	ActiveBindingsNamingKey(ctx context.Context, tx service.Tx, key domain.ResourceRef) ([]domain.AccessBindingID, error)
	// LockBindingsNamingKeys и LockRolesNamingKeys — замки выдач и ролей,
	// называющих любой из ключей, каждый род одним оператором в порядке id
	// (kaname#1019, см. LockTx).
	LockBindingsNamingKeys(ctx context.Context, tx service.Tx, keys []domain.ResourceRef) error
	LockRolesNamingKeys(ctx context.Context, tx service.Tx, keys []domain.ResourceRef) error
	RevokeForUnregistered(ctx context.Context, tx service.Tx, id domain.AccessBindingID) (bool, error)
	NarrowTarget(ctx context.Context, tx service.Tx, id domain.AccessBindingID, target domain.AccessTarget) (bool, error)
	RolesNamingKey(ctx context.Context, tx service.Tx, key domain.ResourceRef) ([]domain.RoleID, error)
	RewriteRoleRules(ctx context.Context, tx service.Tx, id domain.RoleID, rules domain.Rules, perms domain.Permissions) error
}

// UnregisteredKeyWithdrawal — отзыв выдач и названий снятого ключа.
type UnregisteredKeyWithdrawal struct {
	store UnregisteredKeyStore
	cat   catalog.Source
}

// NewUnregisteredKeyWithdrawal — композиционный корень. Каталожный факт нужен
// проекциям правил роли (отбор и глаголы), тем же, что у правки роли.
func NewUnregisteredKeyWithdrawal(store UnregisteredKeyStore, cat catalog.Source) *UnregisteredKeyWithdrawal {
	return &UnregisteredKeyWithdrawal{store: store, cat: cat}
}

// LockTx запирает в транзакции снятия `tx` выдачи, называющие ключ, затем роли,
// называющие его, — оба набора `FOR UPDATE` в порядке id (kaname#974, kaname#975).
// Снятие зовёт его ДО первой записи транзакции — до удаления строки зеркала и строк
// снятия фактов объекта: проход материализации берёт выдачи, их роли и лишь затем
// пишет, и снятие, удержавшее строку факта раньше, чем заперло выдачу или роль
// прохода, сходилось бы с ним в кольцо. Порядок родов у сторон один — выдачи,
// роли, строка зеркала, факты. WithdrawTx после удаления строки запирает те же
// наборы повторно: замки уже удержаны, а выдача или роль, чей писатель держал
// строку зеркала и зафиксировался, пока снятие ждало, добирается тем же чтением
// (проход по такой выдаче строку под удалением не ждёт — `SKIP LOCKED` замка
// строки зеркала, — поэтому позднее чтение кольца не замыкает).
//
// КЛЮЧЕЙ НЕСКОЛЬКО (kaname#1019): снятие родителя снимает и потомков, и выдачи
// всех ключей — родителя и каждого потомка — запираются ОДНИМ оператором в порядке
// id, роли — следующим, тоже одним. Поочерёдный замок по ключу брал выдачи в
// порядке ключей, а проход по потомку — свой веер в порядке id: выдача потомка с
// меньшим id и выдача, названная родителем, у сторон шли в обратном порядке, и
// они сходились в кольцо.
func (u *UnregisteredKeyWithdrawal) LockTx(ctx context.Context, tx service.Tx, keys []domain.ResourceRef) error {
	if len(keys) == 0 {
		return nil
	}
	if err := u.store.LockBindingsNamingKeys(ctx, tx, keys); err != nil {
		return fmt.Errorf("lock bindings naming %d keys: %w", len(keys), err)
	}
	if err := u.store.LockRolesNamingKeys(ctx, tx, keys); err != nil {
		return fmt.Errorf("lock roles naming %d keys: %w", len(keys), err)
	}
	return nil
}

// WithdrawTx отзывает и сужает в транзакции снятия `tx` всё, что называет ключ.
// `key.Type` — точечный тип каталога (тот же словарь, что в цели выдачи), `actor`
// — проверенная личность вызывающего снятие (служебная учётка модуля).
//
// ПОРЯДОК ЗАМКОВ (kaname#974): выдачи, называющие ключ, затем роли, называющие его,
// — оба набора под `FOR UPDATE`, каждый в порядке id и ДО первой записи отзыва. Тот
// же порядок родов берёт проход материализации по объекту (выдачи веера, их роли,
// затем записи — `reconcile.ReconcileStore.LockBindingsAndRoles`). Прежде роли
// запирались после отзыва выдач, то есть после строк снятия их фактов: проход,
// державший роль с именем ключа и пишущий тот же общий факт, сходился со снятием в
// кольцо, и Postgres снимал одну из сторон (40P01).
func (u *UnregisteredKeyWithdrawal) WithdrawTx(ctx context.Context, tx service.Tx, key domain.ResourceRef, actor string) error {
	bindingIDs, err := u.store.ActiveBindingsNamingKey(ctx, tx, key)
	if err != nil {
		return fmt.Errorf("bindings naming %s %s: %w", key.Type, key.ID, err)
	}
	roleIDs, err := u.store.RolesNamingKey(ctx, tx, key)
	if err != nil {
		return fmt.Errorf("roles naming %s %s: %w", key.Type, key.ID, err)
	}
	w := u.store.WriterOn(tx)
	if err := u.withdrawBindings(ctx, tx, w, bindingIDs, key, actor); err != nil {
		return fmt.Errorf("withdraw access bindings naming %s %s: %w", key.Type, key.ID, err)
	}
	return u.withdrawRoleNames(ctx, tx, w, roleIDs, key, actor)
}

func (u *UnregisteredKeyWithdrawal) withdrawBindings(ctx context.Context, tx service.Tx, w Writer, ids []domain.AccessBindingID, key domain.ResourceRef, actor string) error {
	unregistered := map[string]any{"type": key.Type, "id": key.ID}
	for _, id := range ids {
		b, err := w.AccessBindings().Get(ctx, id)
		if err != nil {
			return fmt.Errorf("read access binding %s: %w", id, err)
		}
		remaining := withoutTargetKey(b.Target.Resources, key)
		subjects, err := bindingSubjectsOf(ctx, w.AccessBindings().ListSubjects, b)
		if err != nil {
			return fmt.Errorf("subjects of access binding %s: %w", id, err)
		}
		if len(remaining) == 0 {
			ok, err := u.store.RevokeForUnregistered(ctx, tx, id)
			if err != nil {
				return fmt.Errorf("revoke access binding %s: %w", id, err)
			}
			if !ok {
				continue // строку уже отозвал параллельный отзыв (URG-27)
			}
			if err := revokeEmittedOf(ctx, w, id); err != nil {
				return fmt.Errorf("revoke emitted tuples of access binding %s: %w", id, err)
			}
			if err := emitSubjectChangeFor(ctx, w.AccessBindingsW().EmitSubjectChangeEvent, subjects,
				"binding_revoke", "binding_delete"); err != nil {
				return fmt.Errorf("subject change of revoked access binding %s: %w", id, err)
			}
			for _, s := range subjects {
				if err := w.AccessBindingsW().EmitAuditEvent(ctx, abrepo.AuditEvent{
					EventType: AuditEventResourceUnregisteredRevoked, Actor: actor,
					SubjectType: string(s.Type), SubjectID: string(s.ID),
					ResourceType: string(b.ResourceType), ResourceID: b.ResourceID,
					RoleID: string(b.RoleID), BindingID: string(b.ID), TenantAccountID: auditTenantAccountID(b),
					ExtraPayload: map[string]any{
						"revocation_reason":     "resource_unregistered",
						"unregistered_resource": unregistered,
					},
				}); err != nil {
					return fmt.Errorf("audit revoke of access binding %s: %w", id, err)
				}
			}
			continue
		}
		ok, err := u.store.NarrowTarget(ctx, tx, id, domain.AccessTarget{Resources: remaining})
		if err != nil {
			return fmt.Errorf("narrow target of access binding %s: %w", id, err)
		}
		if !ok {
			continue
		}
		for _, s := range subjects {
			if err := w.AccessBindingsW().EmitAuditEvent(ctx, abrepo.AuditEvent{
				EventType: AuditEventResourceUnregisteredNarrowed, Actor: actor,
				SubjectType: string(s.Type), SubjectID: string(s.ID),
				ResourceType: string(b.ResourceType), ResourceID: b.ResourceID,
				RoleID: string(b.RoleID), BindingID: string(b.ID), TenantAccountID: auditTenantAccountID(b),
				ExtraPayload: map[string]any{
					"unregistered_resource":    unregistered,
					"remaining_resource_count": len(remaining),
				},
			}); err != nil {
				return fmt.Errorf("audit narrowing of access binding %s: %w", id, err)
			}
		}
	}
	return nil
}

// revokeEmittedOf снимает выпущенное выдачей так же, как отзыв глаголом
// (revoke.go): строки снятия — на ВЕСЬ реестр выпущенного, в той же транзакции.
// Выдача к этому моменту уже REVOKED (RevokeForUnregistered), поэтому свой реестр её
// факт не держит; общий кортеж, который держит другая действующая выдача, свёртка
// строки снятия оставляет — вопрос о держателях она задаёт под замком строки факта
// (kaname#919).
func revokeEmittedOf(ctx context.Context, w Writer, id domain.AccessBindingID) error {
	stored, err := w.AccessBindings().SelectEmittedTuples(ctx, id)
	if err != nil {
		return fmt.Errorf("select emitted tuples: %w", err)
	}
	return w.AccessBindingsW().EmitRelationDelete(ctx, stored)
}

// withoutTargetKey — объекты цели без ключа, в прежнем порядке (Р1 (б)).
func withoutTargetKey(refs []domain.ResourceRef, key domain.ResourceRef) []domain.ResourceRef {
	out := make([]domain.ResourceRef, 0, len(refs))
	for _, r := range refs {
		if r == key {
			continue
		}
		out = append(out, r)
	}
	return out
}

func (u *UnregisteredKeyWithdrawal) withdrawRoleNames(ctx context.Context, tx service.Tx, w Writer, ids []domain.RoleID, key domain.ResourceRef, actor string) error {
	if len(ids) == 0 {
		return nil
	}
	facts := u.cat.Facts()
	for _, id := range ids {
		role, err := w.Roles().Get(ctx, id)
		if err != nil {
			return fmt.Errorf("read role %s: %w", id, err)
		}
		rules, removed, changed := role.Rules.WithoutResourceName(key.Type, key.ID)
		if !changed {
			continue
		}
		perms, err := domain.CompileRules(rules)
		if err != nil {
			return fmt.Errorf("compile narrowed rules of role %s: %w", id, err)
		}
		if err := u.store.RewriteRoleRules(ctx, tx, id, rules, perms); err != nil {
			return fmt.Errorf("rewrite rules of role %s: %w", id, err)
		}
		sels := rules.MaterializingSelectors()
		policy := domain.PolicyOfRole(role.IsSystem, role.OwnerModule)
		if err := w.RolesW().ReplaceRuleSelectors(ctx, id, facts.GrantSelectors(sels, policy)); err != nil {
			return fmt.Errorf("replace rule selectors of role %s: %w", id, err)
		}
		if err := w.RolesW().ReplaceRoleVerbs(ctx, id, facts.RoleVerbsFromSelectors(sels, policy)); err != nil {
			return fmt.Errorf("replace verbs of role %s: %w", id, err)
		}
		if err := w.RolesW().ReplaceRuleRefs(ctx, id, domain.RuleRefsOf(rules)); err != nil {
			return fmt.Errorf("replace rule refs of role %s: %w", id, err)
		}
		if err := w.EmitAuditEvent(ctx, outboxtypes.AuditEvent{
			EventType:       AuditEventRoleResourceUnregistered,
			TenantAccountID: string(role.AccountID),
			Payload: map[string]any{
				"actor":                 actor,
				"resource_type":         "role",
				"resource_id":           string(id),
				"role_id":               string(id),
				"unregistered_resource": map[string]any{"type": key.Type, "id": key.ID},
				"removed_rule_count":    removed,
				"remaining_rule_count":  len(rules),
			},
		}); err != nil {
			return fmt.Errorf("audit narrowing of role %s: %w", id, err)
		}
	}
	return nil
}
