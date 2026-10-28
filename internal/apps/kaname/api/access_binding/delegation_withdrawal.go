// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// delegation_withdrawal.go — отзыв делегирования отзывает выданное по нему
// (задача PRO-Robotech/kaname#986, Р4 приёмки
// docs/engineering/acceptance/delegated-grants-stay-within-the-delegation.md).
//
// Каждая отзываемая выдача получает ТЕ ЖЕ следствия, что отзыв по снятию
// регистрации (`withdrawBindings`, kaname#963) и отзыв глаголом: CAS строки,
// строки снятия на весь реестр выпущенного (`revokeEmittedOf`), смена субъекта
// на каждого субъекта (`emitSubjectChangeFor`) и аудит. Голый «один UPDATE
// выдач» этих следствий не даёт, и доступ пережил бы отзыв (условие CE-10
// разбора классов).
//
// Порядок замков — по образцу kaname#963: строка делегирования `FOR UPDATE`
// (её берёт вызывающий), затем выдачи делегирования `FOR UPDATE` по возрастанию
// id; advisory-замка после строчного нет (отзыв глаголом берёт их в обратном
// порядке, `doRevoke`). Защита от удаления условием не является.

import (
	"context"
	"fmt"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	abrepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
)

// AuditEventDelegationRevoked — строка аудита выдачи, отозванной отзывом
// делегирования (Р5).
const AuditEventDelegationRevoked abrepo.AuditEventType = "iam.access_binding.delegation_revoked"

// WithdrawDelegatedBindings — отзывает каждую действующую выдачу делегирования
// `d` в транзакции писателя `w` (строка делегирования уже под замком
// вызывающего). `actor` — отозвавший делегирование: он же `revoked_by_user_id`
// выдачи (Р4). Отдаёт число выдач, которые отозвал ЭТОТ вызов, — сумму успешных
// CAS, а не число отобранных строк.
func WithdrawDelegatedBindings(ctx context.Context, w Writer, d domain.GrantDelegation, actor string, at time.Time) (int, error) {
	gw := w.AccessBindingsW().GrantDelegationsW()
	ids, err := gw.ActiveBindingIDs(ctx, d.ID)
	if err != nil {
		return 0, fmt.Errorf("active bindings of grant delegation %s: %w", d.ID, err)
	}
	revoked := 0
	for _, id := range ids {
		b, err := w.AccessBindings().Get(ctx, id)
		if err != nil {
			return 0, fmt.Errorf("read access binding %s: %w", id, err)
		}
		subjects, err := bindingSubjectsOf(ctx, w.AccessBindings().ListSubjects, b)
		if err != nil {
			return 0, fmt.Errorf("subjects of access binding %s: %w", id, err)
		}
		ok, err := gw.RevokeBindingForDelegation(ctx, id, domain.UserID(actor), at)
		if err != nil {
			return 0, fmt.Errorf("revoke access binding %s: %w", id, err)
		}
		if !ok {
			continue // строку уже отозвал параллельный отзыв
		}
		if err := revokeEmittedOf(ctx, w, id); err != nil {
			return 0, fmt.Errorf("revoke emitted tuples of access binding %s: %w", id, err)
		}
		if err := emitSubjectChangeFor(ctx, w.AccessBindingsW().EmitSubjectChangeEvent, subjects,
			"binding_revoke", "binding_delete"); err != nil {
			return 0, fmt.Errorf("subject change of revoked access binding %s: %w", id, err)
		}
		for _, s := range subjects {
			if err := w.AccessBindingsW().EmitAuditEvent(ctx, abrepo.AuditEvent{
				EventType: AuditEventDelegationRevoked, Actor: actor,
				SubjectType: string(s.Type), SubjectID: string(s.ID),
				ResourceType: string(b.ResourceType), ResourceID: b.ResourceID,
				RoleID: string(b.RoleID), BindingID: string(b.ID),
				// Аккаунт строки — аккаунт делегирования при любой области (Р5).
				TenantAccountID: string(d.AccountID),
				ExtraPayload: map[string]any{
					"delegation_id":     string(d.ID),
					"revocation_reason": "delegation_revoked",
				},
			}); err != nil {
				return 0, fmt.Errorf("audit revoke of access binding %s: %w", id, err)
			}
		}
		revoked++
	}
	return revoked, nil
}
