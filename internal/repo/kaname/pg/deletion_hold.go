// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// deletion_hold.go — отказ снятия по содержимому называет остаток и шаг
// (kaname#725, приёмка `deletion-refusals-name-the-remainder-and-the-step.md`,
// Р1–Р3).
//
// # Один отказ — одна форма на любом рубеже
//
// Отказ рождается на двух рубежах: охрана оператора снятия (`WHERE NOT EXISTS`
// и пробы в том же операторе) и схема — ключ `ON DELETE RESTRICT` либо триггер
// `principal_not_referenced_as_subject` на ТОМ ЖЕ операторе, когда держащий
// зафиксирован после снимка охраны. Оба рубежа дают вид держащего
// (`iamerr.HeldBy`), и оба дочитывают первого держащего и счёт ОДНИМ чтением
// [readHolder] на той же транзакции. Оператор снятия идёт под точкой
// сохранения: отказ схемы отменяет его до точки, транзакция остаётся живой, и
// чтение READ COMMITTED видит держащего, из-за которого схема отказала.
//
// # Это не проверка-перед-снятием (ban #10)
//
// Решает по-прежнему база: охрана и схема. Чтение идёт ПОСЛЕ отказа и только
// затем, чтобы отказ назвал предмет; гонка между отказом и чтением разрешена в
// сторону правды — держащих не осталось, и текст говорит «повторите» (Р2).
//
// # Цена
//
// На успешном снятии — две команды на транзакции (`SAVEPOINT`, `RELEASE`), на
// отказе — ещё одно чтение по индексу ключа держащего. Глаголы снятия
// человека и аккаунта — редкие и асинхронные (операция), горячего пути нет.

import (
	"context"
	stderrors "errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// heldBy — первый держащий вида и их число в момент чтения. ScopeType и
// ScopeID — область выдачи (только у [iamerr.HoldActiveBindings]).
type heldBy struct {
	ID, ScopeType, ScopeID string
	Count                  int
}

// holdShape — всё, что отказ вида знает о себе: прежний текст (префикс,
// который не меняется — Р1), шаг, вид первого держащего в metadata и SQL его
// чтения. SQL отдаёт строку (id, тип области, id области, счёт) либо ничего.
type holdShape struct {
	subject      string // «User» либо «Account»
	state        string // «owns accounts» … — середина прежнего текста
	metadataType string
	step         func(h heldBy) string
	read         string
}

// firstOf — первый (наименьший id) держащий и их число одним оператором:
// оконный счёт считается по всему набору до LIMIT.
func firstOf(table, column string) string {
	return `SELECT id, '', '', count(*) OVER () FROM kaname.` + table +
		` WHERE ` + column + ` = $1 ORDER BY id LIMIT 1`
}

var holdShapes = map[iamerr.HoldKind]holdShape{
	iamerr.HoldAccountsOwned: {
		subject: "User", state: "owns accounts", metadataType: "account",
		step: func(h heldBy) string {
			return fmt.Sprintf("delete Account %s first (accounts owned: %d)", h.ID, h.Count)
		},
		read: firstOf("accounts", "owner_user_id"),
	},
	iamerr.HoldActiveBindings: {
		subject: "User", state: "has active access bindings", metadataType: "access_binding",
		step: func(h heldBy) string {
			return fmt.Sprintf("AccessBinding %s on %s %s is revoked by an administrator of that %s (active bindings: %d)",
				h.ID, h.ScopeType, h.ScopeID, h.ScopeType, h.Count)
		},
		// Условие действующей выдачи — то же, что у охраны `userWriter.Delete`:
		// legacy-проекция subjects[0] и строки `access_binding_subjects`,
		// `revoked_at IS NULL`. UNION снимает выдачу, названную обеими.
		read: `
			WITH h AS (
				SELECT b.id, b.resource_type, b.resource_id FROM kaname.access_bindings b
				 WHERE b.subject_type = 'user' AND b.subject_id = $1 AND b.revoked_at IS NULL
				UNION
				SELECT b.id, b.resource_type, b.resource_id FROM kaname.access_binding_subjects s
				  JOIN kaname.access_bindings b ON b.id = s.binding_id
				 WHERE s.subject_type = 'user' AND s.subject_id = $1 AND b.revoked_at IS NULL
			)
			SELECT id, resource_type, resource_id, count(*) OVER () FROM h ORDER BY id LIMIT 1`,
	},
	iamerr.HoldGroupMembership: {
		subject: "User", state: "is a member of one or more groups", metadataType: "group",
		step: func(h heldBy) string {
			return fmt.Sprintf("Group %s removes the member by its administrator (groups: %d)", h.ID, h.Count)
		},
		read: `SELECT group_id, '', '', count(*) OVER () FROM kaname.group_members
		        WHERE member_type = 'user' AND member_id = $1 ORDER BY group_id LIMIT 1`,
	},
	iamerr.HoldProjects: {
		subject: "Account", state: "contains projects", metadataType: "project",
		step: func(h heldBy) string {
			return fmt.Sprintf("delete Project %s first (projects: %d)", h.ID, h.Count)
		},
		read: firstOf("projects", "account_id"),
	},
	iamerr.HoldServiceAccounts: {
		subject: "Account", state: "contains service accounts", metadataType: "service_account",
		step: func(h heldBy) string {
			return fmt.Sprintf("delete ServiceAccount %s first (service accounts: %d)", h.ID, h.Count)
		},
		read: firstOf("service_accounts", "account_id"),
	},
	iamerr.HoldGroups: {
		subject: "Account", state: "contains groups", metadataType: "group",
		step: func(h heldBy) string {
			return fmt.Sprintf("delete Group %s first (groups: %d)", h.ID, h.Count)
		},
		read: firstOf("groups", "account_id"),
	},
	iamerr.HoldCustomRoles: {
		subject: "Account", state: "contains custom roles", metadataType: "role",
		step: func(h heldBy) string {
			return fmt.Sprintf("delete Role %s first (custom roles: %d)", h.ID, h.Count)
		},
		read: firstOf("roles", "account_id"),
	},
}

// holdBaseText — прежний текст отказа вида ДОСЛОВНО: он остаётся префиксом
// нового (Р1), и его же отдаёт рубеж схемы до дочитывания. Одно место на оба
// рубежа — иначе тексты охраны и схемы разошлись бы молча.
func holdBaseText(kind iamerr.HoldKind, subjectID string) string {
	s := holdShapes[kind]
	return s.subject + " " + subjectID + " " + s.state + " and cannot be deleted"
}

// heldRefusal — отказ вида без дочитанного остатка: полоса [iamerr.HeldBy] и
// прежний текст. Это вход [nameHold], а наружу он уходит только тогда, когда
// дочитать не удалось (база не ответила на чтение) — отказ при этом остаётся
// правдой и не выдумывает держащего.
func heldRefusal(kind iamerr.HoldKind, subjectID string) error {
	return iamerr.Wrapf(iamerr.HeldBy(kind), "%s", holdBaseText(kind, subjectID))
}

// holdRefusal — окончательный отказ: прежний текст, `: `, шаг и счёт; first ==
// nil — держащих этого вида уже нет, текст «повторите», держащего нет (Р2).
func holdRefusal(kind iamerr.HoldKind, subjectID string, first *heldBy) error {
	s := holdShapes[kind]
	base := holdBaseText(kind, subjectID)
	if first == nil {
		return iamerr.NamedHold(base+": nothing holds it now, retry the deletion", nil)
	}
	return iamerr.NamedHold(base+": "+s.step(*first), &iamerr.Holder{
		ResourceType: s.metadataType, ResourceID: first.ID, Remaining: first.Count,
	})
}

// readHolder — первый держащий вида и их число; (nil, nil) — держащих нет.
func readHolder(ctx context.Context, q pgx.Tx, kind iamerr.HoldKind, subjectID string) (*heldBy, error) {
	var h heldBy
	err := q.QueryRow(ctx, holdShapes[kind].read, subjectID).Scan(&h.ID, &h.ScopeType, &h.ScopeID, &h.Count)
	if stderrors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &h, nil
}

// nameHold — отказ refusal, если он полосы [iamerr.HeldBy], дополняется
// первым держащим и счётом чтением на tx; прочие отказы возвращаются как есть.
// Отказ чтения не подменяет отказа снятия: возвращается refusal.
func nameHold(ctx context.Context, tx pgx.Tx, refusal error, subjectID string) error {
	kind, ok := iamerr.HoldKindOf(refusal)
	if !ok {
		return refusal
	}
	first, err := readHolder(ctx, tx, kind, subjectID)
	if err != nil {
		return refusal
	}
	return holdRefusal(kind, subjectID, first)
}

// deleteUnderSavepoint — оператор снятия под точкой сохранения. run получает
// транзакцию точки и возвращает отказ, уже разобранный `mapErr`. Отказ полосы
// [iamerr.HeldBy] — отказ схемы на операторе — отменяется до точки, и остаток
// дочитывается на живой транзакции; прочие отказы возвращаются как есть.
func deleteUnderSavepoint(ctx context.Context, tx pgx.Tx, kindHint, subjectID string, run func(sp pgx.Tx) error) error {
	sp, err := tx.Begin(ctx)
	if err != nil {
		return mapErr(err, kindHint, subjectID)
	}
	if rerr := run(sp); rerr != nil {
		if _, held := iamerr.HoldKindOf(rerr); held {
			if err := sp.Rollback(ctx); err != nil {
				return rerr
			}
			return nameHold(ctx, tx, rerr, subjectID)
		}
		return rerr
	}
	if err := sp.Commit(ctx); err != nil {
		return mapErr(err, kindHint, subjectID)
	}
	return nil
}
