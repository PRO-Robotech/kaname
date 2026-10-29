// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"fmt"

	"github.com/PRO-Robotech/kaname/internal/service"
)

// RegistrationAudit — адаптер аудита регистрации объектов модулем (kaname#1005):
// вопрос «стоит ли кортеж» и строка журнала аудита — в транзакции вызывающего.
//
// Вопрос о кортеже нужен, чтобы событие называло ИЗМЕНЕНИЕ, а не доставку:
// повтор регистрации, чей кортеж уже стоит и чья проекция не сменилась, события
// не пишет. Читается прямой факт — единственный источник ответа о доступе.
type RegistrationAudit struct{}

// NewRegistrationAudit — конструктор композиционного корня.
func NewRegistrationAudit() *RegistrationAudit { return &RegistrationAudit{} }

// TupleStandsTx — стоит ли прямой факт кортежа в снимке транзакции вызывающего.
func (RegistrationAudit) TupleStandsTx(ctx context.Context, tx service.Tx, t service.RelationTuple) (bool, error) {
	objectType, objectID, ok := splitObjectRef(t.Object)
	if !ok {
		return false, fmt.Errorf("relation_fact: объект %q не разбирается как «тип:идентификатор»", t.Object)
	}
	var stands bool
	if err := txAsPgx(tx).QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM kaname.relation_fact
		                 WHERE object_type = $1 AND object_id = $2
		                   AND relation = $3 AND subject = $4)`,
		objectType, objectID, t.Relation, t.User).Scan(&stands); err != nil {
		return false, fmt.Errorf("relation_fact: стоит ли кортеж: %w", err)
	}
	return stands, nil
}

// EmitTx — строка журнала аудита той же транзакцией.
func (RegistrationAudit) EmitTx(ctx context.Context, tx service.Tx, ev service.AuditEvent) error {
	return insertAuditEventTx(ctx, txAsPgx(tx), ev)
}
