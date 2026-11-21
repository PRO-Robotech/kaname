// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
)

// Отрицательный RR witness относится только к новой ссылке GroupAddition.
// Он не подтверждает actor admission и не разрешает добавление участника.
// GLOBAL выбирается до entry; после full population compare под обоими
// GLOBAL coordinator locks точное отсутствие проверяется снова. Одного root
// epoch lock для USER недостаточно. Поздний reference check сохраняется.
type groupAdditionReferenceWitness struct {
	member domain.Subject
}

func discoverGroupAdditionReference(ctx context.Context, tx pgx.Tx, in policyWriteRequest, budget *relverdict.AdministrativeReadBudget) (policyWriteRequest, *groupAdditionReferenceWitness, int, error) {
	if err := ctx.Err(); err != nil {
		return in, nil, 0, err
	}
	if in.groupNative == nil || (in.groupNative.member.MemberType != domain.SubjectTypeServiceAccount && in.groupNative.member.MemberType != domain.SubjectTypeUser) {
		return in, nil, 0, nil
	}
	m := in.groupNative.member
	if tx == nil || budget == nil || in.kind != kaname.AuthorityGroup || in.groupID != m.GroupID || m.Validate() != nil || in.compareGlobalAbsence {
		return in, nil, 0, kaname.ErrInvalidAuthorityFencePlan
	}
	member := domain.Subject{Type: m.MemberType, ID: m.MemberID}
	if in.actor == member {
		// Отсутствующий actor обязан пройти обычный строгий admission.
		return in, nil, 0, nil
	}
	foundSubject, ownerIndex := false, -1
	for _, subject := range in.mutationSubjects {
		foundSubject = foundSubject || subject == member
	}
	for i, owner := range in.owners {
		if member.Type == domain.SubjectTypeServiceAccount && owner.Kind == "service_account" && owner.ID == string(m.MemberID) {
			if ownerIndex != -1 {
				return in, nil, 0, kaname.ErrInvalidAuthorityFencePlan
			}
			ownerIndex = i
		}
	}
	if !foundSubject || (member.Type == domain.SubjectTypeServiceAccount && ownerIndex == -1) {
		return in, nil, 0, kaname.ErrInvalidAuthorityFencePlan
	}
	if err := chargeNativePolicyBudget(budget, 1, 1); err != nil {
		return in, nil, 0, err
	}
	witness := &groupAdditionReferenceWitness{member: member}
	var exists bool
	if err := tx.QueryRow(ctx, witness.presenceQuery(), string(m.MemberID)).Scan(&exists); err != nil {
		return in, nil, 1, err
	}
	if exists {
		return in, nil, 1, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return in, nil, 1, err
	}
	// Исходный request и mutationSubjects неизменны; убираем только ownerref,
	// отсутствие которого доказано отдельным чтением, а не ошибкой discover.
	if ownerIndex != -1 {
		owners := make([]kaname.AuthorityOwnerRef, 0, len(in.owners)-1)
		owners = append(owners, in.owners[:ownerIndex]...)
		owners = append(owners, in.owners[ownerIndex+1:]...)
		in.owners = owners
	}
	in.global = true
	return in, witness, 1, nil
}

// Пропускается только физический strict epoch key отсутствующей новой ссылки.
// Логический guard остаётся в plan.guards и protected policy footprint.
func (w *groupAdditionReferenceWitness) excludes(key string) bool {
	return w.presenceQuery() != "" && key == subjectPolicyKey(w.member)
}

// Только две закрытые формы запроса; имя таблицы не приходит из request.
func (w *groupAdditionReferenceWitness) presenceQuery() string {
	if w == nil || w.member.ID == "" {
		return ""
	}
	switch w.member.Type {
	case domain.SubjectTypeUser:
		return `SELECT EXISTS(SELECT 1 FROM kaname.users WHERE id=$1)`
	case domain.SubjectTypeServiceAccount:
		return `SELECT EXISTS(SELECT 1 FROM kaname.service_accounts WHERE id=$1)`
	default:
		return ""
	}
}

func (w *groupAdditionReferenceWitness) recheck(ctx context.Context, writer *authorityWriteTx, budget *relverdict.AdministrativeReadBudget) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if w == nil {
		return nil
	}
	if w.presenceQuery() == "" || writer == nil || writer.writeTx == nil || writer.tx == nil || writer.fence.mode != kaname.AuthorityFenceGlobal {
		return kaname.ErrSourceUnconfirmed
	}
	if err := chargeNativePolicyBudget(budget, 1, 1); err != nil {
		return err
	}
	var exists bool
	// GLOBAL coordinator и compatibility coordinator удерживаются до конца TX.
	// Они исключают конкурентные signed/compatibility writers users и SA;
	// full population compare выполнен вызывающим protectPolicyPlan.
	// SELECT не добавляет поздних row locks после final clock.
	if err := writer.tx.QueryRow(ctx, w.presenceQuery(), string(w.member.ID)).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return kaname.ErrAuthorityClassificationChanged
	}
	return ctx.Err()
}
