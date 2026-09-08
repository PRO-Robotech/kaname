// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package role

// delete_emits_revoke_test.go — ПОВЕДЕНЧЕСКАЯ проба симметрии снятия
// (PRO-Robotech/kacho#2055).
//
// Гейт дерева (`internal/check`, TestDeletingAnOwnObjectHasARevokeProducer)
// утверждает, что производитель отзыва ЕСТЬ у каждого пути снятия. Он читает
// синтаксис и о доезде до writer-tx не говорит ничего. Здесь утверждается
// второе: событие действительно доходит до писателя, несёт вид «отзыв» и
// называет ТОТ САМЫЙ снятый объект.
//
// Обе стороны названы: рядом положительный контроль — та же тройка на создании
// уже утверждается пробами меток, поэтому здесь контролем служит ВИД события.
// Утверждай проба только «событие эмитировано», она осталась бы зелёной на
// эмиссии вида «upsert» — то есть на прямо противоположном намерении.

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

func TestDeleteRole_EmitsRevokeEventInTheWriterTx(t *testing.T) {
	repo := newRlUpdRepo(domain.Labels{"team": "billing"})
	uc := NewDeleteRoleUseCase(repo, newRlFakeOps())

	_, err := uc.Execute(ownerCtx(), domain.RoleID(rlUpdRoleID))
	require.NoError(t, err)
	waitOps(t)

	want := strings.Join([]string{shared.ReconcileEventDelete, "iam.role", rlUpdRoleID}, "|")
	assert.Contains(t, repo.reconcilAll, want,
		"снятие роли обязано со-коммитить событие ОТЗЫВА на свой объект: без него "+
			"пообъектный кортеж владельца на удалённой роли доживает до "+
			"периодического прохода")

	// Отрицательный контроль той же оси: путь снятия НЕ вправе эмитировать
	// «upsert» на снятый объект — это материализовало бы доступ к тому, чего нет.
	notWant := strings.Join([]string{shared.ReconcileEventUpsert, "iam.role", rlUpdRoleID}, "|")
	assert.NotContains(t, repo.reconcilAll, notWant,
		"снятие не вправе эмитировать событие материализации на снятый объект")
}
