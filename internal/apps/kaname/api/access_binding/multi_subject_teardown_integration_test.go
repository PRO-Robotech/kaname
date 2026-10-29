// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// multi_subject_teardown_integration_test.go — снятие выдачи нескольким
// субъектам оставляет след о КАЖДОМ субъекте (перепись класса kaname#880).
//
// Создание пишет строку аудита «выдано» на каждого субъекта (`create.go`).
// Снятие обязано отвечать тем же перечнем: строку журнала смены субъекта
// (по ней сбрасывается кэш решений и закрываются потоки субъекта) и строку
// аудита «отозвано». Читать перечень после удаления строки выдачи нельзя:
// дочерние строки субъектов уходят каскадом в той же транзакции, и
// перечень вырождается в одиночную проекцию — первого субъекта.
//
// Мир — П1 (`system_class_world_integration_test.go`): выдача `rol-read`
// человеку usr-B и учётке sva-A на obj-1.

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// twoSubjectsGrant — выдача `rol-read` на obj-1 человеку usr-B и учётке sva-A.
func (w *scWorld) twoSubjectsGrant() (id string, subjects []string) {
	w.t.Helper()
	req := withSubjects(w.sc01Request(),
		userSubject(w.usrB),
		&iamv1.Subject{Type: iamv1.SubjectType_SUBJECT_TYPE_SERVICE_ACCOUNT, Id: string(w.svaA)})
	id = w.createDone(asUser(w.ctx, w.usrA), req, "выдача двум субъектам")
	subjects = []string{string(w.usrB), string(w.svaA)}
	sort.Strings(subjects)
	return id, subjects
}

// subjectChangesOf — субъекты строк журнала смены субъекта события `op`.
func (w *scWorld) subjectChangesOf(op string, subjects []string) []string {
	w.t.Helper()
	rows, err := w.pool.Query(w.ctx,
		`SELECT DISTINCT subject_id FROM kaname.subject_change_outbox
		  WHERE event_type = 'binding_revoke' AND op = $1 AND subject_id = ANY($2)
		  ORDER BY subject_id`, op, subjects)
	require.NoError(w.t, err, "чтение журнала смены субъекта")
	return collectStrings(w.t, rows)
}

// revokedAuditSubjects — субъекты строк аудита «отозвано» выдачи id.
func (w *scWorld) revokedAuditSubjects(id string) []string {
	w.t.Helper()
	rows, err := w.pool.Query(w.ctx,
		`SELECT DISTINCT event_payload->>'subject_id' FROM kaname.audit_outbox
		  WHERE event_type = 'iam.access_binding.revoked' AND event_payload->>'binding_id' = $1
		  ORDER BY 1`, id)
	require.NoError(w.t, err, "чтение аудита")
	return collectStrings(w.t, rows)
}

// grantedAuditSubjects — субъекты строк аудита «выдано» выдачи id (близнец).
func (w *scWorld) grantedAuditSubjects(id string) []string {
	w.t.Helper()
	rows, err := w.pool.Query(w.ctx,
		`SELECT DISTINCT event_payload->>'subject_id' FROM kaname.audit_outbox
		  WHERE event_type = 'iam.access_binding.granted' AND event_payload->>'binding_id' = $1
		  ORDER BY 1`, id)
	require.NoError(w.t, err, "чтение аудита")
	return collectStrings(w.t, rows)
}

type stringRows interface {
	Next() bool
	Scan(...any) error
	Err() error
	Close()
}

func collectStrings(t *testing.T, rows stringRows) []string {
	t.Helper()
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var s string
		require.NoError(t, rows.Scan(&s))
		out = append(out, s)
	}
	require.NoError(t, rows.Err())
	return out
}

// TestMultiSubjectTeardown_DeleteNamesEverySubject — удаление выдачи двум
// субъектам пишет строку смены субъекта и аудит «отозвано» на ОБОИХ. Близнец —
// аудит «выдано» той же выдачи: он уже называет обоих.
func TestMultiSubjectTeardown_DeleteNamesEverySubject(t *testing.T) {
	w := newSCWorld(t)
	id, subjects := w.twoSubjectsGrant()
	require.Equal(t, subjects, w.grantedAuditSubjects(id), "близнец: аудит «выдано» называет каждого субъекта")

	w.ownerMayRemove("удаление: Дано", id)
	op, err := w.ab.Delete(asUser(w.ctx, w.usrA), &iamv1.DeleteAccessBindingRequest{AccessBindingId: id})
	require.NoError(t, err, "удаление выдачи")
	done := awaitOp(t, w.ctx, w.ops, op.GetId())
	require.Nilf(t, done.Error, "операция удаления завершилась ошибкой %+v", done.Error)

	require.Equal(t, subjects, w.subjectChangesOf("binding_delete", subjects),
		"удаление: строка смены субъекта — на каждого субъекта выдачи")
	require.Equal(t, subjects, w.revokedAuditSubjects(id), "удаление: аудит «отозвано» — на каждого субъекта выдачи")
}

// TestMultiSubjectTeardown_RevokeNamesEverySubject — отзыв выдачи двум
// субъектам пишет аудит «отозвано» на обоих; строка смены субъекта (уже
// развёрнутая по перечню) — близнец.
func TestMultiSubjectTeardown_RevokeNamesEverySubject(t *testing.T) {
	w := newSCWorld(t)
	id, subjects := w.twoSubjectsGrant()

	w.ownerMayRemove("отзыв: Дано", id)
	revoke := accessbindingapp.NewRevokeAccessBindingUseCase(w.repo, w.ops).WithRelationStore(w.door, nil)
	op, err := revoke.Execute(asUser(w.ctx, w.usrA), domain.AccessBindingID(id))
	require.NoError(t, err, "отзыв выдачи")
	done := awaitOp(t, w.ctx, w.ops, op.ID)
	require.Nilf(t, done.Error, "операция отзыва завершилась ошибкой %+v", done.Error)

	require.Equal(t, subjects, w.subjectChangesOf("binding_delete", subjects),
		"близнец: строка смены субъекта при отзыве — на каждого субъекта выдачи")
	require.Equal(t, subjects, w.revokedAuditSubjects(id), "отзыв: аудит «отозвано» — на каждого субъекта выдачи")
}
