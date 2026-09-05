// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// binding_subject_projection_integration_test.go — накопленные выдачи без
// состава субъектов восстановлены обратным заполнением.
//
// ПРЕДМЕТ. Форма вердикта заходит в выдачи с пары «субъект + область» через
// дочернюю таблицу. Выдача, у которой строк там нет, невидима вердикту целиком:
// право записано, читается всеми списками — и не действует.
//
// На живом стенде таких выдач было 111 из 450 (110 — собственная выдача
// администратора на проект, одна — приглашение). Все они несли пару субъекта в
// собственной строке, поэтому состав восстановим без потери.
//
// ЧТО ЭТА ПРОБА НЕ ПРОВЕРЯЕТ. Она не утверждает, что состав появится сам у
// БУДУЩЕЙ выдачи: это свойство прод-кода, и держит его гейт дерева
// `TestBindingInsertAlwaysWritesItsSubjects`. Здесь — только исход миграции.

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestBindingSubjectBackfill_NoGrantLeftWithoutItsSubjects — после применения
// миграций в базе нет выдачи, которая несёт пару субъекта и при этом не имеет
// ни одной дочерней строки.
func TestBindingSubjectBackfill_NoGrantLeftWithoutItsSubjects(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Postgres container")
	}
	ctx, pool := kac127Setup(t)

	var total, orphan int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.access_bindings`).Scan(&total))
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kacho_iam.access_bindings b
		 WHERE b.subject_type IS NOT NULL AND b.subject_type <> ''
		   AND b.subject_id   IS NOT NULL AND b.subject_id   <> ''
		   AND NOT EXISTS (SELECT 1 FROM kacho_iam.access_binding_subjects s
		                    WHERE s.binding_id = b.id)`).Scan(&orphan))

	// Перепись объявляется всегда: «ноль находок» обязано быть отличимо от
	// «ноль строк вообще» — на пустой базе утверждение ниже выполняется само.
	t.Logf("перепись: выдач в базе %d, из них без состава субъектов %d", total, orphan)

	require.Zero(t, orphan,
		"выдача без состава субъектов невидима форме вердикта: право записано и не действует")
}
