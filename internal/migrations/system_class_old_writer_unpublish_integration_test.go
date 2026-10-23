// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// system_class_old_writer_unpublish_integration_test.go — снятие публикации
// писателем ПРЕЖНЕГО выпуска после наката переезда на системные классы
// (задача PRO-Robotech/kaname#829, находка SD-829-1 рецензента распределённых
// свойств).
//
// Мигратор — init-контейнер нового пода, поэтому во время катящейся выкатки
// под прежнего выпуска служит уже на новой схеме. Снимая публикацию объекта,
// он кладёт в журнал `fga.tuple.delete` с субъектом-подстановкой `user:*`
// (эмиттер публикации ствола: `proxytuple.PublicReadSubject`), а хранимый
// после переезда факт — `system_class:anonymous #v_get`. По приёмке ред. 5
// исходов два: публикация снята ЛИБО строка прежнего писателя отвергнута базой.
// Третий — строка принята, факт уцелел — тихая порча: анонимное чтение
// остаётся у объекта, публикацию которого владелец снял.
//
// Положительный близнец — снятие той же публикации писателем нового выпуска
// (субъект `system_class:anonymous`). Против близнеца меняется ровно один
// факт — субъект строки журнала; объект, отношение, версия и состояние базы
// те же: каждая сторона идёт в своей транзакции, откатываемой после замера.
package migrations_test

import (
	"database/sql"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
)

const (
	sd1Object = "registry_repository:r-sd8291"
	sd1ObjID  = "r-sd8291"
	// sd1V0 — версия владельца публикации, sd1V1 — его более позднего снятия.
	sd1V0 = "2026-10-01T00:00:00Z"
	sd1V1 = "2026-10-02T00:00:00Z"
)

// sd1Unpublish — строка снятия публикации с субъектом subject и версией
// владельца sd1V1 — в форме эмиттера публикации, внутри транзакции tx.
func sd1Unpublish(tx *sql.Tx, subject string) error {
	_, err := tx.Exec(`
		INSERT INTO kaname.fga_outbox (event_type, payload, created_at)
		VALUES ('fga.tuple.delete',
		        jsonb_build_object('user', $1::text, 'relation', 'v_get',
		                           'object', $2::text, 'source_version', $3::timestamptz),
		        now())`, subject, sd1Object, sd1V1)
	return err
}

// sd1AnonymousFacts — число фактов анонимного чтения объекта.
func sd1AnonymousFacts(t *testing.T, q interface {
	QueryRow(string, ...any) *sql.Row
}) int {
	t.Helper()
	var n int
	require.NoError(t, q.QueryRow(`
		SELECT count(*) FROM kaname.relation_fact
		 WHERE object_type = 'registry_repository' AND object_id = $1
		   AND relation = 'v_get' AND subject = 'system_class:anonymous'`, sd1ObjID).Scan(&n))
	return n
}

// SD-829-1: после наката снятие публикации прежним писателем (`user:*`) либо
// снимает факт `system_class:anonymous #v_get`, либо отвергается базой.
func TestSystemClass_SD8291_OldWriterUnpublishAfterMove(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	p := openP2(t)

	// Дано: публикация, положенная на стволе (до переезда) с версией sd1V0.
	_, err := p.db.Exec(`
		INSERT INTO kaname.fga_outbox (event_type, payload, created_at)
		VALUES ('fga.tuple.write',
		        jsonb_build_object('user', 'user:*', 'relation', 'v_get',
		                           'object', $1::text, 'source_version', $2::timestamptz),
		        now())`, sd1Object, sd1V0)
	require.NoError(t, err, "Дано: публикация в форме ствола")
	require.True(t, trunkPublicRead(t, p.db, "registry_repository", sd1ObjID), "Дано: на П2 стоит факт user:* #v_get")

	require.NoError(t, goose.Up(p.db, "."), "накат миграций изменения")

	// Фикстура проверена ДО пробы предмета: переезд перенёс публикацию на класс.
	require.Equal(t, 1, sd1AnonymousFacts(t, p.db), "фикстура: после наката публикация — факт system_class:anonymous #v_get")

	// Близнец: писатель нового выпуска снимает публикацию — факт снят.
	twin, err := p.db.Begin()
	require.NoError(t, err)
	require.NoError(t, sd1Unpublish(twin, "system_class:anonymous"), "близнец: снятие новым писателем принято")
	require.Equal(t, 0, sd1AnonymousFacts(t, twin), "близнец: снятие новым писателем сняло факт анонимного чтения")
	require.NoError(t, twin.Rollback())

	// Предмет: та же строка с субъектом прежнего писателя.
	require.Equal(t, 1, sd1AnonymousFacts(t, p.db), "фикстура: откат близнеца вернул факт")
	old, err := p.db.Begin()
	require.NoError(t, err)
	t.Cleanup(func() { _ = old.Rollback() })
	err = sd1Unpublish(old, "user:*")
	if err != nil {
		// Исход «отвергнута» засчитывается только отказом базы, а не чем угодно.
		require.NotNilf(t, pgErrorOf(err), "SD-829-1: снятие прежним писателем отвергнуто не базой: %v", err)
		return
	}
	require.Equal(t, 0, sd1AnonymousFacts(t, old),
		"SD-829-1: снятие публикации прежним писателем (user:* #v_get, версия новее) принято без ошибки, "+
			"а факт system_class:anonymous #v_get на %s уцелел — публикация не снята молча", sd1Object)
}
