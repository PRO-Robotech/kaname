// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// session_expiry_declared_once_test.go — гейт F4d-27 (Ф3-11): срок записи
// сессии человека объявлен в миграциях РОВНО ОДИН РАЗ; инъекция в обе стороны
// на синтетических телах; перепись объёма печатается; пустой обход — отказ.
package migrations_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// TestHumanSessionExpiryIsDeclaredOnce — по встроенному каталогу миграций.
func TestHumanSessionExpiryIsDeclaredOnce(t *testing.T) {
	found, census, err := migrations.ExpiryDeclarationsInFS(migrations.FS)
	require.NoError(t, err)
	t.Logf("перепись: %s", census)
	require.NotZero(t, census.Files, "пустой обход — отказ, а не ноль находок")
	require.NotZero(t, census.TableMentions, "таблица сессии не найдена ни одной миграцией — обход беспредметен")
	require.NotZero(t, census.ColumnsSeen, "столбцов таблицы сессии не осмотрено — обход беспредметен")
	require.Len(t, found, 1, "F4d-27: объявлений срока обязано быть ровно одно, найдено: %+v", found)
	require.Equal(t, "expires_at", found[0].Column)
	require.NotZero(t, census.MomentColumns,
		"положительный контроль различимости: моменты, сроком не являющиеся, обязаны быть осмотрены и не сосчитаны сроком")
}

// TestHumanSessionExpiryGateFallsOnASecondExpiry — инъекция в обе стороны на
// синтетических телах: второй столбец истечения в объявлении таблицы и окно
// бездействия добавлением столбца — красные с координатой; момент последнего
// предъявления в той же таблице и срок ДРУГОЙ таблицы — молчание.
func TestHumanSessionExpiryGateFallsOnASecondExpiry(t *testing.T) {
	base := `-- +goose Up
CREATE TABLE kaname.human_sessions (
    id text NOT NULL,
    authenticated_at timestamp with time zone NOT NULL,
    last_presented_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    ended_at timestamp with time zone,
    presented_methods text[] NOT NULL,
    CONSTRAINT human_sessions_expiry_after_auth_check CHECK ((expires_at > authenticated_at))
);
-- +goose Down
DROP TABLE kaname.human_sessions;
`
	t.Run("законное объявление — ровно одно, моменты молчат", func(t *testing.T) {
		found, census := migrations.ExpiryDeclarationsIn(map[string]string{"0001_base.sql": base})
		require.Len(t, found, 1)
		require.Equal(t, "expires_at", found[0].Column)
		require.Equal(t, 3, census.MomentColumns, "три момента без срока: authenticated_at, last_presented_at, ended_at")
	})
	t.Run("второй столбец истечения в объявлении таблицы — красное с координатой", func(t *testing.T) {
		injected := map[string]string{"0001_base.sql": base +
			`-- +goose Up
CREATE TABLE kaname.human_sessions_v2 (id text);
`, "0002_inject.sql": `-- +goose Up
CREATE TABLE kaname.human_sessions (
    id text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    valid_until timestamp with time zone NOT NULL
);
`}
		found, _ := migrations.ExpiryDeclarationsIn(injected)
		require.Len(t, found, 3, "оба срока второго файла и срок первого сосчитаны: %+v", found)
		names := map[string]bool{}
		for _, f := range found {
			names[f.File+":"+f.Column] = true
		}
		require.True(t, names["0002_inject.sql:valid_until"], "координата второго срока названа")
	})
	t.Run("окно бездействия добавлением столбца — красное с координатой", func(t *testing.T) {
		injected := map[string]string{"0001_base.sql": base, "0002_idle.sql": `-- +goose Up
ALTER TABLE kaname.human_sessions ADD COLUMN idle_timeout interval NOT NULL DEFAULT '30 minutes';
`}
		found, _ := migrations.ExpiryDeclarationsIn(injected)
		require.Len(t, found, 2)
		require.Equal(t, "idle_timeout", found[1].Column)
		require.Equal(t, "add-column", found[1].Form)
	})
	t.Run("окно бездействия моментом с именем о бездействии — красное", func(t *testing.T) {
		injected := map[string]string{"0001_base.sql": base, "0002_idle.sql": `-- +goose Up
ALTER TABLE kaname.human_sessions ADD COLUMN inactivity_expires_at timestamp with time zone;
`}
		found, _ := migrations.ExpiryDeclarationsIn(injected)
		require.Len(t, found, 2)
	})
	t.Run("законные близнецы молчат: момент предъявления той же таблицы и срок другой таблицы", func(t *testing.T) {
		twin := map[string]string{"0001_base.sql": base, "0002_other.sql": `-- +goose Up
CREATE TABLE kaname.recovery_codes (id text, expires_at timestamp with time zone NOT NULL);
ALTER TABLE kaname.human_sessions ADD COLUMN last_presented_at2 timestamp with time zone;
-- expires_at в комментарии второго срока не объявляет
`}
		found, census := migrations.ExpiryDeclarationsIn(twin)
		require.Len(t, found, 1, "срок другой таблицы и лишний момент — не находки: %+v", found)
		require.Equal(t, 4, census.MomentColumns)
	})
	t.Run("пустой обход — не ноль находок, а беспредметность", func(t *testing.T) {
		found, census := migrations.ExpiryDeclarationsIn(map[string]string{"0001_none.sql": "-- +goose Up\nCREATE TABLE kaname.other (id text);\n"})
		require.Empty(t, found)
		require.Zero(t, census.TableMentions, "гейт обязан отличать «таблицы нет» от «срок один»")
	})
}
