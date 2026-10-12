// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// address_claimed_reason_integration_test.go — СЛОВАРЬ ПРИЧИН КОНЦА СЕССИИ
// ПОЛУЧАЕТ СЛОВО `address-claimed` (задача kaname#458; приёмка
// `docs/engineering/acceptance/unverified-address-passes-to-the-mailbox-owner.md`,
// редакция 3, сценарий A458-10, решения Р7 и §8 п. 4).
//
// # Испытуемый — новая миграция, и её версия пробе неизвестна
//
// Версию назначит реализация, поэтому проба ищет испытуемого в каталоге по
// СОДЕРЖАНИЮ: первая по возрастанию версий миграция, чей накат называет
// ограничение `human_sessions_ended_reason_check` и значение
// `'address-claimed'`. «Версия до испытуемого» — старшая версия каталога ниже
// него; пока испытуемого нет — голова каталога.
//
// Порядок в пробе несущий: сначала строится и проверяется «Дано» — база на
// версии до испытуемого, живые записи, близнец (слово отвергается ограничением
// словаря) — и только потом спрашивается испытуемый. Обратный порядок дал бы
// сломанной фикстуре выдать себя за отсутствующую миграцию.
package migrations_test

import (
	"errors"
	"io/fs"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// a458Word — слово причины перехода записи (приёмка, Р7), дословно.
const a458Word = "address-claimed"

// a458Catalog — каталог миграций и испытуемый в нём.
type a458Catalog struct {
	versions []int64
	subject  int64
	file     string
}

// preceding — старшая версия ниже испытуемого; без испытуемого — голова.
func (c a458Catalog) preceding() int64 {
	var best int64
	for _, v := range c.versions {
		if (c.subject == 0 || v < c.subject) && v > best {
			best = v
		}
	}
	return best
}

func a458ReadCatalog(t *testing.T) a458Catalog {
	t.Helper()
	entries, err := fs.ReadDir(migrations.FS, ".")
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): каталог миграций читается")
	var c a458Catalog
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".sql") {
			continue
		}
		prefix, _, ok := strings.Cut(name, "_")
		require.True(t, ok, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): имя миграции %s без версии", name)
		v, err := strconv.ParseInt(prefix, 10, 64)
		require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): версия миграции %s", name)
		c.versions = append(c.versions, v)
		body, err := fs.ReadFile(migrations.FS, name)
		require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): тело миграции %s", name)
		up := migrations.MigrationUpSection(string(body))
		if c.subject == 0 && strings.Contains(up, serEndedReasonCheck) && strings.Contains(up, "'"+a458Word+"'") {
			c.subject, c.file = v, name
		}
	}
	require.NotEmpty(t, c.versions, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): каталог миграций пуст — судить нечего")
	return c
}

// a458SQLState — код отказа базы; "" — не отказ базы.
func a458SQLState(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

// TestA458_10_AddressClaimedIsAWordOfTheSessionEndVocabulary — A458-10: на
// последней миграции слово принимается, чужое отвергается ограничением
// словаря (SQLSTATE 23514); откат переводит строки слова в `logout` и
// восстанавливает прежнее объявление; повторный накат проходит. Близнец — база
// до миграции: слово отвергается тем же ограничением.
func TestA458_10_AddressClaimedIsAWordOfTheSessionEndVocabulary(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	c := a458ReadCatalog(t)

	// Дано и близнец: база на версии до испытуемого, слово отвергается.
	db := serOpenAt(t, c.preceding())
	person := serSeedPerson(t, db, "a458")
	const before, claimed, foreign, afterDown = "hss-a458-0", "hss-a458-1", "hss-a458-2", "hss-a458-3"
	for i, id := range []string{before, claimed, foreign, afterDown} {
		serLiveRow(t, db, person, id, 0x4580+i)
	}
	at := serMoment()
	err := serEnd(db, before, at, a458Word)
	require.Error(t, err, "A458-10 близнец: до миграции снятие с %q обязано быть отвергнуто", a458Word)
	require.Equal(t, serEndedReasonCheck, serConstraintOf(err), "A458-10 близнец: отказ даёт ограничение словаря: %v", err)

	// Испытуемый.
	if c.subject == 0 {
		t.Fatalf("A458-10 ИСПЫТУЕМОГО НЕТ: в каталоге из %d миграций (голова %d) нет миграции, чей накат вводит '%s' в %s",
			len(c.versions), c.preceding(), a458Word, serEndedReasonCheck)
	}
	require.NoError(t, goose.UpTo(db, ".", c.subject), "A458-10: накат %s", c.file)
	require.NoError(t, serEnd(db, claimed, at, a458Word), "A458-10: запись с %q фиксируется", a458Word)
	err = serEnd(db, foreign, at, "sneeze")
	require.Error(t, err, "A458-10: слово вне словаря отвергается")
	require.Equal(t, serEndedReasonCheck, serConstraintOf(err), "A458-10: отказ даёт ограничение словаря: %v", err)
	require.Equal(t, "23514", a458SQLState(err), "A458-10: SQLSTATE 23514")

	// Откат: строки слова — `logout`, прежнее объявление возвращено.
	require.NoError(t, goose.DownTo(db, ".", c.preceding()), "A458-10: откат %s", c.file)
	if r := serReadRow(t, db, claimed).reason; r == nil || *r != "logout" {
		t.Fatalf("A458-10: после отката строка %q обязана стать `logout`, получено %s", a458Word, serReadRow(t, db, claimed))
	}
	err = serEnd(db, afterDown, at, a458Word)
	require.Equal(t, serEndedReasonCheck, serConstraintOf(err), "A458-10: после отката слово снова отвергается: %v", err)

	// Повторный накат.
	require.NoError(t, goose.UpTo(db, ".", c.subject), "A458-10: повторный накат")
}
