// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

// account_id_string_form_parity_integration_test.go — форма аккаунта и свёртка
// похожих знаков объявлены в схеме и в службе одним предикатом поштучно
// (задача kaname#1052, приёмка
// `docs/engineering/acceptance/account-id-may-be-supplied-at-create.md`, Р2,
// Р5, Р6а, Р10; держатель паритета AID-33 в новой редакции).
//
// # Почему паритет, а не прочтение
//
// Синтаксическую часть формы Р2 (а)–(г) судят два написания: распознаватель
// службы `domain.HasAccountIDSyntax` и функция схемы
// `kaname.account_id_has_account_form` (проверка реестра, отбор триггера,
// отбор обратного заполнения). Свёртку Р6а — `domain.FoldLookAlike` и
// `kaname.account_handle_fold` (ключ строк аккаунтов). Два написания одного
// предиката расходятся молча: диапазон вместо перечня знаков, забытое условие
// о двойном дефисе, свёртка заглавных. Проба сверяет вердикты ПОШТУЧНО на
// корпусе, где каждое негодное значение отличается от годного одним фактом, и
// доказывает в себе же, что корпус способен поймать расхождение: форма без
// условия о двойном дефисе и свёртка без `l` на нём расходятся со службой.
//
// Таблицы AID-05/AID-06 судят тот же паритет через реестр
// (`internal/apps/kaname/api/audit`, `TestAccountID33_RegistryFormAgreesWithTheTables`);
// здесь — функции схемы напрямую и на корпусе шире таблиц.

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// stringFormCorpus — годные значения формы аккаунта и негодные, каждое из
// которых отличается от годного одним фактом.
func stringFormCorpus() []string {
	out := []string{
		"dlputi1u", "godjee", "goj", "abcdefghijklmnopqrstuvwxyz0123", "god-jee", "g1odjee",
		"acc7m3k9q2x5v8b4n6t1", "acc1a18042d81fb438d6", ids.NewID(domain.PrefixAccount),
		"prj7m3k9q2x5v8b4n6t1", "acc-7m3k9q2x5v8b4n6t1", "personal-cloud-godjee",
		"Godjee", " godjee", "godjee ", "god_jee", "god.jee", "god:jee", "god#jee", "god/jee",
		"god--jee", "-godjee", "godjee-", "1godjee", "go", "abcdefghijklmnopqrstuvwxyz01234",
		"godjeе", "gödjee", "god jee", "", "a", "ab", "a-b", "a--b", "z9", "z99",
	}
	// Граница длины в обе стороны и дефис на каждой позиции строки из 5 знаков.
	out = append(out, strings.Repeat("a", 30), strings.Repeat("a", 31), strings.Repeat("a", 3))
	for i := 0; i < 5; i++ {
		b := []byte("abcde")
		b[i] = '-'
		out = append(out, string(b))
	}
	return out
}

// foldCorpus — строки свёртки: каждый сворачиваемый знак, его заглавный
// близнец (не сворачивается) и несворачиваемые соседи.
func foldCorpus() []string {
	return []string{
		"godjee", "g0djee", "dlputi1u", "dlputilu", "dlput11u", "OIL", "oil", "personal-cloud-",
		"pers0nal-c1oud-", "acc7m3k9q2x5v8b4n6tl", "kmnu", "", "ooo", "iii", "lll",
	}
}

func migratedToHead(t *testing.T) *sql.DB {
	t.Helper()
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db, err := sql.Open("pgx", pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.Up(db, "."), "цепь обязана доходить до головы")
	return db
}

// TestAccountIDStringFormInTheSchemaAgreesWithTheRecognizer — паритет (а)–(г).
func TestAccountIDStringFormInTheSchemaAgreesWithTheRecognizer(t *testing.T) {
	db := migratedToHead(t)

	var accepted, refused, diverged int
	for _, v := range stringFormCorpus() {
		var sqlVerdict bool
		require.NoError(t, db.QueryRow(`SELECT kaname.account_id_has_account_form($1)`, v).Scan(&sqlVerdict))
		goVerdict := domain.HasAccountIDSyntax(v)
		require.Equal(t, goVerdict, sqlVerdict, "%q: служба говорит %v, схема — %v", v, goVerdict, sqlVerdict)
		if goVerdict {
			accepted++
		} else {
			refused++
		}
		// Инъекция: та же форма без условия о двойном дефисе.
		var weaker bool
		require.NoError(t, db.QueryRow(
			`SELECT length($1) BETWEEN 3 AND 30 AND $1 ~ '^[a-z][a-z0-9-]*[a-z0-9]$'`, v).Scan(&weaker))
		if weaker != goVerdict {
			diverged++
		}
	}
	t.Logf("перепись формы: значений %d · годных %d · негодных %d · инъекция разошлась на %d",
		accepted+refused, accepted, refused, diverged)
	require.Positive(t, accepted, "корпус без годных значений судит только половину")
	require.Positive(t, refused, "корпус без негодных значений судит только половину")
	require.Positive(t, diverged, "корпус не отличает форму без условия о двойном дефисе")
}

// TestAccountHandleFoldInTheSchemaAgreesWithTheRecognizer — паритет свёртки Р6а.
func TestAccountHandleFoldInTheSchemaAgreesWithTheRecognizer(t *testing.T) {
	db := migratedToHead(t)

	var diverged int
	for _, v := range foldCorpus() {
		var sqlFold string
		require.NoError(t, db.QueryRow(`SELECT kaname.account_handle_fold($1)`, v).Scan(&sqlFold))
		require.Equal(t, domain.FoldLookAlike(v), sqlFold, "%q: свёртка службы и схемы расходятся", v)
		// Инъекция: свёртка без `l`.
		if strings.NewReplacer("o", "0", "i", "1").Replace(v) != sqlFold {
			diverged++
		}
	}
	t.Logf("перепись свёртки: значений %d · инъекция разошлась на %d", len(foldCorpus()), diverged)
	require.Positive(t, diverged, "корпус не отличает свёртку без `l`")
}
