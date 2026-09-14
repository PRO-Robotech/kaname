// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// limit_reader_grant_revoked_integration_test.go — ВЫДАЧА ПРАВА ЧИТАТЬ ПРЕДЕЛЫ
// СНЯТА, и снята целиком.
//
// Задача `kaname#59`, стадия S4 `kacho#2117`.
//
// # Почему утверждается СОСТОЯНИЕ, а не факт наката
//
// Пройденная миграция сама по себе не значит ничего: накат, состоящий из
// пустых операторов, тоже проходит. Утверждается то, что видно снаружи, —
// выдачи нет, проекция снята, след оставлен, — и каждое из трёх могло бы не
// сработать молча.
//
// # Положительный контроль обязателен
//
// Три утверждения ниже — отрицания («строк нет»). На базе, где накат не дошёл
// вовсе либо снёс системную поверхность целиком, они зеленели бы все. Поэтому
// рядом стоит перепись: системных выдач ОСТАЛОСЬ больше нуля, и выдача с
// другим отношением на том же якоре цела.
package migrations_test

import (
	"database/sql"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// limitReaderRelation — отношение, чья выдача снимается. Один раз на файл:
// два места об одном предмете разошлись бы молча.
const limitReaderRelation = "quota_reader"

// limitReaderGrantVersion — версия миграции отзыва. Названа ЧИСЛОМ, а не
// выведена из положения в каталоге: положение и есть то допущение, которое
// ломается от появления следующей миграции.
const limitReaderGrantVersion int64 = 20260914091500

func TestLimitReaderGrant_IsRevokedAndLeavesATrace(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	db, err := sql.Open("pgx", pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	defer db.Close()
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.Up(db, "."))

	// ── ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ ──────────────────────────────────────────────
	// Без него отрицания ниже зеленеют на базе, где системной поверхности нет
	// вовсе, и «выдача снята» становится неотличимо от «накат не дошёл».
	var systemGrants int
	require.NoError(t, db.QueryRow(
		`SELECT count(*) FROM kaname.access_bindings WHERE is_system`).Scan(&systemGrants))
	require.Positive(t, systemGrants,
		"системных выдач ноль — отрицания ниже беспредметны, накат не дошёл до посева")

	var neighbour int
	require.NoError(t, db.QueryRow(
		`SELECT count(*) FROM kaname.access_bindings
		  WHERE is_system AND granted_relation = 'fga_writer'`).Scan(&neighbour))
	require.Positive(t, neighbour,
		"соседняя выдача отношения на том же якоре снята — отзыв задел не свой предмет")

	// ── УТВЕРЖДЕНИЕ 1: выдачи нет ───────────────────────────────────────────
	var grants int
	require.NoError(t, db.QueryRow(
		`SELECT count(*) FROM kaname.access_bindings WHERE granted_relation = $1`,
		limitReaderRelation).Scan(&grants))
	require.Zero(t, grants, "выдача права читать пределы пережила отзыв")

	// ── УТВЕРЖДЕНИЕ 2: проекция снята ───────────────────────────────────────
	// Прямой факт ведёт триггер журнала, а не миграция. Утверждается ИСХОД
	// этого пути: строка события снятия доехала и проекция ей последовала.
	var facts int
	require.NoError(t, db.QueryRow(
		`SELECT count(*) FROM kaname.relation_fact WHERE relation = $1`,
		limitReaderRelation).Scan(&facts))
	require.Zero(t, facts, "прямой факт права пережил снятие кортежа")

	var emitted int
	require.NoError(t, db.QueryRow(
		`SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE relation = $1`,
		limitReaderRelation).Scan(&emitted))
	require.Zero(t, emitted, "ведомость эмитированного не ушла каскадом за выдачей")

	// ── УТВЕРЖДЕНИЕ 3: след оставлен ────────────────────────────────────────
	// Без него «отобрано» неотличимо от «никогда не выдавалось».
	var trace int
	require.NoError(t, db.QueryRow(
		`SELECT count(*) FROM kaname.audit_outbox
		  WHERE event_type = 'iam.access_binding.revoked'
		    AND event_payload ->> 'granted_relation' = $1`,
		limitReaderRelation).Scan(&trace))
	require.Equal(t, 1, trace, "отзыв не оставил следа в журнале служебных записей")

	t.Logf("перепись: системных выдач осталось %d; выдач права «%s» %d; прямых фактов %d; "+
		"строк ведомости эмитированного %d; записей следа %d",
		systemGrants, limitReaderRelation, grants, facts, emitted, trace)
}

// TestLimitReaderGrant_DownRestoresTheGrantAndTheReapplyConverges — откат.
//
// `Down` пишут все, исполняет редко кто: неверный откат обнаруживается в день,
// когда он понадобился. Здесь он возвращает выдачу И её кортеж, и любое из
// двух могло бы не сработать молча.
func TestLimitReaderGrant_DownRestoresTheGrantAndTheReapplyConverges(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	db, err := sql.Open("pgx", pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	defer db.Close()
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.Up(db, "."))

	// Откат идёт ДО СВОЕЙ версии, а не «на один шаг»: шаг утверждал бы, что
	// предмет пробы — последняя миграция дерева, и ломался бы от следующей.
	steps := 0
	for {
		v, verr := goose.GetDBVersion(db)
		require.NoError(t, verr)
		if v < limitReaderGrantVersion {
			break
		}
		require.NoError(t, goose.Down(db, "."), "откат обязан проходить")
		steps++
	}
	require.Positive(t, steps, "откат не сделал ни шага — утверждения ниже беспредметны")
	t.Logf("откат: миграций снято %d (до версии ниже %d)", steps, limitReaderGrantVersion)

	var restored int
	require.NoError(t, db.QueryRow(
		`SELECT count(*) FROM kaname.access_bindings WHERE granted_relation = $1`,
		limitReaderRelation).Scan(&restored))
	require.Equal(t, 1, restored, "откат не вернул выдачу")

	var facts int
	require.NoError(t, db.QueryRow(
		`SELECT count(*) FROM kaname.relation_fact WHERE relation = $1`,
		limitReaderRelation).Scan(&facts))
	require.Equal(t, 1, facts, "откат вернул выдачу, но не её прямой факт — право не действует")

	// Повторный накат: откат, оставивший дерево непригодным для наката, хуже
	// отсутствующего.
	require.NoError(t, goose.Up(db, "."), "повторный накат обязан сходиться")

	var again int
	require.NoError(t, db.QueryRow(
		`SELECT count(*) FROM kaname.access_bindings WHERE granted_relation = $1`,
		limitReaderRelation).Scan(&again))
	require.Zero(t, again, "повторный накат не снял возвращённую откатом выдачу")
}
