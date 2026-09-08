// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// pgmaperr_role_name_form_test.go — форма имени РОЛИ тоже защита последнего
// рубежа, и её срабатывание — НАШ дефект (задача #1903).
//
// Предмет. Общий предикат полосы (`nameform.IsConstraint`) опознаёт ограничение
// точным сравнением `<таблица>_name_check`. У роли ограничений формы ДВА, по
// одному на ярус, и названы они `roles_custom_name_check` / `roles_system_name_check`
// — конструкции они не отвечают и потому не опознавались НИКОГДА. Между тем форму
// имени роли iam проверяет сам, до вставки (`RoleName.ValidateAtTier` — зеркало
// обоих ограничений), значит их срабатывание означает «сервис пропустил негодное
// значение», а отвечало оно `INVALID_ARGUMENT`, обвиняя вызывающего в чужой
// ошибке и не записывая в журнал ничего.
//
// Цена — не в коде отказа, а в НАБЛЮДАЕМОСТИ: полоса дефекта сервиса пишет
// `slog.Error` с именем ограничения и таблицей, полоса ввода не пишет ничего.
// «Ноль таких за всю жизнь» было неотличимо от «никто не смотрел».

import (
	stderrors "errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// roleNameFormConstraints — ограничения формы имени роли, по одному на ярус.
var roleNameFormConstraints = []string{"roles_custom_name_check", "roles_system_name_check"}

// TestWrapPgErr_RoleNameForm_IsOurDefectNotCallerInput — полоса формы имени роли.
func TestWrapPgErr_RoleNameForm_IsOurDefectNotCallerInput(t *testing.T) {
	for _, c := range roleNameFormConstraints {
		t.Run(c, func(t *testing.T) {
			pgErr := &pgconn.PgError{
				Code:           "23514",
				ConstraintName: c,
				TableName:      "roles",
				Message:        secretMessage,
				Detail:         secretDetail,
			}
			err := wrapPgErr(pgErr, "role", "rol-1")

			if stderrors.Is(err, iamerr.ErrInvalidArg) {
				t.Fatalf("отказ формы имени роли объявлен ошибкой ВВОДА — вызывающий "+
					"обвинён в нашем дефекте: %v", err)
			}
			if !stderrors.Is(err, iamerr.ErrInternal) {
				t.Fatalf("want ErrInternal, got %v", err)
			}
			out := iamerr.StripSentinel(err)
			// Текст, ВЫПИСЫВАЮЩИЙ форму, переживает её смену молча — тот же
			// довод, что у соседней полосы.
			if strings.Contains(out, "a-z0-9") || strings.Contains(out, "roles/") {
				t.Errorf("текст отказа выписывает форму (%q) — он переживёт её смену молча", out)
			}
			assertNoLeak(t, out)
		})
	}
	t.Logf("осмотрено ограничений формы имени роли: %d — %s",
		len(roleNameFormConstraints), strings.Join(roleNameFormConstraints, ", "))
}

// TestWrapPgErr_RoleOtherChecks_StayCallerInput — ЗАКОННЫЕ БЛИЗНЕЦЫ.
//
// Без них утверждение выше зеленело бы на отображении, объявившем нашим дефектом
// всякую проверку таблицы `roles`: тогда арендатор перестал бы узнавать, что
// именно во вводе неверно.
func TestWrapPgErr_RoleOtherChecks_StayCallerInput(t *testing.T) {
	cases := []struct{ constraint, table, wantIn string }{
		// Длину описания проверяет и вызывающий, и база — это его ввод.
		{"roles_description_check", "roles", "description"},
		// Ловушка суффиксного предиката на СВОЕЙ таблице: имя кончается на
		// `_name_check`, но сторожит длину другого поля.
		{"users_display_name_check", "users", "display_name"},
	}
	for _, c := range cases {
		t.Run(c.constraint, func(t *testing.T) {
			pgErr := &pgconn.PgError{
				Code:           "23514",
				ConstraintName: c.constraint,
				TableName:      c.table,
				Message:        secretMessage,
				Detail:         secretDetail,
			}
			err := wrapPgErr(pgErr, "", "")
			if !stderrors.Is(err, iamerr.ErrInvalidArg) {
				t.Fatalf("проверка НЕ формы имени обязана остаться отказом по вводу, got %v", err)
			}
			out := iamerr.StripSentinel(err)
			if !strings.Contains(out, c.wantIn) {
				t.Errorf("отказ обязан называть поле %q, got %q", c.wantIn, out)
			}
			assertNoLeak(t, out)
		})
	}
	t.Logf("осмотрено законных близнецов: %d", len(cases))
}

// callerInputNameChecks — ВЕДОМОСТЬ: ограничения с суффиксом `_name_check`,
// которые формой имени ресурса НЕ являются и потому законно остаются отказом по
// вводу. Запись несёт причину; запись, которой нечего исключать, — находка
// (проверяется ниже).
var callerInputNameChecks = map[string]string{
	"users_display_name_check": "сторожит ДЛИНУ отображаемого имени, а не форму имени ресурса; " +
		"вызывающий вправе узнать, что именно во вводе неверно",
}

// TestEveryNameCheckConstraintHasADecidedLane — перепись по дереву: у КАЖДОГО
// ограничения `*_name_check` схемы решена полоса.
//
// Почему перепись, а не перечень в тесте. Ограничение заводится миграцией, и
// новое приезжает без спроса у этого файла. Перечень, выписанный рукой, о нём не
// узнает — и молчание будет неотличимо от согласия. Гейт выводит популяцию из
// миграций и падает на пустом обходе.
func TestEveryNameCheckConstraintHasADecidedLane(t *testing.T) {
	dir := filepath.Join(serviceModuleRoot(t), "internal", "migrations")

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("каталог миграций не прочитан (%v): обход пуст, вердикт беспредметен", err)
	}

	var (
		filesRead   int
		pairs       = map[string]string{} // ограничение → таблица
		alterCheck  = regexp.MustCompile(`(?is)ALTER\s+TABLE\s+(?:ONLY\s+|IF\s+EXISTS\s+)?kaname\.([a-z_0-9]+)\s+ADD\s+CONSTRAINT\s+([a-z_0-9]+)\s+CHECK`)
		createTable = regexp.MustCompile(`(?is)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?kaname\.([a-z_0-9]+)\s*\((.*?)\n\);`)
		inlineCheck = regexp.MustCompile(`(?is)CONSTRAINT\s+([a-z_0-9]+)\s+CHECK`)
	)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		body, rerr := os.ReadFile(filepath.Join(dir, e.Name()))
		if rerr != nil {
			t.Fatalf("миграция %s не прочитана: %v", e.Name(), rerr)
		}
		filesRead++
		// Комментарии снимаются ОБЯЗАТЕЛЬНО: шапки миграций называют имена
		// ограничений, объясняя их, и гейт по подстроке краснел бы на
		// собственном объяснении.
		code := stripSQLCommentsForLaneCensus(string(body))
		for _, m := range alterCheck.FindAllStringSubmatch(code, -1) {
			pairs[m[2]] = m[1]
		}
		for _, m := range createTable.FindAllStringSubmatch(code, -1) {
			for _, c := range inlineCheck.FindAllStringSubmatch(m[2], -1) {
				if _, seen := pairs[c[1]]; !seen {
					pairs[c[1]] = m[1]
				}
			}
		}
	}

	if filesRead == 0 || len(pairs) == 0 {
		t.Fatalf("обход пуст: прочитано файлов %d, пар (ограничение→таблица) %d — "+
			"вердикт был бы о пустоте, а не о дереве", filesRead, len(pairs))
	}

	var nameChecks []string
	for c := range pairs {
		if strings.HasSuffix(c, "_name_check") {
			nameChecks = append(nameChecks, c)
		}
	}
	sort.Strings(nameChecks)
	if len(nameChecks) == 0 {
		t.Fatal("ограничений с суффиксом `_name_check` не найдено ни одного: " +
			"либо схема их лишилась, либо разбор их не видит — оба случая требуют взгляда")
	}

	var defectLane, callerLane int
	for _, c := range nameChecks {
		tbl := pairs[c]
		pgErr := &pgconn.PgError{Code: "23514", ConstraintName: c, TableName: tbl, Message: secretMessage}
		err := wrapPgErr(pgErr, "", "")

		switch {
		case stderrors.Is(err, iamerr.ErrInternal):
			defectLane++
			if why, listed := callerInputNameChecks[c]; listed {
				t.Errorf("%s (таблица %s) объявлен вводом («%s»), а отображение относит его "+
					"к дефекту сервиса — ведомость разошлась с кодом", c, tbl, why)
			}
		case stderrors.Is(err, iamerr.ErrInvalidArg):
			callerLane++
			if _, listed := callerInputNameChecks[c]; !listed {
				t.Errorf("%s (таблица %s) отвечает отказом по ВВОДУ и в ведомости не назван.\n"+
					"  Либо это форма имени, которую сервис проверяет сам, — тогда полоса "+
					"дефекта сервиса;\n  либо это проверка чужого поля — тогда назовите её в "+
					"callerInputNameChecks с причиной.", c, tbl)
			}
		default:
			t.Errorf("%s (таблица %s): полоса не решена вовсе, got %v", c, tbl, err)
		}
	}

	// Ведомость ИСТЕКАЕТ САМА: запись, которой нечего исключать, — находка.
	for c := range callerInputNameChecks {
		if _, alive := pairs[c]; !alive {
			t.Errorf("ведомость называет %s, а такого ограничения в миграциях нет: "+
				"исключение потеряло предмет и молча покрывало бы пустоту", c)
		}
	}

	t.Logf("перепись: прочитано миграций %d; ограничений CHECK распознано %d; из них "+
		"`*_name_check` %d; полоса дефекта сервиса %d; полоса ввода %d; записей ведомости %d",
		filesRead, len(pairs), len(nameChecks), defectLane, callerLane, len(callerInputNameChecks))
	if defectLane == 0 || callerLane == 0 {
		t.Fatal("перепись односторонняя: отображение, отвечающее одинаково на все " +
			"ограничения, прошло бы этот гейт")
	}
}

// serviceModuleRoot — корень МОДУЛЯ службы: подъём от каталога пакета до
// ближайшего `go.mod`.
//
// Берётся ближайший, а не самый внешний: у службы СВОЙ модуль, и её миграции
// лежат относительно него. Гейт от этого исполним и в отдельно вынесенном
// репозитории, где монорепо вокруг нет вовсе.
func serviceModuleRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("рабочий каталог не установлен: %v", err)
	}
	for i := 0; i < 12; i++ {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("корень модуля не найден: подъём от каталога пакета не встретил go.mod — " +
		"обход был бы пуст, а его молчание неотличимо от согласия")
	return ""
}

// stripSQLCommentsForLaneCensus — текст без комментариев SQL.
func stripSQLCommentsForLaneCensus(src string) string {
	src = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(src, " ")
	return regexp.MustCompile(`--[^\n]*`).ReplaceAllString(src, " ")
}
