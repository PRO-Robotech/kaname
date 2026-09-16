// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// TestSQLRelationNaming_EverySpellingOfTheGrammar — по строке перечня шапки
// `sql_relation_name.go` на каждое написание; у каждой различающей оси —
// законный близнец, отличающийся от положительного случая одним фактом.
// Односторонняя проба зеленела бы на распознавателе, отвечающем «да» всему.
func TestSQLRelationNaming_EverySpellingOfTheGrammar(t *testing.T) {
	const rel = "user_login_methods"
	cases := []struct {
		name, src string
		relation  string // пусто — rel
		want      bool
	}{
		// ── имя вне строки ──────────────────────────────────────────────────
		{"без кавычек", `SELECT verifier FROM user_login_methods`, "", true},
		{"без кавычек, верхний регистр со схемой", `SELECT verifier FROM KANAME.USER_LOGIN_METHODS`, "", true},
		{"без кавычек, смешанный регистр", `FROM User_Login_Methods`, "", true},
		{"ONLY и псевдоним", `FROM ONLY user_login_methods AS m`, "", true},
		{"тип строки %ROWTYPE", `DECLARE r kaname.USER_LOGIN_METHODS%ROWTYPE;`, "", true},
		{"в кавычках точно", `FROM "user_login_methods"`, "", true},
		{"в кавычках, схема в кавычках", `FROM "kaname"."user_login_methods"`, "", true},
		{"в кавычках с удвоенной кавычкой", `FROM "we""ird"`, `we"ird`, true},
		{"U&\"…\" с \\XXXX", `FROM kaname.U&"user\005flogin_methods"`, "", true},
		{"u&\"…\" строчной приставкой", `FROM u&"user\005flogin_methods"`, "", true},
		{"U&\"…\" с \\+XXXXXX", `FROM U&"user\+00005flogin_methods"`, "", true},
		{"U&\"…\" с UESCAPE", `FROM U&"user!005flogin_methods" UESCAPE '!'`, "", true},
		{"U&\"…\" с UESCAPE через комментарий", "FROM U&\"user!005flogin_methods\" /* c */ uescape\n'!'", "", true},
		{"U&\"…\" с суррогатной парой", `FROM U&"x\D83D\DE00"`, "x😀", true},
		{"длиннее 63 байт — усечение базы", "FROM " + strings.Repeat("a", 70), strings.Repeat("a", 63), true},
		// ── имя внутри строки ───────────────────────────────────────────────
		{"строка, приводимая к regclass", `SELECT 'user_login_methods'::regclass`, "", true},
		{"строка, верхний регистр", `SELECT 'KANAME.USER_LOGIN_METHODS'::regclass`, "", true},
		{"строка, имя в кавычках точно", `SELECT '"user_login_methods"'::regclass`, "", true},
		{"E-строка, \\xhh", `SELECT E'user\x5flogin_methods'::regclass`, "", true},
		{"E-строка, \\ooo", `SELECT e'user\137login_methods'::regclass`, "", true},
		// Обратная коса собрана склейкой: она с буквой u и четырьмя цифрами в
		// исходнике пробы раскрывается средством, которым проба записана, — так
		// и случилось в первой редакции, и случай проверял не то.
		{"E-строка, \\uXXXX", "SELECT E'user\\" + "u005flogin_methods'::regclass", "", true},
		// Край диапазона экранирования — исход назван по базе (`kaname#161`,
		// проба исходов: `sql_relation_name_escape_test.go`). Восьмеричное выше
		// \377 база усекает до младшего байта: \563 → 's' — отказ раскрытия дал
		// бы ПРОПУСК этого имени. \U выше U+10FFFF база отвергает — экранирование
		// остаётся как написано, и обратная коса становится границей имени.
		{"E-строка, \\ooo выше \\377 — младший байт, как у базы", `SELECT E'user_login_method\563'::regclass`, "", true},
		{"E-строка, \\U выше U+10FFFF не раскрывается — коса граничит имя", `SELECT E'user_login_methods\UFFFFFFFF'`, "", true},
		{"E-строка, \\U00110000 — то же, первое значение вне диапазона", `SELECT E'user_login_methods\U00110000'`, "", true},
		// Экранированная кавычка не закрывает E-строку: иначе строка кончилась бы
		// на ней, а остаток ушёл бы в строчный комментарий вместе с именем.
		{"E-строка, экранированная кавычка не закрывает строку", `SELECT E'\' -- ', user_login_methods`, "", true},
		{"строка при standard_conforming_strings = off", `SELECT 'user\x5flogin_methods'::regclass`, "", true},
		{"N-строка", `SELECT N'user_login_methods'::regclass`, "", true},
		{"U&-строка", `SELECT U&'user\005flogin_methods'::regclass`, "", true},
		{"строка в долларах", `EXECUTE $$SELECT * FROM USER_LOGIN_METHODS$$`, "", true},
		{"строка в долларах с меткой", `EXECUTE $q$SELECT * FROM user_login_methods$q$`, "", true},
		{"строка в долларах внутри строки в долларах", `$a$ EXECUTE $b$SELECT * FROM user_login_methods$b$ $a$`, "", true},
		{"продолжение через перевод строки", "SELECT 'user_login_'\n  'methods'::regclass", "", true},
		{"продолжение через строчный комментарий", "SELECT 'user_login_'\n-- c\n  'methods'::regclass", "", true},
		{"склейка ||", `SELECT ('user_login_' || 'methods')::regclass`, "", true},
		{"склейка || из трёх звеньев", `EXECUTE 'SELECT * FROM kaname.' || 'user_login_' || 'methods'`, "", true},
		{"звено склейки само называет имя", `SELECT 'user_login_methods' || '_pkey'`, "", true},
		{"EXECUTE строки", `EXECUTE 'SELECT verifier FROM user_login_methods WHERE user_id = $1'`, "", true},
		{"аргумент format", `EXECUTE format('SELECT verifier FROM %I', 'user_login_methods')`, "", true},
		{"незакрытая строка осколка", `' FROM user_login_methods`, "", true},
		{"незакрытое имя в кавычках осколка", `" FROM user_login_methods`, "", true},
		{"вложенность глубже предела — без грамматики",
			`$a$ $b$ $c$ $d$ $e$ $f$ $g$ $h$ FROM "USER_LOGIN_METHODS" $h$ $g$ $f$ $e$ $d$ $c$ $b$ $a$`, "", true},
		// ── законные близнецы ───────────────────────────────────────────────
		{"близнец: в кавычках в другом регистре", `FROM "USER_LOGIN_METHODS"`, "", false},
		{"близнец: в кавычках с пробелом", `FROM "user_login_methods "`, "", false},
		{"близнец: U&\"…\" в другом регистре", `FROM U&"USER\005fLOGIN_METHODS"`, "", false},
		{"близнец: без UESCAPE знак экранирования не меняется", `FROM U&"user!005flogin_methods"`, "", false},
		{"близнец: зеркало с общей частью", `FROM w6_user_login_methods_mirror`, "", false},
		{"близнец: имя ограничения", `ALTER TABLE t DROP CONSTRAINT user_login_methods_pkey`, "", false},
		{"близнец: продолжение знаком доллара", `FROM user_login_methods$x`, "", false},
		{"близнец: продолжение буквой вне ASCII", `FROM user_login_methodsé`, "", false},
		{"близнец: буквы вне ASCII база не приводит", `SELECT * FROM ТЕСТ`, "тест", false},
		{"близнец: строчный комментарий", "SELECT 1 -- user_login_methods\n", "", false},
		{"близнец: вложенный блочный комментарий",
			`/* a /* user_login_methods */ всё ещё комментарий user_login_methods */ SELECT 1`, "", false},
		{"близнец: комментарий внутри строки", `EXECUTE 'SELECT 1 /* user_login_methods */'`, "", false},
		{"близнец: имя в кавычках внутри строки в другом регистре", `SELECT '"USER_LOGIN_METHODS"'::regclass`, "", false},
		{"близнец: склейка даёт имя ограничения", `SELECT 'user_login_' || 'methods_pkey'`, "", false},
		{"близнец: битовая строка не судится", `SELECT X'757365725f6c6f67696e5f6d6574686f6473'`, "", false},
		{"близнец: \\777 — байт 0xFF продолжает имя, как у базы", `SELECT E'user_login_methods\777'`, "", false},
		{"близнец: \\U0010FFFF раскрывается и продолжает имя", `SELECT E'user_login_methods\U0010FFFF'`, "", false},
		{"близнец: параметр, а не строка в долларах", `SELECT $1, $2 FROM t`, "", false},
		{"близнец: 64 байта не усекаются в чужое имя", "FROM " + strings.Repeat("a", 62), strings.Repeat("a", 63), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			relation := c.relation
			if relation == "" {
				relation = rel
			}
			require.Equal(t, c.want, check.SQLNamesRelation(c.src, relation),
				"%q: называет ли %q — ждали %v; формы %v", c.src, relation, c.want, check.SQLRelationNamings(c.src, relation))
		})
	}
}

// TestSQLRelationNaming_FormsAreNamed — перепись вызывающих печатает форму
// записи: у каждой — свой случай, иначе форма в переписи была бы словом.
func TestSQLRelationNaming_FormsAreNamed(t *testing.T) {
	const rel = "user_login_methods"
	for src, want := range map[string]string{
		`FROM USER_LOGIN_METHODS`:                      check.SQLFormBare,
		`FROM "user_login_methods"`:                    check.SQLFormQuoted,
		`FROM U&"user\005flogin_methods"`:              check.SQLFormUnicode,
		`EXECUTE 'SELECT 1 FROM "user_login_methods"'`: check.SQLFormInString,
	} {
		require.Equal(t, []string{want}, check.SQLRelationNamings(src, rel), "%q", src)
	}
}

// TestSQLRoutineNaming_LanguageChoosesTheGrammar — язык подпрограммы решает,
// судить ли грамматикой SQL. Текст на чужом языке судится без неё — лишней
// находкой, а не пропуском: строка Python в двойных кавычках для лексики SQL —
// имя в кавычках, и грамматика SQL пропустила бы в ней таблицу.
func TestSQLRoutineNaming_LanguageChoosesTheGrammar(t *testing.T) {
	const rel = "user_login_methods"
	py := `plpy.execute("SELECT verifier FROM user_login_methods")`
	names, grammar := check.SQLRoutineNamesRelation("plpython3u", py, rel)
	require.True(t, names, "текст на чужом языке судится без грамматики и находит имя")
	require.False(t, grammar)
	require.False(t, check.SQLNamesRelation(py, rel),
		"контроль предпосылки: грамматика SQL читает строку Python как имя в кавычках и имени таблицы в ней не видит")

	names, grammar = check.SQLRoutineNamesRelation("plpgsql", "BEGIN PERFORM 1 FROM KANAME.USER_LOGIN_METHODS; END", rel)
	require.True(t, names)
	require.True(t, grammar)

	names, _ = check.SQLRoutineNamesRelation("plpgsql", `BEGIN PERFORM 1 FROM kaname."USER_LOGIN_METHODS"; END`, rel)
	require.False(t, names, "близнец: грамматика SQL различает имя в кавычках")

	names, _ = check.SQLRoutineNamesRelation("c", "user_login_methods_handler", rel)
	require.False(t, names, "без грамматики имя всё равно судится целым словом")
}
