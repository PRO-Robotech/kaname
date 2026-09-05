// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzmap_test

// МОДЕЛЬ И БАЗА ОБЯЗАНЫ НАЗЫВАТЬ ОДИН И ТОТ ЖЕ СОСТАВ ЧЛЕНОВ ГРУППЫ.
//
// Членство в группе объявлено ДВАЖДЫ: моделью прав (`type group`, `define
// member: [...]`) и схемой (`group_members_type_check`). Пока эти два места
// расходятся, продукт обещает возможность, которой не бывает: модель принимает
// вложенность групп и внешнего принципала, а вставка отвергает и то и другое.
// Это тот же класс, что «принято-и-проигнорировано», только на уровне
// авторизационного контракта — и он ТИШЕ: расхождение не проявляется ничем,
// пока кто-нибудь не попробует.
//
// ЭТО НЕ Г17, И ПУТАТЬ ИХ НЕЛЬЗЯ.
//
// Приёмка R7-2 (`docs/specs/sub-phase-R7-2-group-nesting-and-federated-subject-acceptance.md`,
// §6) заводит гейт **Г17**, сверяющий словарь члена группы в ТРЁХ местах:
// канон модели · **ПРИМЕНЁННАЯ схема** (запрос к системному каталогу после
// прогона всех миграций по порядку) · набор самопроверки домена
// (`GroupMember.Validate()`). Здесь сверяются ДВА, и схема читается ТЕКСТОМ
// миграции, а не применённой формой.
//
// Чего здесь по этой причине НЕ проверяется:
//
//	(1) третье место — самопроверка домена: её предмет заводится стадией S1,
//	    которая ещё не сделана, поэтому сверять пока не с чем;
//	(2) применённая схема: текст последней касавшейся миграции и результат
//	    применения ВСЕХ миграций — разные величины, и разойтись они могут
//	    молча (например условным DDL, чья ветвь не исполнилась).
//
// Что здесь всё-таки держится и почему это не бесполезно: правило читает
// **последнюю** миграцию, объявляющую ограничение, а не первую, — значит
// будущее сужение или расширение, пришедшее НОВОЙ миграцией (ban #5 иначе не
// позволяет), гейт увидит. Это промежуточная опора до Г17, а не его замена.
// Заведя Г17, эту пробу **снять** — два места об одном предмете разойдутся.
//
// РЕШЕНИЕ ЗАПИСАНО В ПОЛЬЗУ БАЗЫ (kacho#734,
// services/iam/docs/engineering/architecture/group-membership-is-one-level.md):
// вложенности не существует, движок отношений её и не реализует, а введение
// её — отдельная работа со своей приёмкой, потому что она двигает объявленный
// потолок стоимости вердикта. Гейт держит именно это решение: он не судит, чей
// состав «правильный», он требует, чтобы состав был ОДИН.
//
// ЧТО ГЕЙТ ЧИТАЕТ. С одной стороны — канонический текст модели; с другой —
// текст миграции, а не живую базу: предмет утверждения здесь свойство ДЕРЕВА,
// и подниматься ради него Postgres не должен. Ограничение ищется по имени
// среди ВСЕХ миграций, а последнее слово — за последней по порядку, которая его
// касается: иначе гейт судил бы отменённую редакцию.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/treecorpus"
	"github.com/stretchr/testify/require"
)

// migrationsGlob — где лежат миграции сервиса относительно корня монорепо.
const migrationsGlob = "services/iam/internal/migrations/*.sql"

// groupMemberCheckName — ограничение схемы, называющее допустимые виды члена.
const groupMemberCheckName = "group_members_type_check"

var (
	// reGroupMemberDefine — строка `define member: [...]` внутри `type group`.
	reMemberDefine = regexp.MustCompile(`^\s*define\s+member\s*:\s*\[([^\]]*)\]`)
	// reCheckKinds — литералы внутри объявления ограничения.
	reSQLLiteral = regexp.MustCompile(`'([a-z_]+)'`)
)

func TestGroupMemberKindsAgreeBetweenModelAndMigrationText(t *testing.T) {
	root := monorepoRoot(t)

	model := groupMemberKindsFromModel(t, root)
	schema, from := groupMemberKindsFromSchema(t, root)

	// ОБЪЁМ ОСМОТРЕННОГО — отдельным утверждением: «ноль расхождений» обязано
	// быть отличимо от «ноль прочитанного».
	t.Logf("модель называет виды члена: %s (файл %s)", strings.Join(model, ", "), canonicalModelRelPath)
	t.Logf("схема называет виды члена: %s (ограничение %s, последняя касавшаяся миграция %s)",
		strings.Join(schema, ", "), groupMemberCheckName, from)

	require.NotEmptyf(t, model, "в модели не найдено `define member` у типа group — "+
		"гейт не прочитал своего предмета, и его молчание ничего бы не значило")
	require.NotEmptyf(t, schema, "в миграциях не найдено ограничение %s — "+
		"гейт не прочитал своего предмета", groupMemberCheckName)

	require.Equalf(t, schema, model,
		"состав члена группы назван ДВАЖДЫ и по-разному:\n"+
			"  модель (%s): %s\n"+
			"  схема  (%s, %s): %s\n"+
			"Вставка отвергает всё, чего нет во втором списке, поэтому лишнее в первом — "+
			"обещание возможности, которой не бывает ни при каком входе. Исходов два, и оба "+
			"названы в services/iam/docs/engineering/architecture/group-membership-is-one-level.md: "+
			"сузить модель до схемы (принятое решение kacho#734) либо ввести недостающее как "+
			"ФУНКЦИЮ — со своей приёмкой, потому что вложенность двигает объявленный потолок "+
			"стоимости вердикта.",
		canonicalModelRelPath, strings.Join(model, ", "),
		from, groupMemberCheckName, strings.Join(schema, ", "))
}

// groupMemberKindsFromModel — виды, принимаемые `type group` / `define member`.
func groupMemberKindsFromModel(t *testing.T, root string) []string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(root, canonicalModelRelPath))
	require.NoError(t, err)
	f := parseModelDSL(string(body))
	require.Truef(t, f.types["group"], "модель не объявляет `type group` — гейт беспредметен")
	return modelMemberKinds(string(body))
}

// modelMemberKinds — ЧИСТЫЙ разборщик (без *testing.T), общий с пробой инъекции.
//
// `group#member` в списке означает ВЛОЖЕННОСТЬ (группа как член группы) и потому
// приводится к ВИДУ `group`: схема написаний модели не знает, и сравнивать надо
// виды, а не формы записи.
func modelMemberKinds(dsl string) []string {
	var cur string
	for _, line := range strings.Split(dsl, "\n") {
		if m := reType.FindStringSubmatch(line); m != nil {
			cur = m[1]
			continue
		}
		if cur != "group" {
			continue
		}
		if m := reMemberDefine.FindStringSubmatch(line); m != nil {
			var out []string
			for _, part := range strings.Split(m[1], ",") {
				part = strings.TrimSpace(part)
				if part == "" {
					continue
				}
				out = append(out, strings.TrimSuffix(part, "#member"))
			}
			sort.Strings(out)
			return out
		}
	}
	return nil
}

// groupMemberKindsFromSchema — виды, допускаемые ограничением схемы.
//
// Читается ОБЪЯВЛЕНИЕ ограничения, а не любое упоминание его имени: первая
// редакция брала «текст от имени до точки с запятой» и на миграции 0029
// вычитала литералы соседнего INSERT'а (`member`, `object`, `relation`),
// объявив их видами члена. Прибор, не проверяющий своего входа, даёт ложные
// числа увереннее всего — поэтому здесь: строки-комментарии снимаются,
// объявление опознаётся формой `CONSTRAINT <имя> CHECK (…)`, а скобка
// закрывается счётом, а не первым встречным символом.
//
// Читается ПОСЛЕДНЯЯ по порядку миграция, объявляющая ограничение: редакция
// могла быть заменена, и судить первую значило бы судить отменённое.
func groupMemberKindsFromSchema(t *testing.T, root string) ([]string, string) {
	t.Helper()
	files, err := treecorpus.Glob(filepath.Join(root, migrationsGlob))
	require.NoError(t, err)
	require.NotEmptyf(t, files, "миграций не найдено по %s — гейт беспредметен", migrationsGlob)
	sort.Strings(files)

	var kinds []string
	var from string
	seen := 0
	for _, f := range files {
		body, rerr := os.ReadFile(f) // #nosec G304 -- путь получен обходом СОБСТВЕННОГО дерева
		require.NoError(t, rerr)
		seen++
		decl, ok := constraintCheckBody(stripSQLComments(string(body)), groupMemberCheckName)
		if !ok {
			continue
		}
		var got []string
		for _, m := range reSQLLiteral.FindAllStringSubmatch(decl, -1) {
			got = append(got, m[1])
		}
		if len(got) == 0 {
			continue
		}
		sort.Strings(got)
		kinds, from = got, filepath.Base(f)
	}
	t.Logf("прочитано миграций: %d", seen)
	return kinds, from
}

// stripSQLComments — снимает строчные комментарии `--`.
//
// Без этого имя ограничения находится в прозе миграции, объясняющей ЭТО ЖЕ
// ограничение, и гейт судит комментарий вместо кода — класс, который правила
// требуют различать у всякой проверки по тексту.
func stripSQLComments(sql string) string {
	var b strings.Builder
	for _, line := range strings.Split(sql, "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

// constraintCheckBody — тело `CONSTRAINT <name> CHECK ( … )` со счётом скобок.
func constraintCheckBody(sql, name string) (string, bool) {
	re := regexp.MustCompile(`(?i)CONSTRAINT\s+` + regexp.QuoteMeta(name) + `\s+CHECK\s*\(`)
	loc := re.FindStringIndex(sql)
	if loc == nil {
		return "", false
	}
	depth, start := 0, loc[1]-1
	for i := start; i < len(sql); i++ {
		switch sql[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return sql[start : i+1], true
			}
		}
	}
	return "", false
}

// ── доступ к разборщикам для инъекции ───────────────────────────────────────
//
// Пробе инъекции нужны ИМЕННО эти функции, а не их копии: копия судила бы себя.

func exportedConstraintCheckBody(sql, name string) (string, bool) {
	return constraintCheckBody(sql, name)
}

func exportedStripSQLComments(sql string) string { return stripSQLComments(sql) }

func exportedModelMemberKinds(dsl string) []string { return modelMemberKinds(dsl) }
