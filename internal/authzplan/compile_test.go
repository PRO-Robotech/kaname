// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzplan

import (
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Разбор боевой модели и его перепись — без контейнеров.
//
// Проба быстрая намеренно: она держит предпосылку, на которой стоит всё
// остальное, и обязана падать раньше, чем поднимется хоть один контейнер. Если
// разбор перестал понимать модель, доказательство эквивалентности не «покраснеет
// на паре вопросов» — оно станет утверждением о другом предмете.

func parseCanonical(t *testing.T) *Model {
	t.Helper()
	path, canon, err := ResolveCanonicalModel()
	require.NoError(t, err)
	require.NotEmpty(t, canon, "канонический файл модели пуст: %s", path)
	m, err := ParseModel(string(canon))
	require.NoError(t, err, "разбор канонической модели %s", path)
	return m
}

// TestCanonicalModelIsParsedWhole — перепись разобранного против переписи файла.
//
// Обе стороны считаются РАЗНЫМИ способами: слева дерево разбора, справа строки
// файла. Совпадение означает, что разбор не потерял объявлений молча; расхождение
// назовёт, сколько именно потеряно. Без правой стороны «разобралось» было бы
// неотличимо от «разобралась половина».
func TestCanonicalModelIsParsedWhole(t *testing.T) {
	_, canon, err := ResolveCanonicalModel()
	require.NoError(t, err)
	m := parseCanonical(t)
	c := m.Census()

	var fileTypes, fileDefines, fileVerbs int
	for _, ln := range strings.Split(string(canon), "\n") {
		tr := strings.TrimSpace(ln)
		switch {
		case strings.HasPrefix(tr, "#"):
		case strings.HasPrefix(ln, "type "):
			fileTypes++
		case strings.HasPrefix(tr, "define "):
			fileDefines++
			if strings.HasPrefix(strings.TrimPrefix(tr, "define "), VerbPrefix) {
				fileVerbs++
			}
		}
	}
	require.Equal(t, fileTypes, c.Types, "разобрано типов %d, в файле объявлено %d", c.Types, fileTypes)
	require.Equal(t, fileDefines, c.Declarations,
		"разобрано объявлений %d, в файле %d — разбор потерял часть модели молча", c.Declarations, fileDefines)
	require.Equal(t, fileVerbs, c.VerbDeclaration)
	require.Positive(t, c.VerbTypes)
	require.Positive(t, c.Pointers)

	t.Logf("перепись модели: типов %d · объявлений %d · типов с глаголами %d · глаголов %d · "+
		"указателей %d · условий %d", c.Types, c.Declarations, c.VerbTypes, c.VerbDeclaration,
		c.Pointers, c.Conditions)
}

// TestEveryTermOfEveryRelationIsClassified — у классификатора НЕТ корзины
// «прочее».
//
// Компилятор обязан отнести каждый терм каждого отношения к названному виду.
// Неотнесённое печатается поимённо и роняет пробу: молчаливое проглатывание дало
// бы форму E, «совпавшую» с движком ровно потому, что про непонятое её не
// спросили. Условия на кортеже — отдельная категория, они НЕ ошибка разбора и
// проверяются своей пробой ниже.
func TestEveryTermOfEveryRelationIsClassified(t *testing.T) {
	m := parseCanonical(t)
	require.NoError(t, m.AssertOnePointerPerParentType())

	var unclassified, conditioned []string
	total, expressible := 0, 0
	for _, ty := range m.Types {
		for _, r := range ty.Relations {
			if m.IsPointer(ty.Name, r.Name) {
				continue
			}
			total++
			p, err := m.Compile(ty.Name, r.Name)
			require.NoErrorf(t, err, "компиляция %s.%s", ty.Name, r.Name)
			require.NotEmptyf(t, p.Atoms, "%s.%s: план пуст — ни одного источника разрешения",
				ty.Name, r.Name)
			if p.Expressible() {
				expressible++
			} else {
				unclassified = append(unclassified, p.Unclassified...)
			}
			conditioned = append(conditioned, p.Conditioned...)
		}
	}
	sort.Strings(conditioned)
	t.Logf("отношений, решающих доступ: %d · выразимо целиком: %d · с условием на кортеже: %d",
		total, expressible, len(conditioned))
	for _, c := range conditioned {
		t.Logf("  условие: %s", c)
	}
	require.Emptyf(t, unclassified, "термы, не отнесённые ни к одному виду:\n%s",
		strings.Join(unclassified, "\n"))
	require.Positive(t, total, "ни одного отношения не рассмотрено — «ноль находок» здесь означало бы ноль прочитанного")
	require.NotEmpty(t, conditioned,
		"в модели не нашлось ни одного условия на кортеже, хотя она объявляет условия — "+
			"либо разбор их не видит, либо модель изменилась, и запись про невыразимость условий "+
			"истекла вместе со своим предметом")
}

// TestParserRefusesWhatItCannotUnderstand — отрицательный контроль разбора.
//
// Разбор, молча пропускающий незнакомую конструкцию, произвёл бы план, который
// «совпал» с движком потому, что о пропущенном не спросили. Здесь проверяется,
// что пересечение, вычитание и нераспознанная строка ОТВЕРГАЮТСЯ, а рядом —
// положительный контроль: законная модель той же формы разбирается.
func TestParserRefusesWhatItCannotUnderstand(t *testing.T) {
	ok := "model\n  schema 1.1\n\ntype user\n\ntype doc\n  relations\n    define viewer: [user]\n"
	m, err := ParseModel(ok)
	require.NoError(t, err, "положительный контроль: законная модель обязана разбираться")
	require.Len(t, m.Types, 2)

	for name, bad := range map[string]string{
		"пересечение":           "type user\n\ntype doc\n  relations\n    define viewer: [user] and editor\n    define editor: [user]\n",
		"вычитание":             "type user\n\ntype doc\n  relations\n    define viewer: [user] but not editor\n    define editor: [user]\n",
		"мусор":                 "type user\n\ntype doc\n  relations\n    define viewer: [user]\n    непонятная строка\n",
		"неизвестное отношение": "type user\n\ntype doc\n  relations\n    define viewer: nosuch\n",
	} {
		_, err := ParseModel(bad)
		require.Errorf(t, err, "разбор принял %s — он обязан отвергать непонятое, а не делать вид, что понял", name)
	}
}

// TestPlanNamesItsSourcesForEachShapeOfAnchoring — план обязан РАЗЛИЧАТЬ типы,
// привязанные по-разному.
//
// Это положительная половина контроля к отрицанию «формы совпали»: если бы
// компилятор выдавал один и тот же план всем типам, совпадение вердиктов
// означало бы, что и вопросник, и форма E одинаково слепы. Проверяются три
// заведомо разные привязки, названные поимённо.
func TestPlanNamesItsSourcesForEachShapeOfAnchoring(t *testing.T) {
	m := parseCanonical(t)

	has := func(p Plan, kind AtomKind, parent, rel string) bool {
		for _, a := range p.Atoms {
			if a.Kind == kind && a.ParentType == parent && a.Relation == rel {
				return true
			}
		}
		return false
	}

	leaf, err := m.Compile("vpc_network", "v_get")
	require.NoError(t, err)
	require.True(t, has(leaf, AtomBinding, "", "v_get"), "лист обязан разрешаться выдачей")
	require.True(t, has(leaf, AtomFact, "account", "admin"), "лист обязан наследовать каскад администратора аккаунта")
	require.True(t, has(leaf, AtomFact, "cluster", "system_admin"), "лист обязан наследовать каскад кластера")

	pool, err := m.Compile("vpc_address_pool", "v_get")
	require.NoError(t, err)
	require.True(t, has(pool, AtomFact, "cluster", "system_admin"))
	require.Falsef(t, has(pool, AtomFact, "account", "admin"),
		"тип, привязанный к кластеру, получил источник уровня аккаунта — "+
			"привязка типов перестала различаться, и совпадение вердиктов ничего бы не значило")

	acc, err := m.Compile("account", "v_get")
	require.NoError(t, err)
	require.True(t, has(acc, AtomFact, "", "owner"), "владелец — структурный источник на своём аккаунте")
	require.Falsef(t, has(acc, AtomFact, "", "admin"),
		"администратор аккаунта получил глаголы на САМ аккаунт — модель этого намеренно не даёт")

	tgt, err := m.Compile("nlb_target_group", "v_addtargets")
	require.NoError(t, err)
	require.Truef(t, has(tgt, AtomBinding, "", "v_update"),
		"надмножество `v_addtargets ⊇ v_update` не доехало в план: держатель права менять группу "+
			"перестал бы управлять её составом")

	repo, err := m.Compile("registry_repository", "v_get")
	require.NoError(t, err)
	require.True(t, has(repo, AtomFact, "", "owner"))
	require.Truef(t, has(repo, AtomFact, "registry_registry", "super_admin") ||
		has(repo, AtomFact, "account", "admin"),
		"репозиторий не унаследовал ничего через свой реестр — цепь родительства длиной больше одного "+
			"звена не пройдена")
}

// TestWorldIsBuiltFromTheModelAndIsNotDegenerate — предпосылка вопросника.
//
// Мир строится ИЗ модели, поэтому его полнота — свойство разбора, а не памяти
// автора. Проверяется то, отсутствие чего делает вопросник вырожденным: два
// арендатора, объект на каждый тип с глаголами, вложенная группа, объект вне
// всякой области выдачи и материализованный состав, который не пуст.
