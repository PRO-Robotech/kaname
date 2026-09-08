// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict

// typedict_gate_test.go — КОЛОНКУ ЧИТАЮТ ТЕМ СЛОВАРЁМ, КАКИМ ЕЁ ПИШУТ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Имя типа названо в iam двумя словарями (`authzmap/type_dictionaries.go`), и у
// каждой колонки словарь ровно один. Соединение колонок РАЗНЫХ словарей не
// совпадает НИКОГДА и молча: исход выглядит как «права нет», а не как ошибка.
// Поэтому судится не поведение на фикстуре, а сам текст запроса.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ГЕЙТ, А НЕ ИНТЕГРАЦИОННАЯ ПРОБА
//
// Интеграционная проба ловит дефект только там, где посев идёт через настоящего
// писателя (producerdict_integration_test.go). Все прочие пробы пакета сеют
// литералом в словаре читателя — и потому зелены на любом переводе. Гейт судит
// КАЖДЫЙ запрос и КАЖДУЮ ось, включая те, у которых интеграционной пробы нет.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ГЕЙТ ЧИТАЕТ
//
// СОБРАННЫЙ запрос — тот же, что уходит в базу (`*QuerySQL`), а не литерал
// шаблона: половина соединений подставляется на лету по оси меток, и гейт,
// собирающий запрос сам, судил бы СВОЮ сборку.
//
// Комментарии из текста вырезаются ПЕРЕД разбором: в них те же имена колонок, и
// гейт, читающий их наравне с кодом, зеленел бы на объяснении снятой защиты.

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

// dictionary — словарь имён типа. Именно ДВА: третьего в дереве нет, и появление
// третьего обязано начинаться с правки этого перечня.
type dictionary int

const (
	dictModel   dictionary = iota + 1 // vpc_network · account · project · cluster
	dictCatalog                       // vpc.network · iam.account
)

func (d dictionary) String() string {
	switch d {
	case dictModel:
		return "словарь модели"
	case dictCatalog:
		return "словарь каталога"
	}
	return "не объявлен"
}

// dictionaryOfColumn — словарь КАЖДОЙ колонки, несущей имя типа, во всех
// таблицах, к которым обращаются запросы формы E.
//
// Перечень объявлен здесь, а выводится ли он — вопрос, на который честный ответ
// «нет»: словарь колонки задаёт её писатель, и вывести его из имени колонки
// нельзя. Зато перепись ниже требует, чтобы КАЖДАЯ встреченная в запросе колонка
// с именем типа была здесь названа: колонка, заведённая позже и сюда не
// внесённая, роняет гейт, а не проходит мимо него.
var dictionaryOfColumn = map[string]dictionary{
	"relation_fact.object_type":     dictModel,
	"access_bindings.resource_type": dictModel,
	// Перенесённая копия области выдачи (миграция 732001). Словарь тот же,
	// что у родительской колонки, и это не совпадение: значение приходит
	// оттуда — составной внешний ключ не даёт ему разойтись, а каскад правки
	// переносит изменение сам.
	"access_binding_subjects.resource_type": dictModel,
	"resource_parent_edge.object_type":      dictModel,
	"resource_parent_edge.parent_type":      dictModel,
	// Представление цепи областей (миграция 740001): те же две колонки, тот же
	// словарь. Одна из сторон объединения — сама таблица рёбер, две другие
	// названы литералами модели (`project`, `account`, `cluster`); третьего
	// словаря здесь не заводится, поэтому запись повторяет родительскую, а не
	// вводит новую семантику.
	"resource_scope_edge.object_type": dictModel,
	"resource_scope_edge.parent_type": dictModel,

	"resource_mirror.object_type":      dictCatalog,
	"role_verb.object_type":            dictCatalog,
	"role_rule_selectors.object_types": dictCatalog,
}

// paramDictionary — словарь параметра запроса, несущего имя типа.
//
// Ключ — имя запроса, значение — номера параметров. Оба параметра называют ОДИН
// И ТОТ ЖЕ тип, поэтому и объявлены рядом: расхождение между ними — это и есть
// дефект, ради которого гейт написан.
type paramDictionary struct {
	model   string // $N с именем типа в словаре модели
	catalog string // $N с именем типа в словаре каталога
}

// queryUnderGate — один судимый запрос: как он собирается и чем названы его
// параметры-типы.
type queryUnderGate struct {
	name   string
	build  func(labelTable string) string
	params paramDictionary
}

func queriesUnderGate() []queryUnderGate {
	return []queryUnderGate{
		{"вердикт", verdictQuerySQL, paramDictionary{model: "$2", catalog: "$9"}},
		// Вердикт о СТРАНИЦЕ — отдельный запрос и потому отдельный судимый:
		// он собирает те же ветви, но своими подстановками, и словарь у него
		// может разойтись независимо. Перечень судимых выписан, поэтому запрос,
		// сюда не внесённый, остался бы не осмотренным молча.
		{"вердикт о странице", verdictManyQuerySQL, paramDictionary{model: "$2", catalog: "$9"}},
		{"разбор оснований", expandQuerySQL, paramDictionary{model: "$1", catalog: "$7"}},
		{"перечисление субъектов", subjectsQuerySQL, paramDictionary{model: "$1", catalog: "$9"}},
		{"перечисление объектов", listQuerySQL, paramDictionary{model: "$2", catalog: "$9"}},
	}
}

// axesUnderGate — обе оси меток. Ось зеркала (пустая таблица) и одна из
// собственных таблиц iam: у них РАЗНЫЕ подстановки, и судить надо обе.
func axesUnderGate() []struct {
	name  string
	table string
} {
	return []struct {
		name  string
		table string
	}{
		{"ось зеркала", ""},
		{"ось собственной таблицы iam", "kaname.projects"},
	}
}

var (
	// Алиас таблицы: `FROM|JOIN kaname.<таблица> <алиас>`.
	reAlias = regexp.MustCompile(`(?:FROM|JOIN)\s+kaname\.(\w+)\s+(\w+)`)
	// Сравнение `<алиас>.<колонка> = <правая часть>`.
	reCompare = regexp.MustCompile(`(\w+)\.(\w+)\s*=\s*([\w.$]+)`)
	// Проверка членства `<правая часть> = ANY (<алиас>.<колонка>)`.
	reAnyOf = regexp.MustCompile(`([\w.$]+)(?:::text)?\s*=\s*ANY\s*\(\s*(\w+)\.(\w+)\s*\)`)
	// Имя колонки, несущей ТИП. Идентификаторы и метки сюда не подпадают.
	reTypeColumn = regexp.MustCompile(`^(object_type|object_types|parent_type|resource_type)$`)
)

// stripSQLComments вырезает `--`-комментарии. Без этого гейт читал бы имена
// колонок из объяснения рядом с защитой и зеленел бы при её снятии.
func stripSQLComments(sql string) string {
	var out []string
	for _, line := range strings.Split(sql, "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// aliasesOf — какая таблица стоит за каждым алиасом запроса.
func aliasesOf(sql string) map[string]string {
	out := map[string]string{}
	for _, m := range reAlias.FindAllStringSubmatch(sql, -1) {
		table, alias := m[1], m[2]
		// Ключевые слова после имени таблицы алиасом не являются.
		switch strings.ToUpper(alias) {
		case "ON", "WHERE", "GROUP", "ORDER", "LIMIT", "UNION", "JOIN", "CROSS", "LEFT":
			continue
		}
		out[alias] = table
	}
	return out
}

// side — одна сторона сравнения: её словарь и как её назвать в отказе.
type side struct {
	dict  dictionary
	label string
	known bool
}

// Гейт: обе стороны каждого сравнения имён типа говорят ОДНИМ словарём.
func TestEveryTypeColumnIsReadInItsOwnDictionary(t *testing.T) {
	var (
		comparisons int
		queries     int
		undeclared  []string
		mismatched  []string
	)

	for _, q := range queriesUnderGate() {
		for _, axis := range axesUnderGate() {
			queries++
			sql := stripSQLComments(q.build(axis.table))
			aliases := aliasesOf(sql)

			// Словарь стороны: колонка — по перечню, параметр — по объявлению
			// запроса, столбец цепи областей — словарь модели (её несёт seed и
			// её же несёт `parent_type`).
			classify := func(token string) side {
				switch token {
				case q.params.model:
					return side{dictModel, "параметр " + token, true}
				case q.params.catalog:
					return side{dictCatalog, "параметр " + token, true}
				}
				if strings.HasSuffix(token, ".s_type") || token == "s_type" {
					return side{dictModel, "цепь областей (" + token + ")", true}
				}
				alias, column, ok := strings.Cut(token, ".")
				if !ok {
					return side{}
				}
				table, ok := aliases[alias]
				if !ok || !reTypeColumn.MatchString(column) {
					return side{}
				}
				key := table + "." + column
				d, declared := dictionaryOfColumn[key]
				if !declared {
					undeclared = append(undeclared, q.name+"/"+axis.name+": "+key)
					return side{}
				}
				return side{d, key, true}
			}

			check := func(left, right string) {
				l, r := classify(left), classify(right)
				if !l.known || !r.known {
					return
				}
				comparisons++
				if l.dict != r.dict {
					mismatched = append(mismatched, q.name+" / "+axis.name+": "+
						l.label+" ("+l.dict.String()+") соединён с "+
						r.label+" ("+r.dict.String()+")")
				}
			}

			for _, m := range reCompare.FindAllStringSubmatch(sql, -1) {
				left, column, right := m[1]+"."+m[2], m[2], m[3]
				if !reTypeColumn.MatchString(column) {
					continue
				}
				check(left, strings.TrimSuffix(right, "::text"))
			}
			for _, m := range reAnyOf.FindAllStringSubmatch(sql, -1) {
				check(strings.TrimSuffix(m[1], "::text"), m[2]+"."+m[3])
			}
		}
	}

	// Перепись: «ноль расхождений» обязано быть отличимо от «ноль прочитанного».
	t.Logf("осмотрено: запросов (запрос × ось) %d, сравнений имён типа %d, "+
		"колонок в перечне словарей %d", queries, comparisons, len(dictionaryOfColumn))
	if comparisons == 0 {
		t.Fatal("ни одного сравнения имён типа не найдено — разбор запроса перестал " +
			"их видеть, и гейт молчит не потому, что дерево исправно")
	}
	if len(undeclared) != 0 {
		sort.Strings(undeclared)
		t.Errorf("колонка с именем типа не объявлена в перечне словарей (%d):\n  %s\n"+
			"Словарь колонки задаёт её писатель; невнесённая колонка проходит мимо "+
			"гейта молча", len(undeclared), strings.Join(undeclared, "\n  "))
	}
	if len(mismatched) != 0 {
		sort.Strings(mismatched)
		t.Fatalf("соединение РАЗНЫХ словарей имён типа (%d):\n  %s\n"+
			"Такое соединение не совпадает никогда и не отказывает: исход выглядит "+
			"как «права нет»", len(mismatched), strings.Join(mismatched, "\n  "))
	}
}

// Предпосылка гейта: разбор действительно ВИДИТ обе формы сравнения и обе оси.
//
// Без этого «ноль расхождений» означало бы «ничего не разобрано»: регулярное
// выражение, переставшее совпадать после правки запроса, молча выключило бы
// проверку целиком.
func TestTypeDictionaryGateSeesBothComparisonFormsOnBothAxes(t *testing.T) {
	for _, q := range queriesUnderGate() {
		for _, axis := range axesUnderGate() {
			sql := stripSQLComments(q.build(axis.table))
			if len(aliasesOf(sql)) == 0 {
				t.Errorf("%s / %s: ни одного алиаса таблицы не разобрано", q.name, axis.name)
			}
			if !strings.Contains(sql, q.params.catalog) {
				t.Errorf("%s / %s: параметр словаря каталога %s в запросе отсутствует — "+
					"объявление гейта разошлось с запросом", q.name, axis.name, q.params.catalog)
			}
		}
	}
	// Форма `= ANY (...)` встречается только у селекторов правил; убедимся, что
	// разбор её ловит хотя бы в одном запросе, иначе половина гейта мертва.
	found := false
	for _, q := range queriesUnderGate() {
		if reAnyOf.MatchString(stripSQLComments(q.build(""))) {
			found = true
		}
	}
	if !found {
		t.Error("форма `= ANY (<алиас>.<колонка>)` не разобрана ни в одном запросе — " +
			"проверка членства в наборе типов селектора не судится")
	}
}
