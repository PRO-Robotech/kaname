// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// nonverb_relation_has_reader_test.go — гейт на КЛАСС: НЕглагольное отношение,
// объявленное моделью, обязано кем-то ЧИТАТЬСЯ при решении о доступе.
//
// # Предмет
//
// Объявленное право, которого никто не требует, неотличимо от забытого. Следующий
// читатель модели видит `define token_creator: …` рядом с глаголами и заключает,
// что выпуск ключей чем-то сужен, — тогда как каталог гейтит его совсем другим
// отношением. Ошибка тихая и односторонняя: она не роняет ни один прогон, потому
// что мёртвое отношение согласовано само с собой.
//
// # Почему НЕГЛАГОЛЬНОЕ — и почему это не придирка к охвату
//
// Глагольную ось (`v_*`) уже держат два соседа, и каждый со СВОИМ предикатом:
// verb_relation_has_reader_test.go сверяет объявленное с каталогом равенством
// перечня, materialized_relation_has_reader_test.go — написанное материализацией
// с читателем, ища литерал в прод-коде СЕРВИСА-ВЛАДЕЛЬЦА. Здесь литерал ищется по
// всему дереву сервисов (причина ниже), то есть предикат СЛАБЕЕ соседского. Возьми
// этот файл глаголы себе — он обнулил бы их находки, не заметив этого: два места
// об одном предмете, из которых верно одно.
//
// Поэтому охват разведён по имени отношения: `v_*` — не сюда, всё остальное —
// сюда. До этого файла НЕглагольная ось не рассматривалась вовсе: `token_creator`
// пережил и оба соседних гейта, и гейт дрейфа модели, потому что каждый из них
// спрашивает про глаголы.
//
// # Кого считаем ЧИТАТЕЛЕМ — три источника, объединение
//
//  1. КАТАЛОГ ПРАВ — запись с `required_relation` на этом `object_type`. Это
//     решение, которое принимает край на каждом публичном RPC. Читается вшитая
//     копия iam; побайтовое равенство её с копией края держит отдельный,
//     уже существующий гейт (`make -C gateway permission-catalog-check`), и здесь
//     оно не пересказывается.
//  2. МОДЕЛЬ — отношение, на которое ссылается объявление ДРУГОГО отношения:
//     вычисляемый терм (`viewer: … or editor` читает `editor` того же типа),
//     терм через указатель (`super_admin: admin from account` читает `admin` у
//     типов, на которые ведёт `account`) и userset прямого списка
//     (`[group#member]` читает `member` у `group`). Снять такое отношение значило
//     бы порвать вывод.
//  3. ПРОД-КОД СЕРВИСОВ — строковый литерал, равный имени отношения, в НЕ-тестовом
//     `.go` под `services/`. Так ловятся решения, которых каталог выразить не может:
//     публичный `Check` приводит глагол запроса к отношению сам, и `ssh`, `console`,
//     ярусы `admin`/`editor`/`viewer` живут именно там.
//
// # Границы третьего источника — названы обе, и они смотрят в РАЗНЫЕ стороны
//
// ПО ТИПУ гейт скорее промолчит: литерал виден в файле, но к какому типу он
// относится — из литерала не следует, поэтому найденное отношение засчитывается
// ВСЕМ типам сразу. Резолюция здесь — «отношение», а не «пара (тип, отношение)».
// Выбрано намеренно: ложная находка про доступ дороже пропущенной, потому что
// снимать отношение по ошибке значит закрывать работающий доступ.
//
// ПО СОВПАДЕНИЮ ИМЁН гейт, наоборот, строг: литерал, равный имени ТИПА модели
// (`user`, `service_account`, `group`, …), читателем НЕ считается. Такой литерал
// неоднозначен by construction — `"user"` в этом дереве почти всегда обозначает
// тип субъекта в кортеже, а не отношение, — и засчитывать его значило бы
// объявлять читателя там, где его нет.
//
// ОБА ПРИМЕРА, КОТОРЫМИ ЭТО ОБОСНОВЫВАЛОСЬ, СНЯТЫ С ДЕРЕВА, и сказать об этом
// надо здесь, иначе следующий читатель пойдёт их искать. Отношение «пользоваться
// служебной учёткой» (имя совпадало с именем типа субъекта) и «пользоваться
// подсетью» (текстовый предикат засчитывал ему читателем тег поля в чужом пакете
// и перечисление в комментарии) сняты задачей #1115 — не потому, что предикат
// оказался неверен, а потому, что оба отношения не читал НИКТО.
//
// Отсюда честное измерение сегодняшнего дня: на этом дереве охранитель имён типов
// не меняет НИ ОДНОЙ находки — всякое отношение, чьё имя совпадает с именем типа,
// читается каталогом либо самой моделью. Предмет у него не исчез, а стал
// потенциальным: он сработает на первом же отношении, названном как тип и не
// читаемом ничем, кроме литерала. Что это так — доказано опытом, а не обещанием:
// см. четвёртую ось в `TestNonVerbReaderGate_EverySourceIsLoadBearing`, где
// снятое отношение возвращается инъекцией и обязано остаться находкой ПРИ ТОМ,
// что его литерал в прод-коде есть.
//
// Литералы берутся РАЗБОРОМ Go, а не поиском по тексту: комментарий и тег поля
// структуры содержат имена отношений по построению.
//
// # Что гейт делает с уже известным расхождением
//
// Не прощает молча: `nonVerbWithoutReader` перечисляет пары поимённо с причиной, и
// утверждается РАВЕНСТВО, а не включение. Пара, обретшая читателя либо ушедшая из
// модели, — находка: перечень обязан истекать сам, иначе он переживёт свой предмет
// и прикроет следующую находку.
package authzmap_test

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/authzplan"
	"github.com/PRO-Robotech/kacho/pkg/treecorpus"
)

// relPair — (тип объекта модели, имя отношения).
type relPair struct {
	Type     string
	Relation string
}

func (p relPair) String() string { return p.Type + "#" + p.Relation }

// nonVerbWithoutReader — НЕглагольные отношения, которые модель объявляет и не
// требует НИКТО. Каждая запись несёт причину, по которой она ещё здесь, и предикат,
// по которому её снимут. Запись без предмета — находка (равенство ниже).
//
// ПЕРЕЧЕНЬ ПУСТ, И ЭТО ЕГО ЦЕЛЕВОЕ СОСТОЯНИЕ, А НЕ ЗАБЫТАЯ ЗАГОТОВКА. Пять
// последних записей сняты вместе со своим предметом: `billing_admin` у кластера и
// аккаунта (#1114) и семейство «пользоваться ресурсом» — `use` у подсети и адреса,
// `user` у служебной учётки (#1115). Решения и их цена —
// services/iam/docs/engineering/architecture/relations-without-readers-withdrawn.md.
//
// На пустом перечне гейт утверждает СИЛЬНЕЙШУЮ форму свойства: у КАЖДОГО
// неглагольного отношения модели есть читатель. Пустота здесь не ослабляет
// проверку и не выключает её — сверка ниже требует РАВЕНСТВА, поэтому первое же
// объявление без читателя становится находкой, а не молча пополняет ведомость.
// Способность гейта упасть на пустом перечне доказана отдельно
// (nonverb_relation_has_reader_injection_test.go).
var nonVerbWithoutReader = map[relPair]string{}

// nonVerbCensus — объём осмотренного. Печатается всегда, чтобы «ноль находок»
// было отличимо от «ноль прочитанного».
type nonVerbCensus struct {
	Types         int
	Declarations  int
	VerbSkipped   int
	NonVerb       int
	ReadByCatalog int
	ReadByModel   int
	ReadByCode    int
	Dead          int
}

// nonVerbDeadRelations — ЯДРО предиката, чистая функция от трёх входов. Вынесено
// затем, чтобы проба инъекции кормила его синтетикой и настоящей моделью с
// возвращённым дефектом, не поднимая ничего вокруг.
//
// codeLits — множество строковых литералов прод-кода; литерал, равный имени типа
// модели, читателем не считается (см. шапку).
func nonVerbDeadRelations(
	model *authzplan.Model,
	catalog map[string]map[string]bool,
	codeLits map[string]bool,
) ([]relPair, nonVerbCensus) {
	var census nonVerbCensus
	census.Types = len(model.Types)

	isTypeName := make(map[string]bool, len(model.Types))
	for _, t := range model.Types {
		isTypeName[t.Name] = true
	}
	modelReads := modelInternalRelationReaders(model)

	var dead []relPair
	for _, t := range model.Types {
		for _, r := range t.Relations {
			census.Declarations++
			if authzplan.IsVerb(r.Name) {
				census.VerbSkipped++
				continue
			}
			census.NonVerb++
			switch {
			case catalog[t.Name][r.Name]:
				census.ReadByCatalog++
			case modelReads[t.Name][r.Name]:
				census.ReadByModel++
			case codeLits[r.Name] && !isTypeName[r.Name]:
				census.ReadByCode++
			default:
				dead = append(dead, relPair{Type: t.Name, Relation: r.Name})
			}
		}
	}
	census.Dead = len(dead)
	sort.Slice(dead, func(i, j int) bool { return dead[i].String() < dead[j].String() })
	return dead, census
}

// modelInternalRelationReaders — пары (тип, отношение), которые читает САМА
// модель: вычисляемый терм, терм через указатель и userset прямого списка.
func modelInternalRelationReaders(model *authzplan.Model) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	add := func(typeName, rel string) {
		if out[typeName] == nil {
			out[typeName] = map[string]bool{}
		}
		out[typeName][rel] = true
	}
	for _, t := range model.Types {
		for _, r := range t.Relations {
			for _, term := range r.Terms {
				switch term.Kind {
				case authzplan.TermComputed:
					if term.Computed != r.Name {
						add(t.Name, term.Computed)
					}
				case authzplan.TermTTU:
					// Указатель читается сам…
					add(t.Name, term.TTUPointer)
					// …и через него читается отношение у типов, на которые он ведёт.
					if ptr := t.Rel(term.TTUPointer); ptr != nil {
						for _, target := range model.PointerTargets(ptr) {
							add(target, term.TTURelation)
						}
					}
				case authzplan.TermDirect:
					for _, d := range term.Direct {
						if d.Userset != "" {
							add(d.Type, d.Userset)
						}
					}
				}
			}
		}
	}
	return out
}

// TestEveryNonVerbRelationHasAReader — каждое НЕглагольное отношение модели
// читается каталогом, моделью либо прод-кодом; исключения — только те, что
// перечислены выше, и перечень истекает сам.
func TestEveryNonVerbRelationHasAReader(t *testing.T) {
	root := monorepoRoot(t)
	model := canonicalModel(t)

	catalog, catalogEntries := iamCatalogRequiredRelations(t, root)
	codeLits, filesParsed := prodCodeStringLiterals(t, root)

	require.NotEmpty(t, catalog, "каталог прав пуст — предпосылка гейта сломана, а не дерево чисто")
	require.Positive(t, catalogEntries, "в каталоге ноль записей — читать нечего")
	require.Positive(t, filesParsed, "не разобрано ни одного прод-файла — «ноль находок» означало бы «ноль прочитанного»")
	require.NotEmpty(t, codeLits, "в прод-коде ноль строковых литералов — разбор смотрит не туда")

	dead, census := nonVerbDeadRelations(model, catalog, codeLits)

	require.Positive(t, census.Types, "модель без типов — предпосылка гейта сломана")
	require.Positive(t, census.NonVerb, "неглагольных объявлений ноль — предикат перестал видеть свой предмет")

	t.Logf("перепись: типов %d; объявлений %d (глагольных %d — их ось у соседей, "+
		"неглагольных рассмотрено %d); читаются каталогом %d, моделью %d, прод-кодом %d; "+
		"мёртвых %d. Осмотрено: записей каталога %d, прод-файлов Go разобрано %d",
		census.Types, census.Declarations, census.VerbSkipped, census.NonVerb,
		census.ReadByCatalog, census.ReadByModel, census.ReadByCode, census.Dead,
		catalogEntries, filesParsed)

	unknown, stale := diffAgainstLedger(dead, nonVerbWithoutReader)
	for _, p := range unknown {
		require.Failf(t, "мёртвое отношение",
			"модель объявляет %q, но его не требует ни одна запись каталога, не читает ни одно "+
				"объявление модели и не называет ни один прод-файл. Объявленное право, которого "+
				"никто не требует, неотличимо от забытого: следующий читатель модели решит, что "+
				"оно что-то держит, и построит на нём вывод. Исходов три — снять отношение, "+
				"начать его требовать, либо записать решение здесь с причиной и предикатом снятия.", p)
	}
	for _, p := range stale {
		require.Failf(t, "устаревшее послабление",
			"пара %q числится «объявлена и никем не требуется», но это больше не так — она либо "+
				"обрела читателя, либо ушла из модели. Запись, которой нечего исключать, обязана "+
				"быть снята: иначе перечень переживёт свой предмет и прикроет следующую находку.", p)
	}
}

// diffAgainstLedger сверяет найденное с зафиксированным в ОБЕ стороны:
// unknown — мёртвые пары, которых в перечне нет; stale — записи перечня, которым
// больше нечего исключать.
func diffAgainstLedger(dead []relPair, ledger map[relPair]string) (unknown, stale []relPair) {
	got := make(map[relPair]bool, len(dead))
	for _, p := range dead {
		got[p] = true
		if _, known := ledger[p]; !known {
			unknown = append(unknown, p)
		}
	}
	for p := range ledger {
		if !got[p] {
			stale = append(stale, p)
		}
	}
	sort.Slice(unknown, func(i, j int) bool { return unknown[i].String() < unknown[j].String() })
	sort.Slice(stale, func(i, j int) bool { return stale[i].String() < stale[j].String() })
	return unknown, stale
}

// iamCatalogRequiredRelations — отношения, которые край требует, по типу объекта.
// Читается вшитая копия iam (см. шапку про побайтовое равенство копий).
func iamCatalogRequiredRelations(t *testing.T, root string) (map[string]map[string]bool, int) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(catalogRelPath))
	raw, err := os.ReadFile(path) // #nosec G304 -- фиксированный путь в дереве, только для проб
	require.NoErrorf(t, err, "каталог прав %s недоступен — гейт обязан быть громким, а не пропущенным", path)

	var entries []struct {
		RequiredRelation string `json:"required_relation"`
		ScopeExtractor   struct {
			ObjectType string `json:"object_type"`
		} `json:"scope_extractor"`
	}
	require.NoError(t, json.Unmarshal(raw, &entries))

	out := map[string]map[string]bool{}
	for _, e := range entries {
		if e.RequiredRelation == "" || e.ScopeExtractor.ObjectType == "" {
			continue
		}
		if out[e.ScopeExtractor.ObjectType] == nil {
			out[e.ScopeExtractor.ObjectType] = map[string]bool{}
		}
		out[e.ScopeExtractor.ObjectType][e.RequiredRelation] = true
	}
	return out, len(entries)
}

// prodCodeStringLiterals — строковые литералы НЕ-тестового Go под `services/`,
// собранные РАЗБОРОМ (комментарии узлами литерала не являются, теги полей
// исключены явно). Возвращает также объём осмотренного.
//
// Состав берётся у индекса отслеживаемых файлов, а не обходом диска: под
// `services/` на всякой машине, где поднимали стенд, лежат распаковки чартов и
// отчёты прогонов, и найденный в них литерал сошёл бы за читателя.
func prodCodeStringLiterals(t *testing.T, root string) (map[string]bool, int) {
	t.Helper()
	files, err := treecorpus.UnderWithSuffix(filepath.Join(root, "services"), ".go")
	require.NoError(t, err, "индекс отслеживаемых файлов под services/")

	out := map[string]bool{}
	parsed := 0
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		file, perr := parser.ParseFile(fset, path, nil, 0)
		require.NoErrorf(t, perr, "разбор %s: прод-файл, который не читается, — это слепая зона предиката", path)
		parsed++

		tags := map[*ast.BasicLit]bool{}
		ast.Inspect(file, func(n ast.Node) bool {
			if fld, ok := n.(*ast.Field); ok && fld.Tag != nil {
				tags[fld.Tag] = true
			}
			return true
		})
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING || tags[lit] {
				return true
			}
			if v, uerr := strconv.Unquote(lit.Value); uerr == nil {
				out[v] = true
			}
			return true
		})
	}
	return out, parsed
}

// deadPairNames — имена пар в стабильном порядке (для сообщений проб инъекции).
func deadPairNames(pairs []relPair) []string {
	out := make([]string, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, p.String())
	}
	return out
}
