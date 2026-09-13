// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// subject_change_flush_parity.go — извлечение для гейта «полоса производителей
// очереди смены субъекта не пополняется МОЛЧА» (задача #17, порт-ПОЛОВИНА
// семейства `subjectchangeflushparity` с монорепо
// `internal/repohygiene/subjectchangeflushparity.go`, снятого выносом службы —
// `kacho#2597`).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ ПРЕДКА — ДВЕ ПОЛОСЫ ОДНОГО МЕХАНИЗМА, СВЕРЯЕМЫЕ МЕЖДУ СОБОЙ
//
// Смена прав доезжает до кэша решений края ДВУМЯ независимыми полосами:
//
//   - НЕМЕДЛЕННО, на реплике, обслужившей мутацию, — самосбросом по полному
//     имени метода (набор `subjectChangingFQNs` у края);
//   - С ЗАДЕРЖКОЙ, на соседних репликах, — через очередь смены субъекта
//     (`kaname.subject_change_outbox`), которую край читает сам.
//
// Полосы кормит ОДНО событие, но перечни у них РАЗНЫЕ и ведутся врозь. Заведя
// шестого производителя очереди, легко не вспомнить о самосбросе: соседние
// реплики сойдутся за интервал опроса, а та, что мутацию обслужила, продолжит
// отвечать по закешированному вердикту — то есть по ОТОЗВАННОМУ праву, и дольше
// всех именно там, где пользователь только что нажал «отозвать».
//
// Заметить это по одной полосе нельзя: каждая исправна сама по себе. Предок
// поэтому спрашивал не «верен ли перечень» (это и есть спорный вопрос), а
// РЕШАЛ ЛИ КТО-НИБУДЬ, что полосы различаются.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО РАЗРЕЗ СДЕЛАЛ С ЭТИМ ГЕЙТОМ — СКАЗАНО ЧИСЛОМ, А НЕ ОГОВОРКОЙ
//
// Полосы развело по РАЗНЫМ РЕПОЗИТОРИЯМ. Замер этого дерева (`61053691` плюс
// дифф этого изменения):
//
//	производители очереди   internal/apps/kaname/api            5  ЗДЕСЬ
//	набор самосброса        gateway/internal/middleware/authz.go 0  у края платформы
//
// Предикат второй строки: `git grep -l subjectChangingFQNs` → 0; каталога
// `gateway` в составе этого дерева нет вовсе (`git ls-files gateway | wc -l` → 0).
//
// Сверить полосы МЕЖДУ СОБОЙ отсюда нельзя, и обходить это чтением чужого
// репозитория с диска — НЕЛЬЗЯ ТЕМ БОЛЕЕ: вердикт стал бы свойством того, что
// случайно лежит в модульном кеше машины прогона, а не свойством коммита ни
// одного из двух деревьев. Тот же довод, по которому соседнее семейство
// (`subject_change_gap_detection_test.go`) судит два звена из трёх.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЭТА ПОЛОВИНА ДЕРЖИТ — И ЧЕГО ОНА НЕ ДЕРЖИТ
//
// ДЕРЖИТ: полоса производителей не пополняется молча. Перечень объявлен в
// дереве, и гейт сверяет его с разбором. Шестой производитель делает вердикт
// красным, а правку перечня — ВИДИМОЙ В ДИФФЕ, где обзор и спрашивает: «а краю
// сказали?». Без этого добавление производителя не оставляет в этом
// репозитории следа ВООБЩЕ, и расхождение полос наступает молча.
//
// НЕ ДЕРЖИТ: что край свой набор пополнил. Это утверждение о ЧУЖОМ дереве, и
// сделать его отсюда нечем. Объявленный здесь перечень — ОПЕРАНД для той
// стороны: пинить его вправе гейт платформы, потому что перечень отслеживается
// git и меняется только изменением.
//
// Сказано прямо, потому что половина, выдающая себя за целое, хуже отсутствия:
// зелёный вердикт читался бы как «полосы сошлись».
//
// ─────────────────────────────────────────────────────────────────────────────
// СУДИТСЯ УЗЕЛ ОБРАЩЕНИЯ, А НЕ УЗЕЛ ВЫЗОВА — ЦЕНА ИЗМЕРЕНА ПРЕДКОМ
//
// Обращений к методу в дереве ДВЕ формы, и обе законны:
//
//	w.AccessBindingsW().EmitSubjectChangeEvent(ctx, …)              // вызов на месте
//	fanout(ctx, …, w.AccessBindingsW().EmitSubjectChangeEvent, …)   // передан значением
//
// Вторая появляется, когда строка пишется НА КАЖДОГО субъекта привязки общим
// развёртывателем: сам вызов уезжает в него, а производителем остаётся
// use-case, который метод отдал. Распознаватель, знавший только первую, объявлял
// вторую отсутствующей — не нарушением, а НЕВИДИМОСТЬЮ: два живых производителя
// пропадали из переписи. Поэтому судится `*ast.SelectorExpr`: узел вызова его
// содержит, поэтому обе формы считаются по разу и ни одна дважды.
//
// В этом дереве вторая форма ЖИВАЯ — её несут `access_binding/delete.go` и
// `access_binding/revoke.go`, то есть два производителя из пяти. Слепота стоила
// бы ровно их.
package check

import (
	"fmt"
	"github.com/PRO-Robotech/corelib/treecorpus"
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"sort"
	"strings"
)

// EmitSubjectChangeSelector — имя метода порта, которым производится строка
// очереди смены субъекта.
const EmitSubjectChangeSelector = "EmitSubjectChangeEvent"

// SubjectChangeProducerRootRel — каталог use-case владельца прав.
//
// Каталог СЛОЯ, а не перечень файлов: слой — единица архитектуры службы, и он
// не стареет вместе с деревом. Переедет слой — обход опустеет, и гейт откажет,
// а не смолчит.
const SubjectChangeProducerRootRel = "internal/apps/kaname/api"

// SelfFlushSetName — имя набора самосброса У КРАЯ.
//
// Объявлено здесь, хотя предмета в этом дереве нет: имя есть КООРДИНАТА второй
// полосы, и без неё текст находки не сказал бы читателю, куда идти. Пустой
// результат поиска по нему — не находка, а измеренное отсутствие второй
// стороны, и гейт называет его отдельной строкой переписи.
const SelfFlushSetName = "subjectChangingFQNs"

// SelfFlushSetHome — дерево и файл, где вторая полоса живёт.
const SelfFlushSetHome = "PRO-Robotech/kacho:gateway/internal/middleware/authz.go"

// DeclaresSelfFlushSet — ОБЪЯВЛЯЕТ ли файл набор самосброса.
//
// Судится УЗЕЛ ОБЪЯВЛЕНИЯ, а не вхождение имени, и это не педантизм — цена
// измерена на самом гейте. Первая редакция искала имя ПОДСТРОКОЙ по всем файлам
// Go и на первом же прогоне после посадки нашла… собственное объявление
// координаты второй полосы (`SelfFlushSetName = "subjectChangingFQNs"` строкой
// выше). То есть проверка покраснела на своём же объяснении и объявила, что
// вторая полоса приехала в это дерево, — ровно тот класс, что ловит проверку,
// судящую СЛОВО вместо УЗЛА.
//
// Узел снимает это by construction: строковый литерал, имя типа, комментарий и
// сообщение об отказе объявлением не являются, а `var subjectChangingFQNs = …`
// является — и только оно.
func DeclaresSelfFlushSet(rel, src string) (bool, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path.Base(rel), src, 0)
	if err != nil {
		return false, fmt.Errorf("разбор %s: %w", rel, err)
	}
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for _, name := range vs.Names {
			if name.Name == SelfFlushSetName {
				found = true
				return false
			}
		}
		return true
	})
	return found, nil
}

// SubjectChangeProducer — одно обращение к производителю очереди.
type SubjectChangeProducer struct {
	File string
	Line int
}

func (p SubjectChangeProducer) String() string { return fmt.Sprintf("%s:%d", p.File, p.Line) }

// SubjectChangeProducersIn считает обращения к производителю в ОДНОМ файле.
//
// Возвращает координаты обращений. Разбор — не поиск по подстроке: имя метода
// стоит и в комментариях, объясняющих сам механизм, и предикат по слову краснел
// бы на собственном объяснении.
func SubjectChangeProducersIn(rel, src string) ([]SubjectChangeProducer, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path.Base(rel), src, 0)
	if err != nil {
		return nil, fmt.Errorf("разбор %s: %w", rel, err)
	}
	var out []SubjectChangeProducer
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != EmitSubjectChangeSelector {
			return true
		}
		out = append(out, SubjectChangeProducer{File: rel, Line: fset.Position(sel.Sel.Pos()).Line})
		return true
	})
	return out, nil
}

// SubjectChangeRosterDiff — расхождение перечня с деревом.
type SubjectChangeRosterDiff struct {
	// Undeclared — файл несёт больше обращений, чем объявлено (в том числе
	// файл, которого в перечне нет вовсе).
	Undeclared []string
	// Stale — перечень называет то, чего в дереве больше нет либо стало меньше.
	// Запись, которой нечего называть, — НАХОДКА: послабление обязано истекать
	// само, иначе оно переживает свой предмет, оставаясь на вид рабочим.
	Stale []string
}

// Empty — сошлись ли перечень и дерево.
func (d SubjectChangeRosterDiff) Empty() bool { return len(d.Undeclared) == 0 && len(d.Stale) == 0 }

// CompareSubjectChangeRoster сверяет перечень с разбором — в ОБЕ стороны.
//
// Сверяется пара «файл → сколько обращений», а не только число файлов: второе
// обращение, добавленное в уже объявленный файл, — такой же новый производитель,
// как и первый в новом файле, и полоса пополняется им ровно так же.
//
// Число целиком (а не только состав) сверять обязательно и по другой причине:
// предок сравнивал ЧИСЛА полос, и величина, которую край пинит, — это число.
func CompareSubjectChangeRoster(
	found []SubjectChangeProducer, declared map[string]int,
) SubjectChangeRosterDiff {
	var diff SubjectChangeRosterDiff

	byFile := map[string]int{}
	for _, p := range found {
		byFile[p.File]++
	}

	files := make([]string, 0, len(byFile))
	for f := range byFile {
		files = append(files, f)
	}
	sort.Strings(files)
	for _, f := range files {
		want, ok := declared[f]
		if !ok {
			diff.Undeclared = append(diff.Undeclared, fmt.Sprintf(
				"%s — обращений %d, а в перечне файла нет вовсе", f, byFile[f]))
			continue
		}
		if byFile[f] > want {
			diff.Undeclared = append(diff.Undeclared, fmt.Sprintf(
				"%s — обращений %d, объявлено %d", f, byFile[f], want))
		}
		if byFile[f] < want {
			diff.Stale = append(diff.Stale, fmt.Sprintf(
				"%s — обращений %d, объявлено %d", f, byFile[f], want))
		}
	}

	gone := make([]string, 0)
	for f := range declared {
		if _, ok := byFile[f]; !ok {
			gone = append(gone, fmt.Sprintf("%s — объявлен, а обращений в дереве нет ни одного", f))
		}
	}
	sort.Strings(gone)
	diff.Stale = append(diff.Stale, gone...)
	sort.Strings(diff.Stale)
	return diff
}

// SubjectChangeRosterTotal — сколько обращений объявляет перечень.
func SubjectChangeRosterTotal(declared map[string]int) int {
	total := 0
	for _, n := range declared {
		total += n
	}
	return total
}

// IsSubjectChangeProducerFile — лежит ли координата в слое use-case и не проба ли это.
// SubjectChangeProducerCorpus — корпус производителей полосы самосброса из ДЕРЕВА.
//
// Отбор объявлен `IsSubjectChangeProducerFile` и зовётся отсюда, а дерево
// приходит параметром: гейт и инъекция ходят ОДНОЙ дорогой, поэтому синтетика
// проверяет тот же отбор, что исполняется на боевом прогоне. Пустой обход —
// отказ (`ErrEmptyTraversal`), а не «находок ноль».
func SubjectChangeProducerCorpus(tree *treecorpus.Tree) (TreeCorpus, error) {
	return CorpusFrom(tree, IsSubjectChangeProducerFile)
}

func IsSubjectChangeProducerFile(rel string) bool {
	return strings.HasPrefix(rel, SubjectChangeProducerRootRel+"/") &&
		strings.HasSuffix(rel, ".go") && !strings.HasSuffix(rel, "_test.go")
}
