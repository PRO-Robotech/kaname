// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

// reconcile_outbox_retention_premise_test.go — ПРЕДПОСЫЛКА уборки очереди
// сверки, а не сама уборка (#2050).
//
// # Что уборка себе позволяет и на каком основании
//
// Общий уборщик очередей платформы щадит ДОСТАВЛЕННУЮ строку, если она
// защищает отравленного предшественника от оживления реконсайлером: оживлённый
// предшественник ушёл бы применяться ПОСЛЕ уже применённого потомка, то есть
// порядок партиции развалился бы. Ради этого ему нужен ключ партиции.
//
// У очереди сверки ключа партиции НЕТ и не требуется: её события коммутативны
// (каждое означает «состояние зеркала этого объекта изменилось, пересчитай», а
// пересчёт идёт от ЖИВОГО зеркала). Поэтому её уборщик проще — он снимает
// доставленную строку по возрасту и ничего не щадит.
//
// Это законно ровно пока верна ПРЕДПОСЫЛКА: над очередями iam нет ни одного
// оживителя отравленных строк. «Сегодня оживителя нет» — факт о дереве, а не
// свойство замысла, и он вправе перестать быть верным. Предпосылку и стережёт
// этот гейт.
//
// # Почему гейт, а не абзац
//
// Ровно этого потребовала запись ведомости роста таблиц, объявлявшая очередь
// долгом: «уборка без ключа обязана нести гейт, который покраснеет, когда
// реконсайлер появится». Абзац на это не годится: он не краснеет.
//
// # Что гейт НЕ утверждает
//
// Он не судит саму уборку — её предикат проверяет интеграционная проба
// репозитория. Он судит только предпосылку.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/treecorpus"
)

// reconcileOutboxTable — таблица, чью уборку стережёт предпосылка.
const reconcileOutboxTable = "resource_reconcile_outbox"

// redriveConstructors — конструкторы оживителя отравленных строк из общей
// библиотеки очередей. Гейт судит МЕСТО ПОСТРОЕНИЯ, а не вызов прохода: имя
// таблицы называется здесь, в конфигурации, и только здесь его видно.
var redriveConstructors = map[string]bool{"New": true, "NewRedriveOnly": true}

// TestReconcileOutboxRetentionPremiseHolds — ни один оживитель отравленных строк
// не построен НАД ОЧЕРЕДЬЮ СВЕРКИ, поэтому её уборка вправе снимать доставленную
// строку по возрасту и ничего не щадить.
//
// # Почему судится ТАБЛИЦА, а не служба
//
// Первая редакция гейта спрашивала «есть ли в службе хоть один оживитель» и
// покраснела сразу: оживитель есть — над очередью писем (`invite_mail_outbox`),
// у которой СВОЙ ключ партиции и общий уборщик платформы. К очереди сверки он
// отношения не имеет, и его существование её уборку не делает неверной.
//
// Гейт, красный на исправном дереве, отключают первым, а вместе с ним перестают
// читать и настоящую находку. Поэтому предикат сужен до предмета: оживитель НАД
// ЭТОЙ таблицей. Оживитель над соседней остаётся законным близнецом и обязан
// молчать — это утверждается отдельно, иначе «находок ноль» зеленело бы на
// разборе, не узнающем оживителя вовсе.
//
// # Обход берётся у ИНДЕКСА
//
// Гейт судит о СОСТАВЕ дерева; неотслеживаемый файл, попавший в обход, дал бы
// вердикт о том, чего в дереве нет. Идиому держит `TestTreeWalkersAskTheIndex`.
func TestReconcileOutboxRetentionPremiseHolds(t *testing.T) {
	root := catalogRepoRoot(t)

	files, err := treecorpus.UnderWithSuffix(filepath.Join(root, iamTreeRel), ".go")
	if err != nil {
		t.Fatalf("состав индекса поддерева %s: %v", iamTreeRel, err)
	}

	sites, filesRead, err := redriveSitesOfTree(root, files)
	if err != nil {
		t.Fatalf("%v", err)
	}

	var overThisQueue, overOthers []string
	for _, s := range sites {
		if strings.Contains(s.table, reconcileOutboxTable) {
			overThisQueue = append(overThisQueue, s.where)
			continue
		}
		overOthers = append(overOthers, s.where+" ("+s.table+")")
	}

	t.Logf("перепись: файлов Go в индексе поддерева %d · прод-файлов прочитано %d · "+
		"мест построения оживителя %d · из них над очередью сверки %d · над соседними %d",
		len(files), filesRead, len(sites), len(overThisQueue), len(overOthers))

	// Пустой обход — отказ: гейт, которому нечего было читать, зелен по
	// построению и неотличим от исправного.
	if filesRead == 0 {
		t.Fatalf("обход пуст: в индексе %s ноль прод-файлов Go — вердикт беспредметен", iamTreeRel)
	}
	// Разбор обязан УМЕТЬ узнавать оживителя. Ноль мест построения означал бы,
	// что признак разъехался с кодом, — и молчание гейта означало бы слепоту, а
	// не отсутствие предмета. Законный близнец в дереве есть: оживитель очереди
	// писем.
	if len(sites) == 0 {
		t.Fatal("мест построения оживителя не найдено ни одного — признак разъехался с кодом. " +
			"В дереве службы такой оживитель ЕСТЬ (очередь писем), значит ноль здесь означает слепоту")
	}
	if len(overOthers) == 0 {
		t.Fatal("законный близнец не найден: оживитель над СОСЕДНЕЙ очередью обязан быть виден разбору " +
			"и обязан молчать — без него «над очередью сверки ноль» ничего не доказывает")
	}

	if len(overThisQueue) != 0 {
		t.Fatalf(`ПРЕДПОСЫЛКА УБОРКИ ОЧЕРЕДИ СВЕРКИ БОЛЬШЕ НЕ ВЕРНА.

Над очередью %s построен оживитель отравленных строк: %s

Уборка этой очереди (retention.SubjectReconcileOutbox) снимает ДОСТАВЛЕННУЮ
строку по возрасту и НИЧЕГО не щадит — это было законно ровно пока оживителя
над нею не было. Оживлённая отравленная строка теперь вправе уйти применяться
после уже применённого потомка, чей след уборка сняла.

Исходов два, и «оставить как есть» среди них нет: либо уборка учится щадить
доставленную строку, защищающую отравленного предшественника (то есть заводит
ключ партиции и переходит на общий уборщик платформы), либо оживитель к этой
очереди не подключается и это записано решением.`,
			reconcileOutboxTable, strings.Join(overThisQueue, ", "))
	}
}

// redriveSite — одно место построения оживителя и таблица, которую оно назвало.
type redriveSite struct {
	where string
	table string
}

// redriveSitesOfTree — разбор мест построения оживителя по прод-дереву.
//
// Таблица берётся из поля `Table` конфигурации построения. Значение бывает
// литералом либо ИМЕНЕМ КОНСТАНТЫ (`clients.InviteMailTable`) — обе формы
// законны и обе распознаются: форма, о которой разбор не знает, дала бы не
// красное и не зелёное, а молчание.
func redriveSitesOfTree(root string, files []string) ([]redriveSite, int, error) {
	fset := token.NewFileSet()
	var out []redriveSite
	read := 0
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return nil, read, perr
		}
		read++
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !redriveConstructors[sel.Sel.Name] {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "reconciler" {
				return true
			}
			out = append(out, redriveSite{
				where: rel + ":" + fset.Position(call.Pos()).String()[strings.LastIndex(
					fset.Position(call.Pos()).String(), ":")+1:],
				table: tableArgOf(call),
			})
			return true
		})
	}
	return out, read, nil
}

// tableArgOf — значение поля `Table` в конфигурации построения; пустая строка,
// когда поля нет. Обе законные формы значения — литерал и имя константы —
// возвращаются как есть, чтобы вердикт можно было прочесть глазами.
func tableArgOf(call *ast.CallExpr) string {
	for _, a := range call.Args {
		lit, ok := a.(*ast.CompositeLit)
		if !ok {
			continue
		}
		for _, el := range lit.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			k, ok := kv.Key.(*ast.Ident)
			if !ok || k.Name != "Table" {
				continue
			}
			switch v := kv.Value.(type) {
			case *ast.BasicLit:
				return strings.Trim(v.Value, `"`)
			case *ast.SelectorExpr:
				if x, ok := v.X.(*ast.Ident); ok {
					return x.Name + "." + v.Sel.Name
				}
				return v.Sel.Name
			case *ast.Ident:
				return v.Name
			}
		}
	}
	return ""
}
