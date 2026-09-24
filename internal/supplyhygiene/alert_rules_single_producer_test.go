// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// alert_rules_single_producer_test.go — ПРАВИЛА ТРЕВОГИ ОБЪЯВЛЯЕТ ОДИН
// ПРОИЗВОДИТЕЛЬ, и из документации их пересказывает РОВНО ОДНА страница.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Правила везёт объект чарта. Опубликованная страница пересказывает его —
// законно и НЕ МОЛЧА: набор объекта и набор страницы сверяет в обе стороны
// `TestDeliveredAlertRulesMatchThePublishedPage`. Всякий третий пересказ
// сверять нечем, и он расходится молча — расходится всегда тот, которого не
// считали.
//
// Так и вышло: инженерный документ остался исходником переноса правил на
// страницу (`kacho#2522`) и с тех пор не сверялся ничем. За четыре правки
// объекта он отстал на тринадцать правил, у двух назвал ДРУГИЕ имена
// (`KanameAuthzCheckSlow` против `KanameAuthzSlow`), а два держал у себя при
// том, что поставка их не везла вовсе. Дежурный, скопировавший правило со
// страницы, и инженер, искавший его по имени в инженерном документе, получали
// разные имена (`kacho#2545`).
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЭТО ПОЧИНИЛО СВЕРХ ТЕКСТА — И ПОЧЕМУ ПРОВЕРКА ЗАВЕДЕНА, А НЕ СВЕДЕНЫ СПИСКИ
//
// Копию читал ДЕЙСТВУЮЩИЙ держатель: `TestIdentityGrowthMetricsHaveANamedReader`
// искал читателя ряда в инженерном документе и находил там правило, которого
// поставка не везла. Гейт был зелен, свойство не выполнялось: у того, кто
// поставил продукт, оповещения не существовало. Проверка, судящая пересказ
// вместо производителя, и есть цена третьего места об одном предмете — поэтому
// здесь запрещён сам пересказ, а не сверяется его содержимое.
//
// ─────────────────────────────────────────────────────────────────────────────
// ГРАНИЦА НАЗВАНА
//
// Судится ОБЪЯВЛЕНИЕ правила в блоке кода. Имя тревоги, названное в прозе
// («правило `KanameAuthnHooksSilent` звонит, когда…»), объявлением НЕ является
// и находкой не становится: проза не срабатывает, а объяснить действующее
// правило документ вправе где угодно. Различие несущее — оба текста лежат в
// одних и тех же файлах.
//
// Блок кода берётся ЛЮБОЙ, а не только помеченный `yaml`: в этом дереве блоков
// без языка 757 против шести помеченных, и распознаватель, знающий одну форму,
// молчал бы на остальных — не краснея и не зеленея.
//
// Обход идёт по ВСЕМУ дереву, а не по каталогу документации: `INSTALL.md` и
// `README.md` адресованы ровно тому, кто ставит продукт, то есть читателю
// правил, — и копия там была бы невидима проверке, знающей один каталог.
// Величины названы обе: расширение подняло осмотренное со 121 документа до
// 141, полоса находок при этом НЕ изменилась — значит прибавка была слепой
// зоной, а не регрессией дерева.
//
// Пропускаются три каталога, и каждый назван с причиной: `node_modules` (1858
// чужих документов, привезённых сборкой сайта), `build` (её выход) и `.git`.
// Перечень пропущенного печатается переписью — пропуск, о котором не сказано,
// неотличим от необойдённого.
//
// ЧЕГО ЭТА ПРОВЕРКА НЕ ЗАКРЫВАЕТ: верность самих выражений и совпадение объекта
// со страницей. Первое держится по частям: имя ряда —
// `TestObservabilityPagePromisesOnlyWhatTheServiceProduces`, отбор по имени
// контракта — `TestAlertSelectorsNameAContractTheTreeProduces`, отбор по исходу
// у рядов её таблицы — `TestAlertOutcomeSelectorsNameValuesTheTreeProduces`, ряд
// прохода сметателя ключей — `TestSigningKeySweeperSilenceIsAlerted`. Второе —
// `TestDeliveredAlertRulesMatchThePublishedPage`.
package supplyhygiene

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// alertDeclarationRe — позиция ОБЪЯВЛЕНИЯ правила: ключ `alert:` в начале
// строки, с необязательным дефисом элемента списка. Хвост строки не судится —
// имя правила предметом проверки не является.
var alertDeclarationRe = regexp.MustCompile(`(?m)^[ \t]*-?[ \t]*alert:[ \t]`)

// codeFenceRe — блок кода любого языка, включая блок без языка.
var codeFenceRe = regexp.MustCompile("(?s)```[a-zA-Z]*\n(.*?)```")

// skippedDocDirs — каталоги, которые обход НЕ читает, и причина у каждого своя.
//
//	node_modules — чужие документы, привезённые сборкой сайта: их 1858, и ни
//	               один из них не наш;
//	build        — выход той же сборки: порождённое судить незачем;
//	.git         — служебное.
//
// Перечень закрытый и ПЕЧАТАЕТСЯ числом пропущенных: каталог, о котором не
// сказано, неотличим от необойдённого.
var skippedDocDirs = map[string]bool{"node_modules": true, "build": true, ".git": true}

// alertProducerCensus — объём осмотренного одним обходом. Печатается всегда.
type alertProducerCensus struct {
	docsRead     int // файлов документации прочитано
	dirsSkipped  int // каталогов пропущено (чужое и порождённое)
	fencesRead   int // блоков кода в них прочитано
	declarations int // объявлений правил найдено
	pageDecls    int // из них на опубликованной странице — законных
	strayDecls   int // из них вне её — находки
}

// alertDeclaration — одно объявление: где написано.
type alertDeclaration struct {
	file string
	line int
}

// collectAlertDeclarations — объявления правил во всех документах под корнем.
//
// Возвращает их порознь: законные (опубликованная страница) и все прочие.
// Порознь, а не одним списком с флагом: пустой список законных означает, что
// страница перестала пересказывать правила, — и это тоже находка, только
// другая, и утверждается она своим требованием.
func collectAlertDeclarations(root, page string) (legit, stray []alertDeclaration, census alertProducerCensus, err error) {
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return nil
		}
		if d.IsDir() {
			if skippedDocDirs[d.Name()] {
				census.dirsSkipped++
				return fs.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".md" && ext != ".mdx" {
			return nil
		}
		raw, rerr := os.ReadFile(path) // #nosec G304 -- путь получен обходом корня документации
		if rerr != nil {
			return rerr
		}
		census.docsRead++

		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)
		text := string(raw)

		for _, loc := range codeFenceRe.FindAllStringSubmatchIndex(text, -1) {
			census.fencesRead++
			body := text[loc[2]:loc[3]]
			for _, m := range alertDeclarationRe.FindAllStringIndex(body, -1) {
				census.declarations++
				// Номер строки считается по исходному тексту, а не по телу
				// блока: читателю нужна координата в файле.
				line := 1 + strings.Count(text[:loc[2]+m[0]], "\n")
				decl := alertDeclaration{file: rel, line: line}
				if rel == page {
					census.pageDecls++
					legit = append(legit, decl)
					continue
				}
				census.strayDecls++
				stray = append(stray, decl)
			}
		}
		return nil
	})
	if walkErr != nil {
		return nil, nil, census, walkErr
	}
	sort.Slice(stray, func(i, j int) bool {
		if stray[i].file != stray[j].file {
			return stray[i].file < stray[j].file
		}
		return stray[i].line < stray[j].line
	})
	return legit, stray, census, nil
}

// TestAlertRulesAreDeclaredByOneProducer — правила тревоги пересказывает ровно
// опубликованная страница, и никакой другой документ их не объявляет.
func TestAlertRulesAreDeclaredByOneProducer(t *testing.T) {
	t.Parallel()

	legit, stray, census, err := collectAlertDeclarations(serviceRoot, observabilityPage)
	require.NoError(t, err, "обход документации не состоялся — вердикта нет")

	t.Logf("перепись: документов прочитано %d · каталогов пропущено %d · блоков кода %d · "+
		"объявлений правил %d · на опубликованной странице %d · вне её %d",
		census.docsRead, census.dirsSkipped, census.fencesRead,
		census.declarations, census.pageDecls, census.strayDecls)

	require.NotZero(t, census.docsRead,
		"обход дерева пуст — «ноль находок» здесь означает «ноль прочитанного»")
	require.NotZerof(t, census.fencesRead,
		"ни одного блока кода не прочитано — распознаватель перестал узнавать форму блока, "+
			"и молчание проверки неотличимо от чистого дерева")
	require.NotZerof(t, len(legit),
		"опубликованная страница (%s) не объявляет НИ ОДНОГО правила: либо правила ушли со "+
			"страницы, и тот, кто ставит продукт, больше не знает, о чём ему позвонят, либо "+
			"распознаватель разучился узнавать объявление — и тогда ноль ниже беспредметен",
		observabilityPage)

	var where []string
	for _, d := range stray {
		where = append(where, d.file+":"+itoa(d.line))
	}
	require.Emptyf(t, stray,
		"правила тревоги объявляет документ, который их НЕ ПРОИЗВОДИТ и с производителем НЕ "+
			"СВЕРЯЕТСЯ (%d):\n  %s\n"+
			"Производитель один — объект чарта (deploy/templates/prometheusrule.yaml); "+
			"опубликованная страница пересказывает его и сверяется с ним в обе стороны. "+
			"Третий пересказ сверять нечем: он разойдётся молча, и разойдётся именно он. "+
			"Объяснить действующее правило документ вправе ПРОЗОЙ — проза находкой не является.",
		len(stray), strings.Join(where, "\n  "))
}
