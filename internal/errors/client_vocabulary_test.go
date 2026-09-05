// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package errors_test

// client_vocabulary_test.go — гейт: текст, который читает АРЕНДАТОР, не
// называет внутренних слоёв кода.
//
// ПРЕДМЕТ. Арендатор читает слово, которого нет ни в одном нашем документе, и
// сделать по нему не может ничего. Хуже, когда слово называет СТОРОННЮЮ
// систему: тогда отказ рассказывает об устройстве платформы вместо того, чтобы
// говорить, что делать дальше.
//
// ЧТО СЧИТАЕТСЯ ТЕКСТОМ ДЛЯ АРЕНДАТОРА — определено по ТРАКТУ, а не на глаз:
//
//  1. литерал сообщения в `status.Error/Errorf/New` — такой статус уходит на
//     провод как есть: `shared.MapRepoErr` пропускает готовый статус сквозь
//     себя (ветвь pass-through), то есть схлопывание в фиксированный текст его
//     НЕ касается;
//  2. литерал в `Wrapf(<признак>, …)` для тех признаков, чей текст
//     `MapRepoErr` доносит до провода (`StripSentinel`).
//
// Признаки `ErrInternal` и `ErrUnavailable` в перечень НЕ входят: их ветви
// отдают фиксированный текст, и что бы автор ни написал в обёртке, арендатор
// этого не увидит. Включить их значило бы краснеть на строках, которые
// адресованы журналу.
//
// ГРАНИЦА, названная явно: адресат различает, а не слово. Тексты внутреннего
// слушателя обращены к МОДУЛЮ и его оператору — они называют механизм
// намеренно. Их пакеты перечислены в `operatorAddressed`, и перечень
// САМОИСТЕКАЕТ: запись, у которой не осталось ни одного попадания, — находка.
//
// Способность падать и молчать доказана инъекцией —
// `TestClientVocabularyGateInjection`.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/gitenv"
)

// serviceRoot — корень дерева службы относительно этого пакета.
const serviceRoot = "../.."

// passThroughSentinels — признаки, чей текст доезжает до провода дословно
// (`shared.MapRepoErr` → `status.Error(code, StripSentinel(err))`).
var passThroughSentinels = map[string]bool{
	"ErrNotFound":            true,
	"ErrAlreadyExists":       true,
	"ErrPermissionDenied":    true,
	"ErrUnauthenticated":     true,
	"ErrFailedPrecondition":  true,
	"ErrInvalidArg":          true,
	"ErrAborted":             true,
	"ErrQuotaExceeded":       true,
	"ErrQuotaNotProvisioned": true,
	"ErrQuotaRateExceeded":   true,
	"ErrReferenceMissing":    true,
	"ErrReferenceInUse":      true,
}

// internalVocabulary — закрытый словарь имён внутренних слоёв. Перечень
// закрытый намеренно: широкий («любое английское техническое слово») краснел бы
// на контракт-тоне, который менять нельзя.
var internalVocabulary = []struct {
	word string
	why  string
}{
	{"marshal", "имя операции сериализации — слой кода, а не предмет арендатора"},
	{"unmarshal", "то же"},
	{"serializ", "уровень изоляции СУБД / операция сериализации"},
	{"hydra", "имя стороннего поставщика — арендатору о нём знать не полагается"},
	{"openfga", "имя стороннего хранилища отношений"},
	{"pgx", "имя драйвера СУБД"},
	{"sqlstate", "код состояния СУБД"},
	{"goroutine", "устройство исполнения"},
	{"read committed", "уровень изоляции СУБД"},
	{"repeatable read", "уровень изоляции СУБД"},
}

// operatorAddressed — пакеты, чьи отказы обращены к МОДУЛЮ и его оператору, а
// не к арендатору: они живут на внутреннем слушателе (:9091), куда арендатор не
// дозванивается by construction. Слово механизма там законно и снимать его
// нельзя.
//
// Перечень самоистекает: запись без единого попадания — находка, потому что
// послабление без предмета переживёт свою причину.
// Сегодня перечень ПУСТ, и это состояние, а не недосмотр: ни один клиентский
// текст словаря не оказался адресован оператору. Пустая ведомость — цель, а не
// поломка, поэтому гейт на ней проходит; заводить запись «про запас» нельзя —
// она станет слепой зоной, выданной вперёд.
var operatorAddressed = map[string]string{}

type clientText struct {
	pkg  string
	pos  string
	text string
	// producer — как отказ построен: имя признака (`ErrNotFound`, …) для
	// `Wrapf` либо имя кода (`PermissionDenied`, …) для `status.*`. По нему
	// перепись `client_refusal_reason_coverage_test.go` решает, несёт ли отказ
	// машинный признак полосы.
	producer string
}

func collectClientTexts(t *testing.T) []clientText {
	t.Helper()
	out, err := gitenv.Command(serviceRoot, "ls-files", "internal").Output()
	if err != nil {
		t.Fatalf("перечень файлов службы не получен: %v", err)
	}
	var texts []clientText
	fset := token.NewFileSet()
	files := 0
	for _, rel := range strings.Fields(string(out)) {
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			continue
		}
		files++
		f, perr := parser.ParseFile(fset, path.Join(serviceRoot, rel), nil, 0)
		if perr != nil {
			t.Fatalf("%s не разобран: %v", rel, perr)
		}
		pkgDir := path.Dir(rel)
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			var msgArg ast.Expr
			producer := ""
			switch sel.Sel.Name {
			case "Error", "Errorf", "New":
				// status.Error(codes.X, "…") — подлежащее обязано быть `status`.
				pkgIdent, ok := sel.X.(*ast.Ident)
				if !ok || pkgIdent.Name != "status" || len(call.Args) < 2 {
					return true
				}
				if code, ok := call.Args[0].(*ast.SelectorExpr); ok {
					producer = "codes." + code.Sel.Name
				}
				msgArg = call.Args[1]
			case "Wrapf":
				// Wrapf(<признак>, "…") — только признаки, чей текст доезжает.
				s, ok := call.Args[0].(*ast.SelectorExpr)
				if !ok || !passThroughSentinels[s.Sel.Name] || len(call.Args) < 2 {
					return true
				}
				producer = s.Sel.Name
				msgArg = call.Args[1]
			default:
				return true
			}
			lit, ok := msgArg.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			v, uerr := strconv.Unquote(lit.Value)
			if uerr != nil || strings.TrimSpace(v) == "" || v == "%s" || v == "%v" {
				return true
			}
			texts = append(texts, clientText{
				pkg: pkgDir, pos: fset.Position(lit.Pos()).String(), text: v, producer: producer,
			})
			return true
		})
	}
	if files == 0 {
		t.Fatal("прод-файлов службы прочитано 0 — вердикт беспредметен")
	}
	t.Logf("перепись: прод-файлов %d · клиентских текстов %d", files, len(texts))
	return texts
}

func TestClientRefusalTextNamesNoInternalLayer(t *testing.T) {
	texts := collectClientTexts(t)
	if len(texts) == 0 {
		t.Fatal("клиентских текстов прочитано 0 — разбор разошёлся с деревом")
	}

	findings, exempted := vocabularyFindings(texts, operatorAddressed)

	// Самоистечение послабления: запись, которой больше нечего исключать,
	// переживёт свою причину и достанется следующей слепой зоне.
	var stale []string
	for pkg := range operatorAddressed {
		if exempted[pkg] == 0 {
			stale = append(stale, pkg)
		}
	}
	sort.Strings(stale)

	t.Logf("перепись: клиентских текстов %d · с именем внутреннего слоя %d · прощено адресату-оператору %d",
		len(texts), len(findings), len(exempted))

	if len(stale) > 0 {
		t.Errorf("послабление потеряло предмет — %d записей нечего исключать: %s\n"+
			"Снимите запись: она достанется следующей слепой зоне.", len(stale), strings.Join(stale, ", "))
	}
	if len(findings) > 0 {
		t.Fatalf("клиентский текст называет внутренний слой в %d местах:\n  %s\n"+
			"На месте каждого обязан стоять текст, называющий следующий шаг клиента, а не причину внутри.",
			len(findings), strings.Join(findings, "\n  "))
	}
}

// vocabularyFindings — ЧИСТЫЙ предикат гейта. Выделен ради инъекции: доказывать
// способность падать на живой находке нельзя — такая проба исчезает вместе с
// находкой, то есть ровно тогда, когда дерево починено.
func vocabularyFindings(texts []clientText, ledger map[string]string) ([]string, map[string]int) {
	var findings []string
	exempted := map[string]int{}
	for _, ct := range texts {
		low := strings.ToLower(ct.text)
		for _, w := range internalVocabulary {
			if !strings.Contains(low, w.word) {
				continue
			}
			if _, ok := ledger[ct.pkg]; ok {
				exempted[ct.pkg]++
				continue
			}
			findings = append(findings, ct.pos+" — "+strconv.Quote(ct.text)+": "+w.why)
		}
	}
	sort.Strings(findings)
	return findings, exempted
}
