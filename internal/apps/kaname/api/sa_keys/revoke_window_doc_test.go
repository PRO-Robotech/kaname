// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package sa_keys

// revoke_window_doc_test.go — комментарий, отвечающий на вопрос «как быстро
// действует отзыв», обязан описывать ДЕРЕВО, а не одну из двух полос выдачи.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ (#2484)
//
// В пути снятия ключа служебной учётки стоял развёрнутый разбор, утверждавший,
// что уже выданное удостоверение живёт до собственного истечения, и что ИМЕННО
// эту величину следует называть, когда спрашивают о скорости отзыва.
//
// Для НАШЕЙ чеканки это неверно: снятие строки клиента порождает отсечку той же
// транзакцией, состав наших утверждений несёт ключ отсечки, и обе принимающие
// поверхности читают её НА ПУТИ ЗАПРОСА. Утверждение осталось верным только для
// полосы, где токен выпускает внешний поставщик.
//
// Класс — утверждение, пережившее свой предмет, в ПРОД-КОДЕ, и это был
// единственный в дереве ответ на заданный вопрос. Следующий читатель вправе
// «починить» код под неверный комментарий — сняв либо отсечку, либо её чтение.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕТЫРЕ ОСИ, И КАЖДАЯ ПАДАЕТ САМА
//
//  1. ЧИСЛО ПОВЕРХНОСТЕЙ. Сколько прод-файлов спрашивают правило отзыва —
//     разбор считает САМ, по узлу вызова. Ноль означал бы, что отзыв на
//     предъявлении не читает никто, и разбор о скорости стал бы ложью целиком.
//  2. ОТСЕЧКА В СХЕМЕ. Разбор называет триггер ⟺ схема его ОБЪЯВЛЯЕТ. Обе
//     стороны обязательны: названный и снятый триггер — ложь о настоящем;
//     живой и неназванный — тот же вопрос без ответа.
//  3. КЛЮЧ ОТСЕЧКИ В ПРАВИЛЕ. Разбор называет утверждение-ключ ⟺ закрытый
//     перечень правила его СОДЕРЖИТ. Ключ, выпавший из перечня, дал бы ключ,
//     чей отзыв не доезжает до предъявления, — и не доезжал бы МОЛЧА.
//  4. КООРДИНАТА ДОКУМЕНТА. Всякий путь `*.md`, названный комментариями файла,
//     обязан резолвиться в составе дерева.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ РАЗБОР, А НЕ ПОИСК ПО ТЕКСТУ
//
// Имя триггера встречается в схеме ТРИЖДИ, и только одно вхождение его
// объявляет: остальные — комментарий выгрузки и `COMMENT ON TRIGGER`. Предикат по
// подстроке зеленел бы на дереве, где триггер снят, а комментарий о нём остался,
// то есть ровно на том исходе, ради которого ось заведена. Поэтому существование
// судится по НАЧАЛУ ОПЕРАТОРА `CREATE TRIGGER <имя>`, а перечень ключей — по
// узлу объявления, а не по строке файла.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ЭТА ПРОВЕРКА НЕ ЗАКРЫВАЕТ — сказано прямо
//
// Она НЕ проверяет, что отсечка действительно останавливает токен: это предмет
// сквозной пробы на поднятой базе, и живёт он не здесь. Она судит согласие ПРОЗЫ
// с координатами, которые проза называет.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
	"github.com/stretchr/testify/require"
)

// treeRootFromSAKeys — корень дерева службы от каталога этого пакета.
const treeRootFromSAKeys = "../../../../.."

// revokeDocFile — файл, чью прозу судит гейт (от корня дерева).
const revokeDocFile = "internal/apps/kaname/api/sa_keys/usecases.go"

// revocationRuleFile — файл, объявляющий закрытый перечень ключей отсечки.
const revocationRuleFile = "internal/tokenrevocation/rule.go"

// revocationRuleVar — имя перечня в этом файле.
const revocationRuleVar = "subjectClaims"

// revocationReadName — имя функции правила, чьих вызывающих считает перепись.
const revocationReadName = "Revoked"

// migrationsDir — каталог схемы (от корня дерева). Гейт его только ЧИТАЕТ.
const migrationsDir = "internal/migrations"

// cutoffTrigger — триггер, порождающий отсечку при снятии строки клиента.
const cutoffTrigger = "sa_oauth_client_removal_cuts_minted_tokens"

// saCutoffClaim — утверждение, чьё значение служит ключом отсечки для этой полосы.
const saCutoffClaim = "kaname_sa_key_id"

// cutoffSurfaceMarker — машинно-читаемая форма числа. Проза меняется, маркер — нет.
var cutoffSurfaceMarker = regexp.MustCompile(`ПОВЕРХНОСТЕЙ, ЧИТАЮЩИХ ОТСЕЧКУ:\s*(\d+)`)

// revokeDocCoordinate — КООРДИНАТА документа: путь, несущий хотя бы один сегмент каталога.
//
// Голое имя файла координатой НЕ является и под ось не подпадает. Это решение, а
// не послабление: проза законно называет документ ПО ИМЕНИ («см. security.md»),
// и такое имя в дереве службы не резолвится by construction — регламент
// разработки в поставку продукта не входит. Судить его этой осью значило бы
// краснеть на 214 вхождениях в 160 файлах (замер на дереве) — то есть на классе,
// у которого другой предмет и другой радиус.
//
// Координата с сегментом каталога однозначна: она обещает файл ПО ЭТОМУ ПУТИ, и
// проверить обещание можно.
var revokeDocCoordinate = regexp.MustCompile(`[A-Za-z0-9_][A-Za-z0-9_.-]*(?:/[A-Za-z0-9_.-]+)+\.md\b`)

// createTriggerStatement — НАЧАЛО ОПЕРАТОРА, объявляющего триггер. Именно
// оператор, а не упоминание имени: в схеме имя встречается и в комментарии
// выгрузки, и в `COMMENT ON TRIGGER`.
var createTriggerStatement = regexp.MustCompile(`(?im)^\s*CREATE\s+TRIGGER\s+` + cutoffTrigger + `\b`)

// revokeWindowFacts — вход предиката. Собран так, чтобы предикат можно было
// прогнать инъекцией, не трогая дерево.
type revokeWindowFacts struct {
	// Comments — весь текст комментариев файла.
	Comments string
	// CutoffSurfaces — прод-файлы, где разбор нашёл чтение правила отзыва.
	CutoffSurfaces []string
	// TriggerNamed / TriggerInSchema — называет ли проза триггер и объявляет ли
	// его схема.
	TriggerNamed, TriggerInSchema bool
	// ClaimNamed / ClaimInRule — называет ли проза ключ отсечки и содержит ли
	// его закрытый перечень правила.
	ClaimNamed, ClaimInRule bool
	// DocPaths — координата документа → резолвится ли она в дереве.
	DocPaths map[string]bool
}

// auditRevokeWindowDoc — предикат всех осей. Возвращает находки; пусто = норма.
func auditRevokeWindowDoc(f revokeWindowFacts) []string {
	var found []string

	hits := cutoffSurfaceMarker.FindAllStringSubmatch(f.Comments, -1)
	switch {
	case len(hits) != 1:
		found = append(found, fmt.Sprintf(
			"маркер «ПОВЕРХНОСТЕЙ, ЧИТАЮЩИХ ОТСЕЧКУ: <N>» встречается %d раз(а), а обязан "+
				"ровно один: ноль означает, что сверять с деревом нечего, больше одного — "+
				"два места об одном числе", len(hits)))
	default:
		claimed, err := strconv.Atoi(hits[0][1])
		if err != nil {
			found = append(found, "маркер поверхностей не несёт числа: "+hits[0][1])
		} else if claimed != len(f.CutoffSurfaces) {
			found = append(found, fmt.Sprintf(
				"проза называет поверхностей, читающих отсечку: %d; разбор дерева нашёл %d — %s",
				claimed, len(f.CutoffSurfaces), strings.Join(f.CutoffSurfaces, ", ")))
		}
	}

	switch {
	case f.TriggerNamed && !f.TriggerInSchema:
		found = append(found, "проза называет триггер "+cutoffTrigger+
			", которого схема больше не объявляет — утверждение пережило свой предмет")
	case !f.TriggerNamed && f.TriggerInSchema:
		found = append(found, "схема объявляет триггер "+cutoffTrigger+
			", а проза его не называет — единственный в дереве ответ на вопрос о скорости "+
			"отзыва умалчивает о механизме, который эту скорость и задаёт")
	}

	switch {
	case f.ClaimNamed && !f.ClaimInRule:
		found = append(found, "проза называет ключ отсечки "+saCutoffClaim+
			", которого закрытый перечень правила отзыва не содержит — отзыв этой полосы "+
			"до предъявления не доезжает")
	case !f.ClaimNamed && f.ClaimInRule:
		found = append(found, "перечень правила отзыва содержит "+saCutoffClaim+
			", а проза его не называет — читатель не узнает, ЧЕМ отзыв этой полосы адресуется")
	}

	for _, p := range sortedRevokeDocPaths(f.DocPaths) {
		if !f.DocPaths[p] {
			found = append(found, "проза называет документ "+p+
				", которого в составе дерева нет — утверждение отправляет читателя в никуда")
		}
	}

	return found
}

func sortedRevokeDocPaths(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestRevokeWindowDocDescribesTheTree — гейт на дереве службы.
func TestRevokeWindowDocDescribesTheTree(t *testing.T) {
	tree, err := treecorpus.NewTree(treeRootFromSAKeys)
	require.NoError(t, err, "состав дерева службы не собран — вердикт беспредметен")
	root := tree.Root()

	comments := revokeFileComments(t, filepath.Join(root, filepath.FromSlash(revokeDocFile)))
	surfaces, scanned, parsed := revocationReadSites(t, tree, true)
	inSchema, sqlFiles := cutoffTriggerDeclared(t, tree)
	inRule, ruleKeys := cutoffClaimInRule(t, tree)
	docs := revokeDocPathsIn(comments, tree)

	// ПРЕДПОСЫЛКИ. «Ноль находок» обязано быть отличимо от «ноль прочитанного».
	require.Positive(t, scanned, "не осмотрено ни одного прод-файла Go — перепись сломана")
	require.NotEmpty(t, comments, "комментариев файла не прочитано ни одного")
	require.Positive(t, sqlFiles, "файлов схемы не прочитано ни одного — ось отсечки беспредметна")
	require.NotEmpty(t, ruleKeys, "закрытый перечень ключей отсечки пуст — ось ключа беспредметна")
	require.NotEmpty(t, surfaces,
		"разбор не нашёл НИ ОДНОГО прод-читателя правила отзыва — предикат меряет не то")

	facts := revokeWindowFacts{
		Comments: comments, CutoffSurfaces: surfaces,
		TriggerNamed: strings.Contains(comments, cutoffTrigger), TriggerInSchema: inSchema,
		ClaimNamed: strings.Contains(comments, saCutoffClaim), ClaimInRule: inRule,
		DocPaths: docs,
	}
	found := auditRevokeWindowDoc(facts)

	t.Logf("перепись: прод-файлов Go осмотрено %d, разобрано %d; поверхностей, читающих отсечку, "+
		"%d (%s); файлов схемы прочитано %d, триггер %s объявлен: %t; ключей в перечне правила %d "+
		"(%s), ключ %s в перечне: %t; координат документов в прозе %d",
		scanned, parsed, len(surfaces), strings.Join(surfaces, ", "),
		sqlFiles, cutoffTrigger, inSchema, len(ruleKeys), strings.Join(ruleKeys, ", "),
		saCutoffClaim, inRule, len(docs))

	require.Emptyf(t, found,
		"разбор скорости отзыва расходится с деревом:\n  %s\n\n"+
			"Комментарий, называющий снятый механизм действующим, читается как указание в "+
			"настоящем времени — и следующий идёт по нему, а не по коду.",
		strings.Join(found, "\n  "))
}

// revokeFileComments — текст ВСЕХ комментариев файла.
//
// Именно комментариев, а не файла целиком: иначе идентификатор в коде зачёлся бы
// за утверждение, и гейт судил бы имя переменной вместо прозы.
func revokeFileComments(t *testing.T, abs string) string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, abs, nil, parser.ParseComments)
	require.NoErrorf(t, err, "разбор %s: без него гейт судил бы пустую строку", abs)
	var sb strings.Builder
	for _, g := range f.Comments {
		sb.WriteString(g.Text())
		sb.WriteString("\n")
	}
	return sb.String()
}

// revocationReadSites — прод-файлы, в которых РАЗБОР нашёл чтение правила отзыва.
//
// `prodOnly` исключает пробы и сам пакет правила: вызов из пробы поверхностью на
// пути запроса не является, а объявление правила себя не читает. Флаг — параметр,
// потому что НЕВЫРОЖДЕННОСТЬ исключения обязана быть проверена: перепись без
// фильтра стоит рядом в инъекции и обязана быть СТРОГО шире.
func revocationReadSites(t *testing.T, tree *treecorpus.Tree, prodOnly bool) (surfaces []string, scanned, parsed int) {
	t.Helper()
	root := tree.Root()
	rulePkgDir := filepath.ToSlash(filepath.Dir(revocationRuleFile))
	fset := token.NewFileSet()
	for _, rel := range tree.SortedFiles() {
		slash := filepath.ToSlash(rel)
		if !strings.HasSuffix(slash, ".go") {
			continue
		}
		if prodOnly {
			if strings.HasSuffix(slash, "_test.go") || filepath.ToSlash(filepath.Dir(slash)) == rulePkgDir {
				continue
			}
		}
		scanned++
		body, rerr := os.ReadFile(filepath.Join(root, filepath.FromSlash(slash)))
		require.NoError(t, rerr)
		if !strings.Contains(string(body), revocationReadName) {
			continue
		}
		parsed++
		f, perr := parser.ParseFile(fset, slash, body, 0)
		require.NoErrorf(t, perr, "разбор %s", slash)
		hit := false
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel == nil || sel.Sel.Name != revocationReadName {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if ok && pkg.Name == "tokenrevocation" {
				hit = true
			}
			return true
		})
		if hit {
			surfaces = append(surfaces, slash)
		}
	}
	sort.Strings(surfaces)
	return surfaces, scanned, parsed
}

// cutoffTriggerDeclared — объявляет ли схема триггер отсечки, и сколько файлов
// схемы прочитано.
//
// Судится НАЧАЛО ОПЕРАТОРА, а не упоминание имени: имя стоит в схеме трижды, и
// только одно вхождение его объявляет.
func cutoffTriggerDeclared(t *testing.T, tree *treecorpus.Tree) (declared bool, files int) {
	t.Helper()
	root := tree.Root()
	for _, rel := range tree.SortedFiles() {
		slash := filepath.ToSlash(rel)
		if !strings.HasSuffix(slash, ".sql") || !strings.HasPrefix(slash, migrationsDir+"/") {
			continue
		}
		files++
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(slash)))
		require.NoError(t, err)
		if createTriggerStatement.Match(body) {
			declared = true
		}
	}
	return declared, files
}

// cutoffClaimInRule — содержит ли ЗАКРЫТЫЙ ПЕРЕЧЕНЬ правила ключ этой полосы, и
// каков перечень целиком.
//
// Перечень читается по узлу объявления: то же имя встречается в прозе шапки
// правила, и предикат по строке считал бы её тоже.
func cutoffClaimInRule(t *testing.T, tree *treecorpus.Tree) (contains bool, keys []string) {
	t.Helper()
	abs := filepath.Join(tree.Root(), filepath.FromSlash(revocationRuleFile))
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, abs, nil, 0)
	require.NoErrorf(t, err, "разбор %s: без него ось ключа не проверяла бы ничего", revocationRuleFile)

	for _, d := range f.Decls {
		gen, ok := d.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			named := false
			for _, n := range vs.Names {
				if n.Name == revocationRuleVar {
					named = true
				}
			}
			if !named {
				continue
			}
			for _, v := range vs.Values {
				lit, ok := v.(*ast.CompositeLit)
				if !ok {
					continue
				}
				for _, el := range lit.Elts {
					bl, ok := el.(*ast.BasicLit)
					if !ok || bl.Kind != token.STRING {
						continue
					}
					unquoted, uerr := strconv.Unquote(bl.Value)
					require.NoError(t, uerr)
					keys = append(keys, unquoted)
				}
			}
		}
	}
	for _, k := range keys {
		if k == saCutoffClaim {
			contains = true
		}
	}
	return contains, keys
}

// revokeDocPathsIn — координаты документов, названные прозой, и резолв каждой.
func revokeDocPathsIn(comments string, tree *treecorpus.Tree) map[string]bool {
	out := map[string]bool{}
	for _, p := range revokeDocCoordinate.FindAllString(comments, -1) {
		out[p] = tree.HasFile(p)
	}
	return out
}
