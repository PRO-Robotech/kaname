// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Маска известно-красного не может вычитать больше, чем называет, и не может
// пережить свой предмет.
//
// Гейт `assert-suites-green.sh` вычитает из вердикта перечисленные утверждения.
// Механизм законен, но у него два способа тихо разойтись с деревом, и оба
// случились вживую:
//
//  1. НЕСИММЕТРИЧНОЕ СУЖЕНИЕ. Запись, написанная под один шаг, матчилась по имени
//     ПАПКИ — то есть снимала с вердикта каждое упавшее утверждение этой папки,
//     о чём бы оно ни было. Сужение «папка → шаг» применили к одной арке из
//     четырёх; три остались по папке. Асимметрия не была продумана — просто там
//     остановился предыдущий проход.
//
//  2. ЗАПИСЬ ПЕРЕЖИЛА СВОЙ ПРЕДМЕТ. Обоснование записи ссылалось на субъекта
//     (`jwtInvitee`), которого кейс перестал называть неделей раньше, а пометка
//     «проверено, всё ещё верно» подтверждала утверждение о несуществующем.
//     Кейс при этом жив — поэтому проверка «токен матчит хоть что-то» такого не
//     ловит: разошлась не папка, а СУБЪЕКТ внутри неё.
//
// Проверяется чтением скрипта и сгенерированных коллекций, а не доверием к прозе.
package newmanmask

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

const maskScript = "services/iam/tests/newman/scripts/assert-suites-green.sh"

func repoRoot(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(self)
	for range 12 {
		if fi, err := os.Stat(filepath.Join(dir, ".github", "workflows")); err == nil && fi.IsDir() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not find .github/workflows above this test file")
	return ""
}

// maskLine — строка, собирающая вычитаемое (`known_red=$(jq …)`).
func maskLine(t *testing.T, root string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(root, maskScript))
	if err != nil {
		t.Fatalf("read %s: %v", maskScript, err)
	}
	for _, ln := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(ln)
		if strings.HasPrefix(trimmed, "known_red=") {
			return trimmed
		}
	}
	t.Fatalf("%s has no `known_red=` line — this gate would assert about nothing", maskScript)
	return ""
}

// selectBody — тело последнего `select( … )` строки: именно в нём живёт альтернация
// арок. Возвращает содержимое без внешних скобок.
func selectBody(s string) string {
	key := "select("
	last := strings.LastIndex(s, key)
	if last < 0 {
		return ""
	}
	open := last + len(key) - 1
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return s[open+1 : i]
			}
		}
	}
	return ""
}

// orOperands — операнды `or` НУЛЕВОГО уровня вложенности. Разбор по скобкам, а не
// по тексту: `or` внутри регулярного выражения арки не должен делить выражение.
func orOperands(body string) []string {
	var out []string
	depth, start := 0, 0
	inStr := false
	for i := 0; i < len(body); i++ {
		switch body[i] {
		case '"':
			inStr = !inStr
		case '(':
			if !inStr {
				depth++
			}
		case ')':
			if !inStr {
				depth--
			}
		case 'o':
			if !inStr && depth == 0 && strings.HasPrefix(body[i:], "or ") &&
				(i == 0 || body[i-1] == ' ' || body[i-1] == ')') {
				out = append(out, strings.TrimSpace(body[start:i]))
				start = i + 3
			}
		}
	}
	out = append(out, strings.TrimSpace(body[start:]))
	return out
}

// TestMaskNarrowsByStepNotByFolder — каждая арка, опознающая ПАПКУ, обязана в том же
// операнде сужать до ШАГА. Иначе запись, написанная под одно утверждение, снимает с
// вердикта всё, что упало рядом, — включая стражей утечки.
func TestMaskNarrowsByStepNotByFolder(t *testing.T) {
	line := maskLine(t, repoRoot(t))
	body := selectBody(line)
	if body == "" {
		t.Fatalf("no `select( … )` found in the mask line — either the mechanism changed shape "+
			"or this gate stopped reading it; both need a human:\n  %s", line)
	}

	const folderKey, stepKey = ".parent.name", ".source.name"
	operands := orOperands(body)
	var folderArcs int
	for i, op := range operands {
		if !strings.Contains(op, folderKey) {
			continue
		}
		folderArcs++
		if !strings.Contains(op, stepKey) {
			t.Errorf("arc #%d matches by folder without narrowing to a step:\n  %s\n"+
				"a folder is not a subject: this subtracts EVERY failing assertion in that folder, "+
				"whatever it is about — which is how a leak guard gets absorbed for standing next to "+
				"the timing effect an entry was written for. Conjoin a %s test naming the step.",
				i+1, op, stepKey)
		}
	}

	// «Ноль находок» обязано быть отличимо от «ноль прочитанного».
	if folderArcs == 0 {
		t.Fatalf("no %s arc found among %d top-level operand(s) — the gate inspected nothing",
			folderKey, len(operands))
	}
	t.Logf("inspected %d top-level operand(s), %d of them folder-matching, in %s",
		len(operands), folderArcs, maskScript)
}

// caseIDToken — токен альтернации, который есть литеральный case-id (`^ID`).
var caseIDToken = regexp.MustCompile(`\^([A-Z][A-Z0-9-]{6,})`)

// maskSubjectDecl — машиночитаемое объявление предмета записи:
//
//	# @mask-subject <регексп-папки> <файл-исходник-кейсов> <субъект> [<субъект>…]
//
// Привязка объявлена целиком, а не выведена: ни абзац по окрестности, ни файл по
// имени кейса. Это принципиально с двух сторон. Блок обоснований — одна непрерывная
// область комментария, поэтому любое «окно строк» вокруг упоминания захватывает
// соседей и даёт ложные срабатывания; а имена кейсов этих семейств ГЕНЕРИРУЮТСЯ
// (в исходнике нет литерального `id=`), поэтому поиск файла по id не нашёл бы
// ничего и гейт молча судил бы о пустом множестве. Гейт, который ложно срабатывает,
// отключают первым же коммитом; гейт, который судит о пустоте, не замечают вовсе.
var maskSubjectDecl = regexp.MustCompile(`^#\s*@mask-subject\s+(\S+)\s+(\S+)\s+(.+?)\s*$`)

// TestMaskSubjectDeclarationsStillHold — если запись объявила, о каком СУБЪЕКТЕ она
// рассуждает, кейсы под её регекспом обязаны этого субъекта ещё называть.
//
// Ровно этим разошлись две записи, снятые 2026-07-30: кейс жил, папка матчилась, а
// субъект внутри кейса заменили — в одном случае неделей, в другом девятью днями
// раньше. Проверка «токен матчит хоть что-то» такое пропускает by construction:
// разошлась не папка, а субъект внутри неё.
func TestMaskSubjectDeclarationsStillHold(t *testing.T) {
	root := repoRoot(t)

	raw, err := os.ReadFile(filepath.Join(root, maskScript))
	if err != nil {
		t.Fatalf("read %s: %v", maskScript, err)
	}

	folders := allFolderNames(t, root)

	var decls int
	for _, ln := range strings.Split(string(raw), "\n") {
		m := maskSubjectDecl.FindStringSubmatch(strings.TrimSpace(ln))
		if m == nil {
			continue
		}
		decls++
		pat, cerr := regexp.Compile(m[1])
		if cerr != nil {
			t.Errorf("@mask-subject pattern %q does not compile: %v", m[1], cerr)
			continue
		}
		srcPath := m[2]
		subjects := strings.Fields(m[3])

		// (а) у объявления есть предмет в дереве — иначе оно судит о пустоте.
		var matched int
		for _, f := range folders {
			if pat.MatchString(f) {
				matched++
			}
		}
		if matched == 0 {
			t.Errorf("@mask-subject pattern %q matches no generated case folder — the declaration "+
				"has nothing to be about", m[1])
		}

		// (б) названный исходник существует и всё ещё называет субъекта.
		b, rerr := os.ReadFile(filepath.Join(root, srcPath))
		if rerr != nil {
			t.Errorf("@mask-subject for %q names source %s, which cannot be read: %v", m[1], srcPath, rerr)
			continue
		}
		// ИСПОЛНЯЕМАЯ часть, а не текст файла. Иначе субъект находится в
		// комментарии, объясняющем, что его как раз ЗАМЕНИЛИ: authz-deny.py прямо
		// пишет «раньше здесь стоял jwtNoBindings» — и проверка по сырому тексту
		// зеленела на объявлении, ссылающемся на снятого субъекта. Инъекция это
		// показала: гейт молчал ровно на том дефекте, ради которого написан.
		src := stripPyNonCode(string(b))
		for _, subj := range subjects {
			if !strings.Contains(src, subj) {
				t.Errorf("mask entry %q is justified by reasoning about subject %q, but %s no longer "+
					"names it.\nAn entry whose justification outlived its subject cannot be re-affirmed by "+
					"re-reading the paragraph — only by re-reading the case. Re-derive the entry from the "+
					"case as it is now, or drop it.", m[1], subj, srcPath)
			}
		}
		t.Logf("declaration %q: %d folder(s) matched, source %s, subject(s) %v", m[1], matched, srcPath, subjects)
	}

	t.Logf("%d @mask-subject declaration(s) checked against %d generated folder name(s)", decls, len(folders))
	if decls == 0 {
		t.Fatalf("no @mask-subject declaration found in %s — either every entry lost its declaration "+
			"or this gate stopped reading them; both need a human", maskScript)
	}
}

// TestEveryAlternationTokenHasASubject — исключение живёт, пока у него есть
// предмет: токен, не совпадающий ни с одной папкой сгенерированных коллекций,
// вычитать больше нечего, и он остаётся ловушкой для будущего одноимённого шага.
func TestEveryAlternationTokenHasASubject(t *testing.T) {
	root := repoRoot(t)
	line := maskLine(t, root)
	folders := allFolderNames(t, root)

	var tokens, orphan []string
	for _, m := range caseIDToken.FindAllStringSubmatch(line, -1) {
		tokens = append(tokens, m[1])
	}
	if len(tokens) == 0 {
		t.Fatal("no case-id token parsed out of the mask line — the gate inspected nothing")
	}
	for _, tok := range tokens {
		hit := false
		for _, f := range folders {
			if strings.HasPrefix(f, tok) {
				hit = true
				break
			}
		}
		if !hit {
			orphan = append(orphan, tok)
		}
	}
	t.Logf("checked %d case-id token(s) against %d generated folder name(s)", len(tokens), len(folders))
	if len(orphan) > 0 {
		t.Errorf("mask token(s) with nothing left to exclude: %s\n"+
			"A list of exclusions must expire by itself: an entry that matches no case subtracts nothing "+
			"today and silently absorbs whatever reuses the name tomorrow.", strings.Join(orphan, ", "))
	}
}

// stripPyNonCode — убрать из python-исходника то, что не исполняется: строки
// документации (тройные кавычки) и `#`-комментарии. Обычные строковые литералы
// СОХРАНЯЮТСЯ — субъект живёт именно в них (`auth="jwtX"`, кортежи SUBJECTS).
//
// Нужно потому, что случай, ради которого гейт написан, оставляет в файле фразу
// «раньше здесь стоял <снятый субъект>»: поиск по сырому тексту находит её и
// зеленеет на объявлении, которое как раз и разошлось с деревом.
func stripPyNonCode(s string) string {
	// (1) строки документации.
	for _, q := range []string{`"""`, "'''"} {
		for {
			i := strings.Index(s, q)
			if i < 0 {
				break
			}
			j := strings.Index(s[i+3:], q)
			if j < 0 {
				s = s[:i]
				break
			}
			s = s[:i] + s[i+3+j+3:]
		}
	}
	// (2) `#`-комментарии — вне строковых литералов.
	var out strings.Builder
	for _, line := range strings.Split(s, "\n") {
		var quote byte
		cut := -1
		for i := 0; i < len(line); i++ {
			c := line[i]
			switch {
			case quote != 0:
				if c == '\\' {
					i++
				} else if c == quote {
					quote = 0
				}
			case c == '\'' || c == '"':
				quote = c
			case c == '#':
				cut = i
			}
			if cut >= 0 {
				break
			}
		}
		if cut >= 0 {
			out.WriteString(line[:cut])
		} else {
			out.WriteString(line)
		}
		out.WriteByte('\n')
	}
	return out.String()
}

// allFolderNames — имена папок и запросов ВСЕХ сгенерированных коллекций дерева.
// Перепись отдельным утверждением: «ноль находок» обязано быть отличимо от «ноль
// прочитанного».
func allFolderNames(t *testing.T, root string) []string {
	t.Helper()
	cols, _ := filepath.Glob(filepath.Join(root, "services", "*", "tests", "newman", "collections", "*.json"))
	var out []string
	var parsed int
	for _, p := range cols {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var col struct {
			Item []json.RawMessage `json:"item"`
		}
		if json.Unmarshal(b, &col) != nil {
			continue
		}
		parsed++
		out = append(out, collectNames(col.Item)...)
	}
	if parsed == 0 {
		t.Fatal("no generated collection parsed — this gate inspected nothing")
	}
	return out
}

// collectNames — имена всех папок и запросов коллекции.
func collectNames(items []json.RawMessage) []string {
	var out []string
	for _, raw := range items {
		var node struct {
			Name string            `json:"name"`
			Item []json.RawMessage `json:"item"`
		}
		if json.Unmarshal(raw, &node) != nil {
			continue
		}
		if node.Name != "" {
			out = append(out, node.Name)
		}
		if len(node.Item) > 0 {
			out = append(out, collectNames(node.Item)...)
		}
	}
	return out
}
