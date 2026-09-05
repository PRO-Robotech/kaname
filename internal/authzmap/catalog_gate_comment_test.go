// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// catalog_gate_comment_test.go — КОММЕНТАРИЙ, НАЗЫВАЮЩИЙ ГЕЙТ ГЛАГОЛА, СВЕРЯЕТСЯ
// С КАТАЛОГОМ ПРАВ (#1258).
//
// # Предмет
//
// Комментарий у обработчика объяснял машинный путь через одно отношение прав,
// тогда как каталог гейтит этот глагол другим. Первое из второго не следует, и
// цена расхождения здесь выше обычной неточности: названное отношение
// ВЫДАЁТСЯ ролью, а фактическое — вычисляемое и не выдаётся никому, кроме самого
// человека. Читатель, доверившийся тексту, искал бы, почему выдача не помогает,
// и «исправил» бы гейт на выдаваемое — то есть расширил бы доступ.
//
// Отдельно: названное отношение было СНЯТО со своего типа целиком, поэтому текст
// отсылал к тому, чего в модели уже нет.
//
// # Что судится и чем
//
// Авторитет — каталог прав (разобранный JSON), подсудимый — комментарий. Наоборот
// быть не может: сверять текст комментария с текстом соседнего комментария значило
// бы проверять согласие лжи с самой собой.
//
// # Почему только ОТМЕЧЕННЫЕ строки
//
// Сплошной обход прозы негоден и это замер, а не осторожность: тот же комментарий,
// который ОБЪЯСНЯЕТ дефект, называет прежнее отношение рядом с фактическим —
// значит сплошной предикат краснел бы на собственном разборе. Поэтому утверждение
// о гейте несёт отметку:
//
//	ГЕЙТ КАТАЛОГА <полное имя RPC>: <отношение>@<тип объекта>
//
// Проза не читается вовсе. То же решение и по той же причине принято у гейта
// перечня полос входа (`deploy/identity_method_comment_matches_declaration_test.go`).
//
// # Область обхода
//
// Не-тестовые файлы Go сервиса. Пробы исключены намеренно: там отметка стоит в
// синтетике доказательства, и судить её значило бы судить фикстуру.
package authzmap_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/treecorpus"
)

// iamServiceGoTreeRelPath — что обходится.
const iamServiceGoTreeRelPath = "services/iam/internal"

// catalogGateMarker — отметка, по которой утверждение о гейте отличается от прозы.
var catalogGateMarker = regexp.MustCompile(
	`ГЕЙТ КАТАЛОГА\s+([A-Za-z0-9_.]+/[A-Za-z0-9_]+)\s*:\s*([a-z_0-9]+)@([a-z_0-9]+)`)

// catalogGateMark — одно отмеченное утверждение.
type catalogGateMark struct {
	File     string
	Line     int
	FQN      string
	Relation string
	Object   string
}

// catalogGateEntry — ровно то, что нужно этой проверке.
type catalogGateEntry struct {
	FQN            string `json:"fqn"`
	RequiredRel    string `json:"required_relation"`
	ScopeExtractor *struct {
		ObjectType string `json:"object_type"`
	} `json:"scope_extractor"`
}

// collectCatalogGateMarks снимает отметки с текста файла.
func collectCatalogGateMarks(file, body string) []catalogGateMark {
	var out []catalogGateMark
	for i, ln := range strings.Split(body, "\n") {
		m := catalogGateMarker.FindStringSubmatch(ln)
		if m == nil {
			continue
		}
		out = append(out, catalogGateMark{
			File: file, Line: i + 1, FQN: m[1], Relation: m[2], Object: m[3],
		})
	}
	return out
}

// judgeCatalogGateMarks — ядро гейта, отделённое от чтения дерева, чтобы
// доказательство инъекцией подавало ему и настоящий, и синтетический вход.
func judgeCatalogGateMarks(entries []catalogGateEntry, marks []catalogGateMark) []string {
	byFQN := make(map[string]catalogGateEntry, len(entries))
	for _, e := range entries {
		byFQN[e.FQN] = e
	}

	var findings []string
	for _, mk := range marks {
		e, ok := byFQN[mk.FQN]
		if !ok {
			findings = append(findings, fmt.Sprintf(
				"%s:%d: отметка называет метод %q, которого в каталоге прав НЕТ. "+
					"Либо метод переименован и текст его пережил, либо имя написано неверно",
				mk.File, mk.Line, mk.FQN))
			continue
		}
		if e.RequiredRel != mk.Relation {
			findings = append(findings, fmt.Sprintf(
				"%s:%d: отметка называет отношение %q, каталог гейтит %q (%s). "+
					"Комментарий про доступ, противоречащий каталогу, — ловушка: следующий "+
					"починит ГЕЙТ под неверный текст",
				mk.File, mk.Line, mk.Relation, e.RequiredRel, mk.FQN))
		}
		object := ""
		if e.ScopeExtractor != nil {
			object = e.ScopeExtractor.ObjectType
		}
		if object != mk.Object {
			findings = append(findings, fmt.Sprintf(
				"%s:%d: отметка называет тип объекта %q, каталог берёт область на %q (%s)",
				mk.File, mk.Line, mk.Object, object, mk.FQN))
		}
	}
	sort.Strings(findings)
	return findings
}

func readCatalogGateEntries(t *testing.T) []catalogGateEntry {
	t.Helper()
	path := filepath.Join(monorepoRoot(t), catalogRelPath)
	raw, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 -- путь-константа собственного дерева
	if err != nil {
		t.Fatalf("каталог прав %s не прочитан — судить отметки нечем: %v", catalogRelPath, err)
	}
	var entries []catalogGateEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatalf("каталог прав %s не разобран: %v", catalogRelPath, err)
	}
	if len(entries) == 0 {
		t.Fatalf("каталог прав %s разобран в ноль записей — вердикта нет", catalogRelPath)
	}
	return entries
}

// walkIAMProductionGoFiles обходит не-тестовое дерево Go сервиса.
//
// Состав берётся у ИНДЕКСА git (`pkg/treecorpus`), а не обходом диска.
// Обход диска читал бы игнорируемое — рабочие копии агентов, распаковки чартов,
// отчёты прогонов, — и вердикт стал бы свойством рабочего каталога, а не
// коммита. Пустой корпус там же объявлен отказом, поэтому «ноль находок» здесь
// не может прийти от «ноль прочитанного».
func walkIAMProductionGoFiles(t *testing.T) (marks []catalogGateMark, filesRead int) {
	t.Helper()
	root := monorepoRoot(t)
	files, err := treecorpus.UnderWithSuffix(filepath.Join(root, iamServiceGoTreeRelPath), ".go")
	if err != nil {
		t.Fatalf("состав %s не взят у индекса: %v", iamServiceGoTreeRelPath, err)
	}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		raw, rerr := os.ReadFile(filepath.Clean(path)) // #nosec G304 -- путь из индекса собственного дерева
		if rerr != nil {
			t.Fatalf("файл %s не прочитан: %v", path, rerr)
		}
		filesRead++
		rel, _ := filepath.Rel(root, path)
		marks = append(marks, collectCatalogGateMarks(rel, string(raw))...)
	}
	return marks, filesRead
}

func TestCatalogGateCommentNamesTheRelationTheCatalogEnforces(t *testing.T) {
	entries := readCatalogGateEntries(t)
	marks, filesRead := walkIAMProductionGoFiles(t)

	if filesRead == 0 {
		t.Fatalf("в %s не прочитано ни одного не-тестового файла Go — «ноль находок» здесь "+
			"неотличимо от «ноль прочитанного»", iamServiceGoTreeRelPath)
	}
	t.Logf("перепись: записей каталога %d · файлов прочитано %d · отмеченных утверждений %d",
		len(entries), filesRead, len(marks))

	if len(marks) == 0 {
		t.Fatalf("отмеченных утверждений о гейте глагола в %s НЕТ, а гейт заведён ради их "+
			"правдивости (#1258). Исходов два, третьего нет: вернуть отметку "+
			"(`ГЕЙТ КАТАЛОГА <полное имя RPC>: <отношение>@<тип>`) ЛИБО снять этот гейт "+
			"вместе с ней. Молчаливое исчезновение предмета делает проверку вакуумной, "+
			"оставляя её зелёной", iamServiceGoTreeRelPath)
	}

	for _, f := range judgeCatalogGateMarks(entries, marks) {
		t.Errorf("комментарий расходится с каталогом прав: %s", f)
	}
}
