// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// comment_coordinate_layout_test.go — комментарий прод-кода не называет здешний
// файл адресом ЧУЖОЙ раскладки (задача kaname#117).
//
// Способность гейта упасть и смолчать доказана инъекцией —
// `comment_coordinate_layout_injection_test.go`.
//
// # Граница названа числом, а не умолчанием
//
// Судятся КОММЕНТАРИИ прод-кода. Строковые литералы с той же приставкой —
// законная и действующая форма (`treeposture` резолвит координату платформы в
// обеих посадках), и на день заведения их 16 при 75 строках упоминания всего.
// Пробы из обхода исключены: там приставка живёт ещё и фикстурой инъекции
// соседнего гейта, для которой дурная форма и есть предмет.
package check_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
	"github.com/PRO-Robotech/kaname/internal/check"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// commentCoordCensusFloor — порог переписи.
const commentCoordCensusFloor = 300

// commentCoordWalkable — что гейт осматривает. Вынесено функцией: инъекция
// обязана проверять ТОТ ЖЕ отбор.
func commentCoordWalkable(rel string) bool {
	return strings.HasSuffix(rel, ".go") &&
		!strings.HasSuffix(rel, "_test.go") &&
		!strings.HasPrefix(rel, "pkg/api/")
}

// commentCoordFindings — координаты, чей ХВОСТ резолвится в этом дереве. Тот же
// предикат зовёт инъекция; резолюция подаётся функцией, чтобы инъекция могла
// задать своё дерево, не трогая настоящее.
func commentCoordFindings(coords []check.CommentCoordinate, resolves func(string) bool) []string {
	var out []string
	for _, c := range coords {
		if !resolves(c.Tail) {
			continue
		}
		out = append(out, fmt.Sprintf("%s:%d  `%s` — тот же файл лежит здесь как `%s`",
			c.File, c.Line, c.Text, c.Tail))
	}
	sort.Strings(out)
	return out
}

// TestCommentDoesNotNameThisTreeByTheOtherLayout — сам гейт.
func TestCommentDoesNotNameThisTreeByTheOtherLayout(t *testing.T) {
	corpusRoot, modulePrefix := platformtree.RequireCorpus(t)
	ownDir := corpusRoot
	if modulePrefix != "" {
		ownDir = filepath.Join(corpusRoot, filepath.FromSlash(modulePrefix))
	}
	resolves := func(tail string) bool {
		head := strings.Split(tail, "*")[0]
		head = strings.TrimRight(head, "/")
		if head == "" || strings.Contains(tail, "…") {
			return false
		}
		_, err := os.Stat(filepath.Join(ownDir, filepath.FromSlash(head)))
		return err == nil
	}

	files, err := treecorpus.UnderWithSuffix(ownDir, ".go")
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав дерева не прочитан: %v", err)
	}

	var (
		parsed int
		total  check.CommentCoordinateCensus
		coords []check.CommentCoordinate
	)
	for _, abs := range files {
		rel, rerr := filepath.Rel(corpusRoot, abs)
		if rerr != nil {
			t.Fatalf("относительный путь для %s: %v", abs, rerr)
		}
		rel = filepath.ToSlash(rel)
		if !commentCoordWalkable(rel) {
			continue
		}
		src, rderr := os.ReadFile(abs) // #nosec G304 -- путь взят индексом git, не вводом снаружи
		if rderr != nil {
			continue
		}
		c, census, serr := check.ScanCommentCoordinates(rel, src)
		if serr != nil {
			t.Errorf("разбор %s: %v", rel, serr)
			continue
		}
		parsed++
		total.Comments += census.Comments
		total.Mentions += census.Mentions
		total.WithTail += census.WithTail
		coords = append(coords, c...)
	}

	t.Logf("перепись: не-тестовых файлов Go разобрано %d, групп комментария %d, упоминаний "+
		"приставки `%s` %d, из них с хвостом %d",
		parsed, total.Comments, check.PlatformLayoutPrefix, total.Mentions, total.WithTail)

	if parsed < commentCoordCensusFloor {
		t.Fatalf("перепись обвалилась: разобрано %d файлов при пороге %d", parsed, commentCoordCensusFloor)
	}
	if total.Comments == 0 {
		t.Fatalf("прочитано ноль групп комментария на %d файлах — разбор перестал видеть "+
			"предмет, и его молчание сказано ни о чём", parsed)
	}

	if findings := commentCoordFindings(coords, resolves); len(findings) > 0 {
		t.Fatalf("комментарий называет здешний файл адресом ЧУЖОЙ раскладки — %d место(а):\n  %s\n\n"+
			"Служба переехала из каталога платформы в свой репозиторий: код переезд пережил, "+
			"координата в комментарии — нет. Читателя такой адрес отправляет в никуда, а "+
			"замер делает недействительным: предикат, списанный из комментария, печатает "+
			"пусто, и пусто читается как «находок нет», а не как «искали не там».\n"+
			"Снятие: назвать хвост без приставки. Приставка БЕЗ хвоста (проза о переезде, "+
			"указатель области в чужом дереве) находкой не является и остаётся.",
			len(findings), strings.Join(findings, "\n  "))
	}
}
