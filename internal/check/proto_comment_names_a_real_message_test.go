// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// proto_comment_names_a_real_message_test.go — координата, названная
// комментарием контракта, резолвится в этом же дереве контрактов
// (задача kaname#132).
//
// Способность гейта упасть и смолчать доказана инъекцией —
// `proto_comment_names_a_real_message_injection_test.go`.
//
// # Почему обход — СОБСТВЕННЫЙ модуль
//
// Судятся контракты ЭТОЙ службы и копии, которые она несёт рядом. Клиент,
// читающий её комментарий, открывает ровно этот набор; контракты платформы, у
// которой своё дерево, ему в этом вопросе не помогут.
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

// protoCommentCensusFloor — порог переписи файлов контракта: ниже него «ноль
// находок» означало бы «ноль прочитанного».
const protoCommentCensusFloor = 20

// protoCommentWalkable — что гейт осматривает. Вынесено функцией: инъекция
// обязана проверять ТОТ ЖЕ отбор, которым судит гейт.
func protoCommentWalkable(rel string) bool {
	return strings.HasSuffix(rel, ".proto")
}

// protoCommentFindings — ссылки, чей тип в дереве контрактов не объявлен. Тот же
// предикат зовёт инъекция.
func protoCommentFindings(refs []check.ProtoCommentRef, known map[string]bool) []string {
	var out []string
	for _, r := range refs {
		if known[r.Type] {
			continue
		}
		out = append(out, fmt.Sprintf("%s:%d  `%s` — сообщения %q в контрактах дерева нет",
			r.File, r.Line, r.Text, r.Type))
	}
	sort.Strings(out)
	return out
}

// TestProtoCommentNamesAMessageThatExists — сам гейт.
func TestProtoCommentNamesAMessageThatExists(t *testing.T) {
	corpusRoot, modulePrefix := platformtree.RequireCorpus(t)
	ownDir := corpusRoot
	if modulePrefix != "" {
		ownDir = filepath.Join(corpusRoot, filepath.FromSlash(modulePrefix))
	}

	files, err := treecorpus.UnderWithSuffix(ownDir, ".proto")
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав дерева не прочитан: %v", err)
	}

	var (
		parsed int
		total  check.ProtoCommentCensus
		refs   []check.ProtoCommentRef
		known  = map[string]bool{}
	)
	for _, abs := range files {
		rel, rerr := filepath.Rel(corpusRoot, abs)
		if rerr != nil {
			t.Fatalf("относительный путь для %s: %v", abs, rerr)
		}
		rel = filepath.ToSlash(rel)
		if !protoCommentWalkable(rel) {
			continue
		}
		src, rderr := os.ReadFile(abs) // #nosec G304 -- путь взят индексом git, не вводом снаружи
		if rderr != nil {
			continue
		}
		parsed++
		for _, n := range check.ProtoTypeDecls(src) {
			known[n] = true
		}
		r, census := check.ScanProtoCommentRefs(rel, src)
		total.Lines += census.Lines
		total.Comments += census.Comments
		total.Refs += census.Refs
		total.Decls += census.Decls
		refs = append(refs, r...)
	}

	t.Logf("перепись: файлов контракта разобрано %d, строк %d, из них комментария %d, "+
		"объявлений message/enum %d, ссылок формы `Message.field` %d",
		parsed, total.Lines, total.Comments, total.Decls, total.Refs)

	if parsed < protoCommentCensusFloor {
		t.Fatalf("перепись обвалилась: разобрано %d файлов контракта при пороге %d — на таком "+
			"объёме «ноль находок» означало бы «ноль прочитанного»", parsed, protoCommentCensusFloor)
	}
	if total.Decls == 0 {
		t.Fatalf("прочитано ноль объявлений message/enum на %d файлах — множество известных "+
			"типов пусто, и находкой стала бы ЛЮБАЯ ссылка", parsed)
	}
	if total.Refs == 0 {
		t.Fatalf("прочитано ноль ссылок формы `Message.field` на %d файлах и %d строках "+
			"комментария — распознаватель перестал видеть предмет, и его молчание сказано "+
			"ни о чём", parsed, total.Comments)
	}

	if findings := protoCommentFindings(refs, known); len(findings) > 0 {
		t.Fatalf("комментарий контракта обещает координату, которой нет — %d место(а):\n  %s\n\n"+
			"Комментарий контракта читает КЛИЕНТ, и дерева у него может не быть: названная "+
			"координата есть обещание поля. Ни `buf lint`, ни `buf breaking` комментариев не "+
			"читают — обещание переживает свой предмет молча.\n"+
			"Снятие: назвать существующую координату либо снять обещание вместе с предметом.",
			len(findings), strings.Join(findings, "\n  "))
	}
}
