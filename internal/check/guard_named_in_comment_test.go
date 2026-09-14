// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// guard_named_in_comment_test.go — гейт на класс: комментарий, называющий
// защиту действующей, обязан иметь эту защиту в прод-коде своего пакета.
//
// Предмет, устройство разбора и ПЕРЕЧЕНЬ ФОРМ записи — в годке
// `guard_named_in_comment.go`; здесь они не пересказываются.
//
// Способность гейта упасть и смолчать доказана инъекцией —
// `guard_named_in_comment_injection_test.go`.
//
// # Почему обход — СОБСТВЕННЫЙ модуль
//
// Предмет — согласие комментария с кодом ВНУТРИ одного пакета; пакеты службы
// лежат целиком в этом модуле. Дерева платформы рядом может не быть, и вердикт
// о нём этот гейт не выносит.
//
// # Откуда гейт пришёл
//
// Перенесён из корпуса монорепо (`internal/repohygiene/guardnamedincomment_test.go`),
// снятого вместе с выносом службы (kacho#2597). Предмет уехал в этот
// репозиторий, гейт за ним не переехал — и не был назван ни одной ведомостью
// остатка, потому что предикат прежней адъюдикации знал одну форму записи
// пути (`"services/iam"`) из пяти.
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

// guardedIdentifier — защита, которую нельзя называть действующей, не имея её.
//
// Реестр узкий НАМЕРЕННО: гейт закрывает один класс на поимённом наборе защит,
// а не делает читателя из каждого идентификатора дерева. Широкий реестр дал бы
// долю ложных находок, на которой гейт отключают первым.
type guardedIdentifier struct {
	// name — имя как оно пишется в выражении, без квалификатора пакета.
	name string
	// why — почему именно эта защита в реестре.
	why string
	// retireWhen — условие снятия, привязанное к ВНЕШНЕМУ факту.
	retireWhen string
}

var guardedIdentifiers = []guardedIdentifier{
	{
		name: "IsVerbOfType",
		why: "проверка принадлежности глагола НАБОРУ ТИПА: комментарий, называющий её " +
			"действующей, отвечает читателю на вопрос о наличии проверки вместо самой проверки",
		retireWhen: "идентификатор удалён из прод-дерева службы",
	},
	{
		name: "NormalizeVerb",
		why: "единственная точка приведения имени глагола: упоминание её как действующей " +
			"закрывает вопрос, приводится ли имя на этом пути",
		retireWhen: "идентификатор удалён из прод-дерева службы",
	},
}

// guardCensusFloor — порог переписи: ниже него «ноль находок» означало бы
// «ноль прочитанного». На день заведения прод-файлов Go в дереве 829.
const guardCensusFloor = 300

// guardNames — имена реестра одним срезом.
func guardNames() []string {
	out := make([]string, 0, len(guardedIdentifiers))
	for _, g := range guardedIdentifiers {
		out = append(out, g.name)
	}
	return out
}

// guardWalkable — что гейт осматривает. Вынесено функцией, а не оставлено в
// теле обхода: инъекция обязана проверять ТОТ ЖЕ отбор, которым судит гейт.
func guardWalkable(rel string) bool {
	return strings.HasSuffix(rel, ".go") && !strings.HasSuffix(rel, ".pb.go")
}

// guardFindings — находки по собранным фактам. Тот же предикат зовёт инъекция.
//
// Находка — пакет, где комментарий НАЗВАЛ защиту, а прод-код её не вызывает.
func guardFindings(
	mentions map[string]map[string][]check.GuardMention,
	uses map[string]map[string]bool,
) []string {
	var pkgs []string
	for pkg := range mentions {
		pkgs = append(pkgs, pkg)
	}
	sort.Strings(pkgs)

	var out []string
	for _, pkg := range pkgs {
		for _, g := range guardedIdentifiers {
			ms := mentions[pkg][g.name]
			if len(ms) == 0 || uses[pkg][g.name] {
				continue
			}
			var locs []string
			for _, m := range ms {
				locs = append(locs, fmt.Sprintf("%s:%d (форма %s)", m.File, m.Line, m.Form))
			}
			sort.Strings(locs)
			out = append(out, fmt.Sprintf("%s: %s названа действующей защитой в %s, "+
				"но в прод-коде пакета её НЕТ", pkg, g.name, strings.Join(locs, ", ")))
		}
	}
	return out
}

// TestCommentsNamingAGuardHaveItInScope — сам гейт.
func TestCommentsNamingAGuardHaveItInScope(t *testing.T) {
	t.Parallel()
	if len(guardedIdentifiers) == 0 {
		t.Fatalf("реестр защит пуст — гейту нечего проверять, и его молчание сказано ни о чём")
	}

	corpusRoot, modulePrefix := platformtree.RequireCorpus(t)
	ownDir := corpusRoot
	if modulePrefix != "" {
		ownDir = filepath.Join(corpusRoot, filepath.FromSlash(modulePrefix))
	}

	files, err := treecorpus.UnderWithSuffix(ownDir, ".go")
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав дерева не прочитан: %v", err)
	}

	var parsed, comments, idents int
	mentions := map[string]map[string][]check.GuardMention{}
	uses := map[string]map[string]bool{}
	byForm := map[check.GuardMentionForm]int{}

	for _, abs := range files {
		rel, rerr := filepath.Rel(corpusRoot, abs)
		if rerr != nil {
			t.Fatalf("относительный путь для %s: %v", abs, rerr)
		}
		rel = filepath.ToSlash(rel)
		if !guardWalkable(rel) {
			continue
		}
		src, rderr := os.ReadFile(abs) // #nosec G304 -- путь взят индексом git, не вводом снаружи
		if rderr != nil {
			continue
		}
		isTest := strings.HasSuffix(rel, "_test.go")
		scan, serr := check.ScanGuardNaming(rel, src, isTest, guardNames())
		if serr != nil {
			t.Fatalf("разбор %s не удался (%v) — гейт не вправе трактовать неразобранный "+
				"файл как «упоминаний нет»", rel, serr)
		}
		parsed++
		comments += scan.Census.Comments
		idents += scan.Census.Idents

		pkg := filepath.ToSlash(filepath.Dir(rel))
		for _, m := range scan.Mentions {
			if mentions[pkg] == nil {
				mentions[pkg] = map[string][]check.GuardMention{}
			}
			mentions[pkg][m.Name] = append(mentions[pkg][m.Name], m)
			byForm[m.Form]++
		}
		for name := range scan.Uses {
			if uses[pkg] == nil {
				uses[pkg] = map[string]bool{}
			}
			uses[pkg][name] = true
		}
	}

	total := 0
	for _, byName := range mentions {
		for _, ms := range byName {
			total += len(ms)
		}
	}
	t.Logf("перепись: файлов Go разобрано %d, узлов-комментариев прочитано %d, "+
		"узлов-идентификаторов прочитано %d, защит в реестре %d, "+
		"упоминаний в комментариях найдено %d (по формам: %v)",
		parsed, comments, idents, len(guardedIdentifiers), total, byForm)

	if parsed < guardCensusFloor {
		t.Fatalf("перепись обвалилась: разобрано %d файлов при пороге %d — на таком объёме "+
			"«ноль находок» означало бы «ноль прочитанного»", parsed, guardCensusFloor)
	}
	if comments == 0 || idents == 0 {
		t.Fatalf("прочитано комментариев %d, идентификаторов %d на %d файлах — разбор "+
			"перестал видеть предмет, и его молчание сказано ни о чём", comments, idents, parsed)
	}
	if total == 0 {
		t.Fatalf("ни одного упоминания защит реестра не найдено во всём дереве — либо реестр " +
			"устарел (снимите записи), либо обход не дошёл до кода; молчание при нуле " +
			"упоминаний ничего не утверждает")
	}

	for _, f := range guardFindings(mentions, uses) {
		var why string
		for _, g := range guardedIdentifiers {
			if strings.Contains(f, g.name) {
				why = g.why
				break
			}
		}
		t.Errorf("%s.\nЭто хуже обычного расхождения комментария с кодом: комментарий уже "+
			"ОТВЕТИЛ на вопрос «закрыт ли этот сегмент», поэтому читатель не идёт проверять "+
			"и пробел остаётся незамеченным именно потому, что о нём написано.\n"+
			"Исходы: сказать правду о том, чем сегмент закрыт на самом деле / реально вызвать "+
			"защиту / снять упоминание.\nЗачем запись в реестре: %s", f, why)
	}
}

// TestGuardedIdentifiersStillHaveSubject — самоистечение реестра: запись про
// идентификатор, которого в прод-дереве больше нет, исключать нечего.
//
// Без этой половины реестр пережил бы свой предмет молча: гейт продолжал бы
// проходить, ничего не стерегя.
func TestGuardedIdentifiersStillHaveSubject(t *testing.T) {
	t.Parallel()
	corpusRoot, modulePrefix := platformtree.RequireCorpus(t)
	ownDir := corpusRoot
	if modulePrefix != "" {
		ownDir = filepath.Join(corpusRoot, filepath.FromSlash(modulePrefix))
	}

	files, err := treecorpus.UnderWithSuffix(ownDir, ".go")
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав дерева не прочитан: %v", err)
	}

	alive := map[string]bool{}
	parsed := 0
	for _, abs := range files {
		rel, rerr := filepath.Rel(corpusRoot, abs)
		if rerr != nil {
			continue
		}
		rel = filepath.ToSlash(rel)
		if !guardWalkable(rel) || strings.HasSuffix(rel, "_test.go") {
			continue
		}
		src, rderr := os.ReadFile(abs) // #nosec G304 -- путь взят индексом git, не вводом снаружи
		if rderr != nil {
			continue
		}
		scan, serr := check.ScanGuardNaming(rel, src, false, guardNames())
		if serr != nil {
			continue
		}
		parsed++
		for name := range scan.Uses {
			alive[name] = true
		}
	}

	t.Logf("перепись: прод-файлов Go разобрано %d, записей реестра %d, из них с живым "+
		"предметом %d", parsed, len(guardedIdentifiers), len(alive))

	if parsed < guardCensusFloor {
		t.Fatalf("перепись обвалилась: разобрано %d прод-файлов при пороге %d — "+
			"самоистечению нечего проверять", parsed, guardCensusFloor)
	}
	for _, g := range guardedIdentifiers {
		if !alive[g.name] {
			t.Errorf("запись реестра %q больше нечего исключать — идентификатора нет в "+
				"прод-коде дерева. Это находка: снимите запись (условие снятия: %s). "+
				"Оставленная запись описывает вчерашнее дерево", g.name, g.retireWhen)
		}
	}
}
