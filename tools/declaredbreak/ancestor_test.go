// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ancestor_test.go — отказ называет по КАЖДОЙ находке, есть ли её предмет в общем
// предке головы и базы (задача kaname#1055, пункт 5 предиката).
//
// Находка против базы бывает двух родов: предмет был в предке, и голова его
// сняла; либо предмета в предке нет — его внесла база после ответвления. Без
// этой строки читатель отказа не отличает собственную правку ветки от
// отставания и тянется за записью перечня там, где нужен догон базы.
//
// ВХОД НАСТОЯЩИЙ: находки — фикстура `testdata/buf-breaking-real.jsonl`,
// снятая buf 1.72.0 по контрактам этого дерева. «Вывод против предка» —
// подмножество того же вывода: находка с той же координатой там есть ⟺ предмет
// в предке есть.
package declaredbreak_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/tools/declaredbreak"
)

const (
	inAncestorMark    = "предмет ЕСТЬ"
	notInAncestorMark = "предмета НЕТ"
	ancestorUnknown   = "не установлен"
	ancestorUnseen    = "общий предок не осмотрен"
)

func emptyLedger(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "declared-breaks.yaml")
	if err := os.WriteFile(p, []byte("breaks: []\n"), 0o600); err != nil {
		t.Fatalf("перечень пробы не записан: %v", err)
	}
	return p
}

func realOutputText(t *testing.T) string {
	t.Helper()
	body, err := os.ReadFile(realOutput)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: фикстура не прочитана: %v", err)
	}
	return string(body)
}

// findingBlocks — строки отчёта, относящиеся к каждой находке вне перечня: сама
// находка и строки-пояснения под ней до следующей находки.
func findingBlocks(rep string) map[string]string {
	out := map[string]string{}
	cur := ""
	for _, line := range strings.Split(rep, "\n") {
		if strings.HasPrefix(line, "  РАЗРЫВ ВНЕ ПЕРЕЧНЯ: ") {
			cur = line
			out[cur] = ""
			continue
		}
		if cur != "" && strings.HasPrefix(line, "    ") {
			out[cur] += line + "\n"
			continue
		}
		cur = ""
	}
	return out
}

func run(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	rc := declaredbreak.Run(args, strings.NewReader(stdin), &out, &errb)
	return rc, out.String(), errb.String()
}

// TestRefusalNamesWhetherTheSubjectIsInTheCommonAncestor — ИНЪЕКЦИЯ и БЛИЗНЕЦ в
// одном отчёте: у находки, чья координата есть и в выводе против предка, —
// «ЕСТЬ»; у прочих — «НЕТ». Каждая находка получает ровно одну строку о предке.
func TestRefusalNamesWhetherTheSubjectIsInTheCommonAncestor(t *testing.T) {
	all := realFindings(t)
	lines := strings.Split(strings.TrimSpace(realOutputText(t)), "\n")
	anc := filepath.Join(t.TempDir(), "ancestor.jsonl")
	if err := os.WriteFile(anc, []byte(lines[0]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	inAnc, err := declaredbreak.ParseFindings(strings.NewReader(lines[0]))
	if err != nil || len(inAnc) != 1 {
		t.Fatalf("первая строка фикстуры не разобрана: %v", err)
	}

	rc, rep, stderr := run(t, realOutputText(t),
		"--ancestor-findings", anc, "--ancestor-ref", "0123456789ab", emptyLedger(t))
	if rc != 1 {
		t.Fatalf("находки вне перечня обязаны дать код 1, получен %d\n%s%s", rc, rep, stderr)
	}
	blocks := findingBlocks(rep)
	if len(blocks) != len(all) {
		t.Fatalf("находок в отчёте %d, в выводе buf %d\n%s", len(blocks), len(all), rep)
	}
	for head, body := range blocks {
		want := notInAncestorMark
		if strings.Contains(head, inAnc[0].Coordinate()) {
			want = inAncestorMark
		}
		if !strings.Contains(body, want) || !strings.Contains(body, "0123456789ab") {
			t.Errorf("у находки %q нет строки «%s» с ревизией предка:\n%s", head, want, body)
		}
		if n := strings.Count(body, "общ"); n != 1 {
			t.Errorf("у находки %q строк о предке %d, а не одна:\n%s", head, n, body)
		}
	}
}

// TestAncestorDoesNotForgiveTheLag — ОТСТАВАНИЕ НЕ ПРОЩАЕТСЯ: предмета в предке
// нет у всех находок, а гейт красен по-прежнему. Строка о предке — сведение для
// читателя, перечня она не расширяет (пункт 6 предиката).
func TestAncestorDoesNotForgiveTheLag(t *testing.T) {
	anc := filepath.Join(t.TempDir(), "ancestor.jsonl")
	if err := os.WriteFile(anc, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	rc, rep, _ := run(t, realOutputText(t),
		"--ancestor-findings", anc, "--ancestor-ref", "feedface", emptyLedger(t))
	if rc != 1 {
		t.Fatalf("отставание базы простило находки: код %d\n%s", rc, rep)
	}
	if strings.Contains(rep, inAncestorMark) {
		t.Fatalf("при пустом выводе против предка названо «%s»:\n%s", inAncestorMark, rep)
	}
}

// TestUnknownAncestorIsSaidPerFinding — предок не установлен: у каждой находки
// сказано «не установлен» с причиной; ни «есть», ни «нет» не выдумывается.
func TestUnknownAncestorIsSaidPerFinding(t *testing.T) {
	all := realFindings(t)
	rc, rep, _ := run(t, realOutputText(t), "--ancestor-unknown", "история не получена", emptyLedger(t))
	if rc != 1 {
		t.Fatalf("код %d вместо 1\n%s", rc, rep)
	}
	if n := strings.Count(rep, ancestorUnknown+": история не получена"); n != len(all) {
		t.Fatalf("строк «не установлен» %d при находках %d\n%s", n, len(all), rep)
	}
	if strings.Contains(rep, inAncestorMark) || strings.Contains(rep, notInAncestorMark) {
		t.Fatalf("при неизвестном предке назван ответ:\n%s", rep)
	}
}

// TestUnparsableAncestorOutputKeepsTheVerdict — вывод против предка не разобран:
// вердикт по базе остаётся (1), а не превращается в третий исход и не в «есть/нет».
func TestUnparsableAncestorOutputKeepsTheVerdict(t *testing.T) {
	anc := filepath.Join(t.TempDir(), "ancestor.jsonl")
	if err := os.WriteFile(anc, []byte("Failure: not json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rc, rep, _ := run(t, realOutputText(t),
		"--ancestor-findings", anc, "--ancestor-ref", "feedface", emptyLedger(t))
	if rc != 1 {
		t.Fatalf("код %d вместо 1\n%s", rc, rep)
	}
	if n := strings.Count(rep, ancestorUnknown); n != len(realFindings(t)) {
		t.Fatalf("строк «не установлен» %d\n%s", n, rep)
	}
}

// TestUnseenAncestorIsSaidNotSilent — без сведений о предке отчёт так и говорит:
// «не осмотрен» отлично от «нет».
func TestUnseenAncestorIsSaidNotSilent(t *testing.T) {
	all := realFindings(t)
	rep := declaredbreak.Adjudicate(all, nil).Report()
	if n := strings.Count(rep, ancestorUnseen); n != len(all) {
		t.Fatalf("строк «%s» %d при находках %d\n%s", ancestorUnseen, n, len(all), rep)
	}
}

// TestCleanInputIsGreenWithAncestorFlags — ЗАКОННЫЙ БЛИЗНЕЦ: разрывов нет —
// код 0, строк о предке нет.
func TestCleanInputIsGreenWithAncestorFlags(t *testing.T) {
	rc, rep, stderr := run(t, "", "--ancestor-unknown", "не спрашивали", emptyLedger(t))
	if rc != 0 {
		t.Fatalf("чистый вход дал код %d\n%s%s", rc, rep, stderr)
	}
	if strings.Contains(rep, "общ") {
		t.Fatalf("на чистом входе напечатана строка о предке:\n%s", rep)
	}
}

// TestCallOutsideTheFormIsTheThirdCategory — вызов вне формы есть «гейт не сделал
// своей работы», а не вердикт.
func TestCallOutsideTheFormIsTheThirdCategory(t *testing.T) {
	ledger := emptyLedger(t)
	for name, args := range map[string][]string{
		"без перечня":           nil,
		"два перечня":           {ledger, ledger},
		"находки без ревизии":   {"--ancestor-findings", "x.jsonl", ledger},
		"ревизия без находок":   {"--ancestor-ref", "abc", ledger},
		"известно и неизвестно": {"--ancestor-findings", "x.jsonl", "--ancestor-ref", "abc", "--ancestor-unknown", "y", ledger},
		"незнакомый флаг":       {"--against", "main", ledger},
	} {
		t.Run(name, func(t *testing.T) {
			if rc, out, errb := run(t, "", args...); rc != 2 {
				t.Fatalf("вызов вне формы дал код %d вместо 2\n%s%s", rc, out, errb)
			}
		})
	}
}
