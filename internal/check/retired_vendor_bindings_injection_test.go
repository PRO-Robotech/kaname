// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// Способность гейта упасть — на СИНТЕТИКЕ: фикстура, привязанная к живой
// привязке дерева, истекла бы вместе с ней, а эти переживут день, когда предмет
// уйдёт. Имя провайдера в фикстурах берётся из `check.RetiredVendorMarks`, а не
// пишется литералом: так каждая метка гоняется поимённо, и метка, о которой
// забыла проба, не проходит молча.

// vendorCorpus — синтетическое дерево с файлом ведомости: без него судья
// отказывает, а не судит.
func vendorCorpus(files map[string]string) check.TreeCorpus {
	c := check.TreeCorpus{check.RetiredVendorLedgerRel: "package check\n"}
	for rel, body := range files {
		c[rel] = body
	}
	return c
}

// vendorLine — строка кода, несущая метку.
func vendorLine(mark string) string { return "\taddr := \"" + mark + "\"" }

func judgeVendor(t *testing.T, corpus check.TreeCorpus, ledger []check.RetiredVendorLedgerEntry) check.RetiredVendorVerdict {
	t.Helper()
	v, err := check.JudgeRetiredVendorBindings(corpus, ledger)
	if err != nil {
		t.Fatalf("фикстура обязана судиться: %v", err)
	}
	if got := v.Census.Text + v.Census.Binary + v.Census.Prose + v.Census.Ledger; got != v.Census.Walked {
		t.Fatalf("разбиение обхода неполно: категорий %d при обойдённых %d — %s", got, v.Census.Walked, v.Census)
	}
	return v
}

func onlyFinding(t *testing.T, v check.RetiredVendorVerdict, kind, file string) check.RetiredVendorFinding {
	t.Helper()
	if len(v.Findings) != 1 {
		t.Fatalf("ожидалась ровно одна находка, получено %d: %v", len(v.Findings), v.Findings)
	}
	f := v.Findings[0]
	if f.Kind != kind || f.File != file {
		t.Fatalf("находка не та: хотели %q по %s, получили %q по %s", kind, file, f.Kind, f.File)
	}
	if v.Census.Findings != 1 {
		t.Fatalf("перепись расходится с находкой: %s", v.Census)
	}
	return f
}

func silent(t *testing.T, v check.RetiredVendorVerdict) {
	t.Helper()
	if len(v.Findings) != 0 || v.Census.Findings != 0 {
		t.Fatalf("законный близнец обязан молчать, получено: %v (%s)", v.Findings, v.Census)
	}
}

// TestRetiredVendorBindings_GrowthIsRedAndItsTwinIsSilent — рост по КАЖДОЙ
// метке и в любом регистре краснеет и называет файл и строку; тот же корпус с
// записью, равной факту, молчит.
func TestRetiredVendorBindings_GrowthIsRedAndItsTwinIsSilent(t *testing.T) {
	t.Parallel()
	for _, mark := range check.RetiredVendorMarks {
		for name, line := range map[string]string{
			"строчными":  vendorLine(mark),
			"прописными": "\tenv := \"KANAME_" + strings.ToUpper(mark) + "ADMIN\"",
			"три вхождения в строке — одна единица": vendorLine(mark + mark + mark),
		} {
			t.Run(mark+" "+name, func(t *testing.T) {
				t.Parallel()
				corpus := vendorCorpus(map[string]string{"internal/x/a.go": "package x\n\n" + line + "\n"})

				f := onlyFinding(t, judgeVendor(t, corpus, nil), check.RetiredVendorGrown, "internal/x/a.go")
				if f.Actual != 1 || f.Recorded != 0 {
					t.Fatalf("числа находки: привязок %d при записи %d, хотели 1 при 0", f.Actual, f.Recorded)
				}
				if len(f.Bindings) != 1 || f.Bindings[0].Line != 3 || f.Bindings[0].Axis != check.RetiredVendorAxisLine {
					t.Fatalf("координата роста обязана быть строкой 3 по оси строки: %+v", f.Bindings)
				}
				if !strings.Contains(f.String(), "internal/x/a.go:3") {
					t.Fatalf("текст находки обязан нести координату строки: %s", f)
				}

				silent(t, judgeVendor(t, corpus, []check.RetiredVendorLedgerEntry{
					{File: "internal/x/a.go", Bindings: 1}}))
			})
		}
	}
}

// TestRetiredVendorBindings_UnrecordedShrinkIsRed — убыль без снижения записи
// краснеет и называет число, до которого снизить; запись, равная факту, молчит.
func TestRetiredVendorBindings_UnrecordedShrinkIsRed(t *testing.T) {
	t.Parallel()
	mark := check.RetiredVendorMarks[0]
	corpus := vendorCorpus(map[string]string{"internal/x/a.go": "package x\n" + vendorLine(mark) + "\n"})

	f := onlyFinding(t, judgeVendor(t, corpus, []check.RetiredVendorLedgerEntry{
		{File: "internal/x/a.go", Bindings: 2}}), check.RetiredVendorShrunk, "internal/x/a.go")
	if f.Actual != 1 || f.Recorded != 2 {
		t.Fatalf("числа находки: привязок %d при записи %d, хотели 1 при 2", f.Actual, f.Recorded)
	}
	if !strings.Contains(f.String(), "до 1") {
		t.Fatalf("находка обязана назвать число, до которого снизить запись: %s", f)
	}

	silent(t, judgeVendor(t, corpus, []check.RetiredVendorLedgerEntry{{File: "internal/x/a.go", Bindings: 1}}))
}

// TestRetiredVendorBindings_EntryWithoutSubjectIsRed — запись файла, которого
// нет, и запись файла, где привязок не осталось, — обе находки; без записи —
// молчание.
func TestRetiredVendorBindings_EntryWithoutSubjectIsRed(t *testing.T) {
	t.Parallel()
	ledger := []check.RetiredVendorLedgerEntry{{File: "internal/x/gone.go", Bindings: 3}}

	onlyFinding(t, judgeVendor(t, vendorCorpus(nil), ledger), check.RetiredVendorOrphan, "internal/x/gone.go")
	clean := vendorCorpus(map[string]string{"internal/x/gone.go": "package x\n"})
	onlyFinding(t, judgeVendor(t, clean, ledger), check.RetiredVendorOrphan, "internal/x/gone.go")

	silent(t, judgeVendor(t, clean, nil))
}

// TestRetiredVendorBindings_MoveBetweenFilesIsNotForgivenBySum — перенос: сумма
// ведомости и сумма дерева равны, а новая привязка в другом файле краснеет, и
// не сниженная запись прежнего файла — тоже. Ровно это отличает ведомость по
// файлам от одного числа на дерево.
func TestRetiredVendorBindings_MoveBetweenFilesIsNotForgivenBySum(t *testing.T) {
	t.Parallel()
	mark := check.RetiredVendorMarks[1]
	corpus := vendorCorpus(map[string]string{
		"internal/x/a.go": "package x\n" + vendorLine(mark) + "\n",
		"internal/x/b.go": "package x\n" + vendorLine(mark) + "\n",
	})
	v := judgeVendor(t, corpus, []check.RetiredVendorLedgerEntry{{File: "internal/x/a.go", Bindings: 2}})
	if v.Census.Bindings != v.Census.Recorded {
		t.Fatalf("предпосылка пробы: суммы обязаны быть равны, %s", v.Census)
	}
	if len(v.Findings) != 2 ||
		v.Findings[0].Kind != check.RetiredVendorShrunk || v.Findings[0].File != "internal/x/a.go" ||
		v.Findings[1].Kind != check.RetiredVendorGrown || v.Findings[1].File != "internal/x/b.go" {
		t.Fatalf("перенос обязан дать убыль прежнего файла и рост нового: %v", v.Findings)
	}

	// Перенос внутри файла — не рост: число файла то же.
	moved := vendorCorpus(map[string]string{"internal/x/a.go": "package x\n\n\n" + vendorLine(mark) + "\n" + vendorLine(mark) + "\n"})
	silent(t, judgeVendor(t, moved, []check.RetiredVendorLedgerEntry{{File: "internal/x/a.go", Bindings: 2}}))
}

// TestRetiredVendorBindings_PathAndBytesAreAxesOfTheirOwn — путь и байты
// двоичного судятся своими осями: файл, чьё тело чисто, привязан путём;
// двоичный без имени в байтах не привязан.
func TestRetiredVendorBindings_PathAndBytesAreAxesOfTheirOwn(t *testing.T) {
	t.Parallel()
	for _, mark := range check.RetiredVendorMarks {
		t.Run(mark, func(t *testing.T) {
			t.Parallel()
			path := "internal/x/" + mark + "client.go"
			f := onlyFinding(t, judgeVendor(t, vendorCorpus(map[string]string{path: "package x\n"}), nil),
				check.RetiredVendorGrown, path)
			if len(f.Bindings) != 1 || f.Bindings[0].Axis != check.RetiredVendorAxisPath || f.Bindings[0].Line != 0 {
				t.Fatalf("путь обязан судиться осью пути: %+v", f.Bindings)
			}

			blob := "assets/x.bin"
			v := judgeVendor(t, vendorCorpus(map[string]string{blob: "\x00\x01" + strings.ToUpper(mark) + "\xff"}), nil)
			f = onlyFinding(t, v, check.RetiredVendorGrown, blob)
			if len(f.Bindings) != 1 || f.Bindings[0].Axis != check.RetiredVendorAxisBinary || v.Census.Binary != 1 {
				t.Fatalf("двоичный обязан судиться байтами: %+v, %s", f.Bindings, v.Census)
			}
		})
	}
	v := judgeVendor(t, vendorCorpus(map[string]string{"assets/y.bin": "\x00\x01\xff"}), nil)
	silent(t, v)
	if v.Census.Binary != 1 {
		t.Fatalf("двоичный без имени обязан быть учтён переписью: %s", v.Census)
	}
}

// TestRetiredVendorBindings_BoundariesAreSilentAndCounted — проза, строка,
// начинающаяся маркером комментария, и сама ведомость не судятся, но
// считаются; флаг командной строки `--имя` комментарием не является.
func TestRetiredVendorBindings_BoundariesAreSilentAndCounted(t *testing.T) {
	t.Parallel()
	mark := check.RetiredVendorMarks[0]
	comments := strings.Join([]string{"// " + mark, "\t# " + mark, "-- " + mark, " * " + mark, "; " + mark}, "\n")
	corpus := vendorCorpus(map[string]string{
		"internal/x/a.go": "package x\n" + comments + "\n",
		"docs/page.md":    vendorLine(mark) + "\n",
		"docs/page.mdx":   vendorLine(mark) + "\n",
	})
	corpus[check.RetiredVendorLedgerRel] = "package check\n" + vendorLine(mark) + "\n"
	v := judgeVendor(t, corpus, nil)
	silent(t, v)
	if v.Census.CommentSkipped != 5 || v.Census.Prose != 2 || v.Census.Ledger != 1 || v.Census.Bindings != 0 {
		t.Fatalf("границы обязаны быть посчитаны, а не пропущены молча: %s", v.Census)
	}

	flag := vendorCorpus(map[string]string{"deploy/run.sh": "--env-var " + mark + "\n"})
	onlyFinding(t, judgeVendor(t, flag, nil), check.RetiredVendorGrown, "deploy/run.sh")
}

// TestRetiredVendorBindings_EmptyLedgerOnACleanTreeIsTheGoal — предмет снят
// целиком: ведомость пуста, привязок ноль — это цель, а не отказ.
func TestRetiredVendorBindings_EmptyLedgerOnACleanTreeIsTheGoal(t *testing.T) {
	t.Parallel()
	v := judgeVendor(t, vendorCorpus(map[string]string{"internal/x/a.go": "package x\n"}), nil)
	silent(t, v)
	if v.Census.Bindings != 0 || v.Census.Entries != 0 || v.Census.Walked != 2 {
		t.Fatalf("перепись пустой цели: %s", v.Census)
	}
}

// TestRetiredVendorBindings_RefusalsAreNotVerdicts — пустой обход, дерево без
// файла ведомости и ведомость не по форме — отказ, а не «находок ноль».
func TestRetiredVendorBindings_RefusalsAreNotVerdicts(t *testing.T) {
	t.Parallel()
	if _, err := check.JudgeRetiredVendorBindings(check.TreeCorpus{}, nil); !errors.Is(err, check.ErrEmptyTraversal) {
		t.Fatalf("пустой обход обязан отказывать: %v", err)
	}
	noLedger := check.TreeCorpus{"internal/x/a.go": "package x\n"}
	if _, err := check.JudgeRetiredVendorBindings(noLedger, nil); !errors.Is(err, check.ErrRetiredVendorLedgerAbsent) {
		t.Fatalf("дерево без ведомости обязано отказывать: %v", err)
	}
	for name, ledger := range map[string][]check.RetiredVendorLedgerEntry{
		"без пути":      {{File: "", Bindings: 1}},
		"ноль":          {{File: "a.go", Bindings: 0}},
		"не по порядку": {{File: "b.go", Bindings: 1}, {File: "a.go", Bindings: 1}},
		"повтор":        {{File: "a.go", Bindings: 1}, {File: "a.go", Bindings: 1}},
		"отрицательное": {{File: "a.go", Bindings: -1}},
	} {
		if _, err := check.JudgeRetiredVendorBindings(vendorCorpus(nil), ledger); !errors.Is(err, check.ErrRetiredVendorLedgerForm) {
			t.Fatalf("ведомость %s обязана отказывать: %v", name, err)
		}
	}
}
