// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package scalegrid

// report_dirty_subject_test.go — «ГРЯЗНОЕ» говорится о ПРЕДМЕТЕ ЗАМЕРА, а не о
// соседях по каталогу.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Отчёты снимались пакетом, один за другим, без коммита между ними, и каждый
// следующий видел записанные раньше `.txt` как несохранённые правки. Шапка
// печатала «Ревизия выше НЕ описывает исполнявшееся дерево целиком» — то есть
// утверждение о НЕГОДНОСТИ замера, — при том что предмет замера (файлы под
// отпечатком) не менялся ни на байт, а грязными были артефакты соседа.
//
// Класс — не «неверное число», а ПРЕДУПРЕЖДЕНИЕ БЕЗ ПРЕДМЕТА: оно неотличимо от
// честного случая (замер на правленом дереве) и потому обесценивает и тот,
// ради которого признак заводился.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО УТВЕРЖДАЕТСЯ, И ПОЧЕМУ ЭТО НЕ ПОСЛАБЛЕНИЕ
//
// Исключение не выписано перечнем — оно ВЫВОДИТСЯ из самого отпечатка: путь
// считается предметом ровно тогда, когда он стоит среди файлов под отпечатком.
// Расширится предмет — расширится и то, о чём шапка обязана предупредить, без
// чьей-либо памяти. Предмет неизвестен (файлов под отпечатком ноль) —
// классифицировать нечем, и шапка обязана остаться пессимистичной: «не знаю» не
// выдаётся за «чисто».
//
// Контроль в обе стороны: грязь ВНУТРИ предмета обязана по-прежнему давать
// «НЕ описывает» — иначе проверка зеленела бы на всём сломанном.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func dirtyBase(t *testing.T) Provenance {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "internal"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module github.com/PRO-Robotech/kaname\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return Provenance{
		treeRoot: root, TreeRev: "abc123", When: time.Now(), CPUCores: 1,
		RunCommand: "make scale-grid-full", GridText: "  ось N: 100\n",
	}
}

func TestDirtinessIsJudgedAgainstTheSubjectOfTheMeasurement(t *testing.T) {
	subject := []string{
		"services/iam/internal/repo/kaname/pg/scalegrid/grid.go",
		"services/iam/internal/repo/kaname/pg/scalegrid/census.go",
	}

	t.Run("грязь ВНЕ предмета: замер воспроизводим, и шапка это говорит", func(t *testing.T) {
		p := dirtyBase(t)
		p.Fingerprint = Fingerprint{Composition: "C1", Content: "C2", Files: subject, Identities: identitiesOf(subject)}
		p.TreeDirty, p.DirtyPaths = true, 3
		p.DirtyPathList = []string{
			"services/iam/internal/repo/kaname/pg/scalegrid/REPORT-R7-2-strength.txt",
			"services/iam/internal/repo/kaname/pg/scalegrid/REPORT-R7-3-matrix-volume.txt",
			"services/iam/internal/repo/kaname/pg/relverdict/REPORT-X.txt",
		}
		text := dirtySubjectHeader(t, p)

		if strings.Contains(text, "НЕ описывает") {
			t.Errorf("шапка объявила замер невоспроизводимым из-за правок ВНЕ предмета — "+
				"предупреждение без предмета:\n%s", text)
		}
		for _, want := range []string{"чистое по предмету замера", "вне предмета", "3"} {
			if !strings.Contains(text, want) {
				t.Errorf("шапка не называет %q — читатель не отличит «грязи не было» от "+
					"«грязь была, но не в предмете»:\n%s", want, text)
			}
		}
		if !strings.Contains(text, "REPORT-R7-2-strength.txt") {
			t.Errorf("шапка не НАЗЫВАЕТ путей вне предмета — оспорить её нечем:\n%s", text)
		}
	})

	t.Run("грязь ВНУТРИ предмета: «НЕ описывает» обязано остаться", func(t *testing.T) {
		p := dirtyBase(t)
		p.Fingerprint = Fingerprint{Composition: "C1", Content: "C2", Files: subject, Identities: identitiesOf(subject)}
		p.TreeDirty, p.DirtyPaths = true, 2
		p.DirtyPathList = []string{
			"services/iam/internal/repo/kaname/pg/scalegrid/grid.go",
			"services/iam/internal/repo/kaname/pg/scalegrid/REPORT-R7-2-strength.txt",
		}
		text := dirtySubjectHeader(t, p)

		for _, want := range []string{"ГРЯЗНОЕ", "НЕ описывает", "grid.go"} {
			if !strings.Contains(text, want) {
				t.Errorf("правка ФАЙЛА ПОД ОТПЕЧАТКОМ не названа (%q) — проверка зеленела бы "+
					"на всём сломанном:\n%s", want, text)
			}
		}
	})

	t.Run("предмет неизвестен: «не знаю» не выдаётся за «чисто»", func(t *testing.T) {
		p := dirtyBase(t)
		p.TreeDirty, p.DirtyPaths = true, 4
		p.DirtyPathList = []string{"README.md"}
		text := dirtySubjectHeader(t, p)

		if !strings.Contains(text, "ГРЯЗНОЕ") || !strings.Contains(text, "НЕ описывает") {
			t.Errorf("файлов под отпечатком ноль — классифицировать нечем, и шапка обязана "+
				"остаться пессимистичной:\n%s", text)
		}
	})

	t.Run("перечень путей не собран: число есть, разбора нет", func(t *testing.T) {
		p := dirtyBase(t)
		p.Fingerprint = Fingerprint{Composition: "C1", Content: "C2", Files: subject, Identities: identitiesOf(subject)}
		p.TreeDirty, p.DirtyPaths = true, 5
		text := dirtySubjectHeader(t, p)

		if !strings.Contains(text, "ГРЯЗНОЕ") || !strings.Contains(text, "НЕ описывает") {
			t.Errorf("путей не названо — судить об их принадлежности предмету нечем, и молчание "+
				"здесь означало бы чистоту, которой никто не проверял:\n%s", text)
		}
	})
}

// TestDirtyPathsAreParsedFromPorcelain — разбор вывода git, а не догадка о нём.
func TestDirtyPathsAreParsedFromPorcelain(t *testing.T) {
	out := " M services/iam/internal/repo/kaname/pg/scalegrid/grid.go\n" +
		"?? services/iam/internal/repo/kaname/pg/scalegrid/REPORT-R7-2-strength.txt\n" +
		"R  old/path.go -> services/iam/new/path.go\n" +
		"\n"
	got := ParsePorcelainPaths([]byte(out))
	want := []string{
		"services/iam/internal/repo/kaname/pg/scalegrid/grid.go",
		"services/iam/internal/repo/kaname/pg/scalegrid/REPORT-R7-2-strength.txt",
		"services/iam/new/path.go",
	}
	if len(got) != len(want) {
		t.Fatalf("путей разобрано %d, ожидалось %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("путь %d разобран как %q, ожидался %q", i, got[i], want[i])
		}
	}
}

// identitiesOf — тождества для синтетического предмета фикстуры.
//
// Прибор их вычисляет сам; фикстура строит `Fingerprint` руками, поэтому обязана
// нести их тоже — иначе она утверждала бы о шапке, которой прибор не производит.
func identitiesOf(files []string) []string {
	out := make([]string, 0, len(files))
	for _, f := range files {
		out = append(out, "предмет/"+filepath.Base(f))
	}
	return out
}

// Тот же Header обязан назвать реальную грязь внутри предмета в обеих посадках;
// соседний report/docs-файл остаётся законным outside twin, а не поводом RED.
func TestReportDirtySubjectCoordinatesMatchBothPostures(t *testing.T) {
	const subject = "services/iam/internal/apps/kaname/api/access_binding/reconcile/reconcile.go"
	for _, standalone := range []bool{false, true} {
		t.Run(fmt.Sprintf("standalone=%t", standalone), func(t *testing.T) {
			root := t.TempDir()
			prefix := "services/iam"
			if standalone {
				prefix = ""
			}
			for _, dir := range []string{filepath.Join(prefix, "internal"), "docs"} {
				if err := os.MkdirAll(filepath.Join(root, dir), 0o750); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(root, prefix, "go.mod"), []byte("module github.com/PRO-Robotech/kaname\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			p := dirtyBase(t)
			p.treeRoot = root
			p.Fingerprint = Fingerprint{Composition: "C1", Content: "C2", Files: []string{subject}, Identities: identitiesOf([]string{subject})}
			dirty := subject
			if standalone {
				dirty = strings.TrimPrefix(dirty, "services/iam/")
			}
			p.TreeDirty = true
			p.DirtyPaths = 1
			p.DirtyPathList = []string{dirty}
			inside, outside, judged := p.splitDirtyBySubject()
			if !judged || len(inside) != 1 || inside[0] != dirty || len(outside) != 0 {
				t.Fatalf("actual in-subject path lost: inside=%v outside=%v judged=%t", inside, outside, judged)
			}
			text := dirtySubjectHeader(t, p)
			if !strings.Contains(text, "ГРЯЗНОЕ ПО ПРЕДМЕТУ ЗАМЕРА") || strings.Contains(text, "чистое по предмету замера") {
				t.Fatalf("false clean header: %s", text)
			}
			p.DirtyPathList = []string{"docs/report-note.txt"}
			inside, outside, judged = p.splitDirtyBySubject()
			if !judged || len(inside) != 0 || len(outside) != 1 {
				t.Fatalf("lawful outside twin rejected: inside=%v outside=%v judged=%t", inside, outside, judged)
			}
			if !strings.Contains(dirtySubjectHeader(t, p), "чистое по предмету замера") {
				t.Fatal("outside twin must remain subject-clean")
			}
		})
	}
}

func TestReportDirtySubjectUnknownPostureFailsClosed(t *testing.T) {
	for _, root := range []string{"", t.TempDir()} {
		p := dirtyBase(t)
		p.treeRoot = root
		p.TreeDirty = true
		p.DirtyPaths = 1
		p.DirtyPathList = []string{"services/iam/internal/x.go"}
		p.Fingerprint = Fingerprint{Composition: "C1", Content: "C2", Files: p.DirtyPathList, Identities: identitiesOf(p.DirtyPathList)}
		if _, _, judged := p.splitDirtyBySubject(); judged {
			t.Fatal("unknown posture was judged")
		}
		text := dirtySubjectHeader(t, p)
		if !strings.Contains(text, "НЕ УСТАНОВЛЕНА") || strings.Contains(text, "чистое по предмету замера") {
			t.Fatalf("unknown posture false clean: %s", text)
		}
	}
}

func dirtySubjectHeader(t *testing.T, p Provenance) string {
	t.Helper()
	text, err := p.Header("проба")
	if err != nil {
		t.Fatal(err)
	}
	return text
}
