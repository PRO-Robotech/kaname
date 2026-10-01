// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// notifytypesafety_test.go — гейты дерева NTF-1 по дереву kaname (З16):
//
//   - NTF1-B28 (гейт) — обход типобезопасности, семь видов;
//   - NTF1-B28 (гейт `Put`) — ссылка на feed.Put вне файлов генератора, вход —
//     вывод `notifygen -list` по этому же дереву;
//   - узел «ошибка Value() отброшена» (CX1-41 (б), УК46);
//   - перепись писателей таблиц ленты (УК87, CX1-74 (а)): у kaname писателей 0.
//
// ТОНКИЕ ВЫЗЫВАЮЩИЕ. Узлы, перечни видов и расширений, ведомость писателей и
// реестр исключений живут в corelib (`treehygiene`); от дерева здесь только
// корень и каталог стабов. Копия перечня в этом дереве разошлась бы с corelib
// молча (УК50).
//
// Инъекции идут ПРОГОНОМ ПО KANAME: в копию отслеживаемого дерева kaname
// вносятся не-тестовые пакеты, каждый своей координатой, и каждый гейт обязан
// назвать ровно свои — близнецом служит прогон по исправному дереву.
package check_test

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/gitenv"
	"github.com/PRO-Robotech/corelib/treehygiene"

	"github.com/PRO-Robotech/kaname/internal/treeposture"
)

// notifyStubDir — каталог стабов дерева kaname: сгенерированный файл
// пропускается гейтами только здесь (Р7).
const notifyStubDir = "pkg/api"

// notifygenPkg — генератор постановки, исполняемый версией пина corelib из
// go.mod этого дерева. Тот же путь зовёт цель `notifications-check`.
const notifygenPkg = "github.com/PRO-Robotech/corelib/cmd/notifygen"

// notifyTreeRoot — корень дерева kaname либо ОТКАЗ.
func notifyTreeRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	root, _, err := treeposture.CorpusRoot(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень дерева не установлен: %v", err)
	}
	return root
}

// logCorelibPin печатает версию corelib, из которой собрана проба: модуль,
// выбранный графом модулей этого дерева (`go list -m`), и требует, чтобы это
// был пин без `replace`.
//
// ПОЧЕМУ НЕ ВЕРСИЯ ИЗ ОТЧЁТА ГЕЙТА. `treehygiene.CorelibVersion` читает
// `debug.ReadBuildInfo` процесса, а тестовый бинарь сведений о зависимостях не
// несёт (go1.26.8: Main — модуль дерева, Deps — 0), и отчёт гейта в прогоне
// `go test` печатает «не в графе модулей процесса». Проба собрана тем же
// графом модулей, о котором спрашивает `go list -m`, — это и есть версия, из
// которой исполнен гейт.
func logCorelibPin(t *testing.T, root string) {
	t.Helper()
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Version}} {{with .Replace}}=> {{.Path}} {{.Version}}{{end}}", // #nosec G204 -- argv фиксирован
		"github.com/PRO-Robotech/corelib")
	cmd.Dir = root
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: версия corelib в графе модулей дерева не установлена: %v\n%s", err, stderr.String())
	}
	v := strings.TrimSpace(string(out))
	if !strings.HasPrefix(v, "v") || strings.Contains(v, "=>") {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: corelib в графе модулей дерева — %q, а не пин без replace", v)
	}
	t.Logf("corelib, из которого собрана проба (go list -m): %s", v)
}

// requireTreeCensus — объём осмотренного дерева root: «ноль находок» отличим
// от «ноль прочитанного»; рядом — версия corelib, из которой исполнен гейт.
func requireTreeCensus(t *testing.T, root string, c treehygiene.TreeCensus) {
	t.Helper()
	logCorelibPin(t, root)
	if c.Module != "github.com/PRO-Robotech/kaname" {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: обойдён модуль %q, а не kaname", c.Module)
	}
	if c.Packages == 0 || c.Files == 0 {
		t.Fatalf("пустой обход — не вердикт: %s", c)
	}
}

// notifygenList — вывод `notifygen -list` по дереву root, исполненного версией
// пина. Генератор, не исполнившийся, — отказ прогона, а не пустое множество.
func notifygenList(t *testing.T, root string) []byte {
	t.Helper()
	cmd := exec.Command("go", "run", notifygenPkg, "-list", "-root", root) // #nosec G204 -- argv фиксирован, корень — дерево пробы
	cmd.Dir = root
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: notifygen -list по %s: %v\n%s", root, err, stderr.String())
	}
	return out
}

func logFindings(t *testing.T, fs []treehygiene.Finding) {
	t.Helper()
	for _, f := range fs {
		t.Log(f.String())
	}
}

// TestNTF1B28Gate_OnKaname — NTF1-B28 (гейт) по дереву kaname: узлов обхода
// типобезопасности 0 по каждому из семи видов, стабы pkg/api пропущены.
func TestNTF1B28Gate_OnKaname(t *testing.T) {
	root := notifyTreeRoot(t)
	r, err := treehygiene.AuditTypeSafetyBypass(root, notifyStubDir)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	t.Log(r.String())
	requireTreeCensus(t, root, r.Census)
	if r.Parsed == 0 || r.Census.Generated == 0 {
		t.Fatalf("обход не тот: разобрано без ограничений сборки %d, пропущено сгенерированных %d — "+
			"стабы pkg/api есть в дереве, и не увидеть их значит не прочитать каталог стабов", r.Parsed, r.Census.Generated)
	}
	for _, f := range r.Findings {
		t.Errorf("NTF1-B28 (гейт) · %s", f)
	}
}

// TestNTF1B28PutGate_OnKaname — NTF1-B28 (гейт `Put`) по дереву kaname: ссылок
// на feed.Put вне файлов генератора 0; вход — вывод генератора пина.
func TestNTF1B28PutGate_OnKaname(t *testing.T) {
	root := notifyTreeRoot(t)
	r, err := treehygiene.AuditFeedPutReferences(root, notifyStubDir, notifygenList(t, root))
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	t.Log(r.String())
	requireTreeCensus(t, root, r.Census)
	for _, f := range r.Findings {
		t.Errorf("NTF1-B28 (гейт Put) · %s", f)
	}
}

// TestUK46ValueErrorDiscard_OnKaname — узел «ошибка Value() отброшена» по
// дереву kaname (CX1-41 (б)).
func TestUK46ValueErrorDiscard_OnKaname(t *testing.T) {
	root := notifyTreeRoot(t)
	r, err := treehygiene.AuditValueErrorDiscard(root, notifyStubDir)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	t.Log(r.String())
	requireTreeCensus(t, root, r.Census)
	for _, f := range r.Findings {
		t.Errorf("УК46 · %s", f)
	}
}

// TestNTF1B19FeedWriters_OnKaname — перепись писателей таблиц ленты по дереву
// kaname (УК87, CX1-74 (а)): мест имени таблицы 0, писателей окна 0, находок
// SQL 0, применимых к kaname записей реестра 0. Имя таблицы ленты производит
// внутренний пакет corelib, и вне `notify/feed` его не импортирует компилятор,
// поэтому писатель в kaname — только находка; запись реестра признаёт
// функцию журнала модуля kacho (Д33) и к kaname не применяется.
func TestNTF1B19FeedWriters_OnKaname(t *testing.T) {
	root := notifyTreeRoot(t)
	r, err := treehygiene.AuditFeedTableWrites(root, notifyStubDir)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	t.Log(r.String())
	requireTreeCensus(t, root, r.Census)
	if r.SQLFiles == 0 {
		t.Fatalf("пустой обход SQL — не вердикт: миграции kaname отслеживаются, а осмотрено файлов *.sql 0")
	}
	for _, f := range r.Findings {
		t.Errorf("NTF1-B19 · %s", f)
	}
	if r.OfCalls != 0 || r.Sites != 0 || r.WindowSites != 0 || r.NameUses != 0 || r.MigrationCalls != 0 {
		t.Errorf("писатели таблиц ленты в kaname: вызовов Of %d, мест %d, мест окна %d %v, Name %d, schema.Migration %d — ожидается 0",
			r.OfCalls, r.Sites, r.WindowSites, r.WindowSiteAt, r.NameUses, r.MigrationCalls)
	}
	if r.Exceptions != 0 || r.Recognized != 0 {
		t.Errorf("применимых к kaname записей реестра %d, признанных функций %d — запись реестра (Д33) "+
			"признаёт функцию журнала модуля kacho, к kaname она не применяется", r.Exceptions, r.Recognized)
	}
}

// Инъекции прогона по kaname. Каждая — не-тестовый пакет своей координатой в
// копии отслеживаемого дерева kaname; узлы разных гейтов не пересекаются, и
// каждый гейт обязан назвать ровно свои находки — чужая инъекция для него
// законный близнец той же копии.
const (
	injIDNA = "internal/ntfinject/idnavalue/idnavalue.go"
	// B27 (гейт) (1): значение-функция idna вне corelib/notify/address.
	injIDNABody = `package idnavalue

import "golang.org/x/net/idna"

// ToASCII — значение-функция нормализации домена вне пакета адреса.
var ToASCII = idna.Lookup.ToASCII
`
	injReflect = "internal/ntfinject/setfirst/setfirst.go"
	// B28 (гейт) (5) — инъекция (1) в kaname: NewAt и UnsafePointer без
	// импорта unsafe, вызов над form.Path.
	injReflectBody = `package setfirst

import (
	"reflect"

	"github.com/PRO-Robotech/corelib/notify/form"
)

// SetFirstString пишет s в первое поле dst в обход функций его пакета.
func SetFirstString(dst any, s string) {
	f := reflect.ValueOf(dst).Elem().Field(0)
	reflect.NewAt(f.Type(), f.Addr().UnsafePointer()).Elem().SetString(s)
}

// Forge — сборщик ссылки над form.Path.
func Forge(raw string) form.Path {
	var p form.Path
	SetFirstString(&p, raw)
	return p
}
`
	injBodyless   = "internal/ntfinject/asmput/asmput.go"
	injBodylessAs = "internal/ntfinject/asmput/asmput_amd64.s"
	// B28 (гейт) (9): объявление без тела и файл .s, зовущий символ feed.Put.
	injBodylessBody = `package asmput

import _ "github.com/PRO-Robotech/corelib/notify/feed"

// callPut — тело в asmput_amd64.s.
func callPut()

// Call — вызов мимо ссылки на объект.
func Call() { callPut() }
`
	injBodylessAsBody = `#include "textflag.h"

TEXT ·callPut(SB),NOSPLIT,$0-0
	JMP github.com∕PRO-Robotech∕corelib∕notify∕feed·Put(SB)
`
	injPut = "internal/ntfinject/putvalue/putvalue.go"
	// B28 (гейт Put) (3): p := feed.Put в не-тестовом пакете kaname.
	injPutBody = `package putvalue

import "github.com/PRO-Robotech/corelib/notify/feed"

// Value — значение-функция feed.Put вне файлов генератора.
func Value() any {
	p := feed.Put
	return p
}
`
)

// injectedKanameTree — копия отслеживаемого дерева kaname с инъекциями: файлы
// рабочей копии по составу индекса, затем инъекции, затем свой индекс git.
// Строится один раз на пробу: каждый гейт проверяет типами дерево целиком.
func injectedKanameTree(t *testing.T) string {
	t.Helper()
	root, err := buildInjectedKaname(notifyTreeRoot(t), t.TempDir())
	if err != nil {
		t.Fatalf("проба НЕ ИСПОЛНЯЛАСЬ: копия дерева kaname с инъекциями не собрана: %v", err)
	}
	return root
}

func buildInjectedKaname(src, dst string) (string, error) {
	out, err := gitenv.Command(src, "ls-files", "-z").Output()
	if err != nil {
		return "", fmt.Errorf("git ls-files %s: %w", src, err)
	}
	copied := 0
	for _, rel := range strings.Split(string(out), "\x00") {
		if rel == "" {
			continue
		}
		from := filepath.Join(src, filepath.FromSlash(rel))
		fi, err := os.Lstat(from)
		if errors.Is(err, fs.ErrNotExist) {
			continue // удалён в рабочей копии: в судимом дереве его нет
		}
		if err != nil {
			return "", fmt.Errorf("lstat %s: %w", rel, err)
		}
		to := filepath.Join(dst, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(to), 0o750); err != nil {
			return "", fmt.Errorf("mkdir %s: %w", rel, err)
		}
		switch {
		case fi.Mode()&fs.ModeSymlink != 0:
			target, err := os.Readlink(from)
			if err != nil {
				return "", fmt.Errorf("readlink %s: %w", rel, err)
			}
			if err := os.Symlink(target, to); err != nil {
				return "", fmt.Errorf("symlink %s: %w", rel, err)
			}
		case fi.Mode().IsRegular():
			raw, err := os.ReadFile(from) // #nosec G304 -- отслеживаемый файл дерева пробы
			if err != nil {
				return "", fmt.Errorf("read %s: %w", rel, err)
			}
			if err := os.WriteFile(to, raw, fi.Mode().Perm()); err != nil {
				return "", fmt.Errorf("write %s: %w", rel, err)
			}
		default:
			continue
		}
		copied++
	}
	if copied == 0 {
		return "", errors.New("в индексе дерева kaname ноль файлов — копия беспредметна")
	}
	for rel, body := range map[string]string{
		injIDNA: injIDNABody, injReflect: injReflectBody,
		injBodyless: injBodylessBody, injBodylessAs: injBodylessAsBody, injPut: injPutBody,
	} {
		to := filepath.Join(dst, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(to), 0o750); err != nil {
			return "", fmt.Errorf("mkdir %s: %w", rel, err)
		}
		if err := os.WriteFile(to, []byte(body), 0o600); err != nil {
			return "", fmt.Errorf("write %s: %w", rel, err)
		}
	}
	for _, args := range [][]string{{"init", "--quiet", "-b", "main"}, {"add", "-A"}} {
		if out, err := gitenv.Command(dst, args...).CombinedOutput(); err != nil {
			return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, out)
		}
	}
	return dst, nil
}

// findingAt — «координата : вид» находки; координата — файл без строки.
func findingAt(f treehygiene.Finding) string {
	file := f.Position
	if i := strings.Index(file, ".go:"); i >= 0 {
		file = file[:i+3]
	}
	return file + " : " + f.Kind
}

func requireExactly(t *testing.T, got []treehygiene.Finding, want ...string) {
	t.Helper()
	var have []string
	for _, f := range got {
		have = append(have, findingAt(f))
	}
	sort.Strings(have)
	sort.Strings(want)
	if !slices.Equal(have, want) {
		logFindings(t, got)
		t.Fatalf("находки прогона по kaname с инъекциями:\n  получено: %q\n  ожидается: %q", have, want)
	}
}

// TestNTF1Gates_InjectionsInKanameAreFound — инъекции B27 (гейт) (1), B28
// (гейт) (5) и (9), B28 (гейт `Put`) (3) прогоном по kaname.
func TestNTF1Gates_InjectionsInKanameAreFound(t *testing.T) {
	root := injectedKanameTree(t)

	t.Run("NTF1-B27 (гейт) (1) значение-функция idna в kaname", func(t *testing.T) {
		r, err := treehygiene.AuditIDNASingular(root, notifyStubDir)
		if err != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
		}
		t.Log(r.String())
		requireTreeCensus(t, root, r.Census)
		requireExactly(t, r.Findings, injIDNA+" : idna")
	})

	t.Run("NTF1-B28 (гейт) (5) и (9) обход типобезопасности в kaname", func(t *testing.T) {
		r, err := treehygiene.AuditTypeSafetyBypass(root, notifyStubDir)
		if err != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
		}
		t.Log(r.String())
		requireTreeCensus(t, root, r.Census)
		requireExactly(t, r.Findings,
			injReflect+" : "+string(treehygiene.KindReflectNewAt),
			injReflect+" : "+string(treehygiene.KindUnsafePointer),
			injBodyless+" : "+string(treehygiene.KindBodyless),
			injBodylessAs+" : "+string(treehygiene.KindNonGoSource))
	})

	t.Run("NTF1-B28 (гейт Put) (3) p := feed.Put в kaname", func(t *testing.T) {
		r, err := treehygiene.AuditFeedPutReferences(root, notifyStubDir, notifygenList(t, root))
		if err != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
		}
		t.Log(r.String())
		requireTreeCensus(t, root, r.Census)
		requireExactly(t, r.Findings, injPut+" : "+string(treehygiene.FeedPutOutsideGenerator))
	})
}
