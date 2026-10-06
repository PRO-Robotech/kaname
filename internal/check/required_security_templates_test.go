// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// required_security_templates_test.go — гейт «обязательный класс» (приёмка
// NTF-2, kacho#2917, Р3, NTF2-99 (а), (в), (г); замысел issue-2917 З19; полоса
// F5).
//
// Гейт читает перечень `notifications/required-security.yaml` (24 имени
// таблицы Р3, файл не производный от шаблонов) и `notification.yaml`
// каталога шаблонов kaname и красен, если имя перечня объявлено не классом
// security, если шаблона с таким именем нет или если перечень пуст.
//
// КОНТРАКТ ГЕЙТА, который проба зовёт (на базе полосы его нет — проба не
// собирается, и все ошибки сборки — имена этого контракта):
//
//	func check.AuditRequiredSecurityTemplates(root string) (check.RequiredSecurityReport, error)
//	type check.RequiredSecurityReport struct {
//		List          string   // перечень от корня дерева
//		Catalog       string   // каталог шаблонов от корня дерева
//		Names         []string // имена перечня в порядке файла
//		TemplatesRead int      // прочитано notification.yaml каталога
//		Findings      []check.RequiredSecurityFinding
//	}
//	type check.RequiredSecurityFinding struct{ File, Template, Violation string }
//	func (check.RequiredSecurityFinding) String() string // файл · шаблон · нарушенное
//
// error — отказ прогона (перечень не читается и т. п.), а не находка.
//
// Близнец каждой инъекции — та же копия без правки: находок 0. Каждая копия
// отличается от близнеца одним фактом, и находка обязана быть ровно одна.
package check_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/PRO-Robotech/corelib/gitenv"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// requiredSecurityList — координата перечня. Приёмка (Р3, NTF2-99) называет её
// `notifications/required-security.yaml` рядом с `notifications/*/notification.yaml`;
// правило генератора corelib (cmd/notifygen ntf2_99_test.go, notify/spec load.go)
// кладёт перечень в каталог шаблонов владельца — обе координаты приёмки в одном
// каталоге, `<владелец>/notifications/`. Перечень вне каталога шаблонов
// генератор отвергает «файл вне раскладки шаблона» либо как каталог без пакета Go.
const requiredSecurityList = requiredSecurityCatalog + "/required-security.yaml"

// requiredSecurityCatalog — каталог шаблонов kaname: владелец генератора — пакет
// функций постановки feedgen (замысел З1, И28; вывод notifygen).
const requiredSecurityCatalog = "internal/apps/kaname/mail/feedgen/notifications"

// r3Templates — имена шаблонов таблицы Р3 приёмки NTF-2 (DoD п.1: сверка
// перечня поимённо).
var r3Templates = []string{
	"access-key-changed", "account-deleted", "backup-codes-regenerated",
	"cluster-admin-granted", "cluster-admin-revoked", "invite", "mail-throttled",
	"new-device-login", "password-changed", "project-deleted", "recovery",
	"recovery-completed", "registration", "registration-existing",
	"removed-from-account", "role-granted", "role-revoked", "sa-key-issued",
	"second-factor-changed", "service-account-disabled", "sessions-revoked",
	"user-blocked", "user-token-issued", "verification",
}

// requiredSecurityRoot — корень дерева kaname либо отказ прогона.
func requiredSecurityRoot(t *testing.T) string {
	t.Helper()
	return notifyTreeRoot(t)
}

// copyKanameTracked — П8: копия отслеживаемого дерева kaname.
func copyKanameTracked(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	out, err := gitenv.Command(src, "ls-files", "-z").Output()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: git ls-files %s: %v", src, err)
	}
	copied := 0
	for _, rel := range strings.Split(string(out), "\x00") {
		if rel == "" {
			continue
		}
		from := filepath.Join(src, filepath.FromSlash(rel))
		fi, err := os.Lstat(from)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: lstat %s: %v", rel, err)
		}
		if !fi.Mode().IsRegular() {
			continue
		}
		to := filepath.Join(dst, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(to), 0o750); err != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
		}
		raw, err := os.ReadFile(from) // #nosec G304 -- отслеживаемый файл дерева пробы
		if err != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
		}
		if err := os.WriteFile(to, raw, fi.Mode().Perm()); err != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
		}
		copied++
	}
	if copied == 0 {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: в индексе дерева kaname ноль файлов — копия беспредметна")
	}
	return dst
}

// auditRequiredSecurity — прогон гейта; отказ прогона — не находка.
func auditRequiredSecurity(t *testing.T, root string) check.RequiredSecurityReport {
	t.Helper()
	r, err := check.AuditRequiredSecurityTemplates(root)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: гейт обязательного класса по %s: %v", root, err)
	}
	t.Logf("перечень %s: имён %d; каталог %s: прочитано шаблонов %d; находок %d",
		r.List, len(r.Names), r.Catalog, r.TemplatesRead, len(r.Findings))
	for _, f := range r.Findings {
		t.Log(f.String())
	}
	return r
}

// TestRequiredSecurityTemplates_OnTree — близнец NTF2-99: на дереве kaname
// перечень несёт 24 имени таблицы Р3, все объявлены классом security,
// находок 0, прочитанных шаблонов не меньше имён перечня.
func TestRequiredSecurityTemplates_OnTree(t *testing.T) {
	r := auditRequiredSecurity(t, requiredSecurityRoot(t))
	if r.List != requiredSecurityList || r.Catalog != requiredSecurityCatalog {
		t.Fatalf("гейт читал перечень %q и каталог %q, ожидались %q и %q", r.List, r.Catalog, requiredSecurityList, requiredSecurityCatalog)
	}
	got := slices.Clone(r.Names)
	slices.Sort(got)
	if !slices.Equal(got, r3Templates) {
		t.Fatalf("перечень %s — %d имён %v; таблица Р3 — %d имён %v", r.List, len(got), got, len(r3Templates), r3Templates)
	}
	if r.TemplatesRead < len(r3Templates) {
		t.Fatalf("прочитано шаблонов %d — меньше имён перечня %d: обход каталога не тот", r.TemplatesRead, len(r3Templates))
	}
	if len(r.Findings) != 0 {
		t.Fatalf("на дереве kaname находок гейта обязательного класса %d, ожидалось 0", len(r.Findings))
	}
}

// editListSequence правит последовательность имён перечня разбором YAML: форма
// файла — его дело, проба ищет ровно одну последовательность скаляров (сам
// документ либо значение ключа верхнего уровня). Иначе инъекция не создана.
func editListSequence(t *testing.T, src string, edit func([]*yaml.Node) []*yaml.Node) string {
	t.Helper()
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil || len(doc.Content) != 1 {
		t.Fatalf("инъекция НЕ СОЗДАНА: перечень не разбирается одним документом YAML: %v", err)
	}
	var seqs []*yaml.Node
	top := doc.Content[0]
	switch top.Kind {
	case yaml.SequenceNode:
		seqs = append(seqs, top)
	case yaml.MappingNode:
		for i := 1; i < len(top.Content); i += 2 {
			if top.Content[i].Kind == yaml.SequenceNode {
				seqs = append(seqs, top.Content[i])
			}
		}
	}
	if len(seqs) != 1 {
		t.Fatalf("инъекция НЕ СОЗДАНА: в перечне последовательностей имён %d, ожидалась одна", len(seqs))
	}
	seqs[0].Content = edit(seqs[0].Content)
	out, err := yaml.Marshal(&doc)
	if err != nil {
		t.Fatalf("инъекция НЕ СОЗДАНА: %v", err)
	}
	return string(out)
}

// requiredSecurityInjection — одна копия П8 с одной правкой.
type requiredSecurityInjection struct {
	name      string
	file      string // правимый файл от корня дерева
	edit      func(string) string
	wantFile  string
	wantParts []string // подстроки находки: шаблон и нарушенное
}

// TestRequiredSecurityTemplates_InjectionsAreFound — NTF2-99 (а), (в), (г): три
// копии П8 красные, находка ровно одна и называет файл, шаблон и нарушенное.
func TestRequiredSecurityTemplates_InjectionsAreFound(t *testing.T) {
	root := requiredSecurityRoot(t)
	const absent = "no-such-template"
	cases := []requiredSecurityInjection{
		{
			name: "(а) класс role-granted заменён на отключаемый",
			file: requiredSecurityCatalog + "/role-granted/notification.yaml",
			edit: func(s string) string {
				return strings.Replace(s, "class: security", "class: notice", 1)
			},
			wantFile:  requiredSecurityCatalog + "/role-granted/notification.yaml",
			wantParts: []string{"role-granted", "не security"},
		},
		{
			name: "(в) перечень пуст",
			file: requiredSecurityList,
			edit: func(s string) string {
				return editListSequence(t, s, func([]*yaml.Node) []*yaml.Node { return nil })
			},
			wantFile:  requiredSecurityList,
			wantParts: []string{"пустой перечень"},
		},
		{
			name: "(г) в перечне имя без шаблона",
			file: requiredSecurityList,
			edit: func(s string) string {
				return editListSequence(t, s, func(items []*yaml.Node) []*yaml.Node {
					return append(items, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: absent})
				})
			},
			wantFile:  requiredSecurityList,
			wantParts: []string{absent, "имя без шаблона"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cp := copyKanameTracked(t, root)
			if twin := auditRequiredSecurity(t, cp); len(twin.Findings) != 0 || len(twin.Names) == 0 {
				t.Fatalf("близнец — копия без правки: находок %d, имён перечня %d; ожидались 0 и > 0",
					len(twin.Findings), len(twin.Names))
			}
			file := filepath.Join(cp, filepath.FromSlash(c.file))
			raw, err := os.ReadFile(file) // #nosec G304 -- файл копии пробы
			if err != nil {
				t.Fatalf("инъекция НЕ СОЗДАНА: %v", err)
			}
			edited := c.edit(string(raw))
			if edited == string(raw) {
				t.Fatalf("инъекция НЕ СОЗДАНА: правка %s ничего не изменила", c.file)
			}
			if err := os.WriteFile(file, []byte(edited), 0o600); err != nil {
				t.Fatalf("инъекция НЕ СОЗДАНА: %v", err)
			}
			r := auditRequiredSecurity(t, cp)
			if len(r.Findings) != 1 {
				t.Fatalf("NTF2-99 %s: находок %d, ожидалась ровно одна", c.name, len(r.Findings))
			}
			f := r.Findings[0]
			if f.File != c.wantFile {
				t.Fatalf("NTF2-99 %s: находка о файле %q, ожидался %q", c.name, f.File, c.wantFile)
			}
			s := f.String()
			for _, part := range append([]string{c.wantFile}, c.wantParts...) {
				if !strings.Contains(s, part) {
					t.Fatalf("NTF2-99 %s: находка %q не называет %q", c.name, s, part)
				}
			}
		})
	}
}
