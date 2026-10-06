// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// templates_check_test.go — шаблоны писем kaname и их сверка генератором
// (приёмка NTF-2, kacho#2917, Р3, Р8; замысел issue-2917 З19, И14; полоса F4).
//
//   - NTF2-08: копия дерева kaname, где у шаблона класса security `recovery`
//     снят раздел `limits`, — `notifygen -check` красный и называет файл, поле
//     `limits` и класс security; близнец — дерево как есть: зелёный и печатает
//     число шаблонов 24 (перечень Р3).
//   - И14: лимит шаблона на адресата в сутки не меньше наибольшего числа писем,
//     которое допускают верхние границы Р8 (окно, пол, запас устройства).
//
// КАТАЛОГ ШАБЛОНОВ. Генератор пишет `notifications_<имя>.gen.go` в каталог,
// несущий подкаталог `notifications/` (corelib cmd/notifygen, tree.go: owner),
// а функции `Send*` kaname живут в этом пакете (замысел З1, И28). Поэтому
// каталог шаблонов — `notifications/` этого пакета, и владелец генератора в
// дереве ровно один — этот пакет. Координату спрашиваем у генератора
// (`notifygen -list`), а не выписываем обходом своего.
//
// ПОРЯДОК ПРОВЕРОК НЕСУЩИЙ: сперва фикстура (генератор исполняется версией
// пина, на синтетическом каталоге различает шаблон с лимитами и без), затем
// близнец на дереве, затем инъекция. Сломанная фикстура не выдаёт себя за
// отсутствие шаблонов.
package feedgen_test

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/PRO-Robotech/corelib/gitenv"
	"github.com/PRO-Robotech/corelib/notify/spec"

	"github.com/PRO-Robotech/kaname/internal/treeposture"
)

// notifygenPkg — генератор постановки версии пина corelib из go.mod дерева.
const notifygenPkg = "github.com/PRO-Robotech/corelib/cmd/notifygen"

// feedgenDir — пакет функций постановки kaname и владелец каталога шаблонов.
const feedgenDir = "internal/apps/kaname/mail/feedgen"

// catalogDir — каталог шаблонов kaname от корня дерева.
const catalogDir = feedgenDir + "/notifications"

// templatesInR3 — число шаблонов перечня Р3 приёмки NTF-2 (пары через «·» —
// два шаблона).
const templatesInR3 = 24

// treeRoot — корень дерева kaname либо отказ прогона.
func treeRoot(t *testing.T) string {
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

// genResult — исход одного вызова генератора.
type genResult struct {
	code           int
	stdout, stderr string
}

// notifygen исполняет генератор версии пина из корня дерева kaname над root.
// Генератор, не запустившийся (нет кода выхода), — отказ прогона, а не исход.
func notifygen(t *testing.T, kaname string, args ...string) genResult {
	t.Helper()
	cmd := exec.Command("go", append([]string{"run", notifygenPkg}, args...)...) // #nosec G204 -- argv собран пробой
	cmd.Dir = kaname
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return genResult{code: 0, stdout: so.String(), stderr: se.String()}
	case errors.As(err, &ee):
		// `go run` печатает «exit status N» и выходит с 1 при любом ненулевом
		// коде программы; код программы 2 (неверный вызов) — отказ прогона.
		if strings.Contains(se.String(), "exit status 2") {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: notifygen %v — неверный вызов:\n%s", args, se.String())
		}
		return genResult{code: ee.ExitCode(), stdout: so.String(), stderr: se.String()}
	}
	t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: notifygen %v не запустился: %v\n%s", args, err, se.String())
	return genResult{}
}

// owners — каталоги-владельцы шаблонов по выводу `notifygen -list`.
func owners(t *testing.T, kaname, root string) []string {
	t.Helper()
	r := notifygen(t, kaname, "-list", "-root", root)
	if r.code != 0 {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: notifygen -list по %s: код %d\n%s", root, r.code, r.stderr)
	}
	set := map[string]bool{}
	for _, line := range strings.Split(r.stdout, "\n") {
		p, ok := strings.CutPrefix(line, "file ")
		if !ok || !strings.HasSuffix(p, ".gen.go") {
			continue
		}
		set[path.Dir(p)] = true
	}
	out := make([]string, 0, len(set))
	for d := range set {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// requireGeneratorTellsLimits — предпосылка: генератор версии пина исполняется
// и на синтетическом каталоге различает шаблон security с лимитами (зелёный)
// и тот же шаблон без раздела `limits` (красный с полем и правилом). Без неё
// красный на дереве не отличим от неисполнившегося генератора.
func requireGeneratorTellsLimits(t *testing.T, kaname string) {
	t.Helper()
	if v := notifygen(t, kaname, "-version"); v.code != 0 || strings.TrimSpace(v.stdout) == "" {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: notifygen -version: код %d, вывод %q\n%s", v.code, v.stdout, v.stderr)
	} else {
		t.Logf("notifygen версии пина: %s", strings.TrimSpace(v.stdout))
	}
	syn := t.TempDir()
	write := func(rel, body string) {
		to := filepath.Join(syn, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(to), 0o750); err != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
		}
		if err := os.WriteFile(to, []byte(body), 0o600); err != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
		}
	}
	const notif = `name: probe
class: security
ttl: 24h
limits:
  - {scope: recipient, window: 24h, max: 3}
attributes:
  code: {type: secret, presence: required}
subject:
  ru: "Проба"
  en: "Probe"
`
	write("pkg/doc.go", "package pkg\n")
	write("pkg/notifications/probe/notification.yaml", notif)
	write("pkg/notifications/probe/body.ru.yaml", "blocks:\n  - code: \"{{ code }}\"\n")
	write("pkg/notifications/probe/body.en.yaml", "blocks:\n  - code: \"{{ code }}\"\n")
	if g := notifygen(t, kaname, "-root", syn); g.code != 0 {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: генерация синтетического каталога: код %d\n%s", g.code, g.stderr)
	}
	if c := notifygen(t, kaname, "-check", "-root", syn); c.code != 0 {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: синтетический близнец с лимитами не зелёный: код %d\n%s", c.code, c.stderr)
	}
	write("pkg/notifications/probe/notification.yaml", strings.Replace(notif,
		"limits:\n  - {scope: recipient, window: 24h, max: 3}\n", "", 1))
	c := notifygen(t, kaname, "-check", "-root", syn)
	if c.code == 0 || !limitsFinding(c.stderr, "pkg/notifications/probe/notification.yaml") {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: генератор пина на синтетическом шаблоне security без limits "+
			"не назвал поле и правило (код %d):\n%s", c.code, c.stderr)
	}
}

// limitsFinding — строка находки «файл · поле limits · класс security требует
// limits» о файле file.
func limitsFinding(stderr, file string) bool {
	for _, line := range strings.Split(stderr, "\n") {
		if strings.HasPrefix(line, file) && strings.Contains(line, "поле limits") &&
			strings.Contains(line, spec.RuleSecurityNeedsLimits) {
			return true
		}
	}
	return false
}

// findingLines — строки находок генератора (без строки переписи и «exit status»).
func findingLines(stderr string) []string {
	var out []string
	for _, line := range strings.Split(stderr, "\n") {
		if line == "" || strings.HasPrefix(line, "exit status") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// copyTrackedTree — П8: копия отслеживаемого дерева kaname (состав индекса,
// содержимое рабочей копии).
func copyTrackedTree(t *testing.T, src string) string {
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

// dropKey снимает ключ верхнего уровня key из YAML-файла разбором; ключа нет —
// отказ: инъекция не создана.
func dropKey(t *testing.T, file, key string) {
	t.Helper()
	raw, err := os.ReadFile(file) // #nosec G304 -- файл копии пробы
	if err != nil {
		t.Fatalf("инъекция НЕ СОЗДАНА: %v", err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		t.Fatalf("инъекция НЕ СОЗДАНА: %s не разбирается отображением верхнего уровня: %v", file, err)
	}
	m := doc.Content[0]
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			out, err := yaml.Marshal(&doc)
			if err != nil {
				t.Fatalf("инъекция НЕ СОЗДАНА: %v", err)
			}
			if err := os.WriteFile(file, out, 0o600); err != nil {
				t.Fatalf("инъекция НЕ СОЗДАНА: %v", err)
			}
			return
		}
	}
	t.Fatalf("инъекция НЕ СОЗДАНА: в %s нет ключа %q — снимать нечего", file, key)
}

// requireCatalogOnTree — владелец шаблонов в дереве ровно один, это пакет
// feedgen, и генератор на дереве зелёный с числом шаблонов перечня Р3.
func requireCatalogOnTree(t *testing.T, root string) {
	t.Helper()
	got := owners(t, root, root)
	if len(got) != 1 || got[0] != feedgenDir {
		t.Fatalf("NTF2-08 близнец: владельцы шаблонов в дереве kaname по notifygen -list — %v, "+
			"ожидался ровно один %s (вывод генератора в feedgen, Р3 и З19)", got, feedgenDir)
	}
	c := notifygen(t, root, "-check", "-root", root)
	t.Logf("notifygen -check по дереву: код %d\n%s%s", c.code, c.stdout, c.stderr)
	if c.code != 0 {
		t.Fatalf("NTF2-08 близнец: notifygen -check по дереву kaname красный (код %d):\n%s", c.code, c.stderr)
	}
	want := fmt.Sprintf("шаблонов %d,", templatesInR3)
	if !strings.HasPrefix(strings.TrimSpace(c.stdout), want) {
		t.Fatalf("NTF2-08 близнец: notifygen -check по дереву печатает %q, ожидалось начало %q — "+
			"шаблонов перечня Р3 в каталоге %s не %d", strings.TrimSpace(c.stdout), want, catalogDir, templatesInR3)
	}
}

// TestNTF208_SecurityTemplateWithoutLimits_CheckIsRed — NTF2-08 и его близнец.
func TestNTF208_SecurityTemplateWithoutLimits_CheckIsRed(t *testing.T) {
	root := treeRoot(t)
	requireGeneratorTellsLimits(t, root)

	requireCatalogOnTree(t, root)

	cp := copyTrackedTree(t, root)
	target := catalogDir + "/recovery/notification.yaml"
	dropKey(t, filepath.Join(cp, filepath.FromSlash(target)), "limits")
	c := notifygen(t, root, "-check", "-root", cp)
	t.Logf("notifygen -check по копии без limits у recovery: код %d\n%s", c.code, c.stderr)
	if c.code == 0 {
		t.Fatalf("NTF2-08: шаблон security без limits — notifygen -check зелёный")
	}
	if !limitsFinding(c.stderr, target) {
		t.Fatalf("NTF2-08: находка не называет %s, поле limits и правило %q:\n%s", target, spec.RuleSecurityNeedsLimits, c.stderr)
	}
	for _, line := range findingLines(c.stderr) {
		if !strings.HasPrefix(line, target) {
			t.Fatalf("NTF2-08: инъекция одного факта дала постороннюю находку %q — копия отличается от близнеца не одним фактом", line)
		}
	}
}

// r8Bounds — верхние границы таблицы Р8 приёмки NTF-2, из которых выводится
// наибольшее число писем адресату в сутки. Это не второе место о ручках
// kaname: таблица границ стража (`mail_bounds.go`, З23) на базе этой полосы не
// существует; когда она появится, проба берёт границы из неё (одно объявление
// границ, З19 «Держатели»).
var r8Bounds = struct {
	perDayMax           int           // authn.login.mail-window.<назначение>.per-day ≤ 20
	floorIntervalMin    time.Duration // floor-interval ≥ 1 ч
	deviceRecoveryMax   int           // authn.login.trusted-device.recovery-per-day ≤ 5
	throttledIntervalMn time.Duration // authn.login.mail-throttled-interval ≥ 1 сут
	inviteRecipientDay  int           // invite.recipient-per-day-all ≤ 50 — лимит шаблона invite
}{20, time.Hour, 5, 24 * time.Hour, 50}

// perDayLimit — лимит шаблона на адресата с окном сутки; нет — 0.
func perDayLimit(tpl spec.Template) int {
	for _, l := range tpl.Limits {
		if l.Scope == spec.ScopeRecipient && l.Window == 24*time.Hour {
			return l.Max
		}
	}
	return 0
}

// TestNTF2I14_TemplateLimitCoversR8Bounds — И14: лимит шаблона не режет письмо,
// пропущенное окном (Р8 «Лимит шаблона не режет письмо», З19).
func TestNTF2I14_TemplateLimitCoversR8Bounds(t *testing.T) {
	root := treeRoot(t)
	requireGeneratorTellsLimits(t, root)

	floors := int((24*time.Hour + r8Bounds.floorIntervalMin - 1) / r8Bounds.floorIntervalMin)
	byWindow := r8Bounds.perDayMax + floors
	want := map[string]int{
		"recovery":              byWindow + r8Bounds.deviceRecoveryMax,
		"verification":          byWindow,
		"registration":          byWindow,
		"registration-existing": byWindow,
		"mail-throttled":        int((24*time.Hour + r8Bounds.throttledIntervalMn - 1) / r8Bounds.throttledIntervalMn),
	}
	t.Logf("наибольшее число писем адресату в сутки по верхним границам Р8: %v", want)

	cat, census, err := spec.Load(filepath.Join(root, filepath.FromSlash(catalogDir)))
	if err != nil {
		t.Fatalf("И14: каталог шаблонов %s не прочитан валидатором notify/spec: %v", catalogDir, err)
	}
	t.Logf("прочитано валидатором: шаблонов %d, файлов %d, блоков %d", census.Templates, census.Files, census.Blocks)
	if census.Templates != templatesInR3 {
		t.Fatalf("И14: в каталоге %s шаблонов %d, ожидалось %d (перечень Р3)", catalogDir, census.Templates, templatesInR3)
	}
	byName := map[string]spec.Template{}
	for _, tpl := range cat.Templates {
		byName[tpl.Name] = tpl
	}
	for name, min := range want {
		tpl, ok := byName[name]
		if !ok {
			t.Errorf("И14: шаблона %s в каталоге нет", name)
			continue
		}
		if got := perDayLimit(tpl); got < min {
			t.Errorf("И14: лимит шаблона %s на адресата в сутки %d меньше %d — наибольшего числа писем по границам Р8; "+
				"лимит отрезал бы письмо, пропущенное окном", name, got, min)
		}
	}
	inv, ok := byName["invite"]
	switch {
	case !ok:
		t.Errorf("И14: шаблона invite в каталоге нет")
	case perDayLimit(inv) != r8Bounds.inviteRecipientDay:
		t.Errorf("Р8: лимит шаблона invite на адресата в сутки %d, граница invite.recipient-per-day-all — %d (З19)",
			perDayLimit(inv), r8Bounds.inviteRecipientDay)
	}
}
