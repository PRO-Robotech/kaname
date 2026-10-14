// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// issue_ref_prefix_test.go — держатель задачи kaname#387: в дереве нет ссылки
// `#<N>` без префикса с номером, который задачей службы быть не может.
//
// Предмет, форма ссылки и граница утверждения — в шапке `issue_ref_prefix.go`.
// Способность падать и молчать доказана инъекцией —
// `issue_ref_prefix_injection_test.go`.
//
// Обход — по ИНДЕКСУ git, а не по диску: чтение диска взяло бы игнорируемое
// (каталоги сборки, node_modules сайта документации), и гейт краснел бы у того,
// кто собрал.
package check_test

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

func TestBareIssueRefsNameTheirRepository(t *testing.T) {
	t.Parallel()
	root := platformtree.Require(t)
	out, err := exec.Command("git", "-C", root, "ls-files", "-z").Output()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: индекс git не прочитан: %v", err)
	}
	var rels []string
	for _, p := range strings.Split(string(out), "\x00") {
		if p != "" {
			rels = append(rels, p)
		}
	}

	findings, census, err := check.AuditBareIssueRefs(root, rels, check.KanameNumberCeiling)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	t.Logf("потолок #%d · %s · находок %d", check.KanameNumberCeiling, census, len(findings))

	if census.Read == 0 || census.Bare == 0 {
		t.Fatalf("прочитано файлов %d, голых ссылок %d — «находок ноль» здесь означало бы "+
			"«ничего не прочитал»: в дереве законно живут ссылки на задачи службы", census.Read, census.Bare)
	}
	for _, e := range check.IssueRefExclusions() {
		if census.Excluded[e.Name] == 0 {
			t.Errorf("исключение %q не исключило ни одной ссылки выше потолка — ему больше нечего "+
				"прощать (заведено потому, что %s). Снимите исключение: оставленное, оно слепая зона",
				e.Name, e.Why)
		}
	}
	for _, a := range check.IssueRefAllowances() {
		if census.Allowed[check.AllowanceKey(a)] == 0 {
			t.Errorf("позволение %s не встретило своего номера — вход, ради которого оно заведено "+
				"(%s), ушёл. Снимите позволение", check.AllowanceKey(a), a.Why)
		}
	}
	for _, f := range findings {
		t.Errorf("%s\nНомер выше потолка задач службы (#%d), значит это задача ДРУГОГО репозитория, "+
			"а без префикса GitHub ищет её здесь и отвечает 404. Напишите `kacho#%d` (монорепо), "+
			"`kacho-workspace#%d` (воркспейс) или `kacho-iam#%d` (трекер до монорепо) — по референту. "+
			"Задача службы новее потолка пишется `kaname#%d`",
			f, check.KanameNumberCeiling, f.Number, f.Number, f.Number, f.Number)
	}
}
