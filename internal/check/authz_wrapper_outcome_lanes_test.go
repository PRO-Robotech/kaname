// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// authz_wrapper_outcome_lanes_test.go — по всему прод-дереву своего модуля.
// Порт с монорепо, см. годок `authz_wrapper_outcome_lanes.go`.
package check_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// TestAuthzBoolWrapperIsNotCalledWhereAnOutcomeFormExists — имя сохранено
// дословно из монорепо.
func TestAuthzBoolWrapperIsNotCalledWhereAnOutcomeFormExists(t *testing.T) {
	t.Parallel()
	root, prefix := platformtree.RequireCorpus(t)
	if prefix != "" {
		root = root + "/" + prefix
	}

	all, err := treecorpus.Under(root)
	if err != nil {
		t.Fatalf("состав дерева: %v", err)
	}
	roots, err := check.ProdGoRoots(root, all)
	if err != nil {
		t.Fatalf("%v", err)
	}
	rep, err := check.ScanBoolWrapperCalls(root, roots, treecorpus.Under)
	if err != nil {
		t.Fatalf("%v", err)
	}

	owners := map[string]struct{}{}
	names := make([]string, 0, len(rep.Pairs))
	for _, p := range rep.Pairs {
		owners[p.PkgDir] = struct{}{}
		names = append(names, p.PkgDir+"."+p.BoolName+"→"+p.OutcomeForms())
	}
	sort.Strings(names)
	t.Logf("осмотрено: каталогов=%d (%s), файлов Go прочитано=%d (сгенерённых пропущено=%d), "+
		"импортов через точку=%d, пар «булева↔с исходом» выведено=%d в %d пакетах-владельцах [%s], "+
		"употреблений булевой половины из чужого пакета=%d",
		len(rep.Roots), strings.Join(rep.Roots, ", "), rep.Files, rep.Generated,
		rep.DotImports, len(rep.Pairs), len(owners), strings.Join(names, "; "), len(rep.Found))

	if len(rep.Roots) == 0 {
		t.Fatalf("предпосылка нарушена: каталогов с не-тестовым кодом Go не найдено — "+
			"состав дерева не прочитан, зелёное здесь не значит ничего (файлов %d)", rep.Files)
	}
	if rep.Files == 0 {
		t.Fatal("предпосылка нарушена: не прочитано ни одного файла Go")
	}
	if len(rep.Pairs) == 0 {
		t.Fatalf("предпосылка нарушена: ни одной пары «булева↔с исходом» в дереве не найдено — "+
			"соглашение об именовании (суффикс E / PlainE при возврате (bool, error)) сменилось; "+
			"пока это не выяснено, гейт не судит ничего (файлов прочитано %d)", rep.Files)
	}

	found := rep.Found
	sort.Slice(found, func(i, j int) bool {
		if found[i].File != found[j].File {
			return found[i].File < found[j].File
		}
		return found[i].Line < found[j].Line
	})
	for _, c := range found {
		t.Errorf("%s:%d — зовётся булева половина %s.%s, у которой В ТОМ ЖЕ ПАКЕТЕ есть парная "+
			"форма %s. Из булевой «хранилище прав не ответило» достать нельзя: отказ теряется "+
			"ВНУТРИ обёртки, и вызывающий читает недоступность как «не положено». Замена "+
			"drop-in: тот же порт, тот же вопрос, третий исход",
			c.File, c.Line, c.Pair.PkgDir, c.Pair.BoolName, c.Pair.OutcomeForms())
	}
}
