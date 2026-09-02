// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// producibility_model_test.go — ПРЕДПОСЫЛКА предиката производимости, а не его
// свойство.
//
// `Produces` держит порядок ярусов литералом (`roleTierCascade`), и литерал
// пережил бы правку модели прав молча: обе стороны отвечают одинаково на входе,
// где они совпадают. Поэтому порядок сверяется с ОБЪЯВЛЕНИЕМ модели —
// `viewer: … or editor` и `editor: … or admin`, — а не с памятью автора.
//
// Перепись печатается всегда: «ноль расхождений» обязано быть отличимо от «ноль
// прочитанных типов».
package roleexport

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// modelPath — канон модели прав. Отсюда же порождается конфигурация модели, то
// есть это ИСТОЧНИК, а не его копия.
const modelPath = "../../../../../proto/kacho/cloud/iam/v1/fga_model.fga"

var (
	typeLineRe     = regexp.MustCompile(`^type\s+([a-z0-9_]+)\s*$`)
	relationLineRe = regexp.MustCompile(`^\s+define\s+([a-z0-9_]+)\s*:\s*(.*)$`)
)

// TestTierCascadeMatchesTheModel — каскад ярусов объявлен моделью именно так.
func TestTierCascadeMatchesTheModel(t *testing.T) {
	data, err := os.ReadFile(modelPath)
	if err != nil {
		t.Fatalf("канон модели прав не прочитан: %v", err)
	}

	type block struct{ relations map[string]string }
	types := map[string]*block{}
	var current *block
	for _, line := range strings.Split(string(data), "\n") {
		if m := typeLineRe.FindStringSubmatch(line); m != nil {
			current = &block{relations: map[string]string{}}
			types[m[1]] = current
			continue
		}
		if current == nil {
			continue
		}
		if m := relationLineRe.FindStringSubmatch(line); m != nil {
			current.relations[m[1]] = m[2]
		}
	}
	if len(types) == 0 {
		t.Fatal("в каноне модели не прочитано ни одного типа — вердикт был бы " +
			"свойством разборщика, а не модели")
	}

	verbBearing, checked, faults := 0, 0, 0
	for name, b := range types {
		hasVerb := false
		for rel := range b.relations {
			if strings.HasPrefix(rel, "v_") {
				hasVerb = true
				break
			}
		}
		if !hasVerb {
			continue
		}
		verbBearing++
		viewer, okV := b.relations["viewer"]
		editor, okE := b.relations["editor"]
		if !okV || !okE {
			// Тип с глаголами, но без пары ярусов — не нарушение каскада, а
			// другой предмет (его ярусы объявлены иначе). Считаем отдельно.
			continue
		}
		checked++
		if !strings.Contains(viewer, "or editor") {
			faults++
			t.Errorf("тип %q: `viewer` не наследует `editor` (%q) — каскад "+
				"`admin ⊇ editor ⊇ viewer`, на который опирается Produces, снят", name, viewer)
		}
		if !strings.Contains(editor, "or admin") {
			faults++
			t.Errorf("тип %q: `editor` не наследует `admin` (%q) — тот же каскад", name, editor)
		}
	}

	if checked == 0 {
		t.Fatal("ни у одного глагольного типа не прочитана пара ярусов: " +
			"сверять каскад не с чем")
	}
	// Порядок литерала — то, ради чего сверка и написана.
	want := []string{"viewer", "editor", "admin"}
	if len(roleTierCascade) != len(want) {
		t.Fatalf("каскад объявлен %d ярусами, модель знает %d", len(roleTierCascade), len(want))
	}
	for i := range want {
		if roleTierCascade[i] != want[i] {
			t.Fatalf("порядок каскада разошёлся с моделью: %v против %v", roleTierCascade, want)
		}
	}
	t.Logf("перепись: типов в каноне %d · глагольных %d · с парой ярусов %d · расхождений %d",
		len(types), verbBearing, checked, faults)
}

// TestTierRankRefusesANonTier — имя, ярусом не являющееся, ярусом не считается.
//
// Без этого `Produces` принял бы `system_admin` за ярус по одному лишь суффиксу
// и объявил бы производимым ровно то, ради отказа на чём написан весь предикат.
func TestTierRankRefusesANonTier(t *testing.T) {
	for _, name := range []string{"system_admin", "system_viewer", "v_get", "", "owner"} {
		if _, ok := tierRank(name); ok {
			t.Errorf("%q принято за ярус правила роли", name)
		}
	}
	for i, name := range roleTierCascade {
		rank, ok := tierRank(name)
		if !ok || rank != i {
			t.Errorf("ярус %q не опознан либо получил место %d вместо %d", name, rank, i)
		}
	}
}
