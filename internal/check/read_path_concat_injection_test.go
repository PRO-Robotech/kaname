// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// read_path_concat_injection_test.go — ГЕЙТ СПОСОБЕН УПАСТЬ И СПОСОБЕН
// СМОЛЧАТЬ (задача #17, семейство `readpathconcat`).
//
// Инъекция идёт НАСТОЯЩИМ входом из дерева: файлы пути чтения копируются во
// временный корень, и в копию возвращается ТА САМАЯ форма, которая в дереве
// стояла. Синтетический литерал доказывал бы, что гейт понимает синтетику.
//
// Плечи парные, и второе не менее важно первого: рядом с возвращённым дефектом
// стоит ЗАКОННЫЙ близнец той же формы — склейка в проекции и склейка, названная
// SQL-комментарием у самого исправленного места. Гейт, краснеющий на них, был
// бы снят первым же ложным срабатыванием.
package check_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// concatOldReverseJoin — форма, стоявшая в обратных вопросах, дословно.
const concatOldReverseJoin = "\n  JOIN kaname.group_members gm ON g.subject IN " +
	"('group:' || gm.group_id, 'group:' || gm.group_id || '#member')"

// concatOldCensusPredicate — форма, стоявшая в приборе замера, дословно.
const concatOldCensusPredicate = "\t\t  WHERE bs.subject_type || ':' || bs.subject_id = ANY($1::text[])"

func TestReadPathConcatGateCanFailAndCanStaySilent(t *testing.T) {
	t.Parallel()

	root, _ := platformtree.RequireCorpus(t)
	resolve := func(rel string) (string, error) { return platformtree.PathUnder(root, rel) }
	files, _, err := check.ReadPathGoFiles(resolve)
	if err != nil {
		t.Fatalf("объём инъекции выведен быть не может: %v", err)
	}

	t.Run("молчит на дереве как есть — и ВСТРЕТИЛ законных близнецов", func(t *testing.T) {
		got, c := concatsOn(t, mirrorReadPath(t, files, nil))
		if len(got) != 0 {
			t.Fatalf("на дереве как есть гейт нашёл %d: %+v", len(got), got)
		}
		if c.ConcatsElsewhere == 0 {
			t.Fatal("гейт не встретил НИ ОДНОЙ склейки вне условия: его молчание о находках " +
				"ничего не стоит, потому что он не дочитал до законного близнеца")
		}
		t.Logf("плечо молчания: склеек вне условия встречено %d, находок 0", c.ConcatsElsewhere)
	})

	t.Run("краснеет на возвращённом развороте членства", func(t *testing.T) {
		target := pickReadPathFile(t, files, "relverdict/expand.go")
		got, _ := concatsOn(t, mirrorReadPath(t, files, map[string]func(string) string{
			target: func(s string) string {
				return strings.Replace(s, "  FROM ground g{{members_join}}",
					"  FROM ground g"+concatOldReverseJoin, 1)
			},
		}))
		assertNamesReadPathFile(t, got, target)
	})

	t.Run("краснеет на возвращённой склейке прибора замера", func(t *testing.T) {
		target := pickReadPathFile(t, files, "scalegrid/census.go")
		got, _ := concatsOn(t, mirrorReadPath(t, files, map[string]func(string) string{
			target: func(s string) string {
				i := strings.Index(s, "\t\t   JOIN (SELECT DISTINCT split_part(w")
				if i < 0 {
					t.Fatalf("в %s не нашлось разобранной формы отбора — инъекция не имеет предмета", target)
				}
				j := strings.Index(s[i:], "sp.s_id`")
				if j < 0 {
					t.Fatalf("в %s не нашлось конца разобранной формы отбора", target)
				}
				return s[:i] + concatOldCensusPredicate + s[i+j+len("sp.s_id"):]
			},
		}))
		assertNamesReadPathFile(t, got, target)
	})

	t.Run("молчит на SQL-комментарии, называющем прежнюю форму", func(t *testing.T) {
		target := pickReadPathFile(t, files, "relverdict/expand.go")
		got, _ := concatsOn(t, mirrorReadPath(t, files, map[string]func(string) string{
			target: func(s string) string {
				return strings.Replace(s, "  FROM ground g{{members_join}}",
					"  FROM ground g\n  -- прежде здесь стояло: ON g.subject IN "+
						"('group:' || gm.group_id, 'group:' || gm.group_id || '#member')"+
						"{{members_join}}", 1)
			},
		}))
		if len(got) != 0 {
			t.Fatalf("гейт покраснел на КОММЕНТАРИИ, объясняющем собственный запрет (%d находок: %+v).\n"+
				"Комментарий у исправленного места обязан называть прежнюю форму дословно — иначе "+
				"следующий читатель не поймёт, что запрещено", len(got), got)
		}
		t.Log("плечо молчания на объяснении запрета: находок 0")
	})
}

// concatsOn — находки и объём по зеркалу пути чтения.
func concatsOn(t *testing.T, files []check.ReadPathFile) ([]check.ConcatFinding, check.ConcatCensus) {
	t.Helper()
	got, c, err := check.CollectPredicateConcats(files, os.ReadFile)
	if err != nil {
		t.Fatalf("зеркало не прочитано: %v", err)
	}
	return got, c
}

// mirrorReadPath — копия пути чтения во временном каталоге с правкой по адресу.
//
// Правится КОПИЯ, а не дерево: гейт судит то же, что и на боевом прогоне, и
// ничего за собой не оставляет.
func mirrorReadPath(t *testing.T, files []check.ReadPathFile,
	patch map[string]func(string) string) []check.ReadPathFile {
	t.Helper()
	dst := t.TempDir()
	out := make([]check.ReadPathFile, 0, len(files))
	for _, f := range files {
		body, err := os.ReadFile(f.Abs)
		if err != nil {
			t.Fatalf("копирование %s: %v", f.Rel, err)
		}
		text := string(body)
		if fn, ok := patch[f.Rel]; ok {
			text = fn(text)
			if text == string(body) {
				t.Fatalf("инъекция в %s ничего не изменила: плечо проверяло бы неправленое дерево", f.Rel)
			}
		}
		abs := filepath.Join(dst, filepath.FromSlash(f.Rel))
		if err := os.MkdirAll(filepath.Dir(abs), 0o750); err != nil {
			t.Fatalf("каталог для %s: %v", f.Rel, err)
		}
		if err := os.WriteFile(abs, []byte(text), 0o600); err != nil {
			t.Fatalf("запись %s: %v", f.Rel, err)
		}
		out = append(out, check.ReadPathFile{Rel: f.Rel, Abs: abs})
	}
	return out
}

func pickReadPathFile(t *testing.T, files []check.ReadPathFile, suffix string) string {
	t.Helper()
	var got []string
	for _, f := range files {
		if strings.HasSuffix(f.Rel, suffix) {
			got = append(got, f.Rel)
		}
	}
	if len(got) != 1 {
		t.Fatalf("файлов с окончанием %q в объёме гейта %d, ожидался ровно один: "+
			"инъекция не знает, куда возвращать дефект", suffix, len(got))
	}
	return got[0]
}

func assertNamesReadPathFile(t *testing.T, got []check.ConcatFinding, want string) {
	t.Helper()
	if len(got) == 0 {
		t.Fatalf("возвращённый дефект в %s гейт НЕ нашёл: он зелен на том, ради чего написан", want)
	}
	for _, f := range got {
		if f.File == want {
			t.Logf("плечо падения: %s:%d — %s", f.File, f.Line, f.Operand)
			return
		}
	}
	t.Fatalf("гейт нашёл %d находок, но НИ ОДНА не называет %s: координата не та, и по сообщению "+
		"нельзя понять, что чинить. Находки: %+v", len(got), want, got)
}
