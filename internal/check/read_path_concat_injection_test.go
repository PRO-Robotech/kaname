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
	"errors"
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
	files, _, err := check.ReadPathGoFiles(root)
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

// --- #17: премиса пустого обхода доказана ИСПОЛНЕНИЕМ ------------------------
//
// Обе ветви отказа переехали к корню, который уже был параметром, и потому
// стали проверяемы синтетикой. Прежде они стояли в теле гейта, корень им
// приходил от своего модуля, и подать им дерево без предмета было НЕЧЕМ:
// ветви читались глазами и не исполнялись ни разу.

// readPathSynthRoot — синтетический корень: объявление предмета замера по своей
// координате плюс перечисленные файлы.
//
// Координата приводится к посадке тем же детектором, что и на боевом прогоне
// (`treeposture` снимает приставку платформы у самостоятельного клона), поэтому
// фикстура кладёт объявление ровно туда, откуда его возьмёт `ReadPathGoFiles`.
func readPathSynthRoot(t *testing.T, decl string, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	all := map[string]string{
		strings.TrimPrefix(check.FingerprintSourceRel, "services/iam/"): decl,
	}
	for rel, body := range files {
		all[rel] = body
	}
	for rel, body := range all {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatalf("фикстура не собрана: %v", err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatalf("фикстура не собрана: %v", err)
		}
	}
	return root
}

// TestReadPathGoFiles_EmptyTraversalIsRefused — обе премисы обхода, исполнением.
func TestReadPathGoFiles_EmptyTraversalIsRefused(t *testing.T) {
	t.Parallel()

	const decl = "package scalegrid\n\nconst (\n\tverdictDir = \"services/iam/internal/repo/kaname/pg/relverdict\"\n)\n"

	// ── КОНТРОЛЬ: каталог объявлен и непуст — обход даёт объём ───────────────
	//
	// Стоит первым: без него оба отказа ниже объяснялись бы обходом, который не
	// находит ничего никогда.
	files, dirs, err := check.ReadPathGoFiles(readPathSynthRoot(t, decl, map[string]string{
		"internal/repo/kaname/pg/relverdict/read.go":      "package relverdict\n",
		"internal/repo/kaname/pg/relverdict/read_test.go": "package relverdict\n",
	}))
	if err != nil {
		t.Fatalf("КОНТРОЛЬ: на дереве С предметом обход объявлен пустым: %v", err)
	}
	if len(dirs) != 1 || len(files) != 1 {
		t.Fatalf("КОНТРОЛЬ: каталогов %d, файлов %d — ожидалось по одному; проверочный "+
			"файл обязан вычитаться, иначе отказ ниже значил бы не то", len(dirs), len(files))
	}

	// ── ОСЬ 1: объявление ЕСТЬ, каталогов в нём НОЛЬ ─────────────────────────
	//
	// Утверждается ТЕКСТ отказа, а не только его вид. Обе премисы дают один
	// `ErrEmptyTraversal`, и на дереве без каталогов пусты ОБА множества —
	// значит проверка «отказ был» прошла бы и через вторую ветвь, оставив первую
	// недоказанной. Это выяснилось оглушением: снятая первая ветвь пробу НЕ
	// покраснила, и проба проходила по причине, к её предмету отношения не
	// имеющей.
	_, _, err = check.ReadPathGoFiles(readPathSynthRoot(t, "package scalegrid\n", nil))
	if !errors.Is(err, check.ErrEmptyTraversal) {
		t.Fatalf("объявление без каталогов не дало отказа: %v — объём гейта был бы выведен "+
			"из ничего, и «находок ноль» получено даром", err)
	}
	if !strings.Contains(err.Error(), check.FingerprintSourceRel) {
		t.Fatalf("отказ не называет ОБЪЯВЛЕНИЕ, в котором нет каталогов (%v) — читателя "+
			"пошлют искать пустой каталог там, где пусто само объявление", err)
	}

	// ── ОСЬ 2: каталог объявлен и СУЩЕСТВУЕТ, но не-тестовых .go в нём ноль ──
	//
	// Отличается от оси 1 ровно одним фактом: каталог есть. Без неё гейт зеленел
	// бы на каталоге, из которого предмет уехал, — самый частый вид слепоты.
	_, _, err = check.ReadPathGoFiles(readPathSynthRoot(t, decl, map[string]string{
		"internal/repo/kaname/pg/relverdict/read_test.go": "package relverdict\n",
	}))
	if !errors.Is(err, check.ErrEmptyTraversal) {
		t.Fatalf("каталог без не-тестовых .go не дал отказа: %v — молчание гейта означало бы "+
			"свойство, которого никто не проверял", err)
	}
	if !strings.Contains(err.Error(), "relverdict") {
		t.Fatalf("отказ не называет КАТАЛОГ, в котором нет предмета (%v) — две премисы "+
			"стали бы неразличимы, и снятие любой из них прошло бы молча", err)
	}

	t.Log("осей 3: контроль · объявление без каталогов · каталог без предмета")
}
