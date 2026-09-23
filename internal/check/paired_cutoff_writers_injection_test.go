// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// paired_cutoff_writers_injection_test.go — ИНЪЕКЦИЯ В ОБЕ СТОРОНЫ для приборов
// ПАРНОЙ ЗАПИСИ (задача kaname#313).
//
// Приборов на этой машинерии два — пара записей отсечки и пара «снятие сессии /
// отзыв семейства», — и склейку по вызову они делят. Поэтому оси здесь про
// САМУ МАШИНЕРИЮ, а предмет подаётся образцами.
//
// Каждая ось сверх исхода утверждает ПЕРЕПИСЬ: функций осмотрено ровно столько,
// сколько подано. Молчание на непрочитанном входе неотличимо от молчания на
// законном.
package check_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

var (
	injFirst  = regexp.MustCompile(`(?is)INTO\s+kaname\.first_rows\b`)
	injSecond = regexp.MustCompile(`(?is)INTO\s+kaname\.second_rows\b`)
)

// injSource — функция, делающая перечисленные действия своим оператором.
func injSource(name string, first, second bool) []byte {
	body := ""
	if first {
		body += "\t_, _ = ex.Exec(ctx, \"INSERT INTO kaname.first_rows (a) VALUES ($1)\")\n"
	}
	if second {
		body += "\t_, _ = ex.Exec(ctx, \"INSERT INTO kaname.second_rows (a) VALUES ($1)\")\n"
	}
	return []byte("package pg\n\nfunc " + name + "(ctx context.Context) error {\n" + body + "\treturn nil\n}\n")
}

func injScan(t *testing.T, srcs ...[]byte) ([]check.PairedWriteFunc, check.PairedWriteCensus) {
	t.Helper()
	var funcs []check.PairedWriteFunc
	var census check.PairedWriteCensus
	for i, src := range srcs {
		f, c, err := check.ScanPairedWrites("synthetic/f.go", src, injFirst, injSecond, map[string][2]bool{})
		if err != nil {
			t.Fatalf("разбор синтетики %d: %v", i, err)
		}
		if c.Funcs != 1 {
			t.Fatalf("вставка %d не долетела: функций осмотрено %d, подана 1 — "+
				"вердикт беспредметен", i, c.Funcs)
		}
		funcs = append(funcs, f...)
		census.Funcs += c.Funcs
		census.DeadCalls += c.DeadCalls
	}
	return funcs, census
}

// TestPairedWriteInjection_FirstWithoutSecondIsFound — дефект ловится.
func TestPairedWriteInjection_FirstWithoutSecondIsFound(t *testing.T) {
	t.Parallel()
	funcs, census := injScan(t, injSource("door", true, false))
	funcs = check.ResolvePairedWrites(funcs, &census)

	found := check.PairedWriteFindings(funcs)
	if len(found) != 1 {
		t.Fatalf("делающий ПЕРВОЕ без второго НЕ пойман: находок %d", len(found))
	}
	if found[0].Name != "door" {
		t.Errorf("находка названа именем %q", found[0].Name)
	}
}

// TestPairedWriteInjection_BothIsSilent — ЗАКОННЫЙ БЛИЗНЕЦ молчит.
//
// Отличается от дефекта РОВНО одним фактом: вторым оператором.
func TestPairedWriteInjection_BothIsSilent(t *testing.T) {
	t.Parallel()
	funcs, census := injScan(t, injSource("door", true, true))
	if !funcs[0].Second {
		t.Fatal("разбор не увидел второго действия — молчание ниже беспредметно")
	}
	funcs = check.ResolvePairedWrites(funcs, &census)
	if found := check.PairedWriteFindings(funcs); len(found) != 0 {
		t.Fatalf("гейт краснеет на ЗАКОННОМ: %+v", found)
	}
}

// TestPairedWriteInjection_SecondOnlyIsNotAFinding — делающий ТОЛЬКО второе
// находкой не является.
func TestPairedWriteInjection_SecondOnlyIsNotAFinding(t *testing.T) {
	t.Parallel()
	funcs, census := injScan(t, injSource("other", false, true))
	funcs = check.ResolvePairedWrites(funcs, &census)
	if found := check.PairedWriteFindings(funcs); len(found) != 0 {
		t.Fatalf("гейт нашёл находку у делающего только второе: %+v", found)
	}
}

// TestPairedWriteInjection_SecondThroughAReachableCallIsSeen — второе действие,
// сделанное ДОСТИЖИМЫМ вызовом, засчитывается.
func TestPairedWriteInjection_SecondThroughAReachableCallIsSeen(t *testing.T) {
	t.Parallel()
	door := []byte("package pg\n\nfunc door(ctx context.Context) error {\n" +
		"\t_, _ = ex.Exec(ctx, \"INSERT INTO kaname.first_rows (a) VALUES ($1)\")\n" +
		"\treturn helper(ctx)\n}\n")
	funcs, census := injScan(t, door, injSource("helper", false, true))

	// ДО склейки дверь читается делающей одно — иначе ось беспредметна.
	if before := check.PairedWriteFindings(funcs); len(before) != 1 {
		t.Fatalf("без склейки дверь обязана читаться делающей одно, находок %d", len(before))
	}
	funcs = check.ResolvePairedWrites(funcs, &census)
	if found := check.PairedWriteFindings(funcs); len(found) != 0 {
		t.Fatalf("достижимый вызов не засчитан: %+v", found)
	}
}

// TestPairedWriteInjection_SecondBehindADeadBranchIsStillAFinding — ОСЬ НА САМО
// ДОСТРАИВАНИЕ: второе действие, спрятанное за заведомо мёртвой ветвью,
// засчитываться НЕ должно.
//
// Без этой оси расширение, которым чинилась ложная находка, никем не
// сторожится. Широкая склейка именно здесь и была пробита: она давала ноль
// находок там, где дефект жив.
func TestPairedWriteInjection_SecondBehindADeadBranchIsStillAFinding(t *testing.T) {
	t.Parallel()
	door := []byte("package pg\n\nfunc door(ctx context.Context) error {\n" +
		"\t_, _ = ex.Exec(ctx, \"INSERT INTO kaname.first_rows (a) VALUES ($1)\")\n" +
		"\tif false {\n\t\treturn helper(ctx)\n\t}\n\treturn nil\n}\n")
	funcs, census := injScan(t, door, injSource("helper", false, true))
	funcs = check.ResolvePairedWrites(funcs, &census)

	if census.DeadCalls != 1 {
		t.Fatalf("вызовов в мёртвой ветви отброшено %d, подан 1 — обход мёртвых "+
			"ветвей не работает, и вердикт ниже беспредметен", census.DeadCalls)
	}
	found := check.PairedWriteFindings(funcs)
	if len(found) != 1 {
		t.Fatalf("дефект за МЁРТВОЙ ветвью НЕ пойман: находок %d — склейка идёт по "+
			"недостижимому вызову", len(found))
	}

	// ЗАКОННЫЙ БЛИЗНЕЦ той же оси: тот же вызов в ЖИВОЙ ветви засчитывается.
	live := []byte("package pg\n\nfunc door(ctx context.Context) error {\n" +
		"\t_, _ = ex.Exec(ctx, \"INSERT INTO kaname.first_rows (a) VALUES ($1)\")\n" +
		"\tif ok {\n\t\treturn helper(ctx)\n\t}\n\treturn nil\n}\n")
	lf, lc := injScan(t, live, injSource("helper", false, true))
	lf = check.ResolvePairedWrites(lf, &lc)
	if got := check.PairedWriteFindings(lf); len(got) != 0 {
		t.Fatalf("вызов в ЖИВОЙ ветви не засчитан: %+v — ось выше краснела бы на "+
			"разборе, отбрасывающем все ветви подряд", got)
	}
}

// TestPairedWriteInjection_AmbiguousNameDoesNotGlue — имя, объявленное в пакете
// не единожды, склейку НЕ даёт.
//
// Разбор без типов не знает, какой из одноимённых вызван; засчитывать любой
// значило бы засчитывать наугад — и терять находку о живом половинном снятии.
func TestPairedWriteInjection_AmbiguousNameDoesNotGlue(t *testing.T) {
	t.Parallel()
	door := []byte("package pg\n\nfunc door(ctx context.Context) error {\n" +
		"\t_, _ = ex.Exec(ctx, \"INSERT INTO kaname.first_rows (a) VALUES ($1)\")\n" +
		"\treturn helper(ctx)\n}\n")
	// Два ОДНОИМЁННЫХ helper в одном пакете: один делает второе, другой нет.
	funcs, census := injScan(t, door, injSource("helper", false, true), injSource("helper", false, false))
	funcs = check.ResolvePairedWrites(funcs, &census)

	if census.Ambiguous == 0 {
		t.Fatal("неоднозначных имён насчитано 0 — разбор не заметил двойного " +
			"объявления, и вердикт ниже беспредметен")
	}
	found := check.PairedWriteFindings(funcs)
	if len(found) == 0 {
		t.Fatal("склейка прошла по НЕОДНОЗНАЧНОМУ имени: гейт засчитал наугад")
	}
	if !strings.Contains(found[0].Name, "door") && !strings.Contains(found[0].Name, "helper") {
		t.Errorf("находка названа неожиданным именем %q", found[0].Name)
	}
}

// TestPairedWriteInjection_ForeignPackageDoesNotGlue — имя из ЧУЖОГО пакета
// склейку не даёт.
func TestPairedWriteInjection_ForeignPackageDoesNotGlue(t *testing.T) {
	t.Parallel()
	door := []byte("package pg\n\nfunc door(ctx context.Context) error {\n" +
		"\t_, _ = ex.Exec(ctx, \"INSERT INTO kaname.first_rows (a) VALUES ($1)\")\n" +
		"\treturn helper(ctx)\n}\n")
	foreign := []byte("package other\n\nfunc helper(ctx context.Context) error {\n" +
		"\t_, _ = ex.Exec(ctx, \"INSERT INTO kaname.second_rows (a) VALUES ($1)\")\n" +
		"\treturn nil\n}\n")
	funcs, census := injScan(t, door, foreign)
	funcs = check.ResolvePairedWrites(funcs, &census)

	if found := check.PairedWriteFindings(funcs); len(found) != 1 {
		t.Fatalf("склейка прошла через ЧУЖОЙ пакет: находок %d, ожидалась 1", len(found))
	}
}
