// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// mirror_catalog_condition_injection_test.go — доказательство, что гейт условия
// каталога СПОСОБЕН упасть и СПОСОБЕН смолчать (задача #17, семейство
// `mirrorcatalogcondition`).
//
// Инъекция зовёт ТУ ЖЕ сверку, что и гейт (`check.MirrorConditionReport`), и тот
// же разбор исходника — а не свои копии.
//
// # Законный близнец у КАЖДОЙ оси
//
// Рядом с каждой находкой стоит вход той же формы, на котором гейт обязан
// МОЛЧАТЬ: читатель зеркала, невводящий оператор и писатель, несущий условие.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// injMirrorReference — эталонная полоса: вводит строку и спрашивает каталог.
// Из неё ВЫВОДИТСЯ требование, поэтому она есть в каждой фикстуре ниже.
const injMirrorReference = `package resource_mirror

func emit() string {
	return ` + "`" + `INSERT INTO kaname.resource_mirror (object_type, object_id)
	        SELECT $1, $2 FROM kaname.catalog_resource c WHERE c.type = $1` + "`" + `
}
`

// injWriterWithCondition — законный писатель: вводит строку И спрашивает тот же
// каталог.
const injWriterWithCondition = `package other

func seed() string {
	return ` + "`" + `INSERT INTO kaname.resource_mirror (object_type) SELECT $1
	        FROM kaname.catalog_resource WHERE type = $1` + "`" + `
}
`

// injWriterWithoutCondition — ДЕФЕКТ: вводит строку, каталога не спрашивает.
// Отличается от близнеца выше РОВНО ОДНИМ фактом.
const injWriterWithoutCondition = `package other

func seed() string {
	return ` + "`" + `INSERT INTO kaname.resource_mirror (object_type) VALUES ($1)` + "`" + `
}
`

// injWriterPromisingInProse — ДЕФЕКТ ТОЙ ЖЕ ФОРМЫ: сверка обещана комментарием
// рядом, а в операторе её нет. Обещание условием не является — иначе писателю
// довольно было бы пообещать её словами.
const injWriterPromisingInProse = `package other

// seed спрашивает kaname.catalog_resource тем же условием, что эталонная полоса.
func seed() string {
	return ` + "`" + `INSERT INTO kaname.resource_mirror (object_type) VALUES ($1)` + "`" + `
}
`

// injReaderOnly — законный близнец: читатель зеркала. Читателей десятки, все
// законны, и гейт обязан на них молчать.
const injReaderOnly = `package other

func read() string {
	return ` + "`" + `SELECT object_type FROM kaname.resource_mirror WHERE object_id = $1` + "`" + `
}
`

// injNonIntroducing — законный близнец: правка и снятие строки. Предмет условия
// есть только у вводящих: правка существующей строки нового типа не заводит.
const injNonIntroducing = `package other

func touch() string {
	return ` + "`" + `UPDATE kaname.resource_mirror SET updated_at = now() WHERE object_id = $1` + "`" + `
}

func drop() string {
	return ` + "`" + `DELETE FROM kaname.resource_mirror WHERE object_id = $1` + "`" + `
}
`

// mirrorWritesFrom — записи из набора синтетических файлов.
func mirrorWritesFrom(t *testing.T, files map[string]string) []check.MirrorWrite {
	t.Helper()
	var out []check.MirrorWrite
	for rel, src := range files {
		w, _, err := check.MirrorWritesIn(rel, src)
		if err != nil {
			t.Fatalf("фикстура %s не разобрана: %v", rel, err)
		}
		for _, one := range w {
			one.File = rel
			out = append(out, one)
		}
	}
	return out
}

func TestMirrorConditionGate_Injection(t *testing.T) {
	t.Parallel()

	ref := check.MirrorReferenceLane + "emitter.go"
	empty := map[string]string{}

	// ── КОНТРОЛЬ: все полосы несут условие — гейт обязан молчать ────────────
	{
		rep := check.MirrorConditionReport(mirrorWritesFrom(t, map[string]string{
			ref:                       injMirrorReference,
			"internal/other/seed.go":  injWriterWithCondition,
			"internal/other/read.go":  injReaderOnly,
			"internal/other/touch.go": injNonIntroducing,
		}), empty)
		if len(rep.Findings) != 0 || len(rep.Stale) != 0 {
			t.Fatalf("КОНТРОЛЬ: на исправном входе гейт нашёл %d находок и %d просроченных "+
				"записей — он краснеет на исправном, и ни одна находка ниже ничего не "+
				"доказывает:\n  %s", len(rep.Findings), len(rep.Stale),
				strings.Join(append(rep.Findings, rep.Stale...), "\n  "))
		}
		if rep.Lanes != 2 || rep.Carriers != 2 {
			t.Fatalf("КОНТРОЛЬ: полос %d, несущих %d — читатель и невводящие операторы зачтены "+
				"полосами либо эталон не опознан", rep.Lanes, rep.Carriers)
		}
		if len(rep.Required) != 1 || rep.Required[0] != "kaname.catalog_resource" {
			t.Fatalf("условие выведено из эталона неверно: %v", rep.Required)
		}
		t.Logf("контроль: полос %d, несут %d, условие %v, находок 0",
			rep.Lanes, rep.Carriers, rep.Required)
	}

	// ── ИНЪЕКЦИЯ: писатель обходит условие ─────────────────────────────────
	for name, src := range map[string]string{
		"условия нет вовсе":           injWriterWithoutCondition,
		"сверка обещана комментарием": injWriterPromisingInProse,
	} {
		rep := check.MirrorConditionReport(mirrorWritesFrom(t, map[string]string{
			ref:                      injMirrorReference,
			"internal/other/seed.go": src,
		}), empty)
		if len(rep.Findings) != 1 {
			t.Fatalf("ось «%s»: ожидалась 1 находка, получено %d:\n  %s",
				name, len(rep.Findings), strings.Join(rep.Findings, "\n  "))
		}
		for _, want := range []string{"internal/other/seed.go", "kaname.catalog_resource"} {
			if !strings.Contains(rep.Findings[0], want) {
				t.Errorf("ось «%s»: находка не называет %q: %s", name, want, rep.Findings[0])
			}
		}
		t.Logf("инъекция «%s»: 1 находка с координатой", name)
	}

	// ── ВЕДОМОСТЬ: гасит названного писателя и ИСТЕКАЕТ сама ───────────────
	{
		key := "internal/other/seed.go::seed"
		writes := mirrorWritesFrom(t, map[string]string{
			ref:                      injMirrorReference,
			"internal/other/seed.go": injWriterWithoutCondition,
		})
		rep := check.MirrorConditionReport(writes, map[string]string{key: "причина названа"})
		if len(rep.Findings) != 0 || rep.Exempt != 1 || len(rep.Stale) != 0 {
			t.Fatalf("ведомость не погасила названного писателя: находок %d, погашено %d, "+
				"просрочено %d", len(rep.Findings), rep.Exempt, len(rep.Stale))
		}
		// Запись БЕЗ причины не гасит — иначе следующий читатель либо снимет её
		// как непонятную, либо оставит навсегда, не зная предмета.
		bare := check.MirrorConditionReport(writes, map[string]string{key: "  "})
		if len(bare.Findings) != 1 || len(bare.Stale) != 1 {
			t.Fatalf("запись БЕЗ причины погасила писателя: находок %d, просрочено %d",
				len(bare.Findings), len(bare.Stale))
		}
		// Запись, которой больше нечего исключать, — НАХОДКА.
		fixed := mirrorWritesFrom(t, map[string]string{
			ref:                      injMirrorReference,
			"internal/other/seed.go": injWriterWithCondition,
		})
		expired := check.MirrorConditionReport(fixed, map[string]string{key: "причина названа"})
		if len(expired.Stale) != 1 || !strings.Contains(expired.Stale[0], key) {
			t.Fatalf("запись без предмета не названа просроченной: %v", expired.Stale)
		}
		t.Log("ведомость: гасит с причиной · не гасит без причины · истекает сама")
	}

	// ── ЭТАЛОН ПРОПАЛ — отказ, а не молчание ───────────────────────────────
	//
	// Переедет каталог эталона — сверять «тем же условием» станет не с чем, и
	// молчание означало бы, что гейт умер вместе с координатой.
	{
		rep := check.MirrorConditionReport(mirrorWritesFrom(t, map[string]string{
			"internal/other/seed.go": injWriterWithCondition,
		}), empty)
		if !rep.ReferenceMissing {
			t.Fatal("отсутствие эталонной полосы не объявлено — гейт сверял бы с пустым " +
				"условием и молчал бы на всех полосах сразу")
		}
		t.Log("ось «эталон пропал»: объявлен отказ, а не молчание")
	}

	// ── ПУСТОЙ ВХОД: полос ноль ────────────────────────────────────────────
	{
		rep := check.MirrorConditionReport(nil, empty)
		if rep.Lanes != 0 || !rep.ReferenceMissing {
			t.Fatalf("на пустом входе полос %d, эталон отсутствует=%v — предпосылки гейта "+
				"перестали бы отличать «нечего судить» от «всё в порядке»",
				rep.Lanes, rep.ReferenceMissing)
		}
	}
}
