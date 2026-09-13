// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// identity_growth_reader_injection_test.go — доказательство способности
// TestIdentityGrowthMetricsHaveANamedReader упасть и смолчать.
//
// Обе стороны гоняют ТУ ЖЕ функцию разбора, что и гейт по дереву, на
// синтетических документах.
//
// БЛИЗНЕЦ ПОДБИРАЕТСЯ ПОД КЛАСС, А НЕ ПОД РЕАЛИЗАЦИЮ. Близнец, занимающий строку
// целиком, подтверждал бы лишь уже написанное; хвостовая форма (выражение
// переписано на другой ряд, а снятый оставлен памяткой в конце строки) проходила
// мимо разбора в ОБЕИХ формах выражения. Поэтому близнецы ниже перечисляют
// КЛАСС: где комментарий, а где знак, комментария не открывающий, — и по каждой
// оси утверждаются обе стороны.
package check_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// TestIdentityGrowthReaderGateJudgesOnlyExecutableText — разбор способен упасть,
// и законная форма его не тревожит.
func TestIdentityGrowthReaderGateJudgesOnlyExecutableText(t *testing.T) {
	t.Parallel()

	// ── ИНЪЕКЦИЯ: ряд назван ТОЛЬКО в пояснении. Пояснение не срабатывает,
	// поэтому читателем не является.
	const proseOnly = "```yaml\n" +
		"- alert: SomethingElse\n" +
		"  expr: rate(kaname_authz_check_decisions_total[5m]) > 1\n" +
		"  annotations:\n" +
		"    summary: \"смотреть также kaname_identities_total\"\n" +
		"```\n"
	got := strings.Join(check.AlertExpressionsIn(proseOnly), "\n")
	if strings.Contains(got, "kaname_identities_total") {
		t.Fatalf("имя ряда из ПОЯСНЕНИЯ принято за читателя: %q", got)
	}
	// Законный близнец: ряд, действительно стоящий в выражении, читателем
	// является. Без этой половины предыдущее утверждение прошло бы на разборе,
	// не находящем вообще ничего.
	if !strings.Contains(got, "kaname_authz_check_decisions_total") {
		t.Fatalf("ряд из выражения правила не найден: %q — тогда молчание на пояснении "+
			"ничего не доказывает", got)
	}

	// ── Законный близнец: многострочное выражение. Правила службы пишут его
	// блоком, и разбор, читающий одну строку, потерял бы каждого такого
	// читателя — то есть объявил бы находкой исправное состояние.
	const multiline = "```yaml\n" +
		"- alert: Multi\n" +
		"  expr: |\n" +
		"    sum(rate(kaname_identities_total[1h]))\n" +
		"      / sum(rate(kaname_identity_ledger_samples_total[1h])) > 0.5\n" +
		"  for: 10m\n" +
		"```\n"
	multi := strings.Join(check.AlertExpressionsIn(multiline), "\n")
	for _, want := range []string{"kaname_identities_total", "kaname_identity_ledger_samples_total"} {
		if !strings.Contains(multi, want) {
			t.Fatalf("многострочное выражение прочитано не целиком: %q не найден в %q", want, multi)
		}
	}
	if strings.Contains(multi, "for: 10m") {
		t.Fatalf("разбор выражения перешагнул границу правила и забрал соседние поля: %q", multi)
	}

	// ── Законный близнец: комментарий ВНУТРИ выражения. Он объясняет отбор и
	// называет ряды; принять его за выражение значило бы зеленеть на правиле,
	// которое ничего не считает.
	const commented = "```yaml\n" +
		"- alert: Commented\n" +
		"  expr: |\n" +
		"    # раньше здесь стоял kaname_identities_total\n" +
		"    rate(kaname_lro_reconcile_runs_total[5m]) > 0\n" +
		"```\n"
	com := strings.Join(check.AlertExpressionsIn(commented), "\n")
	if strings.Contains(com, "kaname_identities_total") {
		t.Fatalf("ряд из комментария внутри выражения принят за читателя: %q", com)
	}
	if !strings.Contains(com, "kaname_lro_reconcile_runs_total") {
		t.Fatalf("исполняемая часть выражения потеряна вместе с комментарием: %q", com)
	}

	// ── ИНЪЕКЦИЯ, ради которой снятие и заведено: ХВОСТОВОЙ комментарий. Это и
	// есть подмена, которой снимают правило: выражение переписано на другой ряд,
	// а снятый оставлен памяткой в конце строки. Обе формы — однострочная и
	// блочная: починка одной оставила бы вторую дырой.
	for _, form := range []struct {
		name string
		doc  string
	}{
		{"однострочная", "```yaml\n- alert: TailInline\n  expr: increase(kaname_lro_inflight[1h]) > 100  # снято правило про kaname_identities_total\n```\n"},
		{"блочная", "```yaml\n- alert: TailBlock\n  expr: |\n    increase(kaname_lro_inflight[1h]) > 100  # снято правило про kaname_identities_total\n```\n"},
	} {
		tail := strings.Join(check.AlertExpressionsIn(form.doc), "\n")
		if strings.Contains(tail, "kaname_identities_total") {
			t.Errorf("%s форма: ряд из ХВОСТОВОГО комментария принят за читателя: %q",
				form.name, tail)
		}
		if !strings.Contains(tail, "kaname_lro_inflight") {
			t.Errorf("%s форма: исполняемая часть снята вместе с хвостовым комментарием: %q",
				form.name, tail)
		}
	}

	// ── Законный близнец: знак ВНУТРИ строкового литерала комментария не
	// открывает. Отрезать по нему значило бы вырезать половину исполняемого
	// выражения — то есть объявить находкой правило, которое читателем является.
	for _, quoted := range []struct {
		name string
		doc  string
	}{
		{"двойные кавычки", "```yaml\n- alert: Q1\n  expr: rate(kaname_identities_total{path=\"/a #b\"}[5m]) > 0\n```\n"},
		{"одинарные кавычки", "```yaml\n- alert: Q2\n  expr: rate(kaname_identities_total{path='/a #b'}[5m]) > 0\n```\n"},
		{"сырая строка", "```yaml\n- alert: Q3\n  expr: rate(kaname_identities_total{path=`/a #b`}[5m]) > 0\n```\n"},
		{"блочная форма", "```yaml\n- alert: Q4\n  expr: |\n    rate(kaname_identities_total{path=\"/a #b\"}[5m]) > 0\n```\n"},
	} {
		q := strings.Join(check.AlertExpressionsIn(quoted.doc), "\n")
		if !strings.Contains(q, "kaname_identities_total") {
			t.Errorf("%s: ряд из выражения потерян — знак внутри литерала принят за "+
				"комментарий: %q", quoted.name, q)
		}
		if !strings.Contains(q, "> 0") {
			t.Errorf("%s: хвост выражения отрезан по знаку внутри литерала: %q", quoted.name, q)
		}
	}

	// ── Законный близнец: знак, прижатый к предыдущему, комментария не
	// открывает ни в разметке, ни в языке выражений.
	const glued = "```yaml\n" +
		"- alert: Glued\n" +
		"  expr: rate(kaname_identities_total{ref=\"a#b\"}[5m]) > 0\n" +
		"```\n"
	gl := strings.Join(check.AlertExpressionsIn(glued), "\n")
	if !strings.Contains(gl, "kaname_identities_total") || !strings.Contains(gl, "> 0") {
		t.Fatalf("прижатый знак принят за начало комментария: %q", gl)
	}
}

// TestIdentityGrowthReaderGateReadsDeclarationsNotProse — имя ряда берётся из
// КОДА объявления, а не из его комментария.
//
// Файл коллектора подробно объясняет, почему рядов два, и называет их имена в
// прозе: разбор сырого текста засчитал бы объявлением упоминание в разборе — и
// снятый ряд продолжал бы считаться объявленным.
func TestIdentityGrowthReaderGateReadsDeclarationsNotProse(t *testing.T) {
	t.Parallel()
	names := check.IdentityGrowthMetricNamesIn(`
// раньше ряд назывался "kaname_identity_old_total"
const IdentitiesTotalMetric = "kaname_identities_total"
`)
	if len(names) != 1 || names[0] != "kaname_identities_total" {
		t.Fatalf("имена рядов прочитаны неверно: %v — имя из комментария принято за "+
			"объявление либо объявление потеряно", names)
	}

	// Положительный контроль: разбор ВООБЩЕ находит имена. Без него предыдущее
	// утверждение прошло бы на разборе, не находящем ничего.
	both := check.IdentityGrowthMetricNamesIn(`
const A = "kaname_identities_total"
const B = "kaname_identity_ledger_samples_total"
`)
	if len(both) != 2 {
		t.Fatalf("разбор не нашёл оба объявленных ряда: %v — тогда молчание на "+
			"комментарии ничего не доказывает", both)
	}

	// Чужой словарь рядом не засчитывается: приставка выводится из СВОЕГО
	// словаря, а не из формы имени вообще.
	foreign := check.IdentityGrowthMetricNamesIn(`const C = "kacho_identities_total"`)
	if len(foreign) != 0 {
		t.Errorf("ряд чужого словаря принят за свой: %v", foreign)
	}
}

// --- #17: премисы обеих сторон доказаны ИСПОЛНЕНИЕМ --------------------------

// TestJudgeIdentityGrowthReaders_EmptySideIsRefused — ни одна сторона не вправе
// прийти пустой молча.
//
// Прежде обе премисы стояли в теле гейта, входом им служили два файла, читаемых
// от корня своего модуля, и подать им пустую сторону было НЕЧЕМ: ветви отказа
// читались глазами и не исполнялись ни разу.
func TestJudgeIdentityGrowthReaders_EmptySideIsRefused(t *testing.T) {
	t.Parallel()

	const collector = "const IdentitiesTotalMetric = \"kaname_identities_total\"\n"
	const doc = "    - alert: IdentitiesStalled\n      expr: kaname_identities_total > 0\n"

	// ── КОНТРОЛЬ: обе стороны непусты, ряд читается — гейт молчит ────────────
	//
	// Стоит первым: без него оба отказа ниже объяснялись бы разбором, который не
	// находит ничего никогда.
	c, findings, err := check.JudgeIdentityGrowthReaders(collector, doc)
	if err != nil {
		t.Fatalf("КОНТРОЛЬ: на непустых сторонах предпосылка не выполнена: %v", err)
	}
	if len(c.Metrics) != 1 || c.Expressions != 1 {
		t.Fatalf("КОНТРОЛЬ: рядов %d, выражений %d — ожидалось по одному; разбор берёт не то, "+
			"и «пусто» ниже значило бы «разбор сломан»", len(c.Metrics), c.Expressions)
	}
	if len(findings) != 0 {
		t.Fatalf("КОНТРОЛЬ: у прочитанного ряда читатель ЕСТЬ, а гейт нашёл %d: %v",
			len(findings), findings)
	}

	// ── ОСЬ 1: сторона ОБЪЯВЛЕНИЯ пуста — отказ ─────────────────────────────
	if _, _, err := check.JudgeIdentityGrowthReaders("package metrics\n", doc); !errors.Is(err, check.ErrEmptyTraversal) {
		t.Fatalf("коллектор без рядов не дал отказа: %v — гейт судил бы пустоту, и "+
			"«читатель есть у всех» получено даром", err)
	}

	// ── ОСЬ 2: сторона ЧИТАТЕЛЯ пуста — отказ ДРУГОЙ ────────────────────────
	//
	// Отличается от оси 1 ровно одним фактом: какая сторона пуста. Слив их в
	// один текст, гейт посылал бы чинить разбор коллектора там, где ослеп
	// разбор правил.
	_, _, err = check.JudgeIdentityGrowthReaders(collector, "# правил нет\n")
	if !errors.Is(err, check.ErrEmptyTraversal) {
		t.Fatalf("документ без выражений не дал отказа: %v", err)
	}
	if !strings.Contains(err.Error(), "выражения правила") {
		t.Errorf("отказ не называет ОСЛЕПШУЮ сторону (%v) — починку будут искать не там", err)
	}

	// ── ОСЬ 3: обе стороны непусты, читателя НЕТ — находка ──────────────────
	//
	// Положительный контроль отрицания: без неё зелёное выше означало бы лишь
	// то, что гейт не находит ничего ни при каком входе.
	_, findings, err = check.JudgeIdentityGrowthReaders(collector, "      expr: up > 0\n")
	if err != nil {
		t.Fatalf("ось «читателя нет»: предпосылка не выполнена: %v", err)
	}
	if len(findings) != 1 || !strings.Contains(findings[0], "kaname_identities_total") {
		t.Fatalf("ряд без читателя не дал находки с его именем: %v", findings)
	}

	t.Log("осей 4: контроль · пуста сторона объявления · пуста сторона читателя · " +
		"читателя нет (отказы двух разных видов, находка одна)")
}
