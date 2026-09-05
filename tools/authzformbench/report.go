// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzformbench

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// Report renders the matrix as a CURVE — one block per operation, forms down, N
// across — because a table keyed by form alone would hide the only thing that
// matters: whether the lines cross, and where.
//
// Every cell prints its outcome. A "not-run" prints as such WITH its reason and is
// never rendered as a blank or a dash that a reader could mistake for a zero.
func Report(w io.Writer, prov Provenance, notes map[Form]string, cfg Config, cells []Cell) {
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }

	p("authzformbench — измерение стоимости реляционной формы выдачи прав\n")
	p("%s\n", strings.Repeat("=", 78))
	p("when         %s\n", prov.When)
	p("tree         %s\n", prov.TreeRev)
	p("machine      %s\n", prov.Machine)
	p("postgres     %s (своя БД прибора, СВОЙ контейнер)\n", prov.Postgres)
	p("каскад       %s (глубина %d, объявлена — не подразумевается)\n", prov.CascadeChain, prov.CascadeDepth)
	p("model        %s (sha256/16 %s)\n", prov.ModelPath, prov.ModelDigest)
	// ОТПЕЧАТОК ПРИБОРА — печатается ЗДЕСЬ, а не считается гейтом отдельно: гейт
	// свежести сверяет значение, полученное ТОЙ ЖЕ функцией. Вторая её реализация
	// разошлась бы с первой молча — и разошлась бы там, где обе печатают «совпало».
	p("%s", FingerprintHeader())
	// Здесь печатался ИЗМЕРЕННЫЙ потолок пакетной проверки движка — снят вместе
	// с движком. Строки нет вовсе, и это вернее прочерка: прочерк сообщал бы,
	// что величину спрашивали.
	p("shape        S=%d subjects, M=%d verbs %v, role=%q, K=%d\n",
		cfg.Subjects, len(cfg.Verbs), cfg.Verbs, cfg.Role, cfg.RelabelK)
	p("page         size=%d, partition=%d, parallel=%d\n",
		cfg.PageSize, cfg.Partition, cfg.Parallelism)
	p("repeats      writes=%d reads=%d (+1 discarded warm-up each)\n",
		cfg.WriteRepeats, cfg.ReadRepeats)
	p("\nформы под замером\n")
	for _, f := range cfg.Forms {
		p("  %-16s %s\n", f, notes[f])
	}
	p("\n  Форма ОДНА, и это надо прочитать как утверждение, а не как недосмотр: пять\n")
	p("  форм хранения во внешнем движке отношений сняты вместе с движком. Сравнивать\n")
	p("  не с чем; измеренное остаётся измеренным, и наклон по N — тоже.\n")

	// Арифметика, объявленная ДО прогона, печатается рядом с числами: против неё
	// сверяется измеренное, и ПОСТОЯНСТВО величины — такой же результат, как рост.
	// Ослабить утверждение после прогона нельзя — оно напечатано здесь же.
	p("\nобъявленная до прогона арифметика формы E (против неё сверяется измеренное)\n")
	p("  выдача            %s строк (привязка + субъекты + селектор), ПОСТОЯННА по N\n", "S+2")
	p("  структурное       N + Spare + 2 + M строк — величина, обязанная расти с N\n")
	for _, op := range opsAll {
		if n := ExpectedStatements(FormE, op); n >= 0 {
			p("  q(%-16s) %d\n", op, n)
		}
	}
	p("\ncell format  p50 (p95) ms, затем q=<SQL-стейтменты> i=<строк намерения>\n")
	p("             колонка e=<обращения к движку> снята вместе с движком, а не оставлена\n")
	p("             нулём: величина без производителя печаталась бы неотличимо от измеренной\n")
	p("             a page at N below the page size IS the whole set — read the item count\n\n")

	p("производители величины q (StmtSQL) — по месту снятия, с контролем в обе стороны\n")
	for _, s := range prov.StmtProducers {
		p("  %s\n", s)
	}
	if !allProducersOK(prov.StmtProducers) {
		p("  ВНИМАНИЕ: контроль пройден не везде ⇒ формулировка «на общем для форм уровне» СНЯТА;\n")
		p("  колонка q непрошедшего места не печатается вовсе — ни нулём, ни прочерком\n")
	}
	p("\n")

	ns := map[int]bool{}
	for _, c := range cells {
		ns[c.N] = true
	}
	nlist := make([]int, 0, len(ns))
	for n := range ns {
		nlist = append(nlist, n)
	}
	sort.Ints(nlist)

	idx := map[string]Cell{}
	for _, c := range cells {
		idx[key(c.Form, c.N, c.Op)] = c
	}

	for _, op := range []Op{OpGrant, OpRevoke, OpRelabel1, OpRelabelK, OpInlineGrant, OpInlineRevoke,
		OpCheck, OpPage50, OpPageFull, OpCascade} {
		p("── %s ──────────────────────────────────────────────\n", op)
		p("%-16s", "form")
		for _, n := range nlist {
			p("  N=%-24d", n)
		}
		p("\n")
		for _, f := range cfg.Forms {
			p("%-16s", f)
			for _, n := range nlist {
				c, ok := idx[key(f, n, op)]
				if !ok {
					p("  %-26s", "not-run: absent")
					continue
				}
				p("  %-26s", cellText(c))
			}
			p("\n")
		}
		p("\n")
	}

	p("── V-volume ── строки выдачи / логические байты ВСЕХ строк хранилища ─────\n")
	p("   структурное (строки зеркала и цепь предков) вынесено отдельной парой: счёт\n")
	p("   строк его вычитает, байты — нет. Асимметрия унаследована от снятой базы\n")
	p("   сравнения и названа здесь, чтобы её можно было вычесть, а не проглотить молча\n")
	p("%-16s", "form")
	for _, n := range nlist {
		p("  N=%-30d", n)
	}
	p("\n")
	for _, f := range cfg.Forms {
		p("%-16s", f)
		for _, n := range nlist {
			c, ok := idx[key(f, n, OpVolume)]
			if !ok || c.Outcome != Measured {
				txt := "not-run: absent"
				if ok {
					txt = string(c.Outcome) + ": " + short(c.Reason)
				}
				p("  %-32s", txt)
				continue
			}
			p("  %-32s", fmt.Sprintf("%d стр / %dБ (+%d стр структ)",
				c.GrantTotal, c.GrantBytes, c.StructuralRows))
		}
		p("\n")
	}
	p("\n")

	p("── откуда снята каждая ячейка ───────────────────────────────────────────\n")
	p("   мест снятия по-прежнему два — своя посадка прибора и продуктовые таблицы\n")
	p("   iam (прогон Ф5); таблица без этого признака выдавала бы за один прогон два\n")
	for _, f := range cfg.Forms {
		p("  %-16s %s\n", f, placeOf(cells, f))
	}
	p("\n")

	byOutcome := map[Outcome][]Cell{}
	for _, c := range cells {
		byOutcome[c.Outcome] = append(byOutcome[c.Outcome], c)
	}
	p("── категории исхода ячейки ──────────────────────────────────────────────\n")
	p("   Их было ЧЕТЫРЕ. «Отказ» был фактом о движке отношений, «неприменимо by\n")
	p("   construction» — самым содержательным результатом таблицы: у движка не могло\n")
	p("   быть общей транзакции с БД предмета выдачи. У формы E эта операция выразима,\n")
	p("   поэтому она ИЗМЕРЯЕТСЯ, и обе категории сняты вместе со своими производителями.\n")
	sum := 0
	for _, o := range []Outcome{Measured, NotRun} {
		p("  %-16s %d\n", o, len(byOutcome[o]))
		sum += len(byOutcome[o])
	}
	p("  %-16s %d (сумма категорий обязана равняться числу ячеек)\n", "ячеек всего", len(cells))
	if sum != len(cells) {
		p("  ВНИМАНИЕ: сумма категорий %d не сошлась с числом ячеек %d\n", sum, len(cells))
	}

	var notRun []Cell
	for _, c := range cells {
		if c.Outcome == NotRun {
			notRun = append(notRun, c)
		}
	}
	p("\n«не выполнилось»: %d of %d cells\n", len(notRun), len(cells))
	for _, c := range notRun {
		p("  %-16s N=%-7d %-16s %-9s %s\n", c.Form, c.N, c.Op, c.Outcome, c.Reason)
	}
	if len(notRun) == 0 {
		p("  (ни одной — каждая ячейка дала число)\n")
	}
}

func allProducersOK(ps []ProducerStatus) bool {
	for _, p := range ps {
		if !p.OK {
			return false
		}
	}
	return len(ps) > 0
}

func placeOf(cells []Cell, f Form) string {
	for _, c := range cells {
		if c.Form == f && c.Place != "" {
			return c.Place
		}
	}
	return "(не названо — ячеек этой формы в матрице нет)"
}

func cellText(c Cell) string {
	if c.Outcome != Measured {
		return string(c.Outcome) + ": " + short(c.Reason)
	}
	// The item count travels with the duration on purpose. A page cell without it
	// cannot say whether a form was quick or merely asked about fewer objects — at
	// N below the page size the page IS the whole set, and reading those columns as
	// "a 1000-object page" would be reading a number that was never measured.
	//
	// Печатаются только те колонки, у которых есть предмет. Непрошедший контроль
	// производителя даёт не ноль, а прочерк с причиной в блоке производителей: ноль
	// читался бы как измеренная величина.
	out := fmt.Sprintf("%.1f (%.1f)", c.P50, c.P95)
	switch {
	case c.StmtNote != "":
		out += " q=н/д"
	case c.StmtSQL > 0:
		out += fmt.Sprintf(" q=%d", c.StmtSQL)
	}
	if c.Tuples > 0 {
		out += fmt.Sprintf(" i=%d", c.Tuples)
	}
	if c.Parts > 0 {
		out += fmt.Sprintf(" ×%d", c.Parts)
	}
	return out
}

// short режет по РУНАМ, а не по байтам: причина исхода пишется по-русски, и рез
// по байту рвал бы её посередине символа — читатель получил бы «фо<мусор>» и
// решил, что сломан отчёт, а не что строка длинная.
func short(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	r := []rune(s)
	if len(r) > 60 {
		return string(r[:57]) + "..."
	}
	return s
}

func key(f Form, n int, op Op) string { return fmt.Sprintf("%s|%d|%s", f, n, op) }
