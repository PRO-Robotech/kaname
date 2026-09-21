// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// paired_cutoff_writers_injection_test.go — ИНЪЕКЦИЯ В ОБЕ СТОРОНЫ для гейта
// «писатель одной записи отсечки из двух» (задача kaname#313).
//
// Каждая ось сверх исхода утверждает ПЕРЕПИСЬ: писателей осмотрено ровно
// столько, сколько подано. Молчание на непрочитанном входе неотличимо от
// молчания на законном, и первая редакция соседнего гейта на этом уже
// поймалась.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// pairedWriterSource — писатель, кладущий записи из `tables`. Оси отличаются
// РОВНО составом этого перечня.
func pairedWriterSource(name string, tables ...string) []byte {
	body := ""
	for _, t := range tables {
		body += "\t_, _ = r.pool.Exec(ctx, \"INSERT INTO kaname." + t + " (user_id) VALUES ($1)\")\n"
	}
	return []byte("package pg\n\nfunc (r *Repo) " + name + "(ctx context.Context) error {\n" +
		body + "\treturn nil\n}\n")
}

func scanPaired(t *testing.T, src []byte, wantWriters int) []check.RevocationWriter {
	t.Helper()
	w, c, err := check.ScanRevocationWriters("synthetic/p.go", src, map[string]string{})
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	if c.Writers != wantWriters {
		t.Fatalf("вставка не долетела: писателей осмотрено %d, подано %d — "+
			"вердикт беспредметен", c.Writers, wantWriters)
	}
	return w
}

// TestPairedCutoffInjection_OneOfTwoIsFound — писатель ОДНОЙ записи ловится.
func TestPairedCutoffInjection_OneOfTwoIsFound(t *testing.T) {
	t.Parallel()
	w := scanPaired(t, pairedWriterSource("UpsertCutoff", pairedCutoffFirst), 1)

	found := check.WritersOfOneCutoffWithoutTheOther(w, pairedCutoffFirst, pairedCutoffSecond)
	if len(found) != 1 {
		t.Fatalf("писатель одной записи НЕ пойман: находок %d", len(found))
	}
	if found[0].Missing != pairedCutoffSecond {
		t.Errorf("находка называет недостающей %q, а не %q", found[0].Missing, pairedCutoffSecond)
	}
	if found[0].Writer.Name != "UpsertCutoff" {
		t.Errorf("находка названа именем %q", found[0].Writer.Name)
	}
}

// TestPairedCutoffInjection_BothIsSilent — ЗАКОННЫЙ БЛИЗНЕЦ молчит.
//
// Отличается от дефекта РОВНО одним фактом: во множестве появилась вторая
// запись.
func TestPairedCutoffInjection_BothIsSilent(t *testing.T) {
	t.Parallel()
	w := scanPaired(t, pairedWriterSource("UpsertCutoff", pairedCutoffFirst, pairedCutoffSecond), 1)

	if got := len(w[0].Tables); got != 2 {
		t.Fatalf("разбор увидел %d записи(ей) из 2 — молчание ниже ничего не доказывает: %v",
			got, w[0].Tables)
	}
	if found := check.WritersOfOneCutoffWithoutTheOther(w, pairedCutoffFirst, pairedCutoffSecond); len(found) != 0 {
		t.Fatalf("гейт краснеет на ЗАКОННОМ писателе обеих записей: %+v", found)
	}
}

// TestPairedCutoffInjection_SecondOnlyIsNotAFinding — писатель ТОЛЬКО второй
// записи находкой не является.
//
// Ось отдельная: схемные писатели второй записи (снятие клиента, деактивация
// владельца) первую не пишут и писать не должны. Гейт, краснеющий на них,
// требовал бы неверного.
func TestPairedCutoffInjection_SecondOnlyIsNotAFinding(t *testing.T) {
	t.Parallel()
	w := scanPaired(t, pairedWriterSource("CutMinted", pairedCutoffSecond), 1)

	if found := check.WritersOfOneCutoffWithoutTheOther(w, pairedCutoffFirst, pairedCutoffSecond); len(found) != 0 {
		t.Fatalf("гейт нашёл находку у писателя ТОЛЬКО второй записи: %+v", found)
	}
}

// TestPairedCutoffInjection_SecondRecordThroughACallIsSeen — вторая запись,
// положенная ВЫЗОВОМ помощника, засчитывается.
//
// Без этой оси гейт даёт ЛОЖНУЮ находку на собственной двери — она кладёт
// вторую запись именно вызовом. Измерено: первая редакция гейта так и сделала.
func TestPairedCutoffInjection_SecondRecordThroughACallIsSeen(t *testing.T) {
	t.Parallel()
	door := []byte("package pg\n\n" +
		"func upsertSubjectCutoff(ctx context.Context) error {\n" +
		"\t_, _ = ex.Exec(ctx, \"INSERT INTO kaname." + pairedCutoffFirst + " (user_id) VALUES ($1)\")\n" +
		"\treturn upsertMintedCutoff(ctx)\n}\n")
	helper := []byte("package pg\n\n" +
		"func upsertMintedCutoff(ctx context.Context) error {\n" +
		"\t_, _ = ex.Exec(ctx, \"INSERT INTO kaname." + pairedCutoffSecond + " (subject) VALUES ($1)\")\n" +
		"\treturn nil\n}\n")

	var writers []check.RevocationWriter
	for _, src := range [][]byte{door, helper} {
		w, c, err := check.ScanRevocationWriters("synthetic/x.go", src, map[string]string{})
		if err != nil {
			t.Fatalf("разбор: %v", err)
		}
		if c.Writers != 1 {
			t.Fatalf("вставка не долетела: писателей осмотрено %d, подан 1", c.Writers)
		}
		writers = append(writers, w...)
	}

	// ДО достраивания дверь читается писателем ОДНОЙ записи — это и есть
	// ложная находка, ради которой достраивание заведено.
	if before := check.WritersOfOneCutoffWithoutTheOther(writers, pairedCutoffFirst, pairedCutoffSecond); len(before) != 1 {
		t.Fatalf("ось беспредметна: без достраивания дверь обязана читаться писателем "+
			"одной записи, находок %d", len(before))
	}

	writers = check.PropagateTablesThroughCalls(writers)
	if found := check.WritersOfOneCutoffWithoutTheOther(writers, pairedCutoffFirst, pairedCutoffSecond); len(found) != 0 {
		t.Fatalf("после достраивания дверь всё ещё читается писателем одной записи: %+v", found)
	}
}

// TestPairedCutoffInjection_ForeignTableIsNotTheSubject — посторонняя запись
// отсечки предметом ЭТОЙ пары не является.
func TestPairedCutoffInjection_ForeignTableIsNotTheSubject(t *testing.T) {
	t.Parallel()
	w := scanPaired(t, pairedWriterSource("RevokeOne", "session_revocations"), 1)

	if found := check.WritersOfOneCutoffWithoutTheOther(w, pairedCutoffFirst, pairedCutoffSecond); len(found) != 0 {
		t.Fatalf("гейт расползся на постороннюю запись отсечки: %+v", found)
	}
	if !strings.Contains(strings.Join(w[0].Tables, ","), "session_revocations") {
		t.Fatalf("вход не прочитан: таблицы %v", w[0].Tables)
	}
}
