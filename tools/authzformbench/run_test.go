// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzformbench

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRunMatrix is the measurement itself.
//
// It is env-gated, and deliberately so: it starts containers and, at the upper end
// of the curve, writes hundreds of thousands of tuples. `go test ./...` must not
// pay for that by accident. It is NOT skipped for being slow when asked for — a
// benchmark that quietly declines to run is the "not executed reported as green"
// class this tree already has a name for.
//
//	AUTHZFORMBENCH=1 go test -C services/iam ./tools/authzformbench/ -run TestRunMatrix -v -timeout 4h
//
// Overrides (all optional):
//
//	AUTHZFORMBENCH_NS=10,100,1000,10000   the curve
//	AUTHZFORMBENCH_SUBJECTS=10            S
//	AUTHZFORMBENCH_FORMS=E-relational
//	AUTHZFORMBENCH_WRITE_REPEATS=5
//	AUTHZFORMBENCH_READ_REPEATS=20
//	AUTHZFORMBENCH_OUT=/path/report.txt   (default: stdout only)
func TestRunMatrix(t *testing.T) {
	if os.Getenv("AUTHZFORMBENCH") == "" {
		t.Skip("set AUTHZFORMBENCH=1 to run the measurement (it starts containers and writes many tuples)")
	}
	ctx := t.Context()
	stack, canon := bootForTest(ctx, t)

	cfg := DefaultConfig()
	if v := os.Getenv("AUTHZFORMBENCH_NS"); v != "" {
		cfg.Ns = parseInts(t, v)
	}
	if v := os.Getenv("AUTHZFORMBENCH_SUBJECTS"); v != "" {
		cfg.Subjects = parseInts(t, v)[0]
	}
	if v := os.Getenv("AUTHZFORMBENCH_WRITE_REPEATS"); v != "" {
		cfg.WriteRepeats = parseInts(t, v)[0]
	}
	if v := os.Getenv("AUTHZFORMBENCH_READ_REPEATS"); v != "" {
		cfg.ReadRepeats = parseInts(t, v)[0]
	}
	if v := os.Getenv("AUTHZFORMBENCH_FORMS"); v != "" {
		cfg.Forms = nil
		for _, f := range strings.Split(v, ",") {
			cfg.Forms = append(cfg.Forms, Form(strings.TrimSpace(f)))
		}
	}

	r := NewRunner(stack, cfg)

	// Здесь ИЗМЕРЯЛСЯ потолок пакетной проверки движка отношений — один раз, до
	// того как что-либо засекалось: отчёт обязан печатать то, что движок реально
	// принимает, а не то, что о нём говорит комментарий. Повод был не
	// педантический — дерево пинило движок в двух местах разными версиями, и
	// спрашивать оказалось дешевле, чем разрешать спор. Потолка нет вместе с
	// движком; часть страницы берётся из настройки и печатается в отчёте.
	//
	// Каноническая модель по-прежнему ЧИТАЕТСЯ, хотя ни одной модели авторизации
	// прибор больше не готовит: её отпечаток — часть провенанса. План вердикта
	// формы E компилируется из неё же (продуктовым `services/iam/internal/authzplan`), поэтому
	// «на какой модели снят замер» остаётся осмысленным вопросом.
	sum := sha256.Sum256([]byte(canon))
	modelPath, _, _ := ResolveCanonicalModel()
	prov := CollectProvenance(stack.Postgres, modelPath, hex.EncodeToString(sum[:])[:16])

	var cells []Cell
	for _, f := range cfg.Forms {
		for _, n := range cfg.Ns {
			spare := 1 + cfg.RelabelK
			sc := NewScenario(n, spare, cfg.Subjects, cfg.Role, cfg.Verbs)
			t.Logf("── %s N=%d (grant tuples predicted: %d)", f, n, ExpectedGrantTuples(f, sc))
			cells = append(cells, r.RunWrites(ctx, f, sc)...)
			cells = append(cells, r.RunReads(ctx, f, sc)...)
		}
	}

	var sb strings.Builder
	Report(&sb, prov, r.Notes, cfg, cells)
	fmt.Print(sb.String())
	if out := os.Getenv("AUTHZFORMBENCH_OUT"); out != "" {
		require.NoError(t, os.WriteFile(out, []byte(sb.String()), 0o600))
		t.Logf("report written to %s", out)
	}

	// Прогон не падает на отдельной неснятой ячейке — это скрыло бы остальную
	// таблицу. Он падает, когда не измерено НИЧЕГО: отчёт из одних исходов третьей
	// категории не должен читаться как состоявшийся замер.
	measured := 0
	for _, c := range cells {
		if c.Outcome == Measured {
			measured++
		}
	}
	require.Positive(t, measured, "не измерена ни одна ячейка — отчёт не является замером")
	t.Logf("cells: %d measured, %d other", measured, len(cells)-measured)
}

func parseInts(t *testing.T, s string) []int {
	t.Helper()
	var out []int
	for _, p := range strings.Split(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		require.NoError(t, err)
		out = append(out, n)
	}
	require.NotEmpty(t, out)
	return out
}
