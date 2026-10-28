// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// unclassified_repo_err_journal_integration_test.go — отказ драйвера, который
// никто не классифицировал, на пути выдачи оставляет запись в журнале со
// СТРУКТУРОЙ отказа и без его текста (задача kaname#662).
//
// Класс отказа — тот, что дал 500 на стенде: строка выдачи несёт NULL там, где
// сканер ждёт строку, pgx отвечает `ScanArgError`, мост SQLSTATE его не узнаёт
// (это не `PgError`), и ветка по умолчанию `MapRepoErr` отвечает `internal error`.
// Сам дефект того столбца снят (COALESCE в abCols); здесь NULL ставится в
// другой столбец той же проекции — через настоящий драйвер, настоящую базу и
// настоящий use-case, а не подставным значением ошибки.
//
// Законный близнец — та же выдача без NULL: чтение проходит, записи нет.

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

const unclassifiedRepoErrMsg = "repository error is not classified"

func captureDefaultJournal(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func unclassifiedRecords(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &rec), "строка журнала не JSON: %q", line)
		if rec["msg"] == unclassifiedRepoErrMsg {
			out = append(out, rec)
		}
	}
	return out
}

func TestAB_Get_UnclassifiedDriverErrorIsJournaledWithoutItsText(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool := poolFromDSN(t, setupTestDB(t))
	repo := kanamepg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "uje-own")
	acc := seedAccountByOwner(t, ctx, pool, "acc-uje", owner)
	rules := domain.Rules{{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"}}}
	role := seedRulesRoleWithSelectors(t, ctx, repo, acc, "uje_a", rules)
	bid := insertAccountBinding(t, ctx, repo, owner, role, acc)
	uc := accessbindingapp.NewGetAccessBindingUseCase(repo)

	// Близнец: та же выдача читается, записи о неразобранном отказе нет.
	twin := captureDefaultJournal(t)
	_, err := uc.Execute(asUser(ctx, owner), bid)
	require.NoError(t, err, "близнец: целая строка выдачи читается")
	require.Empty(t, unclassifiedRecords(t, twin), "близнец: записи нет")

	// Ровно один факт против близнеца: столбец проекции несёт NULL. База
	// пробы своя (setupTestDB), правка схемы живёт и умирает с ней.
	_, err = pool.Exec(ctx, `ALTER TABLE kaname.access_bindings ALTER COLUMN granted_by_user_id DROP NOT NULL`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `UPDATE kaname.access_bindings SET granted_by_user_id = NULL WHERE id = $1`, string(bid))
	require.NoError(t, err)

	buf := captureDefaultJournal(t)
	_, err = uc.Execute(asUser(ctx, owner), bid)

	// Провод — прежний: Internal с фиксированным текстом.
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok, "ответ — статус gRPC: %v", err)
	assert.Equal(t, codes.Internal, st.Code())
	assert.Equal(t, "internal error", st.Message())

	recs := unclassifiedRecords(t, buf)
	require.Len(t, recs, 1, "одна запись о неразобранном отказе; журнал:\n%s", buf.String())
	rec := recs[0]
	assert.Equal(t, "ERROR", rec["level"])
	chain, _ := rec["err_chain"].(string)
	assert.Contains(t, chain, "pgx.ScanArgError", "структура называет тип отказа драйвера")
	site, _ := rec["site"].(string)
	assert.Contains(t, site, "GetAccessBindingUseCase", "запись называет место перевода")

	// Текст драйвера и данные арендатора в журнал не попадают.
	journal := buf.String()
	for _, leak := range []string{"cannot scan", "can't scan", "NULL", "granted_by_user_id",
		string(bid), string(owner), string(acc), string(role)} {
		assert.NotContains(t, journal, leak, "журнал несёт текст драйвера или данные арендатора")
	}
}
