// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// scalegrid_seeder_integration_test.go — ПОСТРОЧНАЯ СВЕРКА ПОСЕВЩИКА С ПРОИЗВОДИТЕЛЕМ.
//
// # Зачем проба вообще существует
//
// Посевщик прибора порядков (`pg/scalegrid`) НЕ идёт через производителя
// зеркала: он подаёт те же стейтменты пачками, чтобы миллион объектов сел за
// сто секунд вместо семи минут. Цена решения — он перестаёт быть тем же путём,
// и потому обязан сам удовлетворять инвариантам, которые производитель держал
// за него.
//
// Гейт дерева `TestCensusFixturesSeedThroughTheProducer` этого не проверяет и
// проверить не может: его предикат обходит `services/iam/**_test.go`, а
// посевщик — не тестовый файл. Значит МОЛЧАНИЕ гейта эквивалентности не
// доказывает. Доказывает её только эта проба.
//
// # Что сверяется и чего сверка НЕ утверждает
//
// Два пути сажают ОДИН И ТОТ ЖЕ набор в ДВЕ РАЗНЫЕ базы, после чего обе таблицы
// вычитываются целиком, по порядку ключа, и сравниваются по всем колонкам,
// КРОМЕ `updated_at`. Исключение названо, а не умолчано: колонка заполняется
// `now()`, то есть временем НАЧАЛА транзакции, и у двух разных транзакций она
// различна by construction — сравнивать её значило бы требовать совпадения
// часов. Что она непуста, проба утверждает отдельно.
//
// Сверка НЕ утверждает, что пути эквивалентны на ПОВТОРНОЙ подаче: производитель
// читает `RowsAffected` и ветвится, пачка ветвиться не может. Посевщик годится
// для посева свежего набора и ни для чего больше — это записано и у него в шапке.

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/resource_mirror"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/scalegrid"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
)

// seederParityObjects — размер малой точки сверки.
//
// Тысяча, а не десяток: приёмка называет N = 10³ именно потому, что на десятке
// пачка не заполняется ни разу и конвейерный путь не исполняется вовсе — сверка
// доказывала бы свойство того кода, который на замере работать не будет.
const seederParityObjects = 1000

// parityChain — цепь предков, одна на все объекты набора.
//
// Типы предков приезжают словарём МОДЕЛИ — так их шлёт владелец ресурса.
var parityChain = []string{"registry_registry:reg-1", "project:prj-1", "account:acc-1"}

// parityCatalogType — тип объекта словарём КАТАЛОГА: им назван `resource_mirror.object_type`.
const parityCatalogType = "registry.repositories"

// mirrorRow / edgeRow — строки в том виде, в каком их сравнивают.
type mirrorRow struct {
	objectType, objectID      string
	parentProject, parentAcct string
	labels                    string
	sourceVersion             string
	updatedAtSet              bool
}

type edgeRow struct {
	objectType, objectID string
	parentType, parentID string
	depth                int
	sourceVersion        string
	updatedAtSet         bool
}

// TestScaleGridSeeder_RowForRowMatchesTheProducer — сверка (2) решения R7-1-01.
func TestScaleGridSeeder_RowForRowMatchesTheProducer(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	ctx := context.Background()

	byProducer := openParityDB(t, ctx)
	bySeeder := openParityDB(t, ctx)

	// ── путь 1: производитель, по объекту за раз ─────────────────────────────
	for _, row := range parityRows() {
		if _, err := resource_mirror.UpsertTx(ctx, byProducer, resource_mirror.Row{
			ObjectType:      row.ObjectType,
			ObjectID:        row.ObjectID,
			ParentProjectID: row.ParentProjectID,
			ParentAccountID: row.ParentAccountID,
			Labels:          row.Labels,
			ParentChain:     row.ParentChain,
		}); err != nil {
			t.Fatalf("производитель на объекте %q: %v", row.ObjectID, err)
		}
	}

	// ── путь 2: посевщик, пачками ────────────────────────────────────────────
	s := scalegrid.NewSeeder(bySeeder)
	for _, row := range parityRows() {
		if err := s.Queue(ctx, row); err != nil {
			t.Fatalf("посевщик на объекте %q: %v", row.ObjectID, err)
		}
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatalf("посевщик, отправка остатка: %v", err)
	}

	// Свойство КОДА, а не машины: пообъектного обмена нет.
	//
	// Стейтментов на объект — 3 + длина ЕГО цепи, а не константа: у листа три
	// предка, у его деда один. Ожидание считается ПО НАБОРУ, потому что
	// константа здесь была бы верна лишь для однородной цепи — и первая
	// редакция этой пробы на ней и упала, объявив расхождением собственную
	// арифметику.
	objects := int64(len(parityRows()))
	var wantStatements int64
	for _, r := range parityRows() {
		wantStatements += int64(3 + len(r.ParentChain))
	}
	maxExchanges := (objects+scalegrid.BatchObjects-1)/scalegrid.BatchObjects + 1
	t.Logf("посевщик: объектов %d, стейтментов %d, обменов с БД %d (предел по сценарию R7-1-01: %d)",
		s.Objects(), s.Statements(), s.Exchanges(), maxExchanges)
	if s.Exchanges() > maxExchanges {
		t.Errorf("обменов с БД %d при пределе %d: подача перестала быть конвейерной, "+
			"и посев миллиона стоил бы миллиона круговых обменов", s.Exchanges(), maxExchanges)
	}
	if s.Statements() != wantStatements {
		t.Errorf("стейтментов подано %d, у производителя их 3+len(цепь) на объект — по набору %d: "+
			"расхождение означает, что посевщик выпускает НЕ ТУ форму, а не ту же быстрее",
			s.Statements(), wantStatements)
	}

	// ── сверка: зеркало ──────────────────────────────────────────────────────
	wantMirror := dumpMirror(t, ctx, byProducer)
	gotMirror := dumpMirror(t, ctx, bySeeder)
	compareMirror(t, wantMirror, gotMirror)

	// ── сверка: рёбра родителя ───────────────────────────────────────────────
	wantEdges := dumpEdges(t, ctx, byProducer)
	gotEdges := dumpEdges(t, ctx, bySeeder)
	compareEdges(t, wantEdges, gotEdges)

	// Положительный контроль: сверка обязана иметь ПРЕДМЕТ. Пустые таблицы
	// совпадают всегда, и «расхождений нет» на них означает «сравнивать было
	// нечего» — ровно тот исход, который выглядит как успех.
	if len(wantMirror) == 0 || len(wantEdges) == 0 {
		t.Fatalf("производитель не посадил ничего (зеркало %d, рёбра %d): сверка беспредметна, "+
			"и её молчание не является совпадением", len(wantMirror), len(wantEdges))
	}
	t.Logf("сверено построчно: строк зеркала %d, рёбер %d", len(wantMirror), len(wantEdges))
}

// parityRows — набор, сажаемый ОБОИМИ путями.
//
// Кроме N листьев — промежуточные звенья цепи СО СВОИМИ цепями: без собственных
// рёбер у предков форма данных вырождается, и сверка проверяла бы случай, до
// которого замер никогда не дойдёт.
func parityRows() []scalegrid.MirrorRow {
	rows := make([]scalegrid.MirrorRow, 0, seederParityObjects+3)
	rows = append(rows,
		scalegrid.MirrorRow{
			ObjectType: "iam.project", ObjectID: "prj-1",
			ParentAccountID: "acc-1",
			ParentChain:     []string{"account:acc-1"},
		},
		scalegrid.MirrorRow{
			ObjectType: "registry.registries", ObjectID: "reg-1",
			ParentProjectID: "prj-1", ParentAccountID: "acc-1",
			ParentChain: []string{"project:prj-1", "account:acc-1"},
		},
	)
	for i := 0; i < seederParityObjects; i++ {
		rows = append(rows, scalegrid.MirrorRow{
			ObjectType:      parityCatalogType,
			ObjectID:        fmt.Sprintf("repo-%07d", i),
			ParentProjectID: "prj-1",
			ParentAccountID: "acc-1",
			Labels:          map[string]string{"env": "prod", "tier": "gold"},
			ParentChain:     parityChain,
		})
	}
	return rows
}

func openParityDB(t *testing.T, ctx context.Context) pgx.Tx {
	t.Helper()
	pool, err := pgxpool.New(ctx, pgtest.NewDB(t))
	if err != nil {
		t.Fatalf("пул: %v", err)
	}
	pgtest.ClosePoolAtEnd(t, pool)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("транзакция: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	return tx
}

func dumpMirror(t *testing.T, ctx context.Context, tx pgx.Tx) []mirrorRow {
	t.Helper()
	rows, err := tx.Query(ctx, `
		SELECT object_type, object_id, parent_project_id, parent_account_id,
		       labels::text, source_version::text, updated_at IS NOT NULL
		  FROM kacho_iam.resource_mirror
		 ORDER BY object_type, object_id`)
	if err != nil {
		t.Fatalf("вычитывание зеркала: %v", err)
	}
	defer rows.Close()
	var out []mirrorRow
	for rows.Next() {
		var r mirrorRow
		if err := rows.Scan(&r.objectType, &r.objectID, &r.parentProject, &r.parentAcct,
			&r.labels, &r.sourceVersion, &r.updatedAtSet); err != nil {
			t.Fatalf("вычитывание зеркала: %v", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("вычитывание зеркала: %v", err)
	}
	return out
}

func dumpEdges(t *testing.T, ctx context.Context, tx pgx.Tx) []edgeRow {
	t.Helper()
	rows, err := tx.Query(ctx, `
		SELECT object_type, object_id, parent_type, parent_id, depth,
		       source_version::text, updated_at IS NOT NULL
		  FROM kacho_iam.resource_parent_edge
		 ORDER BY object_type, object_id, depth`)
	if err != nil {
		t.Fatalf("вычитывание рёбер: %v", err)
	}
	defer rows.Close()
	var out []edgeRow
	for rows.Next() {
		var r edgeRow
		if err := rows.Scan(&r.objectType, &r.objectID, &r.parentType, &r.parentID,
			&r.depth, &r.sourceVersion, &r.updatedAtSet); err != nil {
			t.Fatalf("вычитывание рёбер: %v", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("вычитывание рёбер: %v", err)
	}
	return out
}

func compareMirror(t *testing.T, want, got []mirrorRow) {
	t.Helper()
	if len(want) != len(got) {
		t.Fatalf("строк зеркала: производитель %d, посевщик %d — сравнивать построчно нечего",
			len(want), len(got))
	}
	shown := 0
	for i := range want {
		if want[i] == got[i] {
			continue
		}
		shown++
		if shown <= 5 {
			t.Errorf("строка зеркала %d разошлась:\n  производитель %+v\n  посевщик      %+v", i, want[i], got[i])
		}
	}
	if shown > 5 {
		t.Errorf("…и ещё %d разошедшихся строк зеркала", shown-5)
	}
}

func compareEdges(t *testing.T, want, got []edgeRow) {
	t.Helper()
	if len(want) != len(got) {
		t.Fatalf("рёбер родителя: производитель %d, посевщик %d — сравнивать построчно нечего",
			len(want), len(got))
	}
	shown := 0
	for i := range want {
		if want[i] == got[i] {
			continue
		}
		shown++
		if shown <= 5 {
			t.Errorf("ребро %d разошлось:\n  производитель %+v\n  посевщик      %+v", i, want[i], got[i])
		}
	}
	if shown > 5 {
		t.Errorf("…и ещё %d разошедшихся рёбер", shown-5)
	}
}
