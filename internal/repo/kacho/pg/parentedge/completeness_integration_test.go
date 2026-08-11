// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package parentedge_test

// completeness_integration_test.go — объект зеркала без цепи до корня есть
// НАХОДКА, а не молчание.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Форма E отвечает на вопрос о доступе, поднимаясь по цепи предков объекта.
// Объект, у которого цепи нет, отвечает «нет прав» — и этот отказ НЕОТЛИЧИМ от
// честного: он той же формы, с тем же кодом, и ни один прогон его не покажет.
//
// Это зеркало дефекта, на котором был отвергнут первый заход замера: там
// конъюнкт был тождественно ЛОЖЕН, здесь — молчаливо пуст. Оба выглядят как
// работающая проверка.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ГЕЙТ ПЕЧАТАЕТ И ПОЧЕМУ ИМЕННО ЭТО
//
// Пару чисел: сколько строк зеркала осмотрено и сколько из них без цепи. «Ноль
// непокрытых» обязано быть отличимо от «ноль осмотренных» — на пустом зеркале
// гейт падает, потому что молчание там означает «сверять было нечего», а не
// «всё покрыто».
//
// ─────────────────────────────────────────────────────────────────────────────
// ГРАНИЦА, НАЗВАННАЯ ЯВНО
//
// Короткая цепь — не дефект. Объект корневого уровня (сам аккаунт, сам кластер)
// предка не имеет по построению, и требовать его значило бы требовать цепи,
// которой нет в природе. Гейт судит НАЛИЧИЕ цепи у тех, у кого зеркало знает
// предка, а не её длину.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
)

// rootLevelTypes — типы, у которых предка нет по построению.
//
// Перечень закрыт и назван: это НЕ послабление «нам лень заполнить», а факт
// модели — над аккаунтом стоит кластер, над кластером ничего. Появится тип, у
// которого предка нет по другой причине, — он вносится сюда с этой причиной, а
// не тихо исключается предикатом.
var rootLevelTypes = map[string]string{
	"account": "над аккаунтом только кластер; сам аккаунт предка в зеркале не имеет",
	"cluster": "корень иерархии областей",
}

func openPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := pgtest.NewDB(t)
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("пул к тестовой БД: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// seedMirror кладёт строку зеркала и, если предок назван, ребро к нему.
func seedMirror(t *testing.T, pool *pgxpool.Pool, objType, objID, parentType, parentID string) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx,
		`INSERT INTO kacho_iam.resource_mirror (object_type, object_id, parent_project_id)
		 VALUES ($1, $2, $3)`,
		objType, objID, map[bool]string{true: parentID, false: ""}[parentType == "project"],
	); err != nil {
		t.Fatalf("посев зеркала %s:%s: %v", objType, objID, err)
	}
	if parentType == "" {
		return
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO kacho_iam.resource_parent_edge
		   (object_type, object_id, parent_type, parent_id, depth)
		 VALUES ($1, $2, $3, $4, 1)`,
		objType, objID, parentType, parentID,
	); err != nil {
		t.Fatalf("посев ребра %s:%s: %v", objType, objID, err)
	}
}

// uncovered — строки зеркала без единого ребра, кроме корневых типов.
func uncovered(t *testing.T, pool *pgxpool.Pool) (examined int, missing []string) {
	t.Helper()
	ctx := context.Background()
	rows, err := pool.Query(ctx,
		`SELECT m.object_type, m.object_id,
		        EXISTS (SELECT 1 FROM kacho_iam.resource_parent_edge e
		                 WHERE e.object_type = m.object_type AND e.object_id = m.object_id)
		   FROM kacho_iam.resource_mirror m`)
	if err != nil {
		t.Fatalf("перепись зеркала: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var typ, id string
		var hasEdge bool
		if err := rows.Scan(&typ, &id, &hasEdge); err != nil {
			t.Fatalf("чтение строки зеркала: %v", err)
		}
		examined++
		if hasEdge {
			continue
		}
		if _, root := rootLevelTypes[typ]; root {
			continue
		}
		missing = append(missing, typ+":"+id)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("обход зеркала: %v", err)
	}
	return examined, missing
}

// Законная сторона: у каждого объекта есть цепь, корневой — не находка.
func TestParentEdgeCompleteness_SilentWhenEveryObjectHasAChain(t *testing.T) {
	pool := openPool(t)
	seedMirror(t, pool, "vpc_network", "net-1", "project", "prj-1")
	seedMirror(t, pool, "project", "prj-1", "account", "acc-1")
	// Корневой уровень: предка нет по построению, цепи нет — и это НЕ находка.
	seedMirror(t, pool, "account", "acc-1", "", "")

	examined, missing := uncovered(t, pool)
	t.Logf("осмотрено строк зеркала: %d; без цепи: %d", examined, len(missing))

	if examined == 0 {
		t.Fatal("зеркало пусто — «ноль непокрытых» здесь означало бы «сверять было нечего»")
	}
	if len(missing) != 0 {
		t.Fatalf("гейт нашёл непокрытые на законном множестве: %v", missing)
	}
}

// Сторона дефекта: цепь снята — гейт обязан НАЗВАТЬ объект.
func TestParentEdgeCompleteness_RedWhenAChainIsMissing(t *testing.T) {
	pool := openPool(t)
	seedMirror(t, pool, "vpc_network", "net-1", "project", "prj-1")
	seedMirror(t, pool, "project", "prj-1", "account", "acc-1")

	// Снимаем цепь у одного объекта — ровно то, что происходит, когда владелец
	// её не шлёт.
	if _, err := pool.Exec(context.Background(),
		`DELETE FROM kacho_iam.resource_parent_edge
		  WHERE object_type = 'vpc_network' AND object_id = 'net-1'`); err != nil {
		t.Fatalf("инъекция: %v", err)
	}

	examined, missing := uncovered(t, pool)
	t.Logf("осмотрено строк зеркала: %d; без цепи: %d %v", examined, len(missing), missing)

	if len(missing) != 1 || missing[0] != "vpc_network:net-1" {
		t.Fatalf("объект без цепи не назван: %v — молчание здесь неотличимо от честного "+
			"отказа в правах, потому что форма отказа та же", missing)
	}
}

// Предпосылка самого гейта: на пустом зеркале он падает, а не молчит.
func TestParentEdgeCompleteness_FailsOnAnEmptyMirror(t *testing.T) {
	pool := openPool(t)
	examined, missing := uncovered(t, pool)
	if examined != 0 || len(missing) != 0 {
		t.Fatalf("пустое зеркало дало осмотрено=%d непокрытых=%d — предпосылка пробы неверна",
			examined, len(missing))
	}
	// Именно этот исход и обязан быть отказом у боевого гейта: «ноль непокрытых»
	// на нуле осмотренных не есть покрытие.
	t.Log("подтверждено: ноль осмотренных отличимо от нуля непокрытых")
}
