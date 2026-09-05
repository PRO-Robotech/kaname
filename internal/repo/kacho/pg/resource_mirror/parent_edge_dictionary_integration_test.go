// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// parent_edge_dictionary_integration_test.go — СЛОВАРЬ, КОТОРЫМ ПИСАТЕЛЬ
// НАЗЫВАЕТ ЦЕПЬ.
//
// # Предмет
//
// Регистрация называет объект словарём КАТАЛОГА (`compute.instance`) — им же
// названа строка зеркала. Цепь предков читается вопросом о доступе, а он
// приходит словарём МОДЕЛИ (`compute_instance`), и им же названы три другие
// колонки, с которыми цепь соединяется. Писатель обязан перевести на этом стыке;
// не перевёл — соединение не совпадает НИКОГДА и молча, и выдача на проект или
// аккаунт до ресурса не доходит.
//
// # Почему двух проб мало и нужна третья
//
// Первая утверждает ИСХОД перевода (строка лежит под именем модели), вторая —
// что старого имени не осталось (иначе «перевёл» было бы неотличимо от
// «записал дважды»). Третья спрашивает не писателя, а СХЕМУ: инвариант держится
// проверкой таблицы, а не дисциплиной следующего писателя. Без неё первые две
// доказывали бы поведение одной функции, а не свойство колонки.
package resource_mirror_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/resource_mirror"
	"github.com/PRO-Robotech/kacho-iam/internal/testsupport/iampgtest"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
)

// Цепь записана словарём МОДЕЛИ, хотя регистрация назвала объект каталогом.
func TestParentEdges_AreWrittenInTheModelDictionary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	upsertCommitted(t, ctx, pool, resource_mirror.Row{
		ObjectType:      "compute.instance", // словарь КАТАЛОГА — как зовёт регистрация
		ObjectID:        "inst-dict",
		ParentProjectID: "prj-P",
		ParentAccountID: "acc-A",
		SourceVersion:   time.Now().Truncate(time.Microsecond),
		ParentChain:     []string{"project:prj-P", "account:acc-A"},
	})

	var underModel int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.resource_parent_edge
		  WHERE object_type = 'compute_instance' AND object_id = 'inst-dict'`).Scan(&underModel))
	require.Equal(t, 2, underModel,
		"цепь не записана словарём модели: вопрос о доступе приходит им, и соединение "+
			"по разным написаниям не совпадёт ни на одном шаге — отказ будет неотличим "+
			"от честного")

	// Отрицание рядом: под именем каталога не осталось НИЧЕГО. Без него
	// «перевёл» было бы неотличимо от «записал обоими именами».
	var underCatalog int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.resource_parent_edge
		  WHERE object_type = 'compute.instance'`).Scan(&underCatalog))
	require.Zero(t, underCatalog, "строка осталась под именем словаря каталога")

	// Строка зеркала СВОЙ словарь сохраняет: перевод стоит на стыке, а не
	// подменяет словарь соседней таблицы.
	var mirrored int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.resource_mirror
		  WHERE object_type = 'compute.instance' AND object_id = 'inst-dict'`).Scan(&mirrored))
	require.Equal(t, 1, mirrored,
		"перевод задел зеркало — а его колонка названа словарём каталога, и её читают "+
			"метки и перечисление кандидатов")
}

// Инвариант держит СХЕМА: строку словаря каталога таблица не принимает вовсе.
//
// Проверка стоит здесь, а не «перед записью в коде»: программная дала бы то же
// самое одним писателем позже и молча.
func TestParentEdges_SchemaRejectsTheCatalogDictionary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	// Законный близнец ТОЙ ЖЕ формы проходит — иначе отказ ниже означал бы
	// «таблица не принимает ничего», а не «не принимает чужой словарь».
	_, err = pool.Exec(ctx,
		`INSERT INTO kacho_iam.resource_parent_edge
		   (object_type, object_id, parent_type, parent_id, depth)
		 VALUES ('compute_instance', 'inst-ok', 'project', 'prj-P', 1)`)
	require.NoError(t, err, "строка словаря модели отвергнута — проверка ловит форму, а не словарь")

	for _, bad := range []struct {
		name string
		sql  string
	}{
		{"объект", `INSERT INTO kacho_iam.resource_parent_edge
		   (object_type, object_id, parent_type, parent_id, depth)
		 VALUES ('compute.instance', 'inst-bad', 'project', 'prj-P', 1)`},
		{"предок", `INSERT INTO kacho_iam.resource_parent_edge
		   (object_type, object_id, parent_type, parent_id, depth)
		 VALUES ('compute_instance', 'inst-bad2', 'iam.project', 'prj-P', 1)`},
		{"прямой факт", `INSERT INTO kacho_iam.relation_fact
		   (object_type, object_id, relation, subject)
		 VALUES ('compute.instance', 'inst-bad3', 'v_get', 'user:usr-1')`},
	} {
		_, err := pool.Exec(ctx, bad.sql)
		require.Error(t, err, "%s: строка словаря каталога принята — инвариант не держится схемой", bad.name)
		require.True(t, strings.Contains(err.Error(), "model_dictionary"),
			"%s: отказ пришёл не от проверки словаря, а от чего-то другого: %v", bad.name, err)
	}
}
