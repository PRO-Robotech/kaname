// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// cluster_anchor_agrees_with_the_code_integration_test.go — свод оканчивается
// ТЕМ ЖЕ написанием якоря, каким код спрашивает базу (задача продукта #2113).
//
// # Шов, который до этой пробы не судил НИКТО
//
// Написание якоря объявлено в двух местах, и оба судятся: разбор Go требует,
// чтобы код называл его только через объявление, разбор вне Go — чтобы контракты,
// манифесты и модель прав называли объявленное. Оба спрашивают о ДЕРЕВЕ.
//
// База в этом сравнении не участвовала вовсе. Между тем спрашивает продукт
// именно её: `ClusterService.Get` идёт за строкой по объявленному написанию,
// проверка формы id отвергает всякое другое, каждый кортеж кластерного
// администратора висит на объекте `cluster:<якорь>`. Значит расхождение «код
// говорит одно, свод оканчивается другим» было представимо при ОБОИХ зелёных
// гейтах — и стоило бы оно доступа кластерного администратора, то есть того
// единственного, кто мог бы это починить.
//
// Класс не гипотетический: базовая миграция сеет якорь и править её нельзя
// (ban #5), поэтому всякий переход написания оставляет свод позади кода до тех
// пор, пока переход не проведён отдельной миграцией. Пока такой пробы не было,
// «провели» и «не провели» выглядели одинаково.
//
// # Почему проба спрашивает СВОД, а не текст миграции
//
// Текстовый предикат по каталогу миграций считает объявлением и то, чей предмет
// снят более поздней миграцией. Здесь цепь проигрывается целиком и спрашивается
// значение, которое база отдаёт СЕГОДНЯ, — тем же вызовом, каким его разрешает
// путь возврата доступа.
//
// # Обе стороны, а не одна
//
// Утверждается не только «якорь равен объявленному», но и «остатка прежнего
// написания в схеме нет», с ОБЪЁМОМ ОСМОТРЕННОГО. Одного равенства мало:
// строка якоря переехала бы, а ссылки на него в jsonb, умолчаниях столбцов и
// предикатах ограничений остались бы прежними — и это ровно то состояние,
// которое выглядит исправным до первого запроса.
package migrations_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// retiredAnchorSpelling — написание, с которого якорь переехал (решение W4,
// задача #2113).
//
// Названо здесь ЛИТЕРАЛОМ намеренно: предмет утверждения — что этого написания
// в схеме не осталось, а величина, взятая из объявления, тут была бы тождественно
// неверной (объявление несёт целевое написание, и остаток по нему обязан быть
// ненулевым).
const retiredAnchorSpelling = "cluster_kacho_root"

// TestClusterAnchor_SchemaEndsOnTheDeclaredAnchor — свод оканчивается тем
// написанием, которое объявлено кодом.
func TestClusterAnchor_SchemaEndsOnTheDeclaredAnchor(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	defer func() { _ = db.Close() }()

	var anchor string
	require.NoError(t, db.QueryRow(`SELECT kaname.cluster_anchor()`).Scan(&anchor))
	require.Equal(t, domain.ClusterSingletonID, anchor,
		"свод оканчивается написанием %q, а код спрашивает базу написанием %q — "+
			"кластерного администратора не существует ни для одного запроса",
		anchor, domain.ClusterSingletonID)

	// Предпосылка: строка якоря есть и она одна. Без неё равенство выше
	// зеленело бы на схеме, где кластера нет вовсе.
	var clusters int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.clusters`).Scan(&clusters))
	require.Equal(t, 1, clusters, "кластер обязан быть ровно один — синглтон")

	// Отношения на якоре обязаны существовать: свод сеет кластерного
	// администратора, и якорь без единого отношения означает, что переход
	// унёс их с собой.
	var relations int64
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM kaname.relation_fact
		 WHERE object_type = 'cluster' AND object_id = $1`, anchor).Scan(&relations))
	require.Positive(t, relations,
		"на якоре %q ноль отношений — переход перенёс строку и потерял то, ради чего она есть",
		anchor)

	t.Logf("якорь свода: %q; отношений на нём: %d", anchor, relations)
}

// TestClusterAnchor_NoResidueOfTheRetiredSpelling — прежнего написания в схеме
// не осталось НИГДЕ, и объём осмотренного напечатан.
//
// Отрицание идёт в паре с положительным контролем: та же перепись по
// ДЕЙСТВУЮЩЕМУ написанию обязана дать ненулевой ответ. Без него «ноль находок»
// было бы неотличимо от «перепись обошла пустоту».
func TestClusterAnchor_NoResidueOfTheRetiredSpelling(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	defer func() { _ = db.Close() }()

	live, lookedLive := anchorResidue(t, db, domain.ClusterSingletonID)
	require.Positive(t, lookedLive, "перепись осмотрела ноль мест — её молчание ничего не значит")
	require.Positive(t, live,
		"действующее написание %q не встречается в схеме НИ РАЗУ — перепись смотрит не туда, "+
			"и отрицание ниже было бы вакуумным", domain.ClusterSingletonID)

	retired, lookedRetired := anchorResidue(t, db, retiredAnchorSpelling)
	require.Equal(t, lookedLive, lookedRetired,
		"перепись осмотрела разное число мест по двум написаниям — сравнивать нечего")
	require.Zero(t, retired,
		"прежнее написание %q осталось в схеме (%d мест): переход прошёл наполовину",
		retiredAnchorSpelling, retired)

	t.Logf("осмотрено мест схемы: %d; действующее написание встречается: %d; прежнее: %d",
		lookedLive, live, retired)
}
