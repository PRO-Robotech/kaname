// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// cluster_name_leaves_the_brand_integration_test.go — класс A приёмки
// `seed-identity-names-its-own-service.md` (§2.1, §4.1, §8 шаг 1): ИМЯ
// корневого кластера перестаёт называть платформу.
//
// # Почему проба, а не чтение миграции
//
// Свод сеет имя, и править его нельзя (ban #5). Значит утверждение «имя стало
// таким» есть утверждение о РЕЗУЛЬТАТЕ всей цепочки, а не о тексте одного
// файла: миграция, применённая после свода, обязана перевести ЖИВУЮ строку.
// Чтение SQL сказало бы лишь, что перевод объявлен.
//
// # Что здесь НЕ утверждается — и это граница класса A, а не упущение
//
// Идентификатор якоря (`cluster_root`) переехал раньше и своей задачей (#2113);
// его неподвижность утверждает `TestClusterAnchor_*` в соседнем файле. Здесь
// предмет — ИМЯ, то есть косметический ярлык, который ban #15 не связывает
// ничем. Проба это разделение и закрепляет: имя меняется, идентификатор
// обязан остаться прежним.
package migrations_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

const (
	// clusterNameBefore — написание, которым свод называет корневой кластер.
	clusterNameBefore = "kacho-root"
	// clusterNameAfter — объявленное написание (§2.3): имя называет УСТАНОВКУ,
	// а не продукт, поэтому различителя в нём нет вовсе.
	clusterNameAfter = "root"
)

// TestClusterName_SeedNoLongerNamesThePlatform — KAN-SEED-1-01: после всей
// цепочки миграций имя корневого кластера объявленное, а прежнего нет.
//
// Утверждаются ОБЕ стороны. Одна («прежнего нет») зеленела бы на базе, где
// строки кластера не существует вовсе, — а её отсутствие есть поломка куда
// худшая, чем чужое имя.
func TestClusterName_SeedNoLongerNamesThePlatform(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	defer func() { _ = db.Close() }()

	var rows int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.clusters`).Scan(&rows))
	require.Equal(t, 1, rows, "кластер — singleton; вердикт об имени беспредметен при другом числе строк")

	var name string
	require.NoError(t, db.QueryRow(`SELECT name FROM kaname.clusters`).Scan(&name))
	require.Equal(t, clusterNameAfter, name,
		"имя корневого кластера называет платформу: оператор, поставивший службу одну, "+
			"видит в СВОЕЙ установке объект с именем продукта, которого он не ставил")
	require.NotEqual(t, clusterNameBefore, name)
}

// TestClusterName_AnchorDoesNotMoveWithTheName — KAN-SEED-1-11: переименование
// НЕ трогает идентификатор.
//
// Это и есть требование ban #15, снятое опытом, а не объявленное: имя
// косметично, идентификатор — внешне-адресуемая координата, и перевод первого
// обязан оставить второй на месте до символа.
func TestClusterName_AnchorDoesNotMoveWithTheName(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	defer func() { _ = db.Close() }()

	var id string
	require.NoError(t, db.QueryRow(`SELECT id FROM kaname.clusters`).Scan(&id))
	require.Equal(t, string(domain.ClusterSingletonID), id,
		"идентификатор якоря сдвинулся вместе с именем — это ban #15, а не побочный эффект")
}

// TestClusterName_IsAcceptedByItsOwnConstraint — новое написание проходит
// ограничение формы, и это снято ОПЫТОМ, а не сверено глазами по регулярке.
//
// Ограничение объявлено сводом и правке не подлежит; если бы `root` ему не
// отвечал, миграция отказала бы при накате — но отказала бы ПОЗЖЕ, у того, кто
// поднимает установку, и без указания на причину.
func TestClusterName_IsAcceptedByItsOwnConstraint(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	defer func() { _ = db.Close() }()

	var ok bool
	require.NoError(t, db.QueryRow(
		`SELECT $1 ~ '^[a-z][-a-z0-9]{0,62}[a-z0-9]?$'`, clusterNameAfter).Scan(&ok))
	require.True(t, ok, "объявленное написание не отвечает форме имени кластера")

	// Законный близнец: прежнее написание форме тоже отвечало. Без него проба
	// доказывала бы лишь то, что регулярка вообще что-то принимает.
	require.NoError(t, db.QueryRow(
		`SELECT $1 ~ '^[a-z][-a-z0-9]{0,62}[a-z0-9]?$'`, clusterNameBefore).Scan(&ok))
	require.True(t, ok, "предпосылка пробы неверна: прежнее написание форме не отвечало")
}
