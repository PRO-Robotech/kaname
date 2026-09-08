// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// cluster_anchor_way_back_integration_test.go — поверхность F5 приёмки
// KAN-WIRE-1: якорь кластера, путь возврата доступа и переписчик написания.
//
// # Что здесь утверждается и почему именно так
//
// Ошибка вокруг якоря отбирает доступ у ТОГО ЕДИНСТВЕННОГО, кто мог бы её
// починить. Поэтому каждое утверждение ниже снимается ДВАЖДЫ — до перехода и
// после, — и снимается ОДНИМ И ТЕМ ЖЕ запросом. Проба, переписанная под новое
// написание, утверждала бы о новом мире и о прежнем не сказала бы ничего.
//
// # Посылка приёмки о частичном состоянии ОПРОВЕРГНУТА, и это записано
//
// Родительский разбор исходил из того, что кортежи живут в чужом хранилище, куда
// транзакция не достаёт: там частичное состояние было ожидаемым исходом
// прерывания. Внешний движок прав снят (стадия S6 эпика #747) — решение о
// доступе вычисляет реляционная форма в СВОЕЙ базе, а проекция отношений
// `kaname.relation_fact` лежит в той же транзакции, что и остальное.
//
// Требование от этого не отпадает, а выполняется СИЛЬНЕЕ: частичного состояния
// не бывает by construction, и `TestClusterAnchor_InterruptedRenameIsNotHalfDone`
// это ДОКАЗЫВАЕТ прерыванием, а не объявляет.

package migrations_test

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// Написания якоря: то, что лежит в своде, и то, во что его переписывают.
//
// # Здесь стояло написание перехода W4 — переход ПРОШЁЛ, и посылка истекла
//
// Прежняя редакция брала `cluster_kacho_root` → `cluster_root` и объясняла это
// тем, что переписчик обязан судиться «на том самом переходе, ради которого он
// заведён». Довод был верен ровно до того дня, когда переход состоялся
// (задача #2113, миграция
// `20260906214500_cluster_anchor_moves_to_its_declared_spelling.sql`): свод
// теперь оканчивается объявленным написанием, и проба, требующая прежнего,
// краснела бы НЕ на дефекте, а на собственной устаревшей посылке.
//
// # Откуда берётся «до» — ИЗ ОБЪЯВЛЕНИЯ, а не литералом
//
// `anchorBefore` — то, что свод обязан произвести, и берётся оно из того же
// места, откуда берёт продукт. Литерал здесь разошёлся бы со сводом молча при
// следующем переходе: проба продолжала бы переписывать написание, которого в
// базе нет, и падала бы отказом переписчика вместо утверждения о доступе.
//
// # «После» — написание, которого в дереве НЕТ
//
// Предмет этих проб — переписчик, а не конкретная пара написаний: он обязан
// переносить якорь и сохранять доступ на ЛЮБОМ переходе. Пробное написание
// делает это явным и не может случайно совпасть ни с чем живым.
//
// Что свод оканчивается ИМЕННО объявленным написанием, утверждает отдельная
// проба — TestClusterAnchor_SchemaEndsOnTheDeclaredAnchor. Здесь она не
// повторяется: два места об одном предмете разошлись бы молча.
const (
	anchorBefore = domain.ClusterSingletonID
	anchorAfter  = "cluster_probe_root"
)

// clusterAdminSubject — служебная учётка, посеянная сводом кластерным
// администратором (`kaname.cluster_admin_grants`, выдача `cag_5f4510f927a011885`).
const clusterAdminSubject = "service_account:svab91854890de887e6d"

// outsiderSubject — субъект БЕЗ единой привязки к кластеру.
//
// Он посеян сводом и существует, но кластерным администратором не является:
// отрицание, снятое на несуществующем субъекте, зеленело бы на любой базе.
const outsiderSubject = "service_account:sva3e9556e76be67f816"

// clusterAdminHolds — «доступ кластерного администратора есть», спрошенное ТАК ЖЕ,
// как его спрашивает продукт: одно отношение = один факт
// (`authzguard.SubjectIsClusterAdmin` → `cluster:<якорь>#system_admin@<субъект>`).
//
// Якорь НЕ подставляется литералом: он разрешается по факту той же функцией,
// которой пользуется путь возврата. Иначе проба «после» отвечала бы про объект,
// которого уже нет, и молчала бы о том, есть ли доступ на самом деле.
func clusterAdminHolds(t *testing.T, db *sql.DB, subject string) bool {
	t.Helper()
	var holds bool
	require.NoError(t, db.QueryRow(`
		SELECT EXISTS(
		  SELECT 1 FROM kaname.relation_fact
		   WHERE object_type = 'cluster'
		     AND object_id   = kaname.cluster_anchor()
		     AND relation    = 'system_admin'
		     AND subject     = $1)`, subject).Scan(&holds))
	return holds
}

// anchorResidue — сколько мест схемы ещё несут названное написание, и сколько
// мест при этом осмотрено.
//
// Возвращаются ОБЕ величины: «ноль находок» обязано быть отличимо от «ноль
// прочитанного», и на переписи, обошедшей пустой каталог, они выглядят одинаково.
func anchorResidue(t *testing.T, db *sql.DB, anchor string) (hits, looked int64) {
	t.Helper()
	rows, err := db.Query(`SELECT place, kind, hits FROM kaname.cluster_anchor_residue($1)`, anchor)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var place, kind string
		var n int64
		require.NoError(t, rows.Scan(&place, &kind, &n))
		if kind == "перепись" {
			looked = n
			continue
		}
		t.Logf("остаток %q: %s — %d", anchor, place, n)
		hits += n
	}
	require.NoError(t, rows.Err())
	return hits, looked
}

// renameAnchor прогоняет переписчик и возвращает объём осмотренного.
func renameAnchor(t *testing.T, db *sql.DB, from, to string) (looked int64) {
	t.Helper()
	rows, err := db.Query(`SELECT place, kind, moved FROM kaname.rename_cluster_anchor($1, $2)`, from, to)
	require.NoError(t, err, "переписчик обязан дойти до конца — иначе о переходе не известно ничего")
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var place, kind string
		var n int64
		require.NoError(t, rows.Scan(&place, &kind, &n))
		if kind == "перепись" {
			looked = n
			continue
		}
		t.Logf("переписано: %s (%s) — %d", place, kind, n)
	}
	require.NoError(t, rows.Err())
	return looked
}

// TestClusterAnchor_AdminKeepsAccessAcrossTheRename — KAN-W5-01: доступ
// кластерного администратора снимается ДО перехода и ПОСЛЕ, одним и тем же
// запросом, и оба раза даёт ОДИН результат.
//
// Пара «до/после» несущая. Односторонняя проба «после» зеленела бы на дереве,
// где доступа нет вовсе, — и именно на нём приёмка требует красного.
func TestClusterAnchor_AdminKeepsAccessAcrossTheRename(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	defer func() { _ = db.Close() }()

	// Предпосылка пробы: доступ ДО перехода существует. Без этой строки
	// утверждение «после» зеленело бы, ничего не доказав.
	require.True(t, clusterAdminHolds(t, db, clusterAdminSubject),
		"кластерного администратора нет ДО перехода: сравнивать нечего, "+
			"и любое утверждение «после» было бы вакуумным")

	var anchor string
	require.NoError(t, db.QueryRow(`SELECT kaname.cluster_anchor()`).Scan(&anchor))
	require.Equal(t, anchorBefore, anchor)

	// Счёт отношений на якоре — величина, которая обязана СОХРАНИТЬСЯ.
	var before int64
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM kaname.relation_fact
		 WHERE object_type = 'cluster' AND object_id = $1`, anchorBefore).Scan(&before))
	require.Positive(t, before, "отношений на якоре ноль — переписывать нечего, проба беспредметна")

	looked := renameAnchor(t, db, anchorBefore, anchorAfter)
	require.Positive(t, looked, "переписчик осмотрел ноль мест — его молчание ничего не значит")
	t.Logf("переписчик осмотрел мест: %d; отношений на якоре до перехода: %d", looked, before)

	require.NoError(t, db.QueryRow(`SELECT kaname.cluster_anchor()`).Scan(&anchor))
	require.Equal(t, anchorAfter, anchor, "якорь не переехал")

	require.True(t, clusterAdminHolds(t, db, clusterAdminSubject),
		"доступ кластерного администратора ПОТЕРЯН переходом — то есть потерян у того "+
			"единственного, кто мог бы это починить")
}

// TestClusterAnchor_OutsiderStaysDeniedAcrossTheRename — KAN-W5-02:
// ОТРИЦАТЕЛЬНЫЙ близнец предыдущей пробы.
//
// Отличие от неё — ОДИН факт: субъект. Без этого отрицания «переход сохранил
// доступ» было бы неотличимо от «переход раздал доступ всем»: первая проба на
// такой базе зелена.
func TestClusterAnchor_OutsiderStaysDeniedAcrossTheRename(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	defer func() { _ = db.Close() }()

	// Положительный контроль отрицания: субъект СУЩЕСТВУЕТ и отношения на
	// кластере у него есть — просто не то. Проба на несуществующем субъекте
	// зеленела бы на любой базе.
	var other int64
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM kaname.relation_fact
		 WHERE object_type = 'cluster' AND subject = $1`, outsiderSubject).Scan(&other))
	require.Positive(t, other,
		"у постороннего нет НИ ОДНОГО отношения на кластере: отрицание зеленело бы "+
			"на отсутствии субъекта, а не на отсутствии права")

	require.False(t, clusterAdminHolds(t, db, outsiderSubject),
		"посторонний уже ДО перехода является кластерным администратором — "+
			"проба судит не тот субъект")

	renameAnchor(t, db, anchorBefore, anchorAfter)

	require.False(t, clusterAdminHolds(t, db, outsiderSubject),
		"переход выдал постороннему доступ кластерного администратора")
}

// TestClusterAnchor_RelationsMoveWithTheAnchorAndAreCounted — KAN-W5-04:
// отношений прежнего объекта ноль, нового — СТОЛЬКО ЖЕ, сколько было.
func TestClusterAnchor_RelationsMoveWithTheAnchorAndAreCounted(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	defer func() { _ = db.Close() }()

	countOn := func(anchor string) int64 {
		var n int64
		require.NoError(t, db.QueryRow(`
			SELECT count(*) FROM kaname.relation_fact
			 WHERE object_type = 'cluster' AND object_id = $1`, anchor).Scan(&n))
		return n
	}

	was := countOn(anchorBefore)
	require.Positive(t, was, "отношений на якоре ноль — сохранять нечего")
	require.Zero(t, countOn(anchorAfter), "новое написание занято ДО перехода")

	renameAnchor(t, db, anchorBefore, anchorAfter)

	require.Zero(t, countOn(anchorBefore),
		"отношения остались на прежнем объекте: решение о доступе спрашивает новый, "+
			"и они не ответят ни на один вопрос")
	require.Equal(t, was, countOn(anchorAfter),
		"счёт отношений не сохранён: переход не переименовал, а потерял часть")
}

// TestClusterAnchor_InterruptedRenameIsNotHalfDone — KAN-W5-04, последнее «И»:
// прерывание переписи ОТЛИЧИМО от её завершения.
//
// Приёмка называла частичное состояние ожидаемым исходом прерывания — по
// посылке, что кортежи лежат в чужом хранилище. Посылка опровергнута (см. шапку
// файла), и требование выполняется сильнее: прерывание даёт РОВНО «не начато».
// Утверждается это прерыванием, а не объявлением, и обе стороны — состав до и
// состав после — снимаются одной и той же переписью.
func TestClusterAnchor_InterruptedRenameIsNotHalfDone(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	defer func() { _ = db.Close() }()

	hitsBefore, lookedBefore := anchorResidue(t, db, anchorBefore)
	require.Positive(t, lookedBefore, "перепись осмотрела ноль мест — её молчание ничего не значит")
	require.Positive(t, hitsBefore, "прежнего написания в схеме нет — прерывать нечего")

	// Прерывание: переписчик отработал целиком, транзакция откачена.
	tx, err := db.Begin()
	require.NoError(t, err)
	_, err = tx.Exec(`SELECT * FROM kaname.rename_cluster_anchor($1, $2)`, anchorBefore, anchorAfter)
	require.NoError(t, err)
	// Внутри той же транзакции переход уже виден — иначе «прерывание» было бы
	// прерыванием ничего.
	var seen string
	require.NoError(t, tx.QueryRow(`SELECT kaname.cluster_anchor()`).Scan(&seen))
	require.Equal(t, anchorAfter, seen, "внутри транзакции переход не наступил — прерывать нечего")
	require.NoError(t, tx.Rollback())

	hitsAfter, lookedAfter := anchorResidue(t, db, anchorBefore)
	require.Equal(t, lookedBefore, lookedAfter, "перепись осмотрела разный объём — числа несравнимы")
	require.Equal(t, hitsBefore, hitsAfter,
		"прерванная перепись оставила состояние ИНЫМ, чем было: половина перехода "+
			"снаружи неотличима от целого, а доступ администратора висит на этой половине")

	var anchor string
	require.NoError(t, db.QueryRow(`SELECT kaname.cluster_anchor()`).Scan(&anchor))
	require.Equal(t, anchorBefore, anchor, "прерывание не вернуло якорь к прежнему написанию")
	require.True(t, clusterAdminHolds(t, db, clusterAdminSubject),
		"прерывание отобрало доступ кластерного администратора")
}

// TestClusterAnchor_ResidueIsZeroAfterTheRename — KAN-W5-05: прежних написаний в
// схеме ноль, и перепись печатает осмотренное.
func TestClusterAnchor_ResidueIsZeroAfterTheRename(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	defer func() { _ = db.Close() }()

	hits, looked := anchorResidue(t, db, anchorBefore)
	require.Positive(t, looked, "перепись осмотрела ноль мест")
	require.Positive(t, hits, "прежнего написания в схеме нет ДО перехода — переписывать нечего")
	t.Logf("до перехода: мест с прежним написанием %d, осмотрено мест %d", hits, looked)

	renameAnchor(t, db, anchorBefore, anchorAfter)

	hits, lookedAfter := anchorResidue(t, db, anchorBefore)
	require.Equal(t, looked, lookedAfter, "перепись осмотрела разный объём — числа несравнимы")
	require.Zero(t, hits,
		"прежнее написание пережило переход: умолчание столбца либо предикат ограничения "+
			"вернёт его ТИХО на первой же вставке")

	// Обратная сторона той же переписи: новое написание обязано ПОЯВИТЬСЯ.
	// Без неё «ноль прежних» зеленел бы на схеме, из которой якорь вычистили
	// целиком.
	newHits, _ := anchorResidue(t, db, anchorAfter)
	require.Positive(t, newHits, "нового написания в схеме нет — переход не переименовал, а стёр")
}

// TestClusterAnchor_RestoreGivesTheAdminAccessBack — KAN-W5-07: объявленная
// процедура возврата ИСПОЛНИМА, и после неё проходит KAN-W5-01.
//
// Отличие «дано» от KAN-W5-01 — ОДИН факт: доступ администратора снят. Проба,
// зовущая процедуру на базе, где доступ и так есть, зеленела бы на процедуре,
// не делающей ничего.
func TestClusterAnchor_RestoreGivesTheAdminAccessBack(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	defer func() { _ = db.Close() }()

	// Переход прошёл — именно в этом состоянии процедура и понадобится.
	renameAnchor(t, db, anchorBefore, anchorAfter)

	// Доступ администратора потерян: снимаем и отношение, и строку выдачи.
	_, err := db.Exec(`
		DELETE FROM kaname.relation_fact
		 WHERE object_type = 'cluster' AND relation = 'system_admin' AND subject = $1`,
		clusterAdminSubject)
	require.NoError(t, err)
	_, err = db.Exec(`DELETE FROM kaname.cluster_admin_grants WHERE subject_id = $1`,
		"svab91854890de887e6d")
	require.NoError(t, err)
	require.False(t, clusterAdminHolds(t, db, clusterAdminSubject),
		"доступ не снят — процедуре возврата нечего возвращать, и её зелень вакуумна")

	var report string
	require.NoError(t, db.QueryRow(`SELECT kaname.restore_cluster_admin($1, $2)`,
		"service_account", "svab91854890de887e6d").Scan(&report))
	t.Logf("процедура возврата: %s", report)

	require.True(t, clusterAdminHolds(t, db, clusterAdminSubject),
		"после объявленной процедуры возврата доступ администратора НЕ восстановлен")

	// Идемпотентность: оператор зовёт процедуру, не зная состояния.
	require.NoError(t, db.QueryRow(`SELECT kaname.restore_cluster_admin($1, $2)`,
		"service_account", "svab91854890de887e6d").Scan(&report))
	var grants int
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM kaname.cluster_admin_grants WHERE subject_id = $1`,
		"svab91854890de887e6d").Scan(&grants))
	require.Equal(t, 1, grants, "повтор процедуры завёл вторую выдачу")
}

// TestClusterAnchor_RestoreRefusesASubjectThatDoesNotExist — ОТРИЦАТЕЛЬНЫЙ
// близнец процедуры возврата.
//
// Отличие от предыдущей — ОДИН факт: субъекта в базе нет. Без этого отрицания
// процедура, кладущая отношение кому угодно, была бы зелёной: оператор
// прочитал бы «сделано» там, где отношение не ответит никому.
func TestClusterAnchor_RestoreRefusesASubjectThatDoesNotExist(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	defer func() { _ = db.Close() }()

	var report string
	err := db.QueryRow(`SELECT kaname.restore_cluster_admin($1, $2)`,
		"service_account", "sva00000000000nobody").Scan(&report)
	require.Error(t, err, "процедура вернула доступ субъекту, которого нет")
	require.Contains(t, err.Error(), "не существует",
		"отказ обязан назвать причину: оператор чинит по тексту отказа, а не по коду")

	// Положительный контроль в той же пробе: субъект, который ЕСТЬ, принимается.
	// Без него отрицание зеленело бы на процедуре, отвергающей всё подряд.
	require.NoError(t, db.QueryRow(`SELECT kaname.restore_cluster_admin($1, $2)`,
		"service_account", "svab91854890de887e6d").Scan(&report))
}
