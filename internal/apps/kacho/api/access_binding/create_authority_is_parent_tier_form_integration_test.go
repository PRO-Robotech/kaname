// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// create_authority_is_parent_tier_form_integration_test.go — наблюдаемая проба к
// снятию `v_create` с типов, у которых его никто не спрашивал.
//
// ЧТО ДОКАЗЫВАЕТСЯ. Тенант ПО-ПРЕЖНЕМУ может создать ресурс в СВОЁМ проекте и
// ПО-ПРЕЖНЕМУ не может в чужом. То есть право создавать не зависело от снятого
// отношения ни на йоту — оно и не могло зависеть: ни одна запись каталога прав не
// гейтит создание на `v_*`.
//
// ПОЧЕМУ ЭТО НЕ ПЕРЕСКАЗ ГЕЙТА. Соседний гейт читает ДЕРЕВО и говорит, что
// читателя нет. Эта проба задаёт вопрос НАСТОЯЩЕМУ источнику вердикта тем же
// способом, каким его задаёт край, и на состоянии, которое реконсайлер РЕАЛЬНО
// материализует для роли-редактора: ярусный факт на проекте и ничего больше. Ни
// одного `v_create` не пишется вообще — и создание работает.
//
// ПРЕДПОСЫЛКА ПРОВЕРЯЕТСЯ. Population берётся из каталога прав по ГЛАГОЛУ токена
// права (`<module>.<resources>.create`), а не по имени метода: имя — привычка
// автора, глагол — то, что энфорсится. Если каталог вдруг начнёт гейтить создание
// на `v_*`, проба покраснеет на предпосылке, а не отчитается зелёным.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ИЗМЕНИЛОСЬ ПРОТИВ ПРЕЖНЕЙ РЕДАКЦИИ И ЧЕМ ЗАМЕНЁН ДИСКРИМИНАТОР
//
// Вопросы задавались внешнему движку отношений; движка нет, отвечает форма
// (`repo/kacho/pg/relverdict`) под дверью решения. Одно место потребовало замены
// по существу, и молчать о ней нельзя.
//
// Утверждение «тип НЕ ОБЪЯВЛЯЕТ отношение» нельзя выразить отрицательным ответом:
// «объявлено, но не выдано» и «не объявлено» дали бы одинаковое `false`, и проба
// зеленела бы на возвращённом обратно отношении — ровно на том состоянии, которое
// обещает поймать (это уже проверялось инъекцией на прежней редакции). Движок
// различал их своим кодом отказа. Форма различает ИНАЧЕ: неизвестное модели
// отношение — ОШИБКА, а не отказ (`relverdict.Ask` не выносит вердикта по плану,
// которого нет).
//
// Ошибка сама по себе слабый дискриминатор: недоступная база ошибётся тоже.
// Поэтому утверждается ПАРА — отказ принять вопрос там, где отношение снято, и
// ОТВЕТ на тот же вопрос там, где отношение оставлено. Обрыв базы ломает обе
// половины, и проба не зеленеет ни в одном из двух состояний, которые она
// призвана различать.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// createGate — (тип объекта области, требуемое отношение) одной записи каталога,
// чей глагол — `create`.
type createGate struct {
	ObjectType string
	Relation   string
}

// createGatesFromCatalog читает вшитую копию каталога прав и возвращает
// различные пары для записей с глаголом `create`.
func createGatesFromCatalog(t *testing.T) []createGate {
	t.Helper()
	root := monorepoRootForCreateAuthority(t)
	raw, err := os.ReadFile(filepath.Join(root,
		"services/iam/internal/apps/kacho/seed/embedded/permission_catalog.json"))
	require.NoError(t, err, "каталог прав не прочитан — у пробы нет population")

	var rows []struct {
		FQN            string `json:"fqn"`
		Permission     string `json:"permission"`
		RequiredRel    string `json:"required_relation"`
		ScopeExtractor struct {
			ObjectType string `json:"object_type"`
		} `json:"scope_extractor"`
	}
	require.NoError(t, json.Unmarshal(raw, &rows))
	require.NotEmpty(t, rows, "каталог разобран в ноль записей")

	seen := map[createGate]bool{}
	for _, r := range rows {
		i := strings.LastIndexByte(r.Permission, '.')
		if i < 0 || r.Permission[i+1:] != "create" {
			continue
		}
		seen[createGate{ObjectType: r.ScopeExtractor.ObjectType, Relation: r.RequiredRel}] = true
	}
	out := make([]createGate, 0, len(seen))
	for g := range seen {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ObjectType != out[j].ObjectType {
			return out[i].ObjectType < out[j].ObjectType
		}
		return out[i].Relation < out[j].Relation
	})
	return out
}

func monorepoRootForCreateAuthority(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	dir := wd
	// Корнем берётся САМЫЙ ВНЕШНИЙ `go.mod`, а не первый встречный: у службы
	// теперь СВОЙ модуль (она выносится отдельным репозиторием), и подъём «до
	// первого» останавливался бы в её каталоге. Пути, которые ниже склеиваются с
	// этим корнем, называют место В ДЕРЕВЕ МОНОРЕПО — от корня, — поэтому
	// остановка внутри службы удваивала сегмент и обход искал `services/iam/
	// services/iam/…`, которого не существует.
	outermost := ""
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			outermost = dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			if outermost != "" {
				return outermost
			}
			t.Fatalf("корень монорепо (go.mod) не найден от %s", wd)
		}
		dir = parent
	}
}

// seedCreateAuthorityFixture кладёт две области — свою и чужую — и ровно тот
// набор фактов, который материализует реконсайлер для роли-редактора: ярус на
// СВОЕЙ области и ничего больше. Ни одного `v_*` не пишется нигде.
func seedCreateAuthorityFixture(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	// ОДНОЙ транзакцией: ключ владельца аккаунта отложен до КОММИТА, и посев по
	// одному оператору в автокоммите отвергается на первом же.
	tx, err := pool.Begin(ctx)
	require.NoError(t, err, "транзакция посева")
	defer func() { _ = tx.Rollback(ctx) }()
	run := func(sql string, args ...any) {
		t.Helper()
		_, err := tx.Exec(ctx, sql, args...)
		require.NoErrorf(t, err, "посев (%s)", sql)
	}
	// Имена — по единственной форме имени дерева: подчёркивание законно в
	// идентификаторе и отвергается в имени.
	run(`INSERT INTO kacho_iam.accounts (id, name, owner_user_id)
	     VALUES ('acc_ca_home', 'home-account',    'usr_createauth'),
	            ('acc_ca_fgn',  'foreign-account', 'usr_createauth')
	     ON CONFLICT DO NOTHING`)
	for _, u := range []string{"usr_createauth", "usr_createauth_none"} {
		run(`INSERT INTO kacho_iam.users (id, external_id, email, account_id)
		     VALUES ($1, $1, $1 || '@kacho.local', 'acc_ca_home') ON CONFLICT DO NOTHING`, u)
	}
	run(`INSERT INTO kacho_iam.projects (id, account_id, name)
	     VALUES ('prj_ca_home', 'acc_ca_home', 'home-project'),
	            ('prj_ca_fgn',  'acc_ca_fgn',  'foreign-project')
	     ON CONFLICT DO NOTHING`)
	// Цепь областей — по одному ребру на звено, ровно как её набирают производители
	// дерева. Замыкание (строка на каждого предка) — форма, которой в продукте нет.
	run(`INSERT INTO kacho_iam.resource_parent_edge
	       (object_type, object_id, parent_type, parent_id, depth)
	     VALUES ('project', 'prj_ca_home', 'account', 'acc_ca_home', 1),
	            ('project', 'prj_ca_fgn',  'account', 'acc_ca_fgn',  1)
	     ON CONFLICT DO NOTHING`)
	run(`INSERT INTO kacho_iam.relation_fact (object_type, object_id, relation, subject)
	     VALUES ('project', 'prj_ca_home', 'editor', 'user:usr_createauth'),
	            ('account', 'acc_ca_home', 'editor', 'user:usr_createauth')`)
	require.NoError(t, tx.Commit(ctx), "коммит посева: форма читает СВОЕЙ транзакцией")
}

// TestCreateAuthority_IsTheParentWriteTier_NotAPerObjectVerb — несущая проба.
func TestCreateAuthority_IsTheParentWriteTier_NotAPerObjectVerb(t *testing.T) {
	gates := createGatesFromCatalog(t)
	require.NotEmpty(t, gates, "в каталоге нет ни одной записи с глаголом `create` — "+
		"предикат population перестал читать свой предмет")

	// ПРЕДПОСЫЛКА: создание не гейтится пообъектным глаголом. Это и есть причина, по
	// которой `v_create` можно было снять; если она перестанет быть верной, всё
	// нижеследующее рассуждение недействительно, и проба обязана сказать об этом
	// здесь, а не отчитаться зелёным.
	var verbGated []string
	for _, g := range gates {
		if strings.HasPrefix(g.Relation, "v_") {
			verbGated = append(verbGated, g.ObjectType+"#"+g.Relation)
		}
	}
	require.Emptyf(t, verbGated,
		"каталог гейтит создание на пообъектном глаголе: %s. Создание в Kachō авторизуется "+
			"ярусом записи на РОДИТЕЛЕ — если это изменилось, снятие `v_create` надо пересмотреть, "+
			"а не подтверждать этой пробой", strings.Join(verbGated, ", "))
	t.Logf("перепись: различных гейтов создания в каталоге: %d — %v", len(gates), gates)

	door, pool := formDoor(t)
	ctx := context.Background()
	seedCreateAuthorityFixture(t, ctx, pool)

	const (
		subj     = "user:usr_createauth"
		stranger = "user:usr_createauth_none"
	)

	checkedPos, checkedNeg := 0, 0
	for _, g := range gates {
		var home, foreign string
		switch g.ObjectType {
		case "project":
			home, foreign = "project:prj_ca_home", "project:prj_ca_fgn"
		case "account":
			home, foreign = "account:acc_ca_home", "account:acc_ca_fgn"
		default:
			// `cluster` (админское создание) и родитель-лист (слушатель в своём
			// балансировщике) — не про арендаторскую пару «свой / чужой проект»;
			// их гейтят соседние пробы. Пропуск объявлен, а не молчалив.
			t.Logf("пропущен гейт %s#%s — область не тенантская пара «свой/чужой»", g.ObjectType, g.Relation)
			continue
		}

		allowed, err := door.Check(ctx, subj, g.Relation, home)
		require.NoErrorf(t, err, "вопрос %q о своей области %s не получил ответа", g.Relation, home)
		require.Truef(t, allowed,
			"тенант с ярусом редактора на своей области НЕ резолвит %q на %s — создание ресурса "+
				"в СВОЁМ проекте сломано, притом что ни одного факта `v_create` в базе нет "+
				"вовсе: значит право создавать от снятого отношения не зависело и не зависит",
			g.Relation, home)
		checkedPos++

		allowed, err = door.Check(ctx, subj, g.Relation, foreign)
		require.NoError(t, err)
		require.Falsef(t, allowed,
			"тот же тенант резолвит %q на ЧУЖОЙ области %s — сужение исчезло", g.Relation, foreign)
		allowed, err = door.Check(ctx, stranger, g.Relation, home)
		require.NoError(t, err)
		require.Falsef(t, allowed,
			"субъект без единого факта резолвит %q на %s — гейт создания ничего не сужает",
			g.Relation, home)
		checkedNeg += 2
	}
	require.Positive(t, checkedPos, "ни один гейт создания не был проверен положительно — "+
		"проба ничего не утверждает")

	// И ровно то отношение, которое сняли: тип его НЕ ОБЪЯВЛЯЕТ. Утверждается
	// именно это, а не «не разрешено» (см. шапку про дискриминатор).
	if _, err := door.Check(ctx, subj, "v_create", "project:prj_ca_home"); err == nil {
		t.Fatal("тип `project` ОБЪЯВЛЯЕТ `v_create` — источник принял вопрос и вынес вердикт: " +
			"отношение вернулось туда, где его никто не спрашивает")
	}

	t.Logf("перепись: положительных проверок: %d, отрицательных: %d", checkedPos, checkedNeg)
}

// TestCreateAuthority_RegistryNamespaceKeepsItsReader — вторая половина: у
// единственного оставшегося носителя `v_create` он РАБОТАЕТ.
//
// Без этой пробы «сняли отношение везде» было бы неотличимо от «сняли отношение
// вообще»: первая проба зеленела бы одинаково в обоих случаях, потому что она
// утверждает ОТСУТСТВИЕ. Здесь утверждается присутствие — и именно там, где у
// отношения есть читатель (хендлер CreateRepository / RenameRepository и docker
// data-plane спрашивают `v_create` на `registry_registry`).
func TestCreateAuthority_RegistryNamespaceKeepsItsReader(t *testing.T) {
	door, pool := formDoor(t)
	ctx := context.Background()

	const (
		owner    = "user:usr_regowner_ca"
		outsider = "user:usr_regoutsider_ca"
		registry = "registry_registry:reg_ca000000000000"
	)
	tx, err := pool.Begin(ctx)
	require.NoError(t, err, "транзакция посева")
	defer func() { _ = tx.Rollback(ctx) }()
	run := func(sql string, args ...any) {
		t.Helper()
		_, err := tx.Exec(ctx, sql, args...)
		require.NoErrorf(t, err, "посев (%s)", sql)
	}
	run(`INSERT INTO kacho_iam.accounts (id, name, owner_user_id)
	     VALUES ('acc_regca', 'registry-account', 'usr_regowner_ca') ON CONFLICT DO NOTHING`)
	for _, u := range []string{"usr_regowner_ca", "usr_regoutsider_ca"} {
		run(`INSERT INTO kacho_iam.users (id, external_id, email, account_id)
		     VALUES ($1, $1, $1 || '@kacho.local', 'acc_regca') ON CONFLICT DO NOTHING`, u)
	}
	run(`INSERT INTO kacho_iam.projects (id, account_id, name)
	     VALUES ('prj_regca', 'acc_regca', 'registry-project') ON CONFLICT DO NOTHING`)
	// Ровно то, что пишет регистрация ресурса реестром: структурный указатель на
	// проект и факт владения. Ни одного `v_*` не пишется.
	run(`INSERT INTO kacho_iam.resource_parent_edge
	       (object_type, object_id, parent_type, parent_id, depth)
	     VALUES ('registry_registry', 'reg_ca000000000000', 'project', 'prj_regca', 1)
	     ON CONFLICT DO NOTHING`)
	run(`INSERT INTO kacho_iam.relation_fact (object_type, object_id, relation, subject)
	     VALUES ('registry_registry', 'reg_ca000000000000', 'owner', 'user:usr_regowner_ca')`)
	require.NoError(t, tx.Commit(ctx), "коммит посева: форма читает СВОЕЙ транзакцией")

	allowed, err := door.Check(ctx, owner, "v_create", registry)
	require.NoError(t, err, "источник не принял вопрос про `v_create` на реестре — "+
		"отношение снято и там, где у него есть читатель")
	require.True(t, allowed,
		"владелец реестра не резолвит `v_create` на своём пространстве имён — CreateRepository "+
			"и docker-push в новый repo отказали бы владельцу на его собственном реестре")

	allowed, err = door.Check(ctx, outsider, "v_create", registry)
	require.NoError(t, err)
	require.False(t, allowed, "посторонний резолвит `v_create` на чужом реестре — сужение исчезло")

	// Парный контроль формы: то же отношение на обычном ресурсном типе НЕ
	// ОБЪЯВЛЕНО. Иначе «оставили одному реестру» было бы неотличимо от «оставили
	// всем». Вместе с положительным ответом выше эта пара и есть дискриминатор:
	// обрыв базы сломал бы обе половины сразу.
	if _, err := door.Check(ctx, owner, "v_create", "vpc_network:net_ca000000000000"); err == nil {
		t.Fatal("тип `vpc_network` ОБЪЯВЛЯЕТ `v_create` — источник принял вопрос и вынес вердикт: " +
			"«оставили одному реестру» снова неотличимо от «оставили всем»")
	}
}
