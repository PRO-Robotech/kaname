// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package parentedge_test

// rootreach_integration_test.go — ЦЕПЬ ОБЯЗАНА ДОХОДИТЬ ДО КОРНЯ, А НЕ ПРОСТО
// СУЩЕСТВОВАТЬ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕМ ЭТОТ ГЕЙТ ОТЛИЧАЕТСЯ ОТ СОСЕДНЕГО
//
// Соседний (`completeness_integration_test.go`) судит НАЛИЧИЕ: у строки зеркала
// есть хоть одно ребро. Он сам это оговаривает — «гейт судит наличие цепи, а не
// её длину», — и именно поэтому пропускает целый класс: объект, у которого ребро
// есть, но цепь обрывается ниже корня. Для такого объекта выдача на аккаунт и
// прямой факт администратора облака на кластере НЕ НАХОДЯТСЯ, а отказ той же
// формы, что и честный: ни один прогон его не покажет.
//
// Ровно этим и был kacho#740: рёбра писали пять сервисов-соседей и только для
// СВОИХ ресурсов, объектов типа project и account не регистрировал никто, — то
// есть у каждого объекта арендатора ребро было (гейт наличия молчал), а цепь
// кончалась на проекте.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ИМЕННО ИЗМЕРЯЕТСЯ
//
// Не длина в звеньях: у объектов разной глубины она законно разная (сеть — три
// звена до кластера, репозиторий — четыре). Измеряется ДОСТИЖИМОСТЬ КОРНЯ тем же
// обходом, каким её видит вопрос о доступе: поднимаемся по `resource_scope_edge`
// до предела `MaxAncestorDepth` и требуем, чтобы в замыкании оказался объект типа
// `cluster`.
//
// Перечня исключений у гейта НЕТ, и это не забывчивость. Затравка обхода — сам
// объект на глубине 0, поэтому у строки зеркала типа `cluster` условие выполнено
// ею же; аккаунт поднимается до кластера одним звеном. То есть корневые типы
// удовлетворяют предикату ПО ПОСТРОЕНИЮ, а не по списку — а список, которому
// нечего исключать, сам становится находкой.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ФИКСТУРА СЕЕТСЯ ПРОИЗВОДИТЕЛЕМ
//
// Та же причина, что у соседнего гейта, и она уже подтверждена прогоном: пока
// фикстура клала рёбра прямо, она утверждала собственное свойство и оставалась
// зелёной, когда производителю вырезали запись цепи целиком. Здесь регистрация
// идёт тем же вызовом, которым её делает продукт, а звенья выше проекта берутся
// из настоящих строк `projects` / `accounts` / `clusters` — то есть из того же
// места, откуда их берёт представление.

import (
	"context"
	"fmt"
	"sort"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
)

// seedTenantRows кладёт арендную обвязку НАСТОЯЩИМИ строками: аккаунт,
// пользователя-владельца и проект — И указатель проекта на аккаунт В ЖУРНАЛ.
//
// Звенья достройки берутся из РАЗНЫХ источников, и фикстура обязана повторять
// оба (#781): предок аккаунта — синглтон `clusters` (схема; аккаунты сеются
// миграциями, указателя в журнале у них нет), предок проекта — проекция журнала
// `relation_fact`, куда его со-коммитит `Project.Create` в одной транзакции со
// строкой `projects`.
//
// Прежняя редакция писала ТОЛЬКО строку состояния проекта. Пока цепь брала
// предка оттуда, этого хватало; теперь такая фикстура строила бы проект, о
// котором ЖУРНАЛ не знает, — состояние, которого продукт не производит, и гейт
// судил бы не то дерево. Фикстура, обходящая внешние ключи
// или производителя, доказывала бы работу представления на данных, которых в
// проде не бывает.
func seedTenantRows(t *testing.T, pool *pgxpool.Pool, accountID string, projectIDs ...string) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("транзакция посева арендатора: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Ссылка КРУГОВАЯ: у аккаунта есть владелец-пользователь, у пользователя —
	// аккаунт. Разрешается отложенным внешним ключом владельца — аккаунт
	// вставляется первым и проверяется на COMMIT.
	owner := "usr-" + accountID
	if _, err := tx.Exec(ctx,
		`INSERT INTO kaname.accounts (id, name, owner_user_id) VALUES ($1, $2, $3)`,
		accountID, "acct-"+accountID, owner); err != nil {
		t.Fatalf("посев аккаунта %s: %v", accountID, err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO kaname.users (id, external_id, email, account_id) VALUES ($1, $2, $3, $4)`,
		owner, "ext-"+owner, owner+"@kacho.local", accountID); err != nil {
		t.Fatalf("посев владельца аккаунта %s: %v", accountID, err)
	}
	for i, prj := range projectIDs {
		if _, err := tx.Exec(ctx,
			`INSERT INTO kaname.projects (id, account_id, name) VALUES ($1, $2, $3)`,
			prj, accountID, fmt.Sprintf("prj-name-%d", i)); err != nil {
			t.Fatalf("посев проекта %s: %v", prj, err)
		}
		// Тот же со-коммит, что делает продукт: строка журнала, из которой
		// триггер 0098 наполняет проекцию. Применение проверяется числом —
		// молча не спроецировавшаяся строка оставила бы гейт зелёным ни на чём.
		if _, err := tx.Exec(ctx,
			`INSERT INTO kaname.fga_outbox (event_type, payload, created_at)
			 VALUES ('fga.tuple.write',
			         jsonb_build_object('user', 'account:' || $1::text,
			                            'relation', 'account',
			                            'object', 'project:' || $2::text),
			         now())`, accountID, prj); err != nil {
			t.Fatalf("со-коммит указателя проекта %s в журнал: %v", prj, err)
		}
		var landed int
		if err := tx.QueryRow(ctx,
			`SELECT count(*)::int FROM kaname.relation_fact
			  WHERE object_type = 'project' AND object_id = $1 AND relation = 'account'`,
			prj).Scan(&landed); err != nil {
			t.Fatalf("перепись проекции журнала для %s: %v", prj, err)
		}
		if landed != 1 {
			t.Fatalf("указатель проекта %s не спроецировался в relation_fact (найдено %d): "+
				"фикстура ничего не посеяла", prj, landed)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("фиксация посева арендатора: %v", err)
	}
}

// reach — исход одного объекта зеркала: доходит ли его цепь до корня и есть ли у
// него ребро вообще.
//
// Второе поле стоит рядом с первым НАМЕРЕННО: именно им доказывается, что этот
// гейт судит не то же самое, что соседний. Объект с `hasEdge = true` и
// `reachesRoot = false` — тот самый класс, который гейт наличия объявляет
// покрытым.
type reach struct {
	object      string
	reachesRoot bool
	hasEdge     bool
}

// rootReach — ОДИН стейтмент: обход цепи каждого объекта зеркала до предела и
// проверка, оказался ли в замыкании кластер.
//
// # Почему один стейтмент, а не «прочитать зеркало и спросить по строке»
//
// Утверждение здесь — КВАНТОР по множеству, и он обязан остаться одним вопросом
// к базе (та же причина, что у соседнего гейта: перепись, разложенная на
// строку-за-строкой, перестаёт быть переписью).
//
// # Почему обход, а не одно чтение
//
// Потому что так спрашивает вопрос о доступе. Одно чтение подтвердило бы
// достижимость корня там, где её нет, и гейт зеленел бы на дефекте, ради
// которого написан.
func rootReach(t *testing.T, pool *pgxpool.Pool) (examined int, out []reach) {
	t.Helper()
	ctx := context.Background()

	catalogNames, modelNames := typeDictionaryPairs()
	rows, err := pool.Query(ctx,
		`WITH RECURSIVE
		 dict(catalog_name, model_name) AS (SELECT * FROM unnest($1::text[], $2::text[])),
		 mirrored(model_type, object_id) AS (
		     SELECT COALESCE((SELECT d.model_name FROM dict d WHERE d.catalog_name = m.object_type),
		                     m.object_type),
		            m.object_id
		       FROM kaname.resource_mirror m
		 ),
		 climb(model_type, object_id, s_type, s_id, depth) AS (
		     SELECT o.model_type, o.object_id, o.model_type, o.object_id, 0 FROM mirrored o
		   UNION
		     SELECT c.model_type, c.object_id, e.parent_type, e.parent_id, c.depth + 1
		       FROM climb c
		       JOIN kaname.resource_scope_edge e
		         ON e.object_type = c.s_type AND e.object_id = c.s_id
		      WHERE c.depth < $3::int
		 )
		 SELECT o.model_type, o.object_id,
		        EXISTS (SELECT 1 FROM climb c
		                 WHERE c.model_type = o.model_type AND c.object_id = o.object_id
		                   AND c.s_type = 'cluster'),
		        EXISTS (SELECT 1 FROM kaname.resource_parent_edge e
		                 WHERE e.object_type = o.model_type AND e.object_id = o.object_id)
		   FROM mirrored o`,
		catalogNames, modelNames, relverdict.MaxAncestorDepth)
	if err != nil {
		t.Fatalf("перепись достижимости корня: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var typ, id string
		var reachesRoot, hasEdge bool
		if err := rows.Scan(&typ, &id, &reachesRoot, &hasEdge); err != nil {
			t.Fatalf("чтение строки переписи: %v", err)
		}
		examined++
		out = append(out, reach{object: typ + ":" + id, reachesRoot: reachesRoot, hasEdge: hasEdge})
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("обход переписи: %v", err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].object < out[j].object })
	return examined, out
}

// notReachingRoot — имена объектов, чья цепь до корня не доходит.
func notReachingRoot(rows []reach) []string {
	var out []string
	for _, r := range rows {
		if !r.reachesRoot {
			out = append(out, r.object)
		}
	}
	return out
}

// ЗАКОННАЯ СТОРОНА: цепь КОРОТКАЯ — ровно то одно звено, которое шлёт vpc, — и
// этого достаточно.
//
// Гейт обязан молчать: длина не предмет, предмет — достижимость. Без этой
// стороны гейт ловил бы форму (сколько звеньев прислал владелец), а первое же
// ложное срабатывание сняли бы вместе с запретом.
func TestScopeChainReachesTheRoot_SilentOnTheShortChainTheTreeProduces(t *testing.T) {
	pool := openPool(t)
	seedTenantRows(t, pool, "acc-1", "prj-1")
	seedThroughProducer(t, pool,
		registration{
			consumer: "vpc", objectType: catalogFormOf(t, "vpc_network"), objectID: "net-1",
			parentProjectID: "prj-1",
			parentChain:     []string{"project:prj-1"},
		},
	)

	examined, rows := rootReach(t, pool)
	missing := notReachingRoot(rows)
	t.Logf("осмотрено строк зеркала: %d; не достающих до корня: %d", examined, len(missing))

	if examined == 0 {
		t.Fatal("зеркало пусто — «ноль не достающих» здесь означало бы «сверять было нечего»")
	}
	if len(missing) != 0 {
		t.Fatalf("гейт нашёл недостижимость на законном множестве: %v. Цепь из одного звена "+
			"законна: предок проекта берётся из собственной схемы iam", missing)
	}
}

// СТОРОНА ДЕФЕКТА, РАДИ КОТОРОЙ ГЕЙТ ЗАВЕДЁН: ребро ЕСТЬ, а корня цепь не
// достигает.
//
// Это ровно тот класс, который соседний гейт объявляет покрытым, и проба
// утверждает оба факта разом: `hasEdge` истинно, `reachesRoot` ложно. Ребро
// указывает на проект, которого iam не знает, — то есть достройке не из чего
// взять аккаунт.
func TestScopeChainReachesTheRoot_NamesTheObjectWhoseChainStopsBelowTheRoot(t *testing.T) {
	pool := openPool(t)
	seedTenantRows(t, pool, "acc-1", "prj-1")
	seedThroughProducer(t, pool,
		registration{
			consumer: "vpc", objectType: catalogFormOf(t, "vpc_network"), objectID: "net-1",
			parentProjectID: "prj-1",
			parentChain:     []string{"project:prj-1"},
		},
		registration{
			consumer: "vpc (проект вне iam)", objectType: catalogFormOf(t, "vpc_network"), objectID: "net-9",
			parentProjectID: "prj-unknown",
			parentChain:     []string{"project:prj-unknown"},
		},
	)

	examined, rows := rootReach(t, pool)
	missing := notReachingRoot(rows)
	t.Logf("осмотрено строк зеркала: %d; не достающих до корня: %d %v", examined, len(missing), missing)

	if len(missing) != 1 || missing[0] != "vpc_network:net-9" {
		t.Fatalf("объект, чья цепь обрывается ниже корня, не назван: %v — отказ по нему той же "+
			"формы, что честный, и ни один прогон его не покажет", missing)
	}
	// РАЗЛИЧИЕ С СОСЕДНИМ ГЕЙТОМ, УТВЕРЖДЁННОЕ, А НЕ ЗАЯВЛЕННОЕ: у находки ребро
	// ЕСТЬ. Гейт наличия молчит на ней by construction.
	for _, r := range rows {
		if r.object == "vpc_network:net-9" && !r.hasEdge {
			t.Fatalf("у находки нет ребра вовсе — тогда её поймал бы и гейт наличия, и этот " +
				"гейт не доказал бы, что судит другой предмет")
		}
	}
}

// ВТОРАЯ СТОРОНА ДЕФЕКТА: цепь не выслана вовсе.
//
// Гейт наличия ловит и это; здесь утверждается, что новый гейт не СЛАБЕЕ
// старого, а строго сильнее.
func TestScopeChainReachesTheRoot_NamesTheObjectRegisteredWithoutAChain(t *testing.T) {
	pool := openPool(t)
	seedTenantRows(t, pool, "acc-1", "prj-1")
	seedThroughProducer(t, pool,
		registration{
			consumer: "vpc (цепь не выслана)", objectType: catalogFormOf(t, "vpc_network"), objectID: "net-1",
			parentProjectID: "prj-1",
		},
	)

	_, rows := rootReach(t, pool)
	missing := notReachingRoot(rows)
	if len(missing) != 1 || missing[0] != "vpc_network:net-1" {
		t.Fatalf("объект без цепи не назван: %v", missing)
	}
}

// ГЛУБОКАЯ ЦЕПЬ ЦЕЛИКОМ: репозиторий → реестр → проект → аккаунт → кластер.
//
// Четыре звена — предел `MaxAncestorDepth`. Без этой пробы «достаёт до корня»
// осталось бы утверждением про двухуровневые ресурсы, а самый глубокий в дереве
// путь так и остался бы непроверенным.
func TestScopeChainReachesTheRoot_SilentOnTheDeepestChainInTheTree(t *testing.T) {
	pool := openPool(t)
	seedTenantRows(t, pool, "acc-1", "prj-1")
	seedThroughProducer(t, pool,
		registration{
			consumer: "registry (реестр)", objectType: catalogFormOf(t, "registry_registry"), objectID: "reg-1",
			parentProjectID: "prj-1",
			parentChain:     []string{"project:prj-1"},
		},
		registration{
			consumer: "registry (репозиторий)", objectType: catalogFormOf(t, "registry_repository"), objectID: "repo-1",
			parentChain: []string{"registry_registry:reg-1", "project:prj-1"},
		},
	)

	examined, rows := rootReach(t, pool)
	missing := notReachingRoot(rows)
	t.Logf("осмотрено строк зеркала: %d; не достающих до корня: %d %v", examined, len(missing), missing)
	if len(missing) != 0 {
		t.Fatalf("глубочайшая цепь дерева до корня не дошла: %v — предел обхода (%d) и высота "+
			"цепи разошлись", missing, relverdict.MaxAncestorDepth)
	}
}

// ПРЕДПОСЫЛКА САМОГО ГЕЙТА: на пустом зеркале сверять нечего, и это обязано быть
// отличимо от «всё достаёт».
func TestScopeChainReachesTheRoot_FailsOnAnEmptyMirror(t *testing.T) {
	pool := openPool(t)
	examined, rows := rootReach(t, pool)
	if examined != 0 || len(rows) != 0 {
		t.Fatalf("пустое зеркало дало осмотрено=%d строк=%d — предпосылка пробы неверна",
			examined, len(rows))
	}
	t.Log("подтверждено: ноль осмотренных отличимо от нуля не достающих до корня")
}
