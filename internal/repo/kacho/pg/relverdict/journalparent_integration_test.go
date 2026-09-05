// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// journalparent_integration_test.go — ПРЕДОК БЕРЁТСЯ ОТТУДА ЖЕ, ОТКУДА ЕГО БЕРЁТ
// ДВИЖОК.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ (#781)
//
// Цепь областей выводила звено «проект → аккаунт» из ТАБЛИЦЫ СОСТОЯНИЯ
// (`kacho_iam.projects`), тогда как тот же указатель уже лежит в ПРОЕКЦИИ
// ЖУРНАЛА (`relation_fact`, `object_type='project'`, `relation='account'`) — и
// приезжает он туда ТОЙ ЖЕ строкой журнала, из которой свёрнуто состояние
// движка отношений (миграция 0098). Два места об одном предмете разошлись:
// на стенде 2026-08-20 состояние знало 38 проектов, журнал — 236.
//
// Следствие наблюдаемо: выдача, сделанная на аккаунт, до объекта арендатора под
// «журнальным» проектом НЕ ДОХОДИТ, при том что движок её разрешает. Отказ при
// этом НЕОТЛИЧИМ от честного.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ПРОБА СУДИТ ВЕРДИКТ, А НЕ СТРОКИ ПРЕДСТАВЛЕНИЯ
//
// «Представление вернуло строку» — утверждение о форме, и оно осталось бы
// зелёным при любой ошибке в том, КАК эту строку читает обход. Спрашивается то
// же, что спрашивает продукт: `relverdict.Ask`. Расхождение с движком имеет
// смысл ровно на этом уровне — движку тоже задают вопрос, а не показывают
// таблицу.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ФИКСТУРА СЕЕТ ЧЕРЕЗ ЖУРНАЛ, А НЕ ПРЯМО В ПРОЕКЦИЮ
//
// У проекции ровно один производитель — триггер `relation_fact_follows_journal`
// на строке `kacho_iam.fga_outbox`. Посев прямо в `relation_fact` обошёл бы его
// и доказывал бы работу на данных, которые в продукте появиться не могут.
// Строка журнала кладётся ТЕМИ ЖЕ тремя колонками и той же формой полезной
// нагрузки, какими её кладёт эмиттер (`fga_outbox/emitter.go`), а применение
// проекции проверяется числом: молча не спроецировавшаяся строка оставила бы
// пробу зелёной ни на чём.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/relverdict"
	"github.com/PRO-Robotech/kacho/pkg/ownerregister"
)

// pointerThroughJournal — указатель на предка, положенный ЕДИНСТВЕННЫМ
// производителем проекции: строкой журнала намерений.
//
// Возврата нет, но есть проверка применения: после вставки строка обязана
// появиться в `relation_fact`. Без неё фикстура, разошедшаяся с триггером,
// оставила бы пробу зелёной на пустом месте.
func pointerThroughJournal(t *testing.T, ctx context.Context, tx pgx.Tx,
	objectType, objectID, relation, subject string) {
	t.Helper()
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.fga_outbox (event_type, payload, created_at)
		 VALUES ('fga.tuple.write',
		         jsonb_build_object('user', $1::text, 'relation', $2::text,
		                            'object', $3::text || ':' || $4::text),
		         now())`,
		subject, relation, objectType, objectID)

	var landed int
	if err := tx.QueryRow(ctx,
		`SELECT count(*)::int FROM kacho_iam.relation_fact
		  WHERE object_type = $1 AND object_id = $2 AND relation = $3 AND subject = $4`,
		objectType, objectID, relation, subject).Scan(&landed); err != nil {
		t.Fatalf("перепись проекции журнала: %v", err)
	}
	if landed != 1 {
		t.Fatalf("строка журнала %s:%s --%s--> %s не спроецировалась в relation_fact (найдено %d): "+
			"фикстура ничего не посеяла, и проба судила бы пустое состояние",
			objectType, objectID, relation, subject, landed)
	}
}

// countScalar — короткая перепись одним числом.
func countScalar(t *testing.T, ctx context.Context, tx pgx.Tx, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := tx.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
		t.Fatalf("перепись (%s): %v", sql, err)
	}
	return n
}

// TestScopeChainTakesTheParentFromTheJournalNotTheStateTable — #781.
//
// # Что здесь утверждается
//
// Выдача на АККАУНТ достаёт до объекта арендатора, лежащего под проектом,
// которого таблица состояния НЕ ЗНАЕТ, а журнал знает. Это ровно та форма, из
// которой состоит расхождение стенда: 198 проектов из 236 существуют только в
// журнале.
//
// # Пара, без которой утверждение вакуумно
//
// Положительное утверждение здесь легко зеленеет на форме, которая разрешает
// всем, поэтому рядом стоят три контроля и ни один не факультативен:
//
//	(1) выдача на САМ проект достаёт и сегодня — иначе (2) ничего не говорило бы
//	    о высоте цепи, а говорило бы о том, что сломан обход целиком;
//	(3) субъект БЕЗ выдачи получает отказ — обе стороны отказывают;
//	(4) проект, которого нет НИ в состоянии, НИ в журнале, до корня не поднимает —
//	    иначе «читает журнал» неотличимо от «подставляет корень всякому».
//
// # Почему проба красна ДО правки и по какой причине
//
// Представление `resource_scope_edge` (миграция 740001) выводит предка проекта
// из `kacho_iam.projects`. Строки `prj-journal` там нет, поэтому цепь
// останавливается на проекте: (2) отдаёт Deny. Красное на (2) при зелёных (1),
// (3) и (4) — это и есть нужная причина; красное на (1) означало бы, что сломана
// фикстура, а не предмет.
func TestScopeChainTakesTheParentFromTheJournalNotTheStateTable(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		seedRole(t, ctx, tx, "rol-any", "vpc_network", "get", "anchor", "{}")

		// Проект, существующий ТОЛЬКО в журнале. Указатель кладётся строкой
		// журнала — так же, как его кладёт создание проекта, со-коммитящее
		// иерархический кортеж в той же транзакции.
		pointerThroughJournal(t, ctx, tx, "project", "prj-journal", "account", "account:acc-1")

		// ПРЕДПОСЫЛКА, названная числами. Без неё проба могла бы пройти по
		// причине, которой не заявляла: например, потому что кто-то досеял
		// строку состояния.
		if inState := countScalar(t, ctx, tx,
			`SELECT count(*)::int FROM kacho_iam.projects WHERE id = 'prj-journal'`); inState != 0 {
			t.Fatalf("проект prj-journal оказался в таблице состояния (%d строк) — предмет пробы "+
				"исчез: она судила бы обычный проект, а не тот, что живёт только в журнале", inState)
		}
		inJournal := countScalar(t, ctx, tx,
			`SELECT count(*)::int FROM kacho_iam.relation_fact
			  WHERE object_type = 'project' AND object_id = 'prj-journal' AND relation = 'account'`)
		if inJournal != 1 {
			t.Fatalf("указателя проекта в журнале %d, ожидался ровно один", inJournal)
		}
		t.Logf("предпосылка: prj-journal — в состоянии 0 строк, в проекции журнала %d; "+
			"это форма 198 из 236 проектов стенда", inJournal)

		// Объект арендатора под этим проектом — РОВНО ОДНО звено, как шлёт vpc.
		base := time.Now().UTC().Truncate(time.Microsecond)
		registerThroughProducer(t, ctx, tx, catalogFormOf(t, "vpc_network"), "net-j",
			ownerregister.ParentChain(nil, "prj-journal", ""), "prj-journal", "", base)
		// Второй объект — под проектом, которого не знает НИ ОДИН из двух
		// источников. Он держит отрицание (4).
		registerThroughProducer(t, ctx, tx, catalogFormOf(t, "vpc_network"), "net-nowhere",
			ownerregister.ParentChain(nil, "prj-nowhere", ""), "prj-nowhere", "",
			base.Add(time.Millisecond))

		ask := func(subject, objectID string) relverdict.Verdict {
			t.Helper()
			got, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
				Subject: subject, ObjectType: "vpc_network", ObjectID: objectID, Relation: "v_get",
			})
			if err != nil {
				t.Fatalf("вопрос о %s над %s: %v", subject, objectID, err)
			}
			return got
		}
		grant := func(bindingID, scopeType, scopeID, subjectID string) {
			t.Helper()
			exec(t, ctx, tx,
				`INSERT INTO kacho_iam.access_bindings
				   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
				 VALUES ($1, 'user', $4, 'rol-any', $2, $3, 'ACTIVE')`,
				bindingID, scopeType, scopeID, subjectID)
			exec(t, ctx, tx,
				`INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id)
				 VALUES ($1, 'user', $2)`, bindingID, subjectID)
		}

		// ── (1) КОНТРОЛЬ ПЕРВЫМ: до самого проекта обход доходит ──────────────
		grant("acb-prj", "project", "prj-journal", "usr-1")
		if got := ask("user:usr-1", "net-j"); got != relverdict.Allow {
			t.Fatalf("выдача на САМ проект не достала до объекта: %s. Контроль провален — "+
				"утверждения ниже ничего не сказали бы о высоте цепи", got)
		}
		exec(t, ctx, tx, `DELETE FROM kacho_iam.access_bindings WHERE id = 'acb-prj'`)
		t.Log("контроль: выдача на проект — allow, обход до непосредственного предка работает")

		// ── (2) ПРЕДМЕТ: выдача на АККАУНТ через журнальное звено ─────────────
		grant("acb-acc", "account", "acc-1", "usr-1")
		if got := ask("user:usr-1", "net-j"); got != relverdict.Allow {
			t.Errorf("выдача на АККАУНТ не достала до объекта под «журнальным» проектом: %s. "+
				"Предок проекта берётся из таблицы состояния, которой этот проект неизвестен, "+
				"тогда как движок читает свёртку журнала и доступ РАЗРЕШАЕТ — форма расходится "+
				"с действующим решателем, и отказ неотличим от честного (#781)", got)
		}

		// ── (3) КОНТРОЛЬ ПАРЫ: без выдачи отказывают обе стороны ──────────────
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.users (id, external_id, email, account_id)
			 VALUES ('usr-none', 'ext-none', 'none@kacho.local', 'acc-1')`)
		if got := ask("user:usr-none", "net-j"); got != relverdict.Deny {
			t.Errorf("субъект БЕЗ выдачи получил доступ к объекту: %s — значит утверждение (2) "+
				"зеленело бы на форме, которая разрешает всем", got)
		}

		// ── (4) ОТРИЦАНИЕ: предок не выдумывается там, где его нет ────────────
		if got := ask("user:usr-1", "net-nowhere"); got != relverdict.Deny {
			t.Errorf("выдача на аккаунт достала до объекта под проектом, которого нет НИ в "+
				"состоянии, НИ в журнале: %s — значит звено подставляется безусловно, а не "+
				"читается из данных", got)
		}
	})
}
