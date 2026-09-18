// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// catalog_key_form_test.go — гейт формы ключей (kacho#1030, приёмка
// `rule-segments-have-a-referent.md`, требования Т1 и Т2), судимый по
// ДЕЙСТВУЮЩЕЙ схеме.
//
// Проверяются ДВА свойства, и они разные: `RESTRICT … DEFERRABLE` запрещён у
// всякого внешнего ключа схемы, кроме поимённо прощённых ведомостью, а
// `INITIALLY DEFERRED` запрещён ТОЛЬКО на ключах, названных немедленными.
//
// # Почему гейт переехал из `internal/check` и сменил ярус (kaname#278)
//
// Там он читал ОДНУ базовую миграцию — `0001_initial.sql`, — хотя на ревизии
// переезда (`39628487`) миграций было 32. Отсюда две слепоты сразу:
//
//   - ключ, заведённый ПОЗДНЕЙ миграцией, не судился вовсе: на той же ревизии
//     перепись того гейта считала 42 объявления ключа в базовой миграции, а
//     внешних ключей в действующей схеме 49 — ключи поздних миграций (сессии
//     человека, коды восстановления, ключи доступа) были вне наблюдения;
//   - запись ведомости жила, пока ИМЯ стояло в тексте базовой миграции, а
//     применённую не правят (запрет #5) — значит, она не истекла бы НИКОГДА.
//     `DROP COLUMN users.account_id`, который готовит kacho#1351, неявно уносит
//     `users_account_fk`, и прежний гейт остался бы зелёным (замер — инъекция А
//     задачи). Хуже того: сними автор запись вместе с ключом — прежний гейт
//     покраснел бы на ИСПРАВНОМ дереве, требуя держать мёртвое послабление.
//
// Поэтому гейт судит то, что цепочка ОСТАВЛЯЕТ в базе: накат всех миграций на
// настоящий сервер и чтение `pg_constraint` (`live_schema_test.go`). Имя пробы
// сохранено — его называют приёмки. Дом сменён потому, что база с накатанной
// цепочкой у модуля уже есть ровно здесь (шаблон TestMain пакета); завести её в
// `internal/check` значило бы затянуть весь пакет гейтов дерева (762 пробы на
// ревизии переезда) в контейнерное задание, где они прежде не исполнялись и где
// им подставляется дерево платформы (`PLATFORM_TREE`).
//
// ЯРУС — КОНТЕЙНЕРНЫЙ. Под `-short` гейт пропускает себя с названной причиной;
// исполняет его задание `integration` конвейера (`ci.yml`, «интеграция (Postgres
// в контейнерах)»), которое отбирает этот пакет признаком импорта `corelib/pgtest`.
//
// Способность падать и молчать доказана инъекцией настоящим сервером —
// `catalog_key_form_injection_test.go`.

import (
	"fmt"
	"sort"
	"testing"
)

// keyRef — пара «таблица + имя ключа». Имя ограничения уникально лишь в пределах
// таблицы, поэтому и перечень немедленных, и ведомость послаблений адресуют ключ
// парой: тот же ключ на другой таблице — иной предмет.
type keyRef struct{ table, name string }

// catalogImmediateOnlyKeys — ключи проекции правила, обязанные проверяться
// немедленно: отложенный отказ всплывает на коммите, где подсказка одна на
// транзакцию, а сегментов в правиле много — сценарии отказа теряют своего
// производителя (`fkText`, ветви `role_rule_ref_*`, `role_verb_type_fk`).
var catalogImmediateOnlyKeys = []keyRef{
	{"kaname.role_rule_ref", "role_rule_ref_res_fk"},
	{"kaname.role_rule_ref", "role_rule_ref_verb_fk"},
	{"kaname.role_verb", "role_verb_type_fk"},
}

// restrictDeferrableExempt — ключи, которым форма `RESTRICT … DEFERRABLE`
// прощена ПОИМЁННО, с причиной и предикатом снятия.
//
// # Почему прощены, а не объявлены находкой
//
// `accounts.owner_user_id → users.id` и `users.account_id → accounts.id` — цикл,
// и отложенность на нём НЕСУЩАЯ: заведение личного аккаунта вставляет строку
// пользователя первой, а сам аккаунт — следом, в той же транзакции. Это записано
// решением в дереве и цитирует оба ключа поимённо (снятая миграция
// 470001_memberships_expand.sql, комментарий у ключа членства).
//
// Опасность, которую называет запрет, к ним не относится: `ON DELETE RESTRICT`
// не откладывается никогда, но откладывается ПРОВЕРКА СО СТОРОНЫ ССЫЛАЮЩЕГОСЯ —
// ровно та половина, ради которой цикл и объявлен отложенным. Запрет остаётся
// верным там, где автор ждёт отложенности от самого действия удаления.
//
// # Предикат снятия — внешний факт, а не текст
//
// Запись держится, пока ключ этой ПАРЫ «таблица + имя» ЕСТЬ в действующей схеме и
// НЕСЁТ прощённую форму. Снят ключ — явно либо неявно (снятие колонки
// `users.account_id` по kacho#1351 унесёт `users_account_fk` без единой строки
// о нём), — либо ключ сменил форму, и гейт назовёт запись потерявшей предмет:
// «снимите запись». Правильность самой формы для этих двух ключей ЗДЕСЬ НЕ
// РЕШАЕТСЯ: ведомость фиксирует, что вопрос не рассматривался вместе с этим
// гейтом, а не что он решён.
//
// Ведомость адресует ключ ПАРОЙ, а не именем: имя уникально лишь в пределах
// таблицы, и по-именное прощение открыло бы слепую зону всякому одноимённому
// ключу на ЛЮБОЙ другой таблице (проверено инъекцией «чужая таблица»).
var restrictDeferrableExempt = []keyRef{
	{"kaname.accounts", "accounts_owner_fk"},
	{"kaname.users", "users_account_fk"},
}

// TestIAMCT113_CatalogKeysCarryTheDeclaredForm — Т1 и Т2.
func TestIAMCT113_CatalogKeysCarryTheDeclaredForm(t *testing.T) {
	schema := liveSchemaOfTheChain(t)

	census, findings := auditLiveKeyForm(schema, catalogImmediateOnlyKeys, restrictDeferrableExempt)
	t.Logf("перепись: %s · %s", schema.census(), census)
	if len(schema.foreignKeys()) == 0 {
		t.Fatal("внешних ключей в действующей схеме 0 — обход пуст, вердикт беспредметен")
	}
	for _, f := range findings {
		t.Error(f)
	}
}

// auditLiveKeyForm — ЧИСТЫЙ предикат гейта над действующей схемой. Вынесен,
// чтобы инъекция гоняла ровно его на схеме, которую строит настоящий сервер.
//
// И перечень немедленных, и ведомость послаблений адресуют ключ ПАРОЙ «таблица +
// имя»: имя уникально лишь в пределах таблицы (`live_schema_test.go`
// §foreignKeysByRef).
func auditLiveKeyForm(s liveSchema, immediateOnly, exempt []keyRef) (census string, findings []string) {
	exempted := map[keyRef]bool{}
	for _, r := range exempt {
		exempted[r] = true
	}
	keys := s.foreignKeys()
	restrictDeferrable, forgiven := 0, 0
	for _, k := range keys {
		if !k.restrictBesideDeferrable() {
			continue
		}
		restrictDeferrable++
		if exempted[keyRef{k.relation, k.name}] {
			forgiven++
			continue
		}
		findings = append(findings, fmt.Sprintf("ключ %s на %s несёт RESTRICT рядом с DEFERRABLE: "+
			"форма принимается DDL и молча инертна — проверка остаётся немедленной "+
			"(измерено, приёмка rule-segments-have-a-referent §0.2 Н2)", k.name, k.relation))
	}

	immediateFound := 0
	for _, ref := range immediateOnly {
		named := s.foreignKeysByRef(ref.table, ref.name)
		if len(named) == 0 {
			findings = append(findings, "ключ "+ref.name+" на "+ref.table+" в действующей схеме не существует: "+
				"гейт судил бы имя, которого нет, — снят явно либо унесён неявно (DROP COLUMN, DROP TABLE, CASCADE)")
			continue
		}
		immediateFound++
		for _, c := range named {
			if c.initiallyDeferred {
				findings = append(findings, "ключ "+ref.name+" на "+c.relation+" объявлен INITIALLY DEFERRED: "+
					"отказ всплывёт на коммите, где подсказка одна на транзакцию, а сегментов "+
					"в правиле много — сценарии отказа теряют своего производителя")
			}
		}
	}

	// Самоистечение: запись, у которой в ДЕЙСТВУЮЩЕЙ схеме нет предмета, —
	// находка. Без этого ведомость пережила бы снятие ключа и осталась бы слепой
	// зоной, выданной вперёд следующему ключу той же пары.
	for _, ref := range exempt {
		named := s.foreignKeysByRef(ref.table, ref.name)
		if len(named) == 0 {
			findings = append(findings, "послабление на RESTRICT рядом с DEFERRABLE названо для ключа "+ref.name+
				" на "+ref.table+", а в действующей схеме такого ключа нет (снят явно либо унесён неявно — "+
				"DROP COLUMN, DROP TABLE, CASCADE): исключению нечего исключать — снимите запись, иначе следующий "+
				"ключ той же пары уедет под него незамеченным")
			continue
		}
		carries := false
		for _, c := range named {
			if c.restrictBesideDeferrable() {
				carries = true
			}
		}
		if !carries {
			findings = append(findings, "послабление на RESTRICT рядом с DEFERRABLE названо для ключа "+ref.name+
				" на "+ref.table+", а ключ этой формы больше не несёт: исключению нечего исключать — снимите запись")
		}
	}
	sort.Strings(findings)

	census = fmt.Sprintf("ключей с формой RESTRICT рядом с DEFERRABLE %d, из них прощено ведомостью %d "+
		"(записей %d) · немедленных по объявлению %d, найдено в схеме %d",
		restrictDeferrable, forgiven, len(exempt), len(immediateOnly), immediateFound)
	return census, findings
}
