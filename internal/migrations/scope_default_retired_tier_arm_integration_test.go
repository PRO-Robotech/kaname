// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// scope_default_retired_tier_arm_integration_test.go — умолчание области не
// знает яруса, снятого из словаря (задача продукта #2060).
//
// # Предмет
//
// Триггер `access_bindings_scope_default_trg` проставляет `scope`, когда писатель
// его не назвал, разбирая `resource_type` оператором `CASE`. Среди ветвей стояла
// `organization` → кластерный ярус. Такого яруса в словаре нет: якорь привязки —
// три яруса (`cluster`/`account`/`project`), публичный `Create` приводит
// `scopeType` закрытым переводом, остальные писатели ставят ярус литералом.
//
// Ветвь БЕЗВРЕДНА и НЕДОСТИЖИМА — она ничего не ломает и сломаться не может.
// Чинится не риск, а то, что мёртвая запись читается следующим как ДЕЙСТВУЮЩИЙ
// словарь: перечень ярусов в этом дереве объявлен не одним местом, и лишняя
// запись вводит в заблуждение ровно там, где точность нужна.
//
// # Почему проба судит ЖИВУЮ схему, а не текст миграций
//
// Текстовый предикат по каталогу миграций (`git grep "'organization'"`) считает
// находкой и то объявление, чей предмет снят более поздней миграцией. Здесь
// цепь проигрывается целиком и спрашивается ИТОГОВОЕ состояние: какая функция
// висит на таблице сегодня и что она делает.
//
// # Почему функция зовётся на ЧЕРНОВОЙ таблице, а не на `access_bindings`
//
// Вставка в саму `access_bindings` проходит ещё через три триггера (роль
// назначаема · роль жива · субъект существует) и внешний ключ на роли. Тогда
// отказ пришёл бы от соседа, а не от предмета, и утверждение измеряло бы
// фикстуру. Черновая таблица несёт РОВНО те две колонки, которых функция
// касается (`resource_type`, `scope`), а сама функция берётся ЖИВАЯ, из
// каталога, по имени — не копией её текста.
//
// # Обе стороны, иначе утверждения нет
//
// Отрицание «ветви снятого яруса нет» выполняется тождественно на функции,
// снятой целиком, и на функции, отвергающей всё. Поэтому рядом стоят ЧЕТЫРЕ
// положительных контроля: три живых яруса по-прежнему дают 1 / 2 / 3, неизвестный
// вид по-прежнему падает в умолчание, а названный писателем `scope` по-прежнему
// не перезаписывается. Все четыре зелены и ДО правки, и ПОСЛЕ — краснеет только
// снятый ярус.
package migrations_test

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// retiredScopeTier — ярус, снятый из словаря; ветвь под него и есть предмет.
const retiredScopeTier = "organization"

// scopeDefaultFunc — функция умолчания области, взятая по имени из каталога.
const scopeDefaultFunc = "access_bindings_scope_default"

// TestIntegration_ScopeDefaultKnowsNoRetiredTier — у умолчания области нет ветви
// под ярус, которого нет в словаре.
func TestIntegration_ScopeDefaultKnowsNoRetiredTier(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	db := freshIamSchema(t)

	src := scopeDefaultLiveSource(t, db)

	// ── предпосылка: функция ЖИВА и висит на своей таблице ──
	// Без неё всё нижеследующее зеленело бы на пустой схеме: «ветви нет» верно
	// и там, где нет самой функции.
	require.NotEmpty(t, src,
		"функция %s не найдена среди триггерных функций kaname.access_bindings: "+
			"цепь миграций не накатилась либо триггер снят — тогда утверждения ниже "+
			"беспредметны, а не выполнены", scopeDefaultFunc)

	arms := caseArmsOf(src)
	require.NotEmpty(t, arms,
		"в теле %s не разобрано ни одной ветви CASE: разбор читает не то, "+
			"и «ветви снятого яруса нет» означало бы «ничего не прочитано»", scopeDefaultFunc)
	t.Logf("перепись: ветвей CASE в живом теле %s — %d: %s",
		scopeDefaultFunc, len(arms), strings.Join(arms, " "))

	probe := attachScopeDefaultTo(t, db)

	// ── предмет ──
	t.Run("снятый ярус не назван телом функции", func(t *testing.T) {
		require.NotContains(t, src, retiredScopeTier,
			"живое тело %s всё ещё называет ярус %q, снятый из словаря: "+
				"мёртвая запись читается следующим как действующий перечень ярусов",
			scopeDefaultFunc, retiredScopeTier)
	})

	t.Run("снятый ярус падает в умолчание, а не в кластерный ярус", func(t *testing.T) {
		require.Equal(t, int16(3), scopeAssignedFor(t, db, probe, retiredScopeTier),
			"вид %q получил СВОЙ ярус, а не умолчание: у него осталась собственная ветвь, "+
				"то есть словарь функции шире словаря домена", retiredScopeTier)
	})

	// ── положительные контроли: они зелены по обе стороны правки ──
	for _, tc := range []struct {
		kind string
		want int16
		why  string
	}{
		{"cluster", 1, "кластерный ярус"},
		{"account", 2, "ярус аккаунта"},
		{"project", 3, "ярус проекта"},
		{"nonesuch", 3, "неизвестный вид — ветвь умолчания"},
	} {
		t.Run("контроль: "+tc.why+" сохранён", func(t *testing.T) {
			require.Equal(t, tc.want, scopeAssignedFor(t, db, probe, tc.kind),
				"вид %q больше не даёт ярус %d: правка задела достижимый вход, "+
					"а её предмет — недостижимый", tc.kind, tc.want)
		})
	}

	t.Run("контроль: названный писателем ярус не перезаписывается", func(t *testing.T) {
		var got int16
		require.NoError(t, db.QueryRow(`
			INSERT INTO `+probe+` (resource_type, scope)
			VALUES ('cluster', 2) RETURNING scope`).Scan(&got))
		require.Equal(t, int16(2), got,
			"функция перезаписала явно названный ярус: сторож `IF NEW.scope IS NULL` "+
				"снят — умолчание стало принуждением")
	})
}

// scopeDefaultLiveSource — тело функции умолчания, взятое из каталога и ТОЛЬКО
// если она висит триггером на `kaname.access_bindings`.
//
// Спрашивается связка триггер→функция, а не функция по имени: функция без
// триггера ничего не проставляет, и судить её текст значило бы судить мёртвый код.
func scopeDefaultLiveSource(t *testing.T, db *sql.DB) string {
	t.Helper()
	var src string
	err := db.QueryRow(`
		SELECT p.prosrc
		  FROM pg_trigger tg
		  JOIN pg_proc  p ON p.oid = tg.tgfoid
		  JOIN pg_class c ON c.oid = tg.tgrelid
		  JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE NOT tg.tgisinternal
		   AND n.nspname = 'kaname'
		   AND c.relname = 'access_bindings'
		   AND p.proname = $1`, scopeDefaultFunc).Scan(&src)
	if err == sql.ErrNoRows {
		return ""
	}
	require.NoError(t, err)
	return src
}

// attachScopeDefaultTo — черновая таблица с ЖИВОЙ функцией на BEFORE INSERT.
// Возвращает её полное имя.
func attachScopeDefaultTo(t *testing.T, db *sql.DB) string {
	t.Helper()
	const tbl = "kaname.scope_default_probe"
	_, err := db.Exec(`CREATE TABLE ` + tbl + ` (
		resource_type text NOT NULL,
		scope         smallint)`)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TRIGGER scope_default_probe_trg
		BEFORE INSERT ON ` + tbl + ` FOR EACH ROW
		EXECUTE FUNCTION kaname.` + scopeDefaultFunc + `()`)
	require.NoError(t, err,
		"живая функция не навесилась на черновую таблицу — предмет пробы не создан")
	return tbl
}

// scopeAssignedFor — ярус, который функция проставит виду, если писатель его не назвал.
func scopeAssignedFor(t *testing.T, db *sql.DB, tbl, kind string) int16 {
	t.Helper()
	var got int16
	require.NoError(t, db.QueryRow(`
		INSERT INTO `+tbl+` (resource_type, scope)
		VALUES ($1, NULL) RETURNING scope`, kind).Scan(&got))
	return got
}

// caseArmsOf — виды, названные ветвями `WHEN '<вид>'` тела функции.
//
// Перепись, а не проверка: она печатает объём осмотренного, чтобы «ветви снятого
// яруса нет» было отличимо от «прочитано ноль ветвей».
func caseArmsOf(src string) []string {
	var arms []string
	for _, line := range strings.Split(src, "\n") {
		idx := strings.Index(line, "WHEN '")
		if idx < 0 {
			continue
		}
		rest := line[idx+len("WHEN '"):]
		if end := strings.Index(rest, "'"); end >= 0 {
			arms = append(arms, rest[:end])
		}
	}
	return arms
}
