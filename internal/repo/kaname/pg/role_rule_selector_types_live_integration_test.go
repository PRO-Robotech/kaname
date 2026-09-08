// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// role_rule_selector_types_live_integration_test.go — ТРЕТЬЯ поверхность
// проекции правила получила референт: каждый элемент
// `role_rule_selectors.object_types` называет ЖИВУЮ строку каталога.
//
// Приёмка: services/iam/docs/engineering/acceptance/roles-pointing-at-moved-resources.md
// (APPROVED круга 2), сценарии IAM-RM-1-08, -09, -10, -16. Задача продукта #1825.
//
// Предмет, довод в пользу триггера и выбор fail-closed разобраны в САМОЙ СХЕМЕ —
// комментарием к функции триггера (`COMMENT ON FUNCTION
// kaname.role_rule_selector_types_live()`); здесь они не пересказываются,
// чтобы не завести двух мест об одном предмете.
//
// Здесь стояло имя отдельной миграции, и оно пережило свой предмет вместе со
// сведением цепи в одну первичную. Разбор при этом не пропал — он переехал в
// схему вместе с объявлением, — а вот координата стала ложной. Поэтому названо
// ОБЪЯВЛЕНИЕ, а не файл: имя файла меняет перенос, объявление — нет.
//
// ГРАНИЦА НАЗВАНА: утверждение «отказ приходит от базы» без базы недоказуемо,
// поэтому пробы формы у триггера нет и быть не может. Проба IAM-RM-1-16 читает
// ТЕКСТ поставляемой схемы и о поведении не говорит ничего.

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// selectorTrigger — имя триггера-предмета. ИМЯ, А НЕ КООРДИНАТА: файл, в котором
// объявление лежит, меняет перенос, а объявление переживает его.
//
// Текст читается ИЗ ПОСТАВЛЯЕМОГО НАБОРА (migrations.FS), а не переписывается в
// пробу: копия была бы вторым местом об одном предмете и разошлась бы молча.
const selectorTrigger = "role_rule_selectors_types_live"

// writeSelector — прямая вставка строки селекторов. Прямая намеренно: предмет
// пробы — ТРИГГЕР, то есть инвариант, который обязан держаться независимо от
// писателя. Пиши проба через порт — она проверяла бы одного писателя из двух.
func writeSelector(ctx context.Context, pool *pgxpool.Pool,
	role domain.RoleID, fp string, types []string) error {
	_, err := pool.Exec(ctx, `
		INSERT INTO kaname.role_rule_selectors
		  (role_id, rule_fp, arm, object_types, resource_names, match_labels, created_at, updated_at)
		VALUES ($1, $2, 'anchor', $3, '{}', '{}'::jsonb, now(), now())`,
		string(role), fp, types)
	return err
}

// TestIAMRM108_SelectorNamingARetiredTypeIsRefused — IAM-RM-1-08.
//
// Отрицание идёт В ПАРЕ с положительным контролем: без него «отвергнуто» было бы
// неотличимо от таблицы, которая не принимает ничего.
func TestIAMRM108_SelectorNamingARetiredTypeIsRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)

	// ПРЕДПОСЫЛКА — факт каталога, а не наше допущение о нём.
	var retired int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kaname.catalog_resource
		 WHERE dotted = 'compute.disk' AND NOT live`).Scan(&retired))
	require.Equalf(t, 1, retired, "ПРЕДПОСЫЛКА НАРУШЕНА: снятой строки compute.disk "+
		"в каталоге нет — отвергать было бы нечего, и молчание триггера ничего не значило бы")

	role := catalogRole(t, ctx, pool, "rm108")

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: живой тип записывается.
	require.NoError(t, writeSelector(ctx, pool, role, "fp-live", []string{"compute.instance"}),
		"контроль: живой тип отвергнут — триггер судит не то, что объявляет")

	err := writeSelector(ctx, pool, role, "fp-dead", []string{"compute.disk"})
	require.Error(t, err, "селектор со СНЯТЫМ типом принят")
	code, constraint := pgCode(err)
	require.Equal(t, "23514", code, "отказ пришёл не тем кодом: %v", err)
	require.Equal(t, "role_rule_selectors_types_live", constraint)
	require.Containsf(t, err.Error(), "compute.disk",
		"отказ не называет ЭЛЕМЕНТ — автор правила пойдёт перечитывать массив, "+
			"которого он не писал")
	require.Contains(t, err.Error(), string(role), "отказ не называет роль")

	// Строки нет: отказ пришёл ДО записи, а не после неё.
	var got int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kaname.role_rule_selectors
		 WHERE role_id = $1 AND rule_fp = 'fp-dead'`, string(role)).Scan(&got))
	require.Zero(t, got)
}

// TestIAMRM109_TriggerJudgesEveryElementNotTheFirst — IAM-RM-1-09.
//
// Массив, чей первый тип жив, а второй снят, — самая частая форма после ручной
// вычистки, и разбор, останавливающийся на первом, пропустил бы её целиком.
func TestIAMRM109_TriggerJudgesEveryElementNotTheFirst(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)
	role := catalogRole(t, ctx, pool, "rm109")

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: два живых элемента записываются.
	require.NoError(t, writeSelector(ctx, pool, role, "fp-two-live",
		[]string{"compute.instance", "vpc.network"}))

	err := writeSelector(ctx, pool, role, "fp-second-dead",
		[]string{"compute.instance", "compute.snapshot"})
	require.Error(t, err, "снятый ВТОРОЙ элемент пропущен — разбор остановился на первом")
	require.Containsf(t, err.Error(), "compute.snapshot",
		"отказ называет не тот элемент: %v", err)
	require.NotContainsf(t, err.Error(), "compute.instance",
		"отказ называет ЖИВОЙ элемент — читатель пойдёт чинить исправное: %v", err)

	// ОБНОВЛЕНИЕ судится так же, как вставка: оба писателя пишут через
	// `ON CONFLICT … DO UPDATE`, и сужение `OF object_types` пропустило бы правку
	// массива через EXCLUDED.
	_, uerr := pool.Exec(ctx, `
		UPDATE kaname.role_rule_selectors
		   SET object_types = ARRAY['compute.image']
		 WHERE role_id = $1 AND rule_fp = 'fp-two-live'`, string(role))
	require.Error(t, uerr, "обновление на снятый тип принято")
	require.Contains(t, uerr.Error(), "compute.image")
}

// TestIAMRM110_SystemRoleSelectorSeedPasses — IAM-RM-1-10, характеризующий замок.
//
// Утверждает, что fail-closed НЕ срабатывает на сегодняшнем дереве: литерал типов
// (`domain.AllMaterializableTypes`) и каталог сходятся. Требовать от этой пробы
// красноты запрещено — она обязана ПЕРЕЖИТЬ изменение.
func TestIAMRM110_SystemRoleSelectorSeedPasses(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)

	var before int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.role_rule_selectors`).Scan(&before))

	require.NoError(t, seed.SyncAllSystemRoleSelectors(ctx, pool),
		"досев селекторов отвергнут триггером: литерал типов разошёлся с каталогом — "+
			"это и есть fail-closed §2.4, и чинится он приведением каталога, а не снятием триггера")

	var after int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.role_rule_selectors`).Scan(&after))
	t.Logf("перепись: строк селекторов до досева %d, после %d", before, after)
	require.NotZerof(t, after, "ПРЕДПОСЫЛКА НАРУШЕНА: селекторов ноль — досев прошёл "+
		"даром, и его зелёное ничего не говорит о согласии литерала с каталогом")

	// Вторая половина того же утверждения: ни одна строка, лежащая в таблице,
	// не называет снятого типа. Досев мог пройти и оставить прежние строки.
	var stale []string
	rows, err := pool.Query(ctx, `
		SELECT DISTINCT t
		  FROM kaname.role_rule_selectors s, unnest(s.object_types) AS t
		 WHERE NOT EXISTS (SELECT 1 FROM kaname.catalog_resource cr
		                    WHERE cr.dotted = t AND cr.live)`)
	require.NoError(t, err)
	for rows.Next() {
		var ty string
		require.NoError(t, rows.Scan(&ty))
		stale = append(stale, ty)
	}
	require.NoError(t, rows.Err())
	require.Emptyf(t, stale, "селекторы называют типы вне ЖИВОГО каталога: %s",
		strings.Join(stale, ", "))
}

// TestIAMRM116_DeliveredSchemaCarriesTheTriggerAndItsReversePathRemovesIt —
// IAM-RM-1-16.
//
// Проба ФОРМЫ: читает текст поставляемой схемы. О поведении она не говорит
// ничего — это сказано вслух, чтобы её зелёное не читалось шире сделанного.
//
// РЕФЕРЕНТ ПЕРЕЕХАЛ, И ЭТО НАДО СКАЗАТЬ ПРЯМО. Сценарий приёмки писался под
// «новую миграцию» — отдельный файл, вводивший триггер. Цепь миграций сервиса
// сведена в одну первичную, и такого файла в дереве больше нет: вопрос
// «непуста ли нижняя половина ЭТОЙ миграции» перестал быть задаваемым by
// construction, а не потому, что ответ изменился.
//
// Предмет при этом жив и проверяется ПРЯМЕЕ: триггер лежит в поставляемой схеме,
// а обратный путь этой схемы объявлен, непуст, СНИМАЕТ триггер и ничего не
// восстанавливает. Прежняя редакция утверждала это об одном файле; новая — о
// том, что поставляется, и от числа файлов не зависит.
//
// Снятие триггера засчитывается ДВУМЯ формами, и обе законны: обратный путь либо
// называет его (`DROP TRIGGER`), либо снимает объект, который его несёт
// (`DROP SCHEMA … CASCADE`). Сегодня в дереве вторая; первая была вчера и
// вернётся с любой миграцией, заводящей триггер своим файлом. Обе доказаны
// инъекцией.
func TestIAMRM116_DeliveredSchemaCarriesTheTriggerAndItsReversePathRemovesIt(t *testing.T) {
	name, up := deliveredSchemaDeclaring(t, "CREATE TRIGGER "+selectorTrigger)

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ, и он первый: без него «обратный путь снимает
	// триггер» верно тождественно на схеме, где триггера нет вовсе.
	require.Containsf(t, up, "kaname.role_rule_selector_types_live()",
		"схема (%s) объявляет триггер, но не называет функцию, которую он исполняет: "+
			"объявление есть, предмета у него нет", name)

	for _, f := range auditReversePath(t, name) {
		t.Error(f)
	}
}

// executableLines — строки БЕЗ комментариев. Вырезать обязательно в обе стороны:
// разбор по подстроке зеленел бы на собственном объяснении там, где ищет
// снятие, и краснел бы на нём же там, где ищет запрещённое.
func executableLines(block string) string {
	var kept []string
	for _, line := range strings.Split(block, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.TrimSpace(strings.Join(kept, "\n"))
}

// reversePathOf — откатная половина поставляемой миграции, ИСПОЛНЯЕМАЯ часть.
func reversePathOf(t *testing.T, name string) string {
	t.Helper()
	raw, err := migrations.FS.ReadFile(name)
	require.NoErrorf(t, err, "поставляемая миграция %s не прочитана: отказ чтения — "+
		"не пропуск", name)
	body := string(raw)
	i := strings.Index(body, "-- +goose Down")
	require.Positivef(t, i, "у миграции %s нет откатной половины вовсе", name)
	return executableLines(body[i+len("-- +goose Down"):])
}

// auditReversePath отдаёт находки ЗНАЧЕНИЕМ, а не побочным эффектом: инъекция
// обязана читать ИСХОД разбора, иначе «проба покраснела» неотличимо от «инъекция
// сломала пробу».
func auditReversePath(t *testing.T, name string) []string {
	t.Helper()
	return auditReversePathText(name, reversePathOf(t, name))
}

func auditReversePathText(name, down string) []string {
	var findings []string
	if down == "" {
		return []string{fmt.Sprintf("откатная половина %s ПУСТА: обратный путь объявлен "+
			"полным (§2.9) и не исполнен", name)}
	}
	namesTrigger := strings.Contains(down, "DROP TRIGGER") && strings.Contains(down, selectorTrigger)
	dropsCarrier := strings.Contains(down, "DROP SCHEMA") &&
		strings.Contains(down, "kaname") && strings.Contains(down, "CASCADE")
	if !namesTrigger && !dropsCarrier {
		findings = append(findings, fmt.Sprintf(
			"обратный путь %s не снимает триггер %s: он не называет его (DROP TRIGGER) и "+
				"не снимает объект, который его несёт (DROP SCHEMA … CASCADE).\n"+
				"Откат, оставляющий триггер, возвращает состояние, которого накат не "+
				"отнимал, — и следующий накат встретит его дважды объявленным.",
			name, selectorTrigger))
	}
	// Откат ничего не восстанавливает — иначе он вернул бы состояние, которого
	// накат не отнимал: данных он не трогает вовсе.
	for _, forbidden := range []string{"INSERT INTO", "UPDATE kaname.", "DELETE FROM"} {
		if strings.Contains(down, forbidden) {
			findings = append(findings, fmt.Sprintf(
				"откат %s трогает ДАННЫЕ (%s), хотя накат их не трогал", name, forbidden))
		}
	}
	return findings
}

// ─────────────────────────────────────────────────────────────────────────────
// ИНЪЕКЦИЯ В ОБЕ СТОРОНЫ

// TestIAMRM116_InjectionEmptyReversePathIsFound — ОБЯЗАН ПОКРАСНЕТЬ.
func TestIAMRM116_InjectionEmptyReversePathIsFound(t *testing.T) {
	if found := auditReversePathText("инъекция: пустой откат", ""); len(found) == 0 {
		t.Fatal("разбор ПРОШЁЛ на пустом обратном пути: «объявлен полным» стало " +
			"неотличимо от «не объявлен вовсе»")
	}
}

// TestIAMRM116_InjectionReversePathThatKeepsTheTriggerIsFound — ОБЯЗАН ПОКРАСНЕТЬ.
//
// Кормится НАСТОЯЩИЙ обратный путь дерева с точечной правкой: снятие носителя
// заменено безобидным оператором. Триггер после такого отката остаётся.
func TestIAMRM116_InjectionReversePathThatKeepsTheTriggerIsFound(t *testing.T) {
	name, _ := deliveredSchemaDeclaring(t, "CREATE TRIGGER "+selectorTrigger)
	down := reversePathOf(t, name)
	broken := strings.Replace(down, "DROP SCHEMA", "COMMENT ON SCHEMA", 1)
	if broken == down {
		broken = strings.Replace(down, "DROP TRIGGER", "COMMENT ON TRIGGER", 1)
	}
	if broken == down {
		t.Fatalf("инъекция ничего не изменила: обратный путь %s не снимает ни носителя, "+
			"ни триггер — тогда проба обязана быть красной сама по себе", name)
	}
	found := auditReversePathText(name, broken)
	if len(found) == 0 {
		t.Fatal("разбор ПРОМОЛЧАЛ на откате, оставляющем триггер: он не держит ничего")
	}
	if joined := strings.Join(found, "\n"); !strings.Contains(joined, selectorTrigger) {
		t.Errorf("находка не называет триггер:\n%s", joined)
	}
}

// TestIAMRM116_InjectionNamedDropIsAcceptedToo — ЗАКОННЫЙ БЛИЗНЕЦ.
//
// Обратный путь, снимающий триггер ПОИМЁННО, — та же вторая законная форма.
// Красное здесь означало бы разбор, требующий сноса всей схемы от каждой
// миграции, которая заводит триггер своим файлом.
func TestIAMRM116_InjectionNamedDropIsAcceptedToo(t *testing.T) {
	named := "DROP TRIGGER IF EXISTS " + selectorTrigger +
		" ON kaname.role_rule_selectors;"
	if found := auditReversePathText("инъекция: поимённое снятие", named); len(found) > 0 {
		t.Fatalf("разбор КРАСЕН на обратном пути, снимающем триггер поимённо:\n%s\n"+
			"Это вторая законная форма, и требовать вместо неё сноса схемы значило бы "+
			"краснеть на верной миграции.", strings.Join(found, "\n"))
	}
}

// TestIAMRM116_InjectionReversePathTouchingDataIsFound — ОБЯЗАН ПОКРАСНЕТЬ.
func TestIAMRM116_InjectionReversePathTouchingDataIsFound(t *testing.T) {
	name, _ := deliveredSchemaDeclaring(t, "CREATE TRIGGER "+selectorTrigger)
	down := reversePathOf(t, name) + "\nDELETE FROM kaname.role_rule_selectors;"
	found := auditReversePathText(name, down)
	if len(found) == 0 {
		t.Fatal("разбор ПРОМОЛЧАЛ на откате, трогающем ДАННЫЕ: он вернул бы состояние, " +
			"которого накат не отнимал")
	}
}

// TestIAMRM116_InjectionCommentAboutTheDropIsNotTheDrop — ЗАКОННЫЙ БЛИЗНЕЦ НАОБОРОТ.
//
// Обратный путь, где снятие только ОБЪЯСНЕНО комментарием, снятием не является.
// Без этой пробы разбор зеленел бы на собственном объяснении — тот самый класс,
// ради которого исполняемая часть вырезается.
func TestIAMRM116_InjectionCommentAboutTheDropIsNotTheDrop(t *testing.T) {
	onlyProse := "-- здесь был DROP SCHEMA IF EXISTS kaname CASCADE;\n" +
		"-- и DROP TRIGGER " + selectorTrigger + ";\nSELECT 1;"
	if found := auditReversePathText("инъекция: снятие только в прозе",
		executableLines(onlyProse)); len(found) == 0 {
		t.Fatal("разбор ПРОШЁЛ на откате, где снятие только объяснено комментарием: " +
			"он читает текст, а не исполняемое")
	}
}
