// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// module_identity_seed_test.go — производная личность модуля СХОДИТСЯ С ПОСЕВОМ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Идентификатор модульной служебной учётки выводится формулой из имени службы и
// одновременно ПОСЕЯН применённой миграцией. Это два места об одном предмете, и
// разойтись они могут молча: полученный идентификатор остаётся синтаксически
// верным и просто перестаёт находить строку — сервис, назвавшийся собой, не
// опознаётся, и отказ приходит не там, где причина.
//
// Проба, ближайшая к производителю, строила ожидаемое ТЕМ ЖЕ вызовом, что и
// проверяемый код, поэтому о совпадении с посевом не утверждала ничего и
// осталась бы зелёной при смене приставки (kacho#2098, ПР-10 приёмки WIRE-1).
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ИМЕННО СВЕРЯЕТСЯ — КРУГ, А НЕ ПОВТОР ВЫЧИСЛЕНИЯ
//
// Операнды берутся из РАЗНЫХ мест: имя и идентификатор — из текста применённой
// миграции, формула — из кода. Смена приставки В ОДНОМ из двух разводит операнды
// и роняет пробу; смена в обоих — законное переименование, и оно проходит.
//
// Миграция читается как ТЕКСТ, а не через базу: вердикт обязан быть свойством
// коммита, а не состояния чужого стенда.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ КРУГ ВЫНЕСЕН ЧИСТОЙ ФУНКЦИЕЙ
//
// Способность этой пробы упасть до сих пор держалась ОДНИМ ручным прогоном,
// описанным в чужом комментарии, — то есть утверждением, которого дерево
// проверить не может. Круг вынесен в `reconcileSeedWithFormula`, чтобы
// доказатель по соседству (`module_identity_seed_injection_test.go`) подавал ему
// синтетику и спрашивал то же самое на КАЖДОМ прогоне.
//
// Операнды формулы переданы функции ПАРАМЕТРАМИ ровно ради этого: подменить их
// может только доказатель, а настоящая проба ниже связывает производителя,
// которым пользуется страж прав, и приставки, объявленные рядом с ним.
package authzguard

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// baseMigration — применённая миграция, посеявшая строки. Путь ВНУТРИ модуля:
// миграции едут вместе с ним, поэтому он верен в обеих посадках.
const baseMigration = "../migrations/0001_initial.sql"

// seededServiceAccountRe — строка посева: идентификатор, аккаунт, имя.
var seededServiceAccountRe = regexp.MustCompile(
	`INSERT INTO kaname\.service_accounts \([^)]*\) VALUES \('([^']*)', '([^']*)', '([^']*)'`)

// seedRow — строка посева, прочитанная как ДАННЫЕ: ничего не вычисляется.
type seedRow struct{ id, name string }

// seedCensus — объём осмотренного. Печатается всегда, чтобы «ноль расхождений»
// было отличимо от «ноль прочитанного».
type seedCensus struct{ rows, modules, others int }

// parseSeededServiceAccounts читает посев как текст.
func parseSeededServiceAccounts(raw string) []seedRow {
	matches := seededServiceAccountRe.FindAllStringSubmatch(raw, -1)
	rows := make([]seedRow, 0, len(matches))
	for _, m := range matches {
		rows = append(rows, seedRow{id: m[1], name: m[3]})
	}
	return rows
}

// reconcileSeedWithFormula — КРУГ: сверяет посеянные строки с формулой.
//
// Формула подаётся параметрами (`idPrefix`, `namePrefix`, `deriveSuffix`,
// `moduleID`), чтобы доказатель мог развести операнды поодиночке. Настоящая
// проба передаёт сюда производителя и приставки ИЗ КОДА, а строки — ИЗ ТЕКСТА
// миграции; в этом и состоит независимость сторон.
//
// Возвращает находки и перепись. Пустой перечень строк находкой НЕ считается —
// об этом судит вызывающий: у него есть координата прочитанного.
func reconcileSeedWithFormula(
	rows []seedRow,
	idPrefix, namePrefix string,
	deriveSuffix func(seed string) string,
	moduleID func(svc string) string,
) ([]string, seedCensus) {
	var findings []string
	census := seedCensus{rows: len(rows)}

	for _, row := range rows {
		// Круг первый: идентификатор посева выводится из ИМЕНИ посева той же
		// формулой, которой пользуется код.
		want := idPrefix + deriveSuffix(row.name)
		if row.id != want {
			findings = append(findings, "посев "+quote(row.name)+": идентификатор "+
				quote(row.id)+", а формула даёт "+quote(want)+" — формула и посев "+
				"разошлись. Идентификатор остаётся синтаксически верным и просто "+
				"перестаёт НАХОДИТЬ строку: сервис, назвавшийся собой, не опознаётся")
			continue
		}

		// Круг второй: для модульной учётки тот же идентификатор обязан выдать
		// ПРОИЗВОДИТЕЛЬ, которым пользуется страж прав, — по имени СЛУЖБЫ.
		svc, isModule := strings.CutPrefix(row.name, namePrefix)
		if !isModule {
			census.others++
			continue
		}
		census.modules++
		if got := moduleID(svc); got != row.id {
			findings = append(findings, "служба "+quote(svc)+": производитель личности дал "+
				quote(got)+", посеяно "+quote(row.id)+" — производитель личности и посев "+
				"разошлись")
		}
	}

	return findings, census
}

// quote — кавычки того же вида, что печатал %q, без обращения к fmt в чистой
// функции.
func quote(s string) string { return "\"" + s + "\"" }

// TestSeededModuleIdentityIsReproducedByTheFormula — круговая сверка.
func TestSeededModuleIdentityIsReproducedByTheFormula(t *testing.T) {
	raw, err := os.ReadFile(baseMigration)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: посев %s не прочитан: %v", baseMigration, err)
	}
	rows := parseSeededServiceAccounts(string(raw))
	if len(rows) == 0 {
		t.Fatalf("посев служебных учёток не найден ни одной строкой в %s — распознаватель "+
			"перестал видеть форму посева, и «ноль расхождений» здесь означает «ноль "+
			"прочитанного»", baseMigration)
	}

	// Стороны РАЗНЫЕ: строки — из текста миграции выше, формула — из кода здесь.
	findings, census := reconcileSeedWithFormula(
		rows, saPrefix, svcNamePrefix, domain.DerivedIDSuffix, ServiceAccountIDForService)

	for _, f := range findings {
		t.Error(f)
	}

	if census.modules == 0 {
		t.Fatalf("модульных учёток в посеве не опознано ни одной при %d прочитанных "+
			"строках: приставка имени службы (%q) разошлась с посевом, и второй круг "+
			"сверки не исполнялся вовсе", census.rows, svcNamePrefix)
	}

	t.Logf("перепись: строк посева прочитано %d · сверено формулой %d · из них модульных "+
		"учёток %d · прочих служебных %d · приставка имени службы %q · приставка "+
		"идентификатора %q", census.rows, census.rows, census.modules, census.others,
		svcNamePrefix, saPrefix)
}
