// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// platform_name_axes_test.go — ПЕРЕПИСЬ ОСЕЙ условия «имя платформы не
// остаётся на поверхности службы» по дереву службы (kacho#2076, предикат C,
// пп. 3 и 4).
//
// Почему перепись осей, а не перенос сводного держателя платформы, что она
// судит и чего не судит — в шапке `platform_name_axes.go`; здесь не
// пересказывается.
//
// Способность упасть и смолчать доказана инъекцией —
// platform_name_axes_injection_test.go.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО В ПЕРЕПИСИ И ЧЕГО В НЕЙ НЕТ
//
// Строки — оси, которые называет предикат готовности редакции C: п. 3 (контракт,
// схема, таблицы, ручки, клеймы, метрики, SPIFFE, посев) и п. 4 (витрина
// оператора), плюс две оси, которые называют решения задачи отдельно: форма
// домена в теле отказа (решение W3 приёмки WIRE-1) и клиентский сайт (Р3, «бренд
// в прозе»).
//
// Полный перечень идентичности, названный владельцем 2026-09-05, шире: заголовки
// переданной личности, издатель токенов, путь набора ключей, образ и бинарь,
// пути монтирования, письмо-приглашение. Их В ПЕРЕПИСИ НЕТ, потому что предикат
// C их не называет, — и сказано это здесь, чтобы «перепись зелёная» не читалось
// как «имени нет нигде». Остаток по ним назван отчётом полосы, а не держится.
package supplyhygiene

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// platformNameAxesDeclared — сколько осей перепись обязана нести.
//
// Число объявлено ОТДЕЛЬНО от перечня намеренно: приписать строку, не тронув
// число, нельзя, и наоборот. Два места об одном предмете заведены сознательно —
// как храповик, а не как дубль.
const platformNameAxesDeclared = 11

// platformNameAxes — перепись осей.
//
// Числа строк без держателя сняты прогоном этой переписи на ветке
// `issue-2076-product-name` (от `6e9b94ab`) и держатся ТОЧНО; состав каждой
// назван словами, а поимённо его печатает прогон.
var platformNameAxes = []PlatformNameAxis{
	{
		Axis:    "контракт",
		Holders: []string{"TestLedgerAgreesWithTheContract"},
		Judges: "пакет контракта службы называет владельцем тот продукт, что объявлен " +
			"ведомостью владельцев, и это сверено с дескриптором, произведённым генерацией",
		Subject: "proto/kaname/cloud/iam/v1",
	},
	{
		Axis:    "схема",
		Holders: []string{"TestServiceSchemaIsNamedForItsOwnProduct"},
		Judges:  "схема Postgres, объявленная миграциями и названная кодом, зовётся именем своего продукта",
		Subject: "internal/migrations",
	},
	{
		// Здесь стояло ЧИСЛО — 88 вхождений в 5 файлах каталога миграций (98 в 6
		// после миграции Ф4, kacho#1270), — и оно к нулю не шло НИКОГДА: пять
		// собственных функций заведены применённым сводом, а его не правят
		// (ban #5). Переименование сделано новой миграцией (`20260917130000`),
		// после которой текст свода прежний, а объект в базе — нет; ось поэтому
		// судится по ЖИВОЙ схеме, а не по файлам. Номер переименования стоит
		// ПОСЛЕ Ф4 (`20260917120000`) не случайно: Ф4 замещает тело счётчика
		// темпа ПО ИМЕНИ (`CREATE OR REPLACE`), и переименование, идущее раньше,
		// оставило бы триггеру прежнее тело, а Ф4 — функцию-сироту под именем
		// платформы. Таблиц с приставкой платформы — ноль (и было ноль).
		Axis:    "таблицы",
		Holders: []string{"TestSchemaFunctions_CarryNoForeignBrandAfterTheChain"},
		Judges: "функции схемы `kaname` после всей цепочки миграций не носят имени платформы, " +
			"кроме двух, отрисованных шаблоном фундамента (corelib `quota/refusal.sql.tmpl`) и " +
			"названных ведомостью решённого остаться поимённо и с доводом (kacho#2538); " +
			"запись без функции — находка, а не пропуск",
		Subject: "internal/migrations",
	},
	{
		// Здесь стояло ЧИСЛО — 23 токена `KACHO_…` в 14 не-тестовых файлах, — и
		// к нулю оно не шло: имена ручек СОСЕДЕЙ в тексте отказа и объяснениях,
		// ручки ФУНДАМЕНТА (накатчик; их имя выбирает corelib — PRO-Robotech/corelib#11),
		// ручки собственных проб в ЗАХВАЧЕННЫХ отчётах, объяснение применённого
		// свода и конвенция оснастки воркспейса `KACHO_HOME_<ИМЯ>` (её читает гейт
		// воркспейса, служба лишь следует ей). Ни одно не есть ручка службы;
		// ручка службы — то, что читает ЕЁ ПРОЦЕСС, и судится он. Аргументы сборки
		// образа переведены на нейтральную пару `OCI_IMAGE_*` этим же изменением.
		Axis:    "ручки",
		Holders: []string{"TestServiceProcessReadsNoKnobNamedForThePlatform"},
		Judges: "ни один пакет, линкуемый в двоичные файлы `cmd/...`, не несёт строкового " +
			"литерала формы имени переменной окружения с именем платформы; ручки службы " +
			"выводятся приставкой `config.EnvPrefix`",
		Subject: "internal/apps/kaname/config",
	},
	{
		Axis:    "клеймы",
		Holders: []string{"TestTokenClaimNamesDoNotCarryTheForeignBrand"},
		Judges:  "имя клейма выпущенного токена, записанное литералом в прод-коде, не несёт чужого бренда",
		Subject: "internal/domain/principal_claims.go",
	},
	{
		Axis:    "метрики",
		Subject: "internal/observability/metrics",
		Census: &AxisCensus{
			Paths:       []string{"internal/observability", "deploy/templates"},
			Token:       regexp.MustCompile(`(?i)^kach(o|ō)_[a-z0-9_]+$`),
			Occurrences: 2,
			Files:       1,
			Composition: "ряд общего измерителя фундамента в правиле тревоги; собственные ряды " +
				"службы выводятся одним пространством имён `metrics.Namespace`",
			Owner: "PRO-Robotech/kacho#2076",
		},
	},
	{
		// Здесь стояло ЧИСЛО — 3 вхождения в 2 профилях чарта, — и все три
		// называют не службу: учётку края платформы в круге отправителей боевого
		// профиля (заглушка ровно на одного отправителя) и домен доверия
		// kind-стенда платформы в накладке разработки. Имя службы в SPIFFE — то,
		// что произносит её процесс; домен доверия приходит настройкой
		// (`KANAME_AUTHN__TRUST_DOMAIN`, WIRE-1 WIRE-4-03), и судится код.
		Axis:    "SPIFFE",
		Holders: []string{"TestServiceProcessDeclaresNoTrustDomainLiteral"},
		Judges: "ни один пакет, линкуемый в двоичные файлы, не объявляет SPIFFE-имени " +
			"литералом: домен доверия и круг отправителей принадлежат настройке установки",
		Subject: "internal/apps/kaname/config",
	},
	{
		Axis:    "посев",
		Holders: []string{"TestSeedIdentityCensusMatchesItsAcceptance"},
		Judges: "числа переписи посевной идентичности сходятся с объявленными приёмкой " +
			"`seed-identity-names-its-own-service` — остаток держится точно, а не нулём",
		Subject: "internal/apps/kaname/seed",
	},
	{
		Axis: "витрина оператора",
		Holders: []string{
			"TestOperatorKeysCarryNoForeignPrefix",
			"TestKanameShowcaseNamesItsOwnMigrator",
		},
		Judges: "ключи аннотаций и значений чарта, которые видит оператор, не несут чужой " +
			"приставки; накатчик, названный на витрине, есть накатчик этого продукта",
		Subject: "deploy/templates",
	},
	{
		Axis:    "домен отказа",
		Holders: []string{"TestRefusalDomainComesFromTheDeclaration"},
		Judges: "домен `ErrorInfo` каждого производителя отказа берётся у единственного " +
			"объявления продукта, а не пишется по месту",
		Subject: "internal/refusaldomain/refusaldomain.go",
	},
	{
		Axis:    "клиентский сайт",
		Holders: []string{"TestClientSiteNamesTheProductByItsOwnName"},
		Judges: "страницы и оболочка сайта документации называют продукт своим именем; " +
			"каждое оставшееся имя платформы — ссылка на соседа, фундамент или историю, " +
			"названная поимённо с точным числом",
		Subject: "docs/content",
	},
}

// censusPaths — объединение путей, по которым считается остаток осей без
// держателя. Обход читает только их: тексты прочих файлов перепись не судит.
func censusPaths(axes []PlatformNameAxis) []string {
	set := map[string]bool{}
	for _, a := range axes {
		if a.Census == nil {
			continue
		}
		for _, p := range a.Census.Paths {
			set[p] = true
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// declaredFuncNames — имена функций, ОБЪЯВЛЕННЫХ файлами Go дерева.
//
// Объявление, а не упоминание: разбор узла, а не совпадение текста. Разбор —
// общий на дерево (`check.ScanDeclaredFuncNames`), вторая его копия разошлась бы
// с первой молча.
func declaredFuncNames(tree *treecorpus.Tree) (map[string]bool, check.DeclaredFuncCensus, int, error) {
	declared := map[string]bool{}
	var total check.DeclaredFuncCensus
	parsed := 0
	for _, rel := range tree.SortedFiles() {
		if !strings.HasSuffix(rel, ".go") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(tree.Root(), filepath.FromSlash(rel))) // #nosec G304 -- путь взят индексом git
		if err != nil {
			return nil, total, parsed, err
		}
		names, c, err := check.ScanDeclaredFuncNames(rel, src)
		if err != nil {
			continue
		}
		parsed++
		total.Decls += c.Decls
		total.Tests += c.Tests
		for n := range names {
			declared[n] = true
		}
	}
	return declared, total, parsed, nil
}

func TestEveryPlatformNameAxisHasAHolder(t *testing.T) {
	if len(platformNameAxes) != platformNameAxesDeclared {
		t.Fatalf("перепись несёт %d осей при объявленных %d — храповик разошёлся: строку "+
			"приписали, не тронув число, либо наоборот", len(platformNameAxes), platformNameAxesDeclared)
	}

	tree, err := treecorpus.NewTree(serviceRoot)
	require.NoError(t, err, "состав дерева не прочитан — «ноль находок» здесь означало бы "+
		"«ноль прочитанного»")

	declared, decls, parsed, err := declaredFuncNames(tree)
	require.NoError(t, err, "файл Go из состава дерева не прочитан")
	require.NotZero(t, decls.Tests, "объявлений проб прочитано ноль на %d файлах — разбор "+
		"перестал видеть держателей, и его молчание сказано ни о чём", parsed)

	paths := censusPaths(platformNameAxes)
	corpus, err := check.CorpusFrom(tree, func(rel string) bool { return underAny(rel, paths) })
	require.NoError(t, err, "обход путей переписи остатка")

	census, findings := JudgePlatformNameAxes(platformNameAxes, declared,
		func(rel string) bool { return tree.HasFile(rel) || tree.HasDir(rel) },
		map[string]string(corpus))

	t.Logf("перепись дерева: файлов Go разобрано %d, объявлений функций %d, из них проб %d; "+
		"файлов в путях переписи остатка %d", parsed, decls.Decls, decls.Tests, len(corpus))
	byAxis := map[string]PlatformNameAxis{}
	for _, a := range platformNameAxes {
		byAxis[a.Axis] = a
	}
	for _, v := range census.Verdicts {
		a := byAxis[v.Axis]
		if v.Held {
			t.Logf("  %-18s держит %s — %s", v.Axis, strings.Join(a.Holders, " + "), a.Judges)
			continue
		}
		t.Logf("  %-18s держит ЧИСЛО: %d вхождений в %d файлах (владелец %s) — %s",
			v.Axis, v.Occurrences, v.Files, a.Census.Owner, a.Census.Composition)
		for _, line := range axisResidueTokens(a.Census, corpus) {
			t.Logf("      %s", line)
		}
	}
	t.Logf("итог: осей %d · с держателем %d · держимых числом %d · остаток осей без "+
		"держателя %d вхождений", census.Axes, census.Held, census.Counted, census.Residue)
	if census.Residue > 0 {
		t.Logf("УСЛОВИЕ «ноль имени платформы на поверхности» ПО ОСЯМ БЕЗ ДЕРЖАТЕЛЯ НЕ " +
			"ВЫПОЛНЕНО: зелёный прогон означает лишь, что остаток не вырос и у каждой " +
			"оси есть держатель; вердикт осей с держателем печатает их собственный прогон")
	}

	for _, f := range findings {
		t.Errorf("%s", f)
	}
}

// axisResidueTokens — состав остатка оси поимённо: токен, число, файлы.
//
// Печатается затем, чтобы состав, названный словами в строке оси, можно было
// сверить с деревом одним прогоном, а не поверить строке.
func axisResidueTokens(c *AxisCensus, corpus map[string]string) []string {
	type agg struct {
		n     int
		files map[string]bool
	}
	byToken := map[string]*agg{}
	for rel, body := range corpus {
		if strings.HasSuffix(rel, "_test.go") || !underAny(rel, c.Paths) {
			continue
		}
		lines := strings.Split(body, "\n")
		for _, h := range PlatformNameHits(body) {
			if len(c.LineHas) > 0 && !lineHasAny(lines[h.Line-1], c.LineHas) {
				continue
			}
			if c.Token != nil && !c.Token.MatchString(h.Token) {
				continue
			}
			a := byToken[h.Token]
			if a == nil {
				a = &agg{files: map[string]bool{}}
				byToken[h.Token] = a
			}
			a.n++
			a.files[rel] = true
		}
	}
	out := make([]string, 0, len(byToken))
	for tok, a := range byToken {
		fs := make([]string, 0, len(a.files))
		for f := range a.files {
			fs = append(fs, f)
		}
		sort.Strings(fs)
		out = append(out, fmt.Sprintf("%s × %d — %s", tok, a.n, strings.Join(fs, ", ")))
	}
	sort.Strings(out)
	return out
}
