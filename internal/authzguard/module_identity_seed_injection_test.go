// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Доказательство того, что круговая сверка личности модуля СПОСОБНА упасть и
// способна смолчать (задача продукта #2098, ПР-10 приёмки WIRE-1).
//
// # Зачем артефактом, а не разовым прогоном руками
//
// Сама сверка заведена ради класса «проба строит ожидаемое ТЕМ ЖЕ вызовом, что
// и проверяемый код». Её собственная способность упасть держалась ровно тем, от
// чего она защищает: одним ручным прогоном, описанным в комментарии к запросу
// на слияние. Дерево такого утверждения проверить не может, а проверка,
// переставшая краснеть, на целом дереве выглядит ТОЧНО так же, как исправная
// (`testing.md` §«Гейт на класс», п. 8). Здесь то же самое спрашивается на
// КАЖДОМ прогоне.
//
// # ОДНО-ФАКТНОСТЬ: каждый случай отличается от контроля ровно ОДНИМ фактом
//
// Посев синтетики у всех случаев побайтово один и тот же, кроме названного.
// Инъекция «сменить заодно и имя» негодна: красное пришло бы от чужого
// признака, и вакуумность сверки осталась бы незамеченной (`testing.md`
// §«Гейт на класс», п. 2в).
//
// # ДВУСТОРОННОСТЬ — НЕСУЩАЯ, А НЕ ДЛЯ ПОЛНОТЫ
//
// Односторонняя сверка зеленела бы на СОГЛАСОВАННОМ изменении обеих сторон — а
// именно так выглядит настоящая смена приставки. Поэтому близнец А меняет обе
// стороны сразу и обязан пройти: законное переименование не есть находка.
//
// # ИДЕНТИФИКАТОРЫ СИНТЕТИКИ — ЛИТЕРАЛЫ
//
// Посев подаётся литералами, как он и живёт в применённой миграции. Построй их
// прогон той же формулой — контроль стал бы повтором вычисления, то есть ровно
// тем, что эта сверка и опровергает.
//
// # Настоящие файлы не трогаются
//
// Круг — чистая функция (`reconcileSeedWithFormula`), поэтому синтетика подаётся
// ей напрямую. Правка применённой миграции запрещена (ban #5), а правка общего
// дерева ради прогона — последнее средство, чей след не остаётся by construction
// (`multi-agent-flow.md` §13).
package authzguard

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// Литералы посева: идентификатор выведен ОДНАЖДЫ и записан руками, как в
// применённой миграции. `sva` + первые 17 знаков md5 полного имени.
const (
	seededAlphaID = "sva4eb45766cc857b506" // kacho-alpha
	seededBetaID  = "svaf5f1f9a8dbc6ccc20" // kacho-beta
	seededGammaID = "svaf98367462082075e8" // kacho-gamma
	seededOtherID = "sva9316a9e2698fa762e" // other-thing — НЕ модульная
)

// injectedSeed — посев синтетического дерева: две модульные учётки и одна
// чужая, чтобы полоса «прочих служебных» была не пуста.
func injectedSeed() []seedRow {
	return []seedRow{
		{id: seededAlphaID, name: "kacho-alpha"},
		{id: seededBetaID, name: "kacho-beta"},
		{id: seededOtherID, name: "other-thing"},
	}
}

// reconcileInjected — круг с настоящими приставками и настоящим производителем.
func reconcileInjected(rows []seedRow) ([]string, seedCensus) {
	return reconcileSeedWithFormula(
		rows, saPrefix, svcNamePrefix, domain.DerivedIDSuffix, ServiceAccountIDForService)
}

// TestControlIntactSeedIsSilent — КОНТРОЛЬ: посев сходится с формулой, находок нет.
//
// Контроль не декоративен: он же и есть настоящее утверждение сверки —
// записанный руками литерал обязан совпасть с тем, что даёт формула.
func TestControlIntactSeedIsSilent(t *testing.T) {
	findings, census := reconcileInjected(injectedSeed())
	if len(findings) != 0 {
		t.Fatalf("контроль обязан молчать на целом посеве, а находок %d: %s",
			len(findings), strings.Join(findings, "; "))
	}
	if census.modules != 2 || census.others != 1 {
		t.Fatalf("контроль прочитал не тот посев: модульных %d (ждали 2), прочих %d "+
			"(ждали 1) — синтетика разошлась с замыслом, и вердикты ниже недействительны",
			census.modules, census.others)
	}
	t.Logf("перепись контроля: строк %d · модульных %d · прочих %d",
		census.rows, census.modules, census.others)
}

// TestFormulaIdPrefixDivergenceIsAFinding — приставка ИДЕНТИФИКАТОРА сменена в
// формуле, посев не тронут: один факт.
func TestFormulaIdPrefixDivergenceIsAFinding(t *testing.T) {
	injected := saPrefix + "X"
	findings, _ := reconcileSeedWithFormula(
		injectedSeed(), injected, svcNamePrefix, domain.DerivedIDSuffix,
		func(svc string) string { return injected + domain.DerivedIDSuffix(svcNamePrefix+svc) })

	if len(findings) == 0 {
		t.Fatal("смена приставки идентификатора в ФОРМУЛЕ при нетронутом посеве прошла " +
			"молча — сверка вакуумна: она повторяет вычисление вместо круга")
	}
	// Находка обязана называть ОБЕ величины: без них читатель не узнает, какая
	// сторона разошлась, и пойдёт искать не там.
	first := findings[0]
	if !strings.Contains(first, seededAlphaID) || !strings.Contains(first, injected) {
		t.Errorf("находка не называет обе величины (посеянную и выведенную): %s", first)
	}
	t.Logf("находок %d, первая: %s", len(findings), first)
}

// TestFormulaNamePrefixDivergenceIsAFinding — приставка ИМЕНИ СЛУЖБЫ сменена в
// формуле: модульных учёток не опознаётся ни одной, второй круг не исполняется.
//
// Это отдельный случай, а не повтор предыдущего: здесь сверка обязана сообщить
// не о расхождении величин, а о том, что она НЕ РАБОТАЛА, — иначе «ноль
// расхождений» означало бы «ноль сверенного».
func TestFormulaNamePrefixDivergenceIsAFinding(t *testing.T) {
	_, census := reconcileSeedWithFormula(
		injectedSeed(), saPrefix, "kaname-", domain.DerivedIDSuffix, ServiceAccountIDForService)

	if census.modules != 0 {
		t.Fatalf("приставка имени службы разведена с посевом, а модульных опознано %d — "+
			"признак модульности перестал зависеть от приставки", census.modules)
	}
	if census.rows == 0 {
		t.Fatal("перепись пуста: случай не отличим от непрочитанного посева")
	}
	t.Logf("второй круг не исполнялся: строк прочитано %d, модульных опознано %d — "+
		"настоящая проба обязана на этом упасть", census.rows, census.modules)
}

// TestSeedDivergenceIsAFinding — сменён ПОСЕВ при нетронутой формуле: один факт,
// зеркальный к инъекции формулы.
func TestSeedDivergenceIsAFinding(t *testing.T) {
	rows := injectedSeed()
	tampered := seededAlphaID[:len(seededAlphaID)-1] + "0"
	if tampered == seededAlphaID {
		t.Fatal("подмена посева не изменила строку — инъекция беспредметна")
	}
	rows[0].id = tampered

	findings, _ := reconcileInjected(rows)
	if len(findings) == 0 {
		t.Fatal("подмена ПОСЕВА при нетронутой формуле прошла молча — сверка читает " +
			"формулу вместо посева")
	}
	first := findings[0]
	if !strings.Contains(first, tampered) || !strings.Contains(first, seededAlphaID) {
		t.Errorf("находка не называет обе величины (подменённую и выведенную): %s", first)
	}
	t.Logf("находок %d, первая: %s", len(findings), first)
}

// TestCoordinatedRenameOfBothSidesIsSilent — БЛИЗНЕЦ А: законное переименование.
//
// Обе стороны сменены согласованно — сверка обязана молчать. Красное здесь
// означало бы, что проба запрещает переименование как таковое, а её предмет
// другой: РАСХОЖДЕНИЕ сторон.
func TestCoordinatedRenameOfBothSidesIsSilent(t *testing.T) {
	renamed := "svb"
	rows := injectedSeed()
	for i := range rows {
		rows[i].id = renamed + strings.TrimPrefix(rows[i].id, saPrefix)
	}

	findings, census := reconcileSeedWithFormula(
		rows, renamed, svcNamePrefix, domain.DerivedIDSuffix,
		func(svc string) string { return renamed + domain.DerivedIDSuffix(svcNamePrefix+svc) })

	if len(findings) != 0 {
		t.Fatalf("согласованная смена ОБЕИХ сторон обязана проходить, а находок %d: %s — "+
			"сверка судит переименование, а не расхождение", len(findings),
			strings.Join(findings, "; "))
	}
	if census.modules != 2 {
		t.Fatalf("близнец прошёл вхолостую: модульных сверено %d (ждали 2)", census.modules)
	}
	t.Logf("законное переименование прошло: модульных сверено %d", census.modules)
}

// TestLegitimateNewServiceIsSilent — БЛИЗНЕЦ Б: новая служба, выведенная верно.
//
// Перепись обязана ВЫРАСТИ: молчание при неизменившейся переписи означало бы,
// что строку не читали вовсе.
func TestLegitimateNewServiceIsSilent(t *testing.T) {
	before := injectedSeed()
	_, censusBefore := reconcileInjected(before)

	after := append(before, seedRow{id: seededGammaID, name: "kacho-gamma"})
	findings, censusAfter := reconcileInjected(after)

	if len(findings) != 0 {
		t.Fatalf("законно выведенная новая служба обязана проходить, а находок %d: %s",
			len(findings), strings.Join(findings, "; "))
	}
	if censusAfter.modules != censusBefore.modules+1 {
		t.Fatalf("перепись не выросла: модульных было %d, стало %d — новая строка не "+
			"прочитана, и молчание здесь ничего не доказывает",
			censusBefore.modules, censusAfter.modules)
	}
	t.Logf("законная новая служба принята: модульных %d → %d",
		censusBefore.modules, censusAfter.modules)
}

// TestRecognizerSeesTheSeedForm — ПРЕДПОСЫЛКА распознавателя.
//
// Круг судит то, что прочитал распознаватель. Перестань тот видеть форму
// посева — сверка замолчит, ничего не проверив, и это надо отличать от
// «расхождений нет».
func TestRecognizerSeesTheSeedForm(t *testing.T) {
	const oneRow = `INSERT INTO kaname.service_accounts (id, account_id, name, ` +
		`description, created_at, enabled, labels) VALUES ('` + seededAlphaID +
		`', 'acc0000000000000000', 'kacho-alpha', 'Module SA', now(), true, '{}');`

	if rows := parseSeededServiceAccounts(oneRow); len(rows) != 1 ||
		rows[0].id != seededAlphaID || rows[0].name != "kacho-alpha" {
		t.Fatalf("распознаватель не прочитал форму посева: %#v", rows)
	}
	if rows := parseSeededServiceAccounts("-- ни одной строки посева"); len(rows) != 0 {
		t.Fatalf("распознаватель нашёл посев там, где его нет: %#v", rows)
	}
	t.Log("распознаватель видит форму посева и не выдумывает её на пустом тексте")
}
