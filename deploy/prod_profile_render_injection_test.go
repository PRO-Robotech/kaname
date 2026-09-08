// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// prod_profile_render_injection_test.go — доказательство того, что рендер-гейт
// СПОСОБЕН УПАСТЬ и падает ровно на своём предмете.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗАЧЕМ ОНО ЗДЕСЬ
//
// Гейт заведён потому, что прежний был зелен при сломанном профиле: переложение
// не несло двух ключей, и о них проба не утверждала НИЧЕГО. Новый гейт обязан
// доказать обратное свойство — что молчание у него означает «нечего находить»,
// а не «нечем искать».
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРОГОНОВ ТРИ, А НЕ ДВА (testing.md §«Гейт на класс», п. 2в)
//
//	контроль          действующее переложение против рендера — молчат ОБА
//	                  направления переписи;
//	инъекция НОВОГО   у переложения снят ключ, который чарт рендерит, — красное
//	                  с ИМЕНЕМ этого ключа и только его;
//	инъекция СТАРОГО  переложению добавлен ключ, которого рендер не даёт, —
//	                  красное с именем в ДРУГУЮ сторону.
//
// Без третьего молчание первого направления неотличимо от молчания мёртвого.
//
// ─────────────────────────────────────────────────────────────────────────────
// ОСЕЙ ЧЕТЫРЕ, И У КАЖДОЙ ЗАКОННЫЙ БЛИЗНЕЦ
//
//  1. ПОКРЫТИЕ. Переложение уже рендера — находка; вровень — молчание.
//  2. ПУСТОТА. Пустая конфигурация — ОТКАЗ, а не «ключей 0, все покрыты»:
//     вакуумное зелёное здесь и было предметом задачи #2334.
//  3. ДОСЯГАЕМОСТЬ. Путь вне монтирований — находка с именем ручки; путь под
//     монтированием — молчание.
//  4. ЗАМЕНИТЕЛЬ. Переменная из секрета без заменителя — находка; заменитель
//     без предмета — тоже находка (запись живёт, пока есть что заменять).
package deploy_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/multierr"
)

// ── ось 1: покрытие переложения рендером ─────────────────────────────────────

func TestBridgeCoverageCensusCanFail(t *testing.T) {
	in := readRenderedInput(t, renderStandaloneChart(t, chartProfiles))
	rendered := configLeafKeys(t, in.ConfigBody)
	require.NotEmpty(t, rendered, "рендер не дал ни одного ключа — инъекция была бы беспредметна")

	// КОНТРОЛЬ: действующее переложение вровень с рендером — молчат оба
	// направления.
	missing, extra, census := bridgeCoverageOf(configBridge, rendered)
	require.Empty(t, missing, "контроль: действующее переложение уже рендера — инъекция ниже "+
		"покраснела бы и без неё, то есть ничего не доказала бы")
	require.Empty(t, extra, "контроль: действующее переложение шире рендера")
	require.Equal(t, census.RenderKeys, census.BridgeKeys,
		"контроль: числа переписи разошлись при пустых обеих разностях — перепись считает не то")

	// ИНЪЕКЦИЯ НОВОГО, РОВНО ОДИН ФАКТ: у переложения снята запись ключа,
	// который чарт РЕНДЕРИТ. Именно этот класс был невидим.
	const blinded = "api-server.rest-endpoint"
	require.Contains(t, rendered, blinded,
		"инъекция беспредметна: чарт не рендерит ключ %q, а на нём и держится случай", blinded)

	narrowed := make([]bridged, 0, len(configBridge))
	for _, b := range configBridge {
		if b.configKey == blinded {
			continue
		}
		narrowed = append(narrowed, b)
	}
	gotMissing, gotExtra, narrowedCensus := bridgeCoverageOf(narrowed, rendered)
	require.Equal(t, []string{blinded}, gotMissing,
		"ключ снят из переложения, а перепись его не назвала — вход, собранный переложением, "+
			"был бы уже рендера молча, и проба боевого профиля осталась бы зелёной при профиле, "+
			"который не поднимается")
	require.Empty(t, gotExtra, "инъекция уронила ВТОРОЕ направление переписи — красное пришло бы "+
		"не от проверяемого, и о нём самом мы не узнали бы ничего")
	require.Equal(t, census.BridgeKeys-1, narrowedCensus.BridgeKeys,
		"перепись не заметила снятой записи — она считает не записи переложения")

	// ИНЪЕКЦИЯ СТАРОГО: переложению добавлен ключ, которого рендер не даёт.
	// Второе направление обязано покраснеть, первое — молчать.
	const invented = "api-server.no-such-key"
	require.NotContains(t, rendered, invented, "инъекция беспредметна: рендер уже даёт этот ключ")
	widened := append(append([]bridged{}, configBridge...), bridged{configKey: invented})
	gotMissing, gotExtra, _ = bridgeCoverageOf(widened, rendered)
	require.Empty(t, gotMissing, "инъекция уронила ПЕРВОЕ направление — красное пришло от соседа")
	require.Equal(t, []string{invented}, gotExtra,
		"переложение несёт ключ, которого в рендере нет, а перепись молчит — вход был бы шире "+
			"действительного, и проба стерегла бы величину, которой процесс не получит")

	t.Logf("перепись контроля: %s", census)
}

// ── ось 2: пустой вход — отказ, а не вакуумное зелёное ───────────────────────

// TestRenderedInputRefusesAnEmptyRender — «ноль находок» обязано быть отличимо
// от «ноль прочитанного».
//
// Проба зовёт разбор в ПОДПРОЦЕССЕ-помощнике `t.Run` не может: разбор падает
// через `require`, то есть роняет свою пробу. Поэтому предпосылка проверяется
// на функции, которая ошибку ВОЗВРАЩАЕТ, а не роняет.
func TestRenderedInputRefusesAnEmptyRender(t *testing.T) {
	// КОНТРОЛЬ: настоящее тело настроек даёт непустой перечень ключей.
	in := readRenderedInput(t, renderStandaloneChart(t, chartProfiles))
	require.NotEmpty(t, configLeafKeys(t, in.ConfigBody),
		"контроль: настоящий рендер дал ноль ключей — судить нечем")

	// ИНЪЕКЦИЯ: пустое тело. Перепись обязана назвать это отказом, а не
	// «ключей 0, покрыты все».
	missing, extra, census := bridgeCoverageOf(configBridge, nil)
	require.Empty(t, missing, "предпосылка случая: на пустом рендере недостающих быть не может")
	require.NotEmpty(t, extra,
		"на ПУСТОМ рендере перепись не назвала ни одного лишнего ключа переложения — значит "+
			"вакуумное зелёное здесь возможно, и гейт согласился бы с рендером, которого нет")
	require.Zero(t, census.RenderKeys, "перепись насчитала ключи там, где их нет")

	t.Logf("на пустом рендере перепись назвала лишними %d записей переложения — вакуумного "+
		"зелёного нет", len(extra))
}

// ── ось 3: досягаемость файлов ───────────────────────────────────────────────

func TestRenderedFilesAreMountableCanFail(t *testing.T) {
	legal := func() renderedInput {
		return renderedInput{
			Envs:   map[string]string{"KANAME_X_CERTFILE": "/etc/kaname/tls/server/tls.crt"},
			Mounts: []string{"/etc/kaname/tls"},
		}
	}

	// КОНТРОЛЬ: путь под монтированием — молчание.
	require.NoError(t, renderedFilesAreMountable(legal()),
		"контроль: путь под смонтированным каталогом объявлен недосягаемым — проверка "+
			"краснела бы на исправном профиле, и её сняли бы первой")

	// ИНЪЕКЦИЯ, РОВНО ОДИН ФАКТ: тот же путь, монтирование в стороне.
	astray := legal()
	astray.Mounts = []string{"/etc/kaname/other"}
	err := renderedFilesAreMountable(astray)
	require.Error(t, err, "ручка называет файл, которого под не несёт, а проверка молчит — "+
		"процесс откажет в пуске на нечитаемом файле, при том что профиль читается как настроенный")
	require.Contains(t, err.Error(), "KANAME_X_CERTFILE", "отказ не называет ручку — читатель "+
		"пойдёт искать не там")

	// ИНЪЕКЦИЯ ПРЕДПОСЫЛКИ: монтирований нет вовсе — ОТКАЗ, а не «все пути
	// досягаемы».
	none := legal()
	none.Mounts = nil
	require.Error(t, renderedFilesAreMountable(none),
		"без единого монтирования проверка объявила все пути досягаемыми — предпосылка "+
			"нарушена, а вердикт вынесен")

	// ЗАКОННЫЙ БЛИЗНЕЦ: величина, не являющаяся путём, под проверку не подпадает.
	notAPath := legal()
	notAPath.Envs["KANAME_X_MODE"] = "server-tls-only"
	require.NoError(t, renderedFilesAreMountable(notAPath),
		"проверка приняла за путь величину, путём не являющуюся — первый же ложный срабат её отключит")
}

// ── ось 4: заменитель живёт, пока есть что заменять ──────────────────────────

func TestRenderedSecretStandInsCanFail(t *testing.T) {
	all := make([]string, 0, len(renderedSecretStandIns))
	for name := range renderedSecretStandIns {
		all = append(all, name)
	}
	require.NotEmpty(t, all, "у пробы нет ни одного заменителя — случаи ниже беспредметны")

	// КОНТРОЛЬ: рендер объявляет ровно те переменные, для которых заменители
	// есть, — молчание.
	control := renderedInput{Envs: map[string]string{}, FromSecret: all}
	require.NoError(t, substituteRenderedSecrets(control),
		"контроль: на полном совпадении проверка нашла находку — краснела бы на исправном рендере")
	require.Len(t, control.Envs, len(all), "заменители не доехали до карты окружения")

	// ИНЪЕКЦИЯ: рендер объявил переменную, заменителя которой нет.
	unknown := renderedInput{Envs: map[string]string{}, FromSecret: append(append([]string{}, all...), "KANAME_NO_SUCH_SECRET")}
	err := substituteRenderedSecrets(unknown)
	require.Error(t, err, "переменная из секрета без заменителя не названа — вердикт о полноте "+
		"профиля выносился бы при неподанной величине")
	require.Contains(t, err.Error(), "KANAME_NO_SUCH_SECRET")

	// ИНЪЕКЦИЯ ОБРАТНОЙ СТОРОНЫ: заменитель, которому больше нечего заменять.
	orphan := renderedInput{Envs: map[string]string{}, FromSecret: all[1:]}
	err = substituteRenderedSecrets(orphan)
	require.Error(t, err, "заменитель пережил свой предмет, а проверка молчит — послабление, "+
		"которое не истечёт само")
	require.Contains(t, err.Error(), all[0])

	// ИНЪЕКЦИЯ: величина выразима двумя способами разом.
	clash := renderedInput{Envs: map[string]string{all[0]: "значением"}, FromSecret: all}
	err = substituteRenderedSecrets(clash)
	require.Error(t, err, "переменная объявлена и значением, и ссылкой на секрет, а проверка "+
		"молчит — какой путь действует, решал бы шаблон, а не оператор")
	require.Contains(t, err.Error(), all[0])

	t.Logf("перепись: заменителей %d · случаев 4 (контроль · нет заменителя · осиротевший · двойное объявление)",
		len(all))
}

// ── что вердикт рендер-гейта НЕ засчитывает в успех ──────────────────────────

// TestRenderedVerdictNamesEveryRefusal — вердикт обязан НАЗЫВАТЬ каждый упрёк,
// а не отдавать один.
//
// Отказ, схлопнутый в первый попавшийся, стоит круга прогона на каждую
// следующую находку — а на боевом профиле их бывает несколько сразу.
func TestRenderedVerdictNamesEveryRefusal(t *testing.T) {
	in := readRenderedInput(t, renderStandaloneChart(t, []string{"values.yaml"}, minimalOperatorCoordinates...))
	verdict := renderedVerdict(t, in)
	require.Error(t, verdict, "предпосылка случая: без боевого профиля страж обязан отказать")

	parts := multierr.Errors(verdict)
	require.Greater(t, len(parts), 1,
		"вердикт схлопнут в один упрёк — оператор чинил бы профиль по одному отказу за перезапуск")
	for i, p := range parts {
		require.NotEmpty(t, strings.TrimSpace(p.Error()), "упрёк %d пуст", i)
	}
	t.Logf("перепись: упрёков в вердикте %d", len(parts))
}
