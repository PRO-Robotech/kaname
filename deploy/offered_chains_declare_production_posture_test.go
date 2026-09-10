// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// offered_chains_declare_production_posture_test.go — ГЕЙТ КЛАССА: цепочка,
// которую ЭТОТ чарт ПРЕДЛАГАЕТ для установки, обязана объявлять боевую посадку;
// поставляемый профиль, цепочкой не предлагаемый, назван поимённо с причиной.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// ban #16: любой РАЗВЁРНУТЫЙ стенд работает в боевой посадке, а
// dev-небезопасная допустима ТОЛЬКО во внутрипроцессных фикстурах и запрещена на
// поднятом кластере. Профиль helm по построению относится к поднятому кластеру.
//
// Замер, из которого гейт выведен (задача #2473): чарт ПРЕДЛАГАЛ ДВЕ цепочки —
// боевую и `values.yaml + values.dev.yaml`, — и вторая объявляла `authMode: dev`
// и оставляла режим шифрования до базы небезопасным значением из базовых. Ни
// один гейт этого не судил: боевые пробы смотрят боевую цепочку, а перепись
// поставки судит СОСТАВ каталога, а не посадку его профилей. Потребителей у
// цепочки не было ни одного — то есть её единственным возможным потребителем
// был КЛИЕНТ, которому чарт уезжает.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ СУДЯТСЯ ЦЕПОЧКИ, А НЕ ФАЙЛЫ
//
// Посадку задаёт не файл, а НАЛОЖЕНИЕ: базовые значения объявляют
// `authMode: production`, и небезопасной цепочку делает накладка. Судить файлы
// по одному значило бы (а) краснеть на базовых значениях, которые в одиночку
// вообще не устанавливаются, и (б) молчать о накладке, которая посадку
// понижает, — то есть ровно наоборот.
//
// Перечень предлагаемых цепочек берётся ОТТУДА ЖЕ, где его объявляет перепись
// контуров поставщика (`chartChains` в provider_hops_test.go, тот же пакет).
// Второе место об одном предмете разошлось бы молча — и разошлось бы на
// цепочке, которую в него забыли дописать.
//
// ─────────────────────────────────────────────────────────────────────────────
// ВЕДОМОСТЬ НЕПРЕДЛАГАЕМЫХ — САМОИСТЕКАЮЩАЯ
//
// Поставляемый профиль, не входящий ни в одну предлагаемую цепочку, обязан быть
// назван с причиной. Запись, называющая файл, которого в каталоге больше нет, —
// НАХОДКА: иначе снятый профиль оставил бы за собой прощение, под которое уедет
// следующий. Запись, чей файл ВЕРНУЛСЯ в предлагаемую цепочку, — тоже находка:
// прощение выдано тому, кого теперь судят.
package deploy_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// productionPosturePrefix — посадка считается боевой по ПРЕФИКСУ, а не по
// точному значению: боевых посадок в этом дереве две (`production` и
// `production-strict`), и перечисление их поимённо разошлось бы с процессом на
// третьей. Тот же предикат исполняет проба боевого профиля в композиционном
// корне.
const productionPosturePrefix = "production"

// profilesNotOfferedForInstallation — поставляемые профили, которые чарт
// установкой НЕ ПРЕДЛАГАЕТ, с причиной по каждому.
//
// Причина обязана называть, ЧЕЙ это предмет, а не почему до него не дошли руки.
var profilesNotOfferedForInstallation = map[string]string{
	"values.dev.yaml": "не посадка, а ФИКСТУРА ОТКРЫТОГО ТЕКСТА для двух шипованных " +
		"гейтов, которым нужен ОБА конца оси: `probe_scheme_follows_edge_test.go` " +
		"сверяет, что схема пробы следует транспорту ребра (шифрованное ребро → HTTPS, " +
		"открытое → HTTP), а `scrape_declared_test.go` — что сбор величин объявлен на " +
		"обоих. Отобрав у них открытый конец, мы получили бы односторонние гейты, " +
		"зеленеющие на всём сломанном. Установкой она не предлагается: её нет ни в " +
		"одной цепочке `chartChains`, и координат TLS чужого кластера она не называет " +
		"вовсе, поэтому боевой посадки на ней не собрать (задача #2473).",
}

// chainPosture — посадка, объявленная наложением профилей цепочки, по правилам
// helm: карта сливается вглубь, скаляр замещается целиком.
func chainPosture(t *testing.T, dir string, files []string) (string, int) {
	t.Helper()
	values := map[string]any{}
	read := 0
	for _, name := range files {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("профиль цепочки не читается (%s): %v", name, err)
		}
		var profile map[string]any
		if err := yaml.Unmarshal(raw, &profile); err != nil {
			t.Fatalf("профиль цепочки не разбирается (%s): %v", name, err)
		}
		mergeValuesInto(values, profile)
		read++
	}
	posture, _ := values["authMode"].(string)
	return posture, read
}

// mergeValuesInto — наложение профиля поверх накопленного, по правилам helm.
func mergeValuesInto(dst, src map[string]any) {
	for key, srcVal := range src {
		srcMap, srcIsMap := srcVal.(map[string]any)
		dstMap, dstIsMap := dst[key].(map[string]any)
		if srcIsMap && dstIsMap {
			mergeValuesInto(dstMap, srcMap)
			continue
		}
		dst[key] = srcVal
	}
}

// judgeOfferedChainPostures — ТЕЛО гейта, вынесенное отдельно, чтобы инъекция
// звала то же, что исполняется на дереве.
//
// Находок три вида, и они РАЗНЫЕ: общий текст скрыл бы, что именно чинить.
func judgeOfferedChainPostures(
	postures map[string]string, shippedProfiles []string, offeredIn map[string]bool,
	excused map[string]string,
) (findings []string) {
	for chain, posture := range postures {
		if strings.HasPrefix(posture, productionPosturePrefix) {
			continue
		}
		findings = append(findings, "цепочка "+chain+" предлагается для установки и объявляет "+
			"посадку "+quoteOrNone(posture)+": ban #16 разрешает небезопасную посадку только "+
			"во внутрипроцессных фикстурах и запрещает её на поднятом кластере, а профиль helm "+
			"по построению относится к поднятому кластеру")
	}
	for _, profile := range shippedProfiles {
		if offeredIn[profile] {
			if _, ok := excused[profile]; ok {
				findings = append(findings, "профиль "+profile+" назван в ведомости "+
					"непредлагаемых и при этом входит в предлагаемую цепочку: прощение выдано "+
					"тому, кого теперь судят")
			}
			continue
		}
		if _, ok := excused[profile]; !ok {
			findings = append(findings, "поставляемый профиль "+profile+" не входит ни в одну "+
				"предлагаемую цепочку и не назван в ведомости непредлагаемых: клиент вправе "+
				"поставить чарт с ним, и никто не решал, что за посадку он получит")
		}
	}
	for profile := range excused {
		if !containsString(shippedProfiles, profile) {
			findings = append(findings, "ведомость непредлагаемых называет "+profile+
				", а такого профиля в поставляемом каталоге нет: запись пережила свой предмет")
		}
	}
	sort.Strings(findings)
	return findings
}

func quoteOrNone(s string) string {
	if s == "" {
		return "НЕ ОБЪЯВЛЕННУЮ вовсе"
	}
	return `"` + s + `"`
}

func containsString(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func TestOfferedInstallationChainsDeclareAProductionPosture(t *testing.T) {
	dir := filepath.Join(serviceRoot(t), "deploy")

	// Поставляемые профили берутся из ВЕДОМОСТИ ПОСТАВКИ, а не с диска: предмет
	// гейта — то, что уезжает клиенту, и ведомость есть единственное место, где
	// это объявлено. Она же сверена с диском в обе стороны своим гейтом.
	var shipped []string
	for _, name := range deliveryRoster {
		if strings.HasPrefix(name, "values.") && strings.HasSuffix(name, ".yaml") {
			shipped = append(shipped, name)
		}
	}
	if len(shipped) == 0 {
		t.Fatal("обход пуст: в ведомости поставки нет ни одного профиля — вердикт беспредметен")
	}
	if len(chartChains) == 0 {
		t.Fatal("обход пуст: чарт не предлагает ни одной цепочки — вердикт беспредметен")
	}

	postures := map[string]string{}
	offeredIn := map[string]bool{}
	profilesRead := 0
	for chain, files := range chartChains {
		posture, read := chainPosture(t, dir, files)
		postures[chain] = posture
		profilesRead += read
		for _, f := range files {
			offeredIn[f] = true
		}
	}

	findings := judgeOfferedChainPostures(postures, shipped, offeredIn, profilesNotOfferedForInstallation)

	names := make([]string, 0, len(postures))
	for chain, posture := range postures {
		names = append(names, chain+"="+quoteOrNone(posture))
	}
	sort.Strings(names)
	t.Logf("перепись: поставляемых профилей %d · предлагаемых цепочек %d "+
		"(прочитано наложений %d) · названо в ведомости непредлагаемых %d",
		len(shipped), len(chartChains), profilesRead, len(profilesNotOfferedForInstallation))
	t.Logf("посадки предлагаемых цепочек: %s", strings.Join(names, ", "))

	for _, f := range findings {
		t.Error(f)
	}
}
