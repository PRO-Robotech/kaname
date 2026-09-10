// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// service_links_are_off_test.go — ПОСТАВЛЯЕМЫЙ ЧАРТ ГАСИТ ПОДСТАНОВКУ АДРЕСОВ
// СЛУЖБ: она перебивает величины оператора.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Kubernetes объявляет каждому поду адреса всех служб своего пространства имён
// переменными окружения, выводя имя переменной из ИМЕНИ СЛУЖБЫ: верхний
// регистр, дефис → подчёркивание. Корневой сегмент всех переменных этой службы —
// тот же `KANAME`, что и имя её собственной службы в кластере, поэтому служба
// `<имя>-internal` объявляет поду `KANAME_INTERNAL_PORT` со значением
// `tcp://<адрес>:<порт>` — прямо в пространство имён настроек процесса, где это
// имя есть РУЧКА ПОРТА внутреннего слушателя.
//
// Цена измерена, а не предположена: поставка не поднималась. Процесс проходил
// ВСЕ миграции, отчитывался о посадке, о шифровании до базы и о взаимном
// транспорте на пяти слушателях — и падал ПОСЛЕДНИМ шагом, на открытии
// слушателя, отказом от библиотеки, не называвшим ни ручки, ни того, откуда
// взялось значение.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЭТО НЕ ДУБЛИРУЕТ СТРАЖА ПРОЦЕССА
//
// Процесс с тех пор такое значение отвергает сам, называя ручку
// (`config/service_link_collision.go`). Это разные предметы, и одно другого не
// заменяет: здесь снимается ПРИЧИНА, там — молчание. Оператор, разворачивающий
// службу СВОИМИ манифестами, этого ключа не получит, и страж процесса —
// единственное, что у него есть; поставка же обязана подниматься без чтения
// текстов отказа.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ УТВЕРЖДАЕТСЯ
//
//	Р1  spec пода объявляет `enableServiceLinks: false` на КАЖДОЙ поставляемой
//	    цепочке профилей;
//	Р2  ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: чарт ничего из адресов служб не читает — иначе
//	    гашение сломало бы адресацию соседа;
//	Р3  перепись печатается величинами: «ноль находок» отличимо от «ноль
//	    прочитанного».
//
// Вердикт выносится по РЕНДЕРУ, а не по тексту шаблона: спрашивается «что
// получит кластер», а не «упомянут ли ключ». Ключ, стоящий под условием, которое
// на поставляемом профиле ложно, в тексте есть, а в рендере его нет.
package deploy_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// deliveredProfileChains — цепочки профилей, которыми поставку РАЗВОРАЧИВАЮТ.
// Перечень мал и закрыт: каждая запись — путь, которым чарт доезжает до
// кластера.
var deliveredProfileChains = [][]string{
	{"values.yaml", "values.prod.yaml"},
	{"values.yaml", "values.dev.yaml"},
}

// podSpecsOfDeployments — spec пода каждого Deployment рендера.
func podSpecsOfDeployments(t *testing.T, rendered string) []map[string]any {
	t.Helper()
	var specs []map[string]any
	for _, doc := range strings.Split(rendered, "\n---") {
		if strings.TrimSpace(doc) == "" {
			continue
		}
		var obj map[string]any
		if err := yaml.Unmarshal([]byte(doc), &obj); err != nil {
			continue // не объект — о нём судит рендер, не эта мера
		}
		if kind, _ := obj["kind"].(string); kind != "Deployment" {
			continue
		}
		spec, _ := obj["spec"].(map[string]any)
		tmpl, _ := spec["template"].(map[string]any)
		if ps, ok := tmpl["spec"].(map[string]any); ok {
			specs = append(specs, ps)
		}
	}
	return specs
}

// TestDeliveredChartTurnsClusterServiceLinksOff — Р1 и Р3.
func TestDeliveredChartTurnsClusterServiceLinksOff(t *testing.T) {
	var chainsSeen, specsSeen, off int
	for _, chain := range deliveredProfileChains {
		rendered := renderStandaloneChart(t, chain, minimalOperatorCoordinates...)
		chainsSeen++
		specs := podSpecsOfDeployments(t, rendered)
		require.NotEmptyf(t, specs, "цепочка %v: Deployment в рендере не найден ни один — "+
			"обход пуст, и вердикт беспредметен", chain)
		for _, ps := range specs {
			specsSeen++
			v, declared := ps["enableServiceLinks"]
			if !declared {
				t.Errorf("цепочка %v: spec пода НЕ объявляет `enableServiceLinks` — кластер "+
					"подставит поду адреса всех служб пространства имён, и подстановка "+
					"`KANAME_INTERNAL_PORT=tcp://<адрес>:<порт>` перебьёт ручку порта "+
					"внутреннего слушателя. Умолчание платформы — ВКЛЮЧЕНО", chain)
				continue
			}
			b, isBool := v.(bool)
			if !isBool || b {
				t.Errorf("цепочка %v: `enableServiceLinks` объявлен как %#v, ожидалось false", chain, v)
				continue
			}
			off++
		}
	}
	if chainsSeen == 0 || specsSeen == 0 {
		t.Fatalf("обход пуст: цепочек %d, spec пода %d — «находок ноль» неотличимо от "+
			"«ноль прочитанного»", chainsSeen, specsSeen)
	}
	t.Logf("перепись: поставляемых цепочек профилей %d · spec пода осмотрено %d · "+
		"подстановка погашена в %d", chainsSeen, specsSeen, off)
}

// clusterLinkVarRe — форма имени, которую подставляет кластер. Держится ЗДЕСЬ
// намеренно узко: предмет положительного контроля — не грамматика (её судит
// распознаватель службы), а вопрос «читает ли чарт хоть одно такое имя».
var clusterLinkVarRe = regexp.MustCompile(`[A-Z0-9_]+_(SERVICE_HOST|SERVICE_PORT|PORT)(_[A-Z0-9_]+)?\b`)

// TestNothingInTheDeliveredChartReadsAServiceLinkVariable — Р2, ПОЛОЖИТЕЛЬНЫЙ
// КОНТРОЛЬ.
//
// Без него гашение выглядело бы бесплатным по построению. Спрашивается обратное:
// не адресуется ли кто-то из соседей ИМЕННО подстановкой — тогда гашение сломало
// бы адресацию, и решение было бы неверным.
//
// Судится РЕНДЕР: величина, подставленная в env, видна только в нём.
func TestNothingInTheDeliveredChartReadsAServiceLinkVariable(t *testing.T) {
	var chainsSeen, envsSeen, reads int
	for _, chain := range deliveredProfileChains {
		rendered := renderStandaloneChart(t, chain, minimalOperatorCoordinates...)
		chainsSeen++
		for _, ps := range podSpecsOfDeployments(t, rendered) {
			for _, key := range []string{"initContainers", "containers"} {
				list, _ := ps[key].([]any)
				for _, c := range list {
					cm, _ := c.(map[string]any)
					envs, _ := cm["env"].([]any)
					for _, e := range envs {
						em, _ := e.(map[string]any)
						envsSeen++
						val, _ := em["value"].(string)
						// Читают подстановку двумя способами: раскрытием
						// `$(ИМЯ)` платформой либо ссылкой в самом значении.
						if !strings.Contains(val, "$(") {
							continue
						}
						if m := clusterLinkVarRe.FindString(val); m != "" {
							name, _ := em["name"].(string)
							reads++
							t.Errorf("переменная %s читает подстановку адресов служб (%s): "+
								"гашение `enableServiceLinks: false` сломает эту адресацию — "+
								"сосед обязан адресоваться ОБЪЯВЛЕННОЙ величиной профиля",
								name, m)
						}
					}
				}
			}
		}
	}
	if chainsSeen == 0 || envsSeen == 0 {
		t.Fatalf("обход пуст: цепочек %d, переменных %d — вердикт беспредметен", chainsSeen, envsSeen)
	}
	t.Logf("перепись: цепочек %d · переменных контейнеров осмотрено %d · "+
		"читающих подстановку %d", chainsSeen, envsSeen, reads)
}
