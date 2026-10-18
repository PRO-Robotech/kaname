// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// own_lane_cpu_supply_test.go — ПОСТАВЛЯЕМЫЙ ПРОФИЛЬ ОБЪЯВЛЯЕТ ПРОЦЕССОРЫ
// СЛУЖБЫ ТАК, ЧТОБЫ МЕСТА ВЫЧИСЛЕНИЯ ПРОВЕРЯЮЩЕГО РАВНЯЛИСЬ ПРОЦЕССОРАМ, КОТОРЫЕ
// ПРОЦЕССУ ДАНЫ (kaname#891).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Проверяющий секретов (`internal/passwordverify`, места вычисления, kaname#882)
// пускает к вычислению не больше `min(GOMAXPROCS, ёмкость)` проверок, остальные
// ждут в порядке прихода; срок операции церемонии — два предела вызова базы
// плюс ёмкость × стоимость одной проверки, откалиброванной огибающей при
// старте (`ceremonyOperationDeadline`). Обе величины верны, лишь пока процессу
// дано ровно столько процессоров, сколько видели GOMAXPROCS и калибровка.
//
// Среда исполнения Go 1.26 выводит GOMAXPROCS так (`runtime/cgroup_linux.go`,
// `defaultGOMAXPROCS` и `adjustCgroupGOMAXPROCS`, go1.26.9): меньшее из числа
// процессоров узла и предела контрольной группы, предел округляется вверх и не
// ниже двух. Запрос (`requests.cpu`) среде не виден вовсе. Отсюда три условия
// профиля, и каждое — отдельный отказ:
//
//	П1  предел процессора объявлен. Без него GOMAXPROCS — число процессоров
//	    узла, места вычисления — вся ёмкость, очереди нет;
//	П2  запрос равен пределу. Под нагрузкой узла процессу гарантирован лишь
//	    запрос, а калибровка на старте видит до предела: при запросе 100m и
//	    пределе 2 стоимость, измеренная на двух процессорах, на занятом узле
//	    растёт в 20 раз, и срок операции её не покрывает;
//	П3  предел — целое число процессоров, не меньше двух. Дробный предел
//	    округляется вверх, предел 1 поднимается до 2: GOMAXPROCS, а с ним места
//	    вычисления, больше процессоров, и проверки снова делят процессор.
//
// Места вычисления считает НЕ копия формулы, а сам проверяющий: он строится
// при GOMAXPROCS, который среда выведет из предела профиля, и отвечает
// `ProcessorSlots`. Правило выведения GOMAXPROCS из предела — функция среды
// исполнения, недоступная снаружи; она переписана здесь одной строкой
// (`gomaxprocsUnderCPULimit`) со ссылкой на исходник версии из go.mod.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ПРОБА НЕ УТВЕРЖДАЕТ
//
// Она не утверждает, что обмены укладываются в срок на развёрнутом процессе:
// это свойство прогона на стенде под нагрузкой (предикат kaname#891), и судит
// его прогон. Она утверждает, что поставляемый профиль даёт процессу то
// предложение процессора, на котором срок и места #882 верны. Узел с числом
// процессоров меньше предела даст меньше мест — это свойство узла, а не
// профиля, и проба его не судит.
package deploy_test

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

// serviceContainerResources — блок `resources` контейнера СЛУЖБЫ из рендера
// (контейнер носит имя развёртывания; контейнер наката отдельный и здесь не
// судится). Обход пуст либо контейнера нет — отказ пробы, а не пустой блок.
func serviceContainerResources(t *testing.T, rendered string) map[string]any {
	t.Helper()
	var deployments int
	for _, doc := range strings.Split(rendered, "\n---") {
		var obj map[string]any
		if strings.TrimSpace(doc) == "" || yaml.Unmarshal([]byte(doc), &obj) != nil {
			continue
		}
		if kind, _ := obj["kind"].(string); kind != "Deployment" {
			continue
		}
		deployments++
		meta, _ := obj["metadata"].(map[string]any)
		name, _ := meta["name"].(string)
		spec, _ := obj["spec"].(map[string]any)
		tmpl, _ := spec["template"].(map[string]any)
		ps, _ := tmpl["spec"].(map[string]any)
		list, _ := ps["containers"].([]any)
		for _, c := range list {
			cm, _ := c.(map[string]any)
			if cname, _ := cm["name"].(string); cname != name {
				continue
			}
			res, _ := cm["resources"].(map[string]any)
			if res == nil {
				res = map[string]any{}
			}
			return res
		}
	}
	require.NotZerof(t, deployments, "обход пуст: Deployment в рендере не найден — вердикт беспредметен")
	require.Failf(t, "обход пуст", "контейнер службы не найден ни в одном из %d Deployment — вердикт беспредметен", deployments)
	return nil
}

// parseCPUQuantity — количество процессора Kubernetes в тысячных: целое,
// десятичная дробь либо суффикс `m`. Разбор строгий: незнакомая форма — отказ,
// а не ноль, иначе опечатка читалась бы как «предела нет».
func parseCPUQuantity(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, "m") {
		n, err := strconv.ParseInt(strings.TrimSuffix(s, "m"), 10, 64)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("количество процессора %q не читается", s)
		}
		return n, nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f < 0 {
		return 0, fmt.Errorf("количество процессора %q не читается", s)
	}
	return int64(f*1000 + 0.5), nil
}

// gomaxprocsUnderCPULimit — GOMAXPROCS, который среда исполнения Go 1.26
// выведет из предела контрольной группы на узле с процессорами не меньше
// предела: предел вверх до целого и не ниже двух (`adjustCgroupGOMAXPROCS`,
// `runtime/cgroup_linux.go`, go1.26.9).
func gomaxprocsUnderCPULimit(limitMilli int64) int {
	return int(max((limitMilli+999)/1000, 2))
}

// cpuSupplyCensus — прочитанное и выведенное; печатается всегда.
type cpuSupplyCensus struct {
	RequestRaw, LimitRaw     string
	RequestMilli, LimitMilli int64
	GOMAXPROCS               int
	Capacity                 int
	ProcessorSlots           int
}

func (c cpuSupplyCensus) String() string {
	or := func(s string) string {
		if s == "" {
			return "<не объявлен>"
		}
		return s
	}
	return fmt.Sprintf("requests.cpu %s · limits.cpu %s · GOMAXPROCS среды %d · ёмкость проверяющего %d · мест вычисления %d",
		or(c.RequestRaw), or(c.LimitRaw), c.GOMAXPROCS, c.Capacity, c.ProcessorSlots)
}

// processorSlotsAt — места вычисления, которые построит САМ проверяющий при
// данном GOMAXPROCS (`passwordverify.New` читает его при построении).
func processorSlotsAt(gomaxprocs, capacity int) (int, error) {
	prev := runtime.GOMAXPROCS(gomaxprocs)
	defer runtime.GOMAXPROCS(prev)
	v, err := passwordverify.New(capacity, silentVerifierObserver{})
	if err != nil {
		return 0, err
	}
	return v.ProcessorSlots(), nil
}

type silentVerifierObserver struct{}

func (silentVerifierObserver) VerificationObserved(passwordverify.Outcome) {}

// judgeOwnLaneCPUSupply — ТЕЛО меры; инъекции зовут его же.
func judgeOwnLaneCPUSupply(res map[string]any, capacity int) (cpuSupplyCensus, error) {
	census := cpuSupplyCensus{Capacity: capacity}
	requests, _ := res["requests"].(map[string]any)
	limits, _ := res["limits"].(map[string]any)
	if v, ok := requests["cpu"]; ok && v != nil {
		census.RequestRaw = fmt.Sprint(v)
	}
	if v, ok := limits["cpu"]; ok && v != nil {
		census.LimitRaw = fmt.Sprint(v)
	}
	if census.LimitRaw == "" {
		return census, fmt.Errorf("П1: предел процессора не объявлен — GOMAXPROCS равен числу процессоров узла, " +
			"места вычисления проверяющего равны всей ёмкости, очереди проверок нет")
	}
	var err error
	if census.LimitMilli, err = parseCPUQuantity(census.LimitRaw); err != nil {
		return census, fmt.Errorf("П1: %w", err)
	}
	if census.RequestRaw != "" {
		if census.RequestMilli, err = parseCPUQuantity(census.RequestRaw); err != nil {
			return census, fmt.Errorf("П2: %w", err)
		}
	}
	census.GOMAXPROCS = gomaxprocsUnderCPULimit(census.LimitMilli)
	if census.ProcessorSlots, err = processorSlotsAt(census.GOMAXPROCS, capacity); err != nil {
		return census, fmt.Errorf("проверяющий не строится с ёмкостью профиля: %w", err)
	}
	if census.RequestMilli != census.LimitMilli {
		return census, fmt.Errorf("П2: запрос процессора %dm не равен пределу %dm — на занятом узле процессу "+
			"гарантирован запрос, а стоимость проверки калибруется на старте до предела, и срок операции "+
			"церемонии её не покрывает", census.RequestMilli, census.LimitMilli)
	}
	if census.LimitMilli%1000 != 0 || int64(census.GOMAXPROCS)*1000 != census.LimitMilli {
		return census, fmt.Errorf("П3: предел %dm даёт GOMAXPROCS %d — места вычисления больше процессоров, "+
			"данных процессу; предел обязан быть целым числом процессоров не меньше двух",
			census.LimitMilli, census.GOMAXPROCS)
	}
	return census, nil
}

// TestProdProfileCPUSupplyMatchesTheVerifierProcessorSlots — П1–П3 на рендере
// поставляемой цепочки с накладкой оператора.
func TestProdProfileCPUSupplyMatchesTheVerifierProcessorSlots(t *testing.T) {
	rendered := renderStandaloneChart(t, chartProfiles, withOperatorOverlay(minimalOperatorCoordinates...)...)
	login := loginLaneOfRender(t, rendered)
	require.Positive(t, login.VerifierCapacity, "ёмкость проверяющего в рендере не прочитана — вердикт беспредметен")

	census, err := judgeOwnLaneCPUSupply(serviceContainerResources(t, rendered), login.VerifierCapacity)
	t.Logf("перепись: цепочка %v · %s", chartProfiles, census)
	require.NoErrorf(t, err, "поставляемая цепочка %v: %s", chartProfiles, census)
}
