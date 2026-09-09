// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// port_knob_moves_its_listener_test.go — У ОДНОЙ ДВЕРИ ОДНА РУЧКА: ключ посадки
// под `ports:` обязан двигать СЛУШАТЕЛЬ, а не только маршрут к нему.
//
// # Предмет
//
// Ключ `ports.metrics` читали порт пода и объявление сбора, а карта настроек
// адреса диагностической поверхности не эмитила вовсе — процесс брал его
// умолчанием (задача #2394). Оператор, задавший ключ, получал маршрут на один
// порт и слушатель на другом, и узнавал об этом не рендером, а тем, что
// собиратель приходил туда, где никто не отвечает.
//
// Класс тот же, что закрыт для собственных REST-фронтов задачей #2337, и он
// молчит by construction: каждое из двух объявлений по отдельности верно.
//
// # Почему гейт БЕХАВИОРАЛЬНЫЙ, а не текстовый
//
// Сосед (`TestServiceRoutesEverySurfaceItRaises`) сверяет маршрут с адресом на
// ПОСТАВЛЯЕМЫХ профилях, где величины сегодня совпадают, — то есть ловит
// расхождение, которое мы завели сами, и молчит о том, которое заведёт
// оператор. Здесь спрашивается другое: ЧТО СДЕЛАЕТ ключ, если его тронуть.
// Производитель входа — сам helm: ключ двигается на пробную величину, и
// вердикт выносится по тому, что получилось.
//
// Разбор ТЕКСТА шаблонов на эту роль не годится: он отвечает «читает ли кто-то
// `.Values.ports.X`», а спрашивать надо «доедет ли новая величина до процесса».
// Между этими вопросами и жил дефект.
//
// # Что здесь утверждается
//
//	Р1  перечень ключей ВЫВЕДЕН из профиля, а не выписан;
//	Р2  тронутый ключ либо доезжает до слушателя, либо ОТВЕРГАЕТСЯ рендером;
//	Р3  ключ, не двигающий ничего, — тоже находка (принято-и-проигнорировано);
//	Р4  перепись печатается ДВУМЯ величинами.
//
// # Три исхода у ключа, а не два
//
// «Отказ рендера» — законный исход и означает СНЯТЫЙ ключ: снятие, о котором
// оператору не сказали, неотличимо от работающей ручки, поэтому снятый ключ
// обязан отвергаться вслух (`kaname-svc.requireNoRetiredPortKnobs`).
//
// # Область
//
// Судится РЕНДЕР. Поднятия пода здесь нет: свободного кластера нет, и это
// третья категория — не зелёное и не красное.
package deploy_test

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// knobProbeBase — начало полосы пробных величин. Величина обязана отличаться от
// всякой, которую профиль объявляет сам: совпадение сделало бы «ручка двигает»
// неотличимым от «ничего не менялось».
const knobProbeBase = 9700

// portKnobVerdict — исход одного ключа.
type portKnobVerdict struct {
	key  string
	port string
	// how — чем ключ оказался одной ручкой одной двери.
	how string
	// why — почему он ею НЕ оказался.
	why string
}

func TestEveryPortKnobMovesTheListenerItRoutes(t *testing.T) {
	files := []string{"values.yaml", "values.prod.yaml"}

	knobs := portKnobsIn(t, readChartFile(t, ".", "values.yaml"))
	require.NotEmpty(t, knobs,
		"под `ports:` профиля нет ни одного ключа — вердикт был бы о пустоте, а не о чарте")

	// ПРЕДПОСЫЛКА: базовый рендер вообще даёт слушателей. Без неё «ни один ключ
	// не двигает слушатель» было бы неотличимо от «слушателей читать неоткуда».
	base := renderChartAt(t, ".", files...)
	baseListeners := listenerPortsOf(t, base)
	require.NotEmptyf(t, baseListeners,
		"базовый рендер не объявил ни одного адреса слушателя — читать нечего, "+
			"и «ноль находок» было бы неотличимо от «ноль прочитанного»")

	single, verdicts, findings := judgePortKnobsIn(t, ".", files, knobs, baseListeners)

	lines := make([]string, 0, len(verdicts))
	for _, v := range verdicts {
		if v.why == "" {
			lines = append(lines, fmt.Sprintf("  ports.%-14s → :%-5s %s", v.key, v.port, v.how))
		} else {
			lines = append(lines, fmt.Sprintf("  ports.%-14s → :%-5s ДВЕ РУЧКИ ОБ ОДНОЙ ДВЕРИ", v.key, v.port))
		}
	}
	sort.Strings(lines)
	t.Logf("ПЕРЕПИСЬ ключей посадки чарта службы:\n%s\n"+
		"  ключей под `ports:` ОСМОТРЕНО %d · РУЧКОЙ ОДНОЙ ДВЕРИ оказалось %d\n"+
		"  адресов слушателя в базовом рендере: %d",
		strings.Join(lines, "\n"), len(knobs), single, len(baseListeners))

	require.Emptyf(t, findings,
		"ключей осмотрено %d · ручкой одной двери %d; двигают маршрут и не двигают слушатель — %d:\n  - %s",
		len(knobs), single, len(findings), strings.Join(findings, "\n  - "))
}

// judgePortKnobsIn — САМО СУЖДЕНИЕ, отделённое от пробы и от каталога чарта:
// доказательство способности гейта упасть обязано звать ЕГО ЖЕ над своей копией,
// иначе оно доказывало бы о пересказе, а не о гейте.
func judgePortKnobsIn(t *testing.T, dir string, files, knobs []string, baseListeners map[string]bool) (int, []portKnobVerdict, []string) {
	t.Helper()

	var single int
	var verdicts []portKnobVerdict
	var findings []string

	for i, key := range knobs {
		probe := fmt.Sprintf("%d", knobProbeBase+i)
		// Пробная величина обязана отличаться от всякой, которую профиль
		// объявляет сам: совпади она — «ручка двигает слушатель» стало бы
		// неотличимо от «ничего не менялось», и гейт зеленел бы вакуумно.
		require.Falsef(t, baseListeners[probe],
			"пробная величина :%s уже объявлена базовым рендером — вердикт по ports.%s был бы вакуумным",
			probe, key)
		v := portKnobVerdict{key: key, port: probe}

		out, err := renderChartAtAllowingFailure(t, dir, files, "ports."+key+"="+probe)
		if err != nil {
			// ОТКАЗ РЕНДЕРА — исход законный ТОЛЬКО когда он про этот ключ:
			// снятие, о котором оператору не сказали, неотличимо от работающей
			// ручки, поэтому снятый ключ отвергается вслух и НАЗЫВАЕТ себя.
			//
			// Отказ, ключа не называющий, — это «не выполнилось», третья
			// категория: рендер сломан по чужой причине, и вердикта о ручках у
			// него нет ни зелёного, ни красного. Засчитать его в «одна ручка на
			// дверь» значило бы зеленеть на сломанном чарте.
			if !strings.Contains(out, "ports."+key) {
				t.Fatalf("рендер с ports.%s=%s отказал, НЕ НАЗВАВ ключа — это «не выполнилось», "+
					"а не вердикт о ручке:\n%s", key, probe, out)
			}
			v.how = "ключ СНЯТ: рендер отвергает его вслух"
			single++
			verdicts = append(verdicts, v)
			continue
		}

		listeners := listenerPortsOf(t, out)
		routes := routePortsOf(t, out)

		switch {
		case listeners[probe]:
			v.how = "двигает слушатель (адрес процесса) вместе с маршрутом"
			single++
		case routes[probe]:
			v.why = fmt.Sprintf(
				"ключ двинул маршрут на :%s (порт пода / объект Service / объявление сбора), "+
					"а адрес, по которому поверхность поднимает ПРОЦЕСС, остался прежним: "+
					"карта настроек этой величины не эмитит. Рендер зелёный, дверь ведёт в никуда",
				probe)
		default:
			v.why = fmt.Sprintf(
				"ключ не двинул НИЧЕГО — ни адреса слушателя, ни маршрута: :%s не встретился нигде. "+
					"Ручка, которую принимают и не читают, обещает возможность, которой нет",
				probe)
		}

		if v.why != "" {
			findings = append(findings, fmt.Sprintf("ports.%s: %s", key, v.why))
		}
		verdicts = append(verdicts, v)
	}

	return single, verdicts, findings
}

// portKnobsIn — ключи под `ports:` названного профиля.
//
// ВЫВОДЯТСЯ, а не выписываются: выписанный перечень разошёлся бы с профилем
// молча, и новый ключ попал бы вне наблюдения — не находкой и не зелёным.
func portKnobsIn(t *testing.T, b string) []string {
	t.Helper()
	var doc struct {
		Ports map[string]any `yaml:"ports"`
	}
	require.NoError(t, yaml.Unmarshal([]byte(b), &doc), "разбор values.yaml")
	keys := make([]string, 0, len(doc.Ports))
	for k := range doc.Ports {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// listenerPortsOf — порты АДРЕСОВ, которые рендер отдаёт процессу.
//
// Перечень ключей адресов берётся у перечня поверхностей процесса, а не
// выписывается здесь: второе место об одном предмете разошлось бы с процессом
// молча — ровно тот класс, ради которого перечень и заведён.
func listenerPortsOf(t *testing.T, rendered string) map[string]bool {
	t.Helper()
	cfg := renderedConfigTree(t, rendered)
	out := map[string]bool{}
	for _, s := range readSurfaceRoster(t).Surfaces {
		if p := portOfAddr(configString(cfg, s.SettingKey)); p != "" {
			out[p] = true
		}
	}
	return out
}

// routePortsOf — порты, которыми рендер ВЕДЁТ к поверхностям: объекты Service,
// порты пода и объявление сбора.
func routePortsOf(t *testing.T, rendered string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	svcPorts, _ := renderedServicePorts(t, rendered)
	for _, set := range svcPorts {
		for p := range set {
			out[p] = true
		}
	}
	for p := range renderedContainerPorts(t, rendered) {
		out[p] = true
	}
	if sc := renderedScrapeDeclared(t, rendered); sc.enabled && sc.port != "" {
		out[sc.port] = true
	}
	return out
}

// TestRetiredPortKnobIsRefusedAloud — СНЯТЫЙ ключ отвергается, а не игнорируется.
//
// Гейт выше засчитывает отказ рендера как «одна ручка на дверь», и это верно
// ровно потому, что отказ существует. Без него снятый ключ принимался бы молча —
// то есть «принято-и-проигнорировано» на поверхности установки: оператор правит
// профиль, рендер зелёный, поведение прежнее.
//
// Ось одна, и у неё законный близнец: ЖИВОЙ ключ той же формы отказа не даёт.
func TestRetiredPortKnobIsRefusedAloud(t *testing.T) {
	files := []string{"values.yaml", "values.prod.yaml"}

	out, err := renderChartAtAllowingFailure(t, ".", files, "ports.metrics=9195")
	require.Errorf(t, err,
		"снятый ключ принят молча — оператору он неотличим от работающего:\n%s", out)
	require.Contains(t, out, "ports.metrics",
		"отказ не называет ключ: оператор не узнает, что именно убрать")
	require.Contains(t, out, "KANAME_API_SERVER__METRICS_ENDPOINT",
		"отказ не называет, ЧЕМ двигать предмет теперь: запрет без замены снимут как непонятный")

	// ЗАКОННЫЙ БЛИЗНЕЦ: живой ключ той же формы обязан рендериться.
	// Без него «отказ на всём» выглядел бы как исполненная проверка.
	out, err = renderChartAtAllowingFailure(t, ".", files, "ports.grpc=9190")
	require.NoErrorf(t, err, "живой ключ отвергнут — страж судит форму, а не предмет:\n%s", out)
}
