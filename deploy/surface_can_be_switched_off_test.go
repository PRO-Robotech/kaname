// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// surface_can_be_switched_off_test.go — ГЕЙТ КЛАССА: поверхность, которую
// процесс поднимает УМОЛЧАНИЕМ, обязана выключаться профилем.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// «Выключено» у поверхности выражается ПУСТЫМ АДРЕСОМ — так это читает и сам
// процесс, и каждый его страж («пустой адрес — слушателя нет, судить нечего»).
// Поверхность, чей адрес приходит непустым умолчанием, поднимается ВСЕГДА, и
// выключить её оператор может ровно одним способом: объявив адрес пустым.
//
// Замер, из которого гейт выведен (задача #2477): у ЧЕТЫРЁХ поверхностей
// умолчание непусто, и ни одну из них чарт выключить не давал — их ключей он не
// эмитил в настройки ВОВСЕ. Свободная карта переменных этого не заменяет:
// `AutomaticEnv` без `AllowEmptyEnv` читает пустую переменную как незаданную,
// то есть возвращает то же умолчание. Одна из четырёх — ВНЕШНЕ ДОСЯГАЕМАЯ
// поверхность выдачи токенов; для службы, которую ставят в чужом облаке,
// «сузить периметр» — законное и частое требование оператора, и оно было
// невыразимо.
//
// Поверхность, которую нельзя выключить, — это поверхность, которую оператор не
// выбирал.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ПЕРЕЧЕНЬ ВЫВОДИТСЯ, А НЕ ВЫПИСЫВАЕТСЯ
//
// Он берётся из переписи поверхностей самого процесса (`tools/surfaceroster`),
// той же, что читает гейт объявления сбора величин. Выписанный перечень
// разошёлся бы с процессом молча — и разошёлся бы на поверхности, которую в него
// забыли дописать, то есть ровно на той, ради которой гейт заведён.
//
// Ручка чарта ВЫВОДИТСЯ из ключа настройки тем же правилом, которым чарт их и
// именует (`api-server.metrics-endpoint` → `apiServer.metricsEndpoint`).
// Рукописная таблица «ключ → ручка» была бы вторым местом об одном предмете.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ ОБЯЗАТЕЛЕН
//
// Отрицание «пустая ручка не гасит» зеленело бы на чарте, который не эмитит
// НИЧЕГО. Поэтому та же ручка проверяется и НЕПУСТОЙ: она обязана доехать до
// настроек своим значением. Без этой половины гейт не отличил бы «ручка гасит»
// от «загрузчик вообще не читает этот ключ».
package deploy_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/PRO-Robotech/kaname/tools/surfaceroster"
)

// chartKnobOf — ручка чарта, отвечающая ключу настройки.
//
// Правило одно на все ключи и то же, которым чарт их именует: сегменты пути
// сохраняются, дефисы внутри сегмента складываются в верблюжий регистр.
func chartKnobOf(settingKey string) string {
	segs := strings.Split(settingKey, ".")
	for i, seg := range segs {
		parts := strings.Split(seg, "-")
		for j := 1; j < len(parts); j++ {
			if parts[j] == "" {
				continue
			}
			parts[j] = strings.ToUpper(parts[j][:1]) + parts[j][1:]
		}
		segs[i] = strings.Join(parts, "")
	}
	return strings.Join(segs, ".")
}

// configValueAt — значение по пути ключа настройки в теле отрендеренных
// настроек. Второй результат говорит, есть ли ключ ВООБЩЕ: отсутствие ключа и
// пустое значение — РАЗНЫЕ состояния, и весь предмет гейта в их различии.
func configValueAt(t *testing.T, body, settingKey string) (string, bool) {
	t.Helper()
	var doc map[string]any
	require.NoError(t, yaml.Unmarshal([]byte(body), &doc), "тело настроек не разбирается")

	var cur any = doc
	for _, seg := range strings.Split(settingKey, ".") {
		asMap, ok := cur.(map[string]any)
		if !ok {
			return "", false
		}
		cur, ok = asMap[seg]
		if !ok {
			return "", false
		}
	}
	if cur == nil {
		return "", true
	}
	s, ok := cur.(string)
	if !ok {
		return "", false
	}
	return s, true
}

func TestEverySurfaceRaisedByDefaultCanBeSwitchedOffByTheProfile(t *testing.T) {
	roster, err := surfaceroster.Read(serviceRoot(t))
	require.NoError(t, err, "перечень поверхностей процесса")
	require.NotEmpty(t, roster.Surfaces,
		"обход пуст: поверхностей процесса прочитано 0 — вердикт беспредметен")

	var raisedByDefault []surfaceroster.Surface
	for _, s := range roster.Surfaces {
		if s.GRPC {
			// У gRPC-ног адрес выводится из порта, а не из ключа-адреса: их
			// выключение — отдельный предмет, и этот гейт о нём не говорит.
			continue
		}
		if strings.TrimSpace(s.DefaultAddr) != "" {
			raisedByDefault = append(raisedByDefault, s)
		}
	}
	require.NotEmpty(t, raisedByDefault,
		"обход пуст: поверхностей с непустым умолчанием 0 — вердикт беспредметен: "+
			"гейт заведён ровно про них")

	names := make([]string, 0, len(raisedByDefault))
	for _, s := range raisedByDefault {
		names = append(names, s.SettingKey+"→"+chartKnobOf(s.SettingKey))
	}
	sort.Strings(names)
	t.Logf("перепись: поверхностей процесса %d (прочитано файлов %d, умолчаний %d) · "+
		"поднимаемых умолчанием %d",
		len(roster.Surfaces), roster.FilesRead, roster.DefaultsRead, len(raisedByDefault))
	t.Logf("судится: %s", strings.Join(names, ", "))

	for _, s := range raisedByDefault {
		t.Run(s.SettingKey, func(t *testing.T) {
			knob := chartKnobOf(s.SettingKey)

			// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ, и он идёт первым: без него отрицание ниже
			// зеленело бы на чарте, который не эмитит ключ ни при каком входе.
			const moved = "tcp://0.0.0.0:19999"
			rendered := renderStandaloneChart(t,
				[]string{"values.yaml", "values.prod.yaml"}, knob+"="+moved)
			body := readRenderedInput(t, rendered).ConfigBody
			got, present := configValueAt(t, body, s.SettingKey)
			require.Truef(t, present,
				"ручка %s объявлена непустой, а ключа %s в настройках нет вовсе: чарт не эмитит "+
					"его ни при каком входе, поэтому профиль этой поверхностью не управляет",
				knob, s.SettingKey)
			require.Equalf(t, moved, got,
				"ручка %s объявлена значением %q, а в настройки уехало %q", knob, moved, got)

			// ОТРИЦАНИЕ: пустая ручка обязана доехать ПУСТОЙ, а не исчезнуть.
			// Исчезнув, она вернула бы поверхность к умолчанию — то есть
			// «выключить» означало бы «оставить как было».
			rendered = renderStandaloneChart(t,
				[]string{"values.yaml", "values.prod.yaml"}, knob+"=")
			body = readRenderedInput(t, rendered).ConfigBody
			got, present = configValueAt(t, body, s.SettingKey)
			require.Truef(t, present,
				"ручка %s объявлена ПУСТОЙ, а ключа %s в настройках нет: процесс возьмёт своё "+
					"умолчание %q и поднимет поверхность, которую оператор только что выключил — "+
					"«выключено» здесь означает «как было»",
				knob, s.SettingKey, s.DefaultAddr)
			require.Emptyf(t, got,
				"ручка %s объявлена ПУСТОЙ, а в настройки уехало %q", knob, got)
		})
	}
}
