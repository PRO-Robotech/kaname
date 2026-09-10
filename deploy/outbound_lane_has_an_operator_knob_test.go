// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// outbound_lane_has_an_operator_knob_test.go — ГЕЙТ ОБРАТНОГО НАПРАВЛЕНИЯ:
// у КАЖДОЙ исходящей полосы, которую поднимает процесс, есть операторская ручка
// в ПОСТАВКЕ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ (#2474)
//
// Гейты этого каталога до сих пор смотрели в ОДНУ сторону: «всё, что чарт
// рендерит, процесс читает» (`TestConfigBridge_CoversEveryKeyTheChartRenders`).
// Обратного не было ни одного, и обратное — это как раз то, где живёт класс
// «возможность объявлена и неисполнима штатным путём».
//
// Наблюдалось на почтовой полосе: очередь есть, писатель есть (намерение
// со-коммичено строкой приглашения), исполнитель есть и поднимается ВСЕГДА — а
// настроить полосу поставкой было НЕЧЕМ. Ни чарт, ни его профили, ни документ
// установки не называли ни узла, ни отправителя, ни якоря. Для оператора это
// значит: приглашение создаётся успешно, письмо не уходит НИКОГДА, и каждая
// попытка отправки даёт исход «настройка», пока строка не отравится.
//
// Соседний гейт этого не ловит BY CONSTRUCTION: обе его стороны про то, что чарт
// РЕНДЕРИТ, а здесь предмет ровно в том, чего он не рендерит.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО СЧИТАЕТСЯ «ИСХОДЯЩЕЙ ПОЛОСОЙ» — ОПРЕДЕЛЕНИЕ МЕХАНИЧЕСКОЕ
//
// Ключ настроек, называющий СЕТЕВУЮ КООРДИНАТУ ЧУЖОГО УЗЛА: последний сегмент
// `url`, `relay` либо оканчивается на `-url`. Из популяции вычитаются адреса
// СОБСТВЕННЫХ слушателей: их перечень берётся у переписи поверхностей процесса
// (`tools/surfaceroster`), а не выписывается — выписанный разошёлся бы с
// процессом молча, и разошёлся бы на поверхности, которую в него забыли
// дописать.
//
// Популяция ВЫВОДИТСЯ разбором объявления настроек (`config.Config`) отражением,
// поэтому новая исходящая полоса входит в неё САМА, вместе со своим полем.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО СЧИТАЕТСЯ «ОПЕРАТОРСКОЙ РУЧКОЙ В ПОСТАВКЕ» — ДВЕ ФОРМЫ, ОБЕ ЗАКОННЫ
//
//  1. чарт РЕНДЕРИТ ключ в файл настроек (`templates/configmap.yaml`);
//  2. поставляемый профиль НАЗЫВАЕТ переменную окружения этого ключа в карте
//     `env` — так объявлены три дороги к поставщику личности.
//
// Свободная карта `env` сама по себе ручкой НЕ является, и это несущее
// различие: задать через неё можно что угодно, но узнать, ЧТО задавать, неоткуда
// — а поставка обязана называть свои величины, а не предполагать, что оператор
// прочтёт наш код. Поэтому засчитывается НАЗВАННАЯ переменная, а не наличие
// карты.
//
// ФОРМ ИМЕНИ ПЕРЕМЕННОЙ ТОЖЕ ДВЕ. Каноническая выводится из ключа
// (`invite-mail.relay` → `KANAME_INVITE_MAIL__RELAY`), но у части ключей есть
// СВОЯ привязка, и профиль называет именно её (`authn.hydra-admin-url` →
// `KANAME_HYDRA_ADMIN_URL`). Вторая форма берётся у владельца объявления
// (`config.RequiredSettings`), а не угадывается: распознаватель, знающий одну
// форму, о другой МОЛЧИТ — не краснеет и не зеленеет.
package deploy_test

import (
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/tools/surfaceroster"
)

// dialCoordinateLeaf — называет ли ключ сетевую координату чужого узла.
//
// Словарь назван поимённо и доказан инъекцией по каждому имени: форма, о которой
// распознаватель не знает, не даёт ни красного, ни зелёного — она молчит.
func dialCoordinateLeaf(key string) bool {
	seg := key
	if i := strings.LastIndex(key, "."); i >= 0 {
		seg = key[i+1:]
	}
	return seg == "url" || seg == "relay" || strings.HasSuffix(seg, "-url")
}

// configLeafPaths — точечные пути ЛИСТЬЕВ объявления настроек, выведенные
// отражением. Новое поле входит в популяцию само, вместе со своим объявлением.
func configLeafPaths() []string {
	out := []string{}
	var walk func(t reflect.Type, prefix string, depth int)
	walk = func(t reflect.Type, prefix string, depth int) {
		if depth > 8 || t.Kind() != reflect.Struct {
			return
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := f.Tag.Get("mapstructure")
			if tag == "" || tag == "-" {
				continue
			}
			path := tag
			if prefix != "" {
				path = prefix + "." + tag
			}
			ft := f.Type
			for ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			// Длительность — структура по представлению и ЛИСТ по смыслу;
			// спуск в неё дал бы пути, которых у настроек не существует.
			if ft.Kind() == reflect.Struct && ft.String() != "time.Duration" {
				walk(ft, path, depth+1)
				continue
			}
			out = append(out, path)
		}
	}
	walk(reflect.TypeOf(config.Config{}), "", 0)
	sort.Strings(out)
	return out
}

// canonicalEnvName — каноническое имя переменной окружения для ключа настроек.
func canonicalEnvName(key string) string {
	s := strings.ReplaceAll(key, ".", "__")
	s = strings.ReplaceAll(s, "-", "_")
	return "KANAME_" + strings.ToUpper(s)
}

// declaredEnvNames — все имена переменных, которыми ключ подаётся: каноническое
// плюс объявленное владельцем таблицы обязательных величин.
func declaredEnvNames(key string) []string {
	names := []string{canonicalEnvName(key)}
	for _, rs := range config.RequiredSettings {
		if rs.Key == key && rs.Env != "" && rs.Env != names[0] {
			names = append(names, rs.Env)
		}
	}
	return names
}

// profileEnvNames — имена переменных, названные картой `env` поставляемых
// профилей чарта.
func profileEnvNames(t *testing.T, chartDir string) (map[string]bool, int) {
	t.Helper()
	out := map[string]bool{}
	profiles, err := chartProfileNames(chartDir)
	require.NoError(t, err, "профили чарта не читаются")
	for _, p := range profiles {
		values, err := readChartValues(filepath.Join(chartDir, p))
		require.NoErrorf(t, err, "профиль %s не читается", p)
		envs, ok := values["env"].(map[string]any)
		if !ok {
			continue
		}
		for k := range envs {
			out[k] = true
		}
	}
	return out, len(profiles)
}

// judgeOutboundLanes — ЧИСТОЕ ТЕЛО ВЕРДИКТА. Вынесено ради инъекции: доказать
// способность гейта упасть можно только подачей ему полосы без ручки, а такой
// полосы в дереве быть не должно.
func judgeOutboundLanes(lanes []string, rendered map[string]bool, envNamed map[string]bool, envOf func(string) []string) []string {
	findings := []string{}
	for _, key := range lanes {
		if rendered[key] {
			continue
		}
		named := false
		for _, e := range envOf(key) {
			if envNamed[e] {
				named = true
				break
			}
		}
		if named {
			continue
		}
		findings = append(findings, "  "+key+" — исходящая полоса, которую процесс поднимает, а поставка "+
			"настроить не даёт: чарт этого ключа не рендерит, и ни один его профиль не называет переменной "+
			"("+strings.Join(envOf(key), " либо ")+"). Возможность объявлена и неисполнима штатным путём: "+
			"оператор, ставящий продукт его же чартом, узнать о ней может только из нашего кода. Исхода два: "+
			"назвать ключ в templates/configmap.yaml (ветвью, если полоса необязательна) либо назвать его "+
			"переменную в поставляемом профиле.")
	}
	return findings
}

// TestEveryOutboundLaneHasAnOperatorKnobInTheDelivery — несущая проба.
func TestEveryOutboundLaneHasAnOperatorKnobInTheDelivery(t *testing.T) {
	chartDir := filepath.Join(serviceRoot(t), "deploy")

	roster, err := surfaceroster.Read(serviceRoot(t))
	require.NoError(t, err, "перепись поверхностей процесса")
	listener := map[string]bool{}
	for _, s := range roster.Surfaces {
		listener[s.SettingKey] = true
	}

	leaves := configLeafPaths()
	lanes := []string{}
	for _, k := range leaves {
		if dialCoordinateLeaf(k) && !listener[k] {
			lanes = append(lanes, k)
		}
	}

	settings, filesRead, _, _, err := collectRenderedSettings(chartDir)
	require.NoError(t, err, "ключи, рендерящиеся чартом, не прочитаны")
	rendered := map[string]bool{}
	for _, s := range settings {
		rendered[s.key] = true
	}
	envNamed, profiles := profileEnvNames(t, chartDir)

	// «Ноль находок» обязано быть отличимо от «ноль прочитанного».
	require.NotEmpty(t, leaves, "обход пуст: листьев объявления настроек 0 — вердикт беспредметен")
	require.NotEmpty(t, roster.Surfaces, "обход пуст: поверхностей процесса 0 — вычитать нечего")
	require.NotEmpty(t, lanes, "обход пуст: исходящих полос 0 — гейт заведён ровно про них")
	require.NotEmpty(t, rendered, "обход пуст: чарт не рендерит ни одного ключа настроек")

	findings := judgeOutboundLanes(lanes, rendered, envNamed, declaredEnvNames)

	t.Logf("перепись: листьев настроек %d · поверхностей процесса %d · исходящих полос %d (%s) · "+
		"ключей рендерит чарт %d (шаблонов %d) · переменных названо профилями %d (профилей %d) · находок %d",
		len(leaves), len(roster.Surfaces), len(lanes), strings.Join(lanes, ", "),
		len(rendered), filesRead, len(envNamed), profiles, len(findings))

	require.Empty(t, findings,
		"исходящая полоса поднимается, а объявить её нечем:\n%s", strings.Join(findings, "\n"))
}
