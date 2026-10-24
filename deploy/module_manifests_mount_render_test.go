// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package deploy_test

// module_manifests_mount_render_test.go — чарт ДОСТАВЛЯЕТ манифесты модулей в
// каталог доставки службы ровно из тех ConfigMap, которые перечислены в
// значениях, и ни из каких других (задача kaname#964).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Процесс читает каталог доставки на старте (`cmd/kaname/module_manifests.go`,
// ручки `manifests.dir` и `manifests.required`), а чарт этого каталога не
// монтировал вовсе: модуль клал свой ConfigMap, служба его не видела, и стенд
// держался ручным монтированием. Решение диспетчера: чарт монтирует ПЕРЕЧИСЛЕННЫЕ
// в значениях ConfigMap одним томом projected в своём namespace; прав на list и
// watch ConfigMap по кластеру служба не получает; пустой перечень — ни тома, ни
// монтирования, ни ручек, поведение прежнее.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО УТВЕРЖДАЕТСЯ, И КАЖДОЕ ОТРИЦАНИЕ — В ПАРЕ С ПОЛОЖИТЕЛЬНЫМ БЛИЗНЕЦОМ
//
//  1. Два ConfigMap в перечне дают ОБА файла в каталоге пода — множество
//     файлов выводится из рендера (том × монтирование × элементы), а не из
//     значений; процессу отдана пара ручек, и страж старта принимает весь вход.
//  2. Близнец п.1 без одного ConfigMap: снятый ConfigMap не монтируется НИКАК —
//     ни файлом, ни ссылкой тома; ссылок пода на ConfigMap ровно «своя карта
//     настроек плюс перечень».
//  3. Пустой перечень: тома нет, монтирования каталога нет, ручек доставки нет.
//     Положительный контроль на том же рендере: карта настроек смонтирована —
//     иначе «тома нет» зеленело бы на рендере, где нет ничего.
//  4. Входы, которые том исполнил бы молча и неверно, — ОТКАЗ рендера с ключом
//     в тексте: один ключ в двух ConfigMap (том кладёт второй поверх первого без
//     ошибки — kubelet собирает полезную нагрузку картой), ConfigMap без ключей,
//     ключ со служебной приставкой тома `..` (обход доставки его пропускает —
//     `internal/manifest/check.go`, isDeliveredManifestName), относительный
//     каталог, ручка доставки вторым адресом в `env` или `secrets`.
//
// Вход собирается настоящим `helm template`; без helm проба — третья категория,
// а на объявленной полосе рендера (deploy/render-guard.sh) — отказ.

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// moduleManifestsDefaultDir — каталог доставки по умолчанию в значениях чарта;
// та же величина, которой на стенде монтировали вручную (`/etc/kaname/manifests`).
const moduleManifestsDefaultDir = "/etc/kaname/manifests"

// ownConfigMapName — карта настроек самого чарта: единственная ссылка пода на
// ConfigMap вне перечня доставки.
const ownConfigMapName = "kaname-config"

// moduleManifestsEntry — `--set` одного элемента перечня: имя ConfigMap и его ключи.
func moduleManifestsEntry(i int, name string, keys ...string) []string {
	out := []string{fmt.Sprintf("moduleManifests.configMaps[%d].name=%s", i, name)}
	for j, k := range keys {
		out = append(out, fmt.Sprintf("moduleManifests.configMaps[%d].keys[%d]=%s", i, j, k))
	}
	return out
}

// podDelivery — то, что рендер отдаёт поду о ConfigMap: файлы под
// монтированиями контейнера службы, ссылки томов на ConfigMap и ручки доставки.
type podDelivery struct {
	// Files — путь файла в контейнере службы → «ConfigMap/ключ».
	Files map[string]string
	// WholeMaps — чужие ConfigMap, смонтированные целиком (без перечня
	// элементов), → путь монтирования; их файлы рендер не называет. Своя карта
	// настроек сюда не входит: её монтирует чарт и судит соседняя проба.
	WholeMaps map[string]string
	// Referenced — каждый ConfigMap, на который ссылается хоть один том пода.
	Referenced []string
	// Optional — ссылки томов с `optional: true`: отсутствие такого ConfigMap
	// под пропускает молча.
	Optional []string
	// Mounts — путь монтирования → имя тома, контейнер службы.
	Mounts map[string]string
	// Env — переменные контейнера службы, заданные значением.
	Env map[string]string
	// Deployments — сколько развёртываний прочитано: объём осмотренного.
	Deployments int
}

// readPodDelivery разбирает рендер. Контейнер службы — первый в `containers`
// (тот же выбор, что у readContainerInput).
func readPodDelivery(t *testing.T, rendered string) podDelivery {
	t.Helper()
	pd := podDelivery{Files: map[string]string{}, WholeMaps: map[string]string{}, Mounts: map[string]string{}, Env: map[string]string{}}
	dec := yaml.NewDecoder(strings.NewReader(rendered))
	for {
		var doc map[string]any
		if err := dec.Decode(&doc); err != nil {
			break
		}
		if doc == nil || doc["kind"] != "Deployment" {
			continue
		}
		pd.Deployments++
		spec, _ := doc["spec"].(map[string]any)
		tpl, _ := spec["template"].(map[string]any)
		pod, _ := tpl["spec"].(map[string]any)

		// Том → его источники ConfigMap (имя, элементы, optional).
		type cmSource struct {
			name     string
			items    [][2]string // ключ, путь
			whole    bool
			optional bool
		}
		volumes := map[string][]cmSource{}
		vols, _ := pod["volumes"].([]any)
		for _, rv := range vols {
			v, _ := rv.(map[string]any)
			vname, _ := v["name"].(string)
			var raw []map[string]any
			if cm, ok := v["configMap"].(map[string]any); ok {
				raw = append(raw, cm)
			}
			if pj, ok := v["projected"].(map[string]any); ok {
				srcs, _ := pj["sources"].([]any)
				for _, rs := range srcs {
					s, _ := rs.(map[string]any)
					if cm, ok := s["configMap"].(map[string]any); ok {
						raw = append(raw, cm)
					}
				}
			}
			for _, cm := range raw {
				src := cmSource{}
				src.name, _ = cm["name"].(string)
				src.optional, _ = cm["optional"].(bool)
				items, _ := cm["items"].([]any)
				src.whole = len(items) == 0
				for _, ri := range items {
					it, _ := ri.(map[string]any)
					k, _ := it["key"].(string)
					p, _ := it["path"].(string)
					src.items = append(src.items, [2]string{k, p})
				}
				volumes[vname] = append(volumes[vname], src)
				pd.Referenced = append(pd.Referenced, src.name)
				if src.optional {
					pd.Optional = append(pd.Optional, src.name)
				}
			}
		}

		containers, _ := pod["containers"].([]any)
		require.NotEmpty(t, containers, "у развёртывания нет контейнеров — судить нечего")
		c, _ := containers[0].(map[string]any)
		mounts, _ := c["volumeMounts"].([]any)
		for _, rm := range mounts {
			m, _ := rm.(map[string]any)
			path, _ := m["mountPath"].(string)
			vname, _ := m["name"].(string)
			pd.Mounts[path] = vname
			for _, src := range volumes[vname] {
				if src.whole && src.name != ownConfigMapName {
					pd.WholeMaps[src.name] = path
					continue
				}
				if src.whole {
					continue // своя карта настроек: её файлы — config.yaml процесса, не доставка
				}
				for _, kp := range src.items {
					pd.Files[strings.TrimSuffix(path, "/")+"/"+kp[1]] = src.name + "/" + kp[0]
				}
			}
		}
		envs, _ := c["env"].([]any)
		for _, re := range envs {
			e, _ := re.(map[string]any)
			n, _ := e["name"].(string)
			if v, ok := e["value"].(string); ok {
				pd.Env[n] = v
			}
		}
	}
	require.Equal(t, 1, pd.Deployments, "в рендере ожидалось ровно одно развёртывание")
	sort.Strings(pd.Referenced)
	sort.Strings(pd.Optional)
	return pd
}

// deliveryEnvKeys — ручки доставки, которыми чарт отдаёт процессу каталог
// (привязка — `internal/apps/kaname/config/load.go`).
var deliveryEnvKeys = []string{"KANAME_MANIFESTS__DIR", "KANAME_MANIFESTS__REQUIRED"}

func TestModuleManifests_TwoListedConfigMapsLandAsFilesInTheDeliveryDir(t *testing.T) {
	sets := append(moduleManifestsEntry(0, "registry-module-manifest", "registry.manifest.yaml"),
		moduleManifestsEntry(1, "compute-kaname-module", "compute.manifest.yaml")...)
	out := renderStandaloneChart(t, chartProfiles, sets...)
	pd := readPodDelivery(t, out)

	require.Equal(t, map[string]string{
		moduleManifestsDefaultDir + "/registry.manifest.yaml": "registry-module-manifest/registry.manifest.yaml",
		moduleManifestsDefaultDir + "/compute.manifest.yaml":  "compute-kaname-module/compute.manifest.yaml",
	}, pd.Files, "файлы каталога доставки в поде не те, что перечислены в значениях")
	require.Empty(t, pd.WholeMaps, "ConfigMap смонтирован целиком — ключ, которого перечень не называл, лёг бы в каталог доставки")
	require.Equal(t, []string{"compute-kaname-module", ownConfigMapName, "registry-module-manifest"}, pd.Referenced,
		"под ссылается на ConfigMap вне перечня")
	require.Empty(t, pd.Optional, "ссылка тома с optional: true — отсутствие манифеста под пропустил бы молча, "+
		"а отсутствие снятием модуля не является")
	require.Equal(t, moduleManifestsDefaultDir, pd.Env["KANAME_MANIFESTS__DIR"], "каталог не отдан процессу")
	require.Equal(t, "true", pd.Env["KANAME_MANIFESTS__REQUIRED"], "опора на доставку не объявлена процессу")

	// Вход целиком принимает страж старта: пара ручек доставки, каталог под
	// смонтированным томом, весь прочий боевой профиль.
	in := readRenderedInput(t, out)
	require.NoError(t, renderedVerdict(t, in), "рендер с доставкой не принят стражем старта")
	t.Logf("перепись: файлов доставки %d · ссылок на ConfigMap %d · монтирований %d", len(pd.Files), len(pd.Referenced), len(pd.Mounts))
}

func TestModuleManifests_UnlistedConfigMapIsNotMounted(t *testing.T) {
	// Близнец пробы выше ровно без второго элемента.
	out := renderStandaloneChart(t, chartProfiles,
		moduleManifestsEntry(0, "registry-module-manifest", "registry.manifest.yaml")...)
	pd := readPodDelivery(t, out)

	require.Equal(t, map[string]string{
		moduleManifestsDefaultDir + "/registry.manifest.yaml": "registry-module-manifest/registry.manifest.yaml",
	}, pd.Files, "в каталоге доставки файл ConfigMap, которого перечень не называет")
	require.NotContains(t, pd.Referenced, "compute-kaname-module", "ConfigMap вне перечня смонтирован")
	require.Equal(t, []string{ownConfigMapName, "registry-module-manifest"}, pd.Referenced)
}

func TestModuleManifests_EmptyListRendersNoVolumeNoMountNoKnob(t *testing.T) {
	pd := readPodDelivery(t, renderStandaloneChart(t, chartProfiles))

	// Положительный контроль: карта настроек смонтирована.
	require.Equal(t, "config", pd.Mounts["/etc/kaname"], "карта настроек не смонтирована — рендер не тот, судить нечего")
	require.Equal(t, []string{ownConfigMapName}, pd.Referenced, "при пустом перечне под ссылается на чужой ConfigMap")
	require.Empty(t, pd.Files, "при пустом перечне в поде есть файлы доставки")
	_, mounted := pd.Mounts[moduleManifestsDefaultDir]
	require.False(t, mounted, "при пустом перечне каталог доставки смонтирован")
	for _, k := range deliveryEnvKeys {
		_, set := pd.Env[k]
		require.Falsef(t, set, "при пустом перечне процессу отдана ручка %s — доставка объявлена без тома", k)
	}
}

func TestModuleManifests_RenderRefusesInputsTheVolumeWouldExecuteWrongly(t *testing.T) {
	two := append(moduleManifestsEntry(0, "a-kaname-module", "a.manifest.yaml"),
		moduleManifestsEntry(1, "b-kaname-module", "b.manifest.yaml")...)
	for _, tc := range []struct {
		name string
		sets []string
		want string // часть текста отказа: ключ или координата
	}{
		{"один ключ в двух ConfigMap",
			append(moduleManifestsEntry(0, "a-kaname-module", "same.manifest.yaml"),
				moduleManifestsEntry(1, "b-kaname-module", "same.manifest.yaml")...),
			"same.manifest.yaml"},
		{"ConfigMap без ключей",
			[]string{"moduleManifests.configMaps[0].name=a-kaname-module"},
			"moduleManifests.configMaps[0].keys"},
		{"ключ со служебной приставкой тома",
			moduleManifestsEntry(0, "a-kaname-module", "..hidden.yaml"),
			"..hidden.yaml"},
		{"один ConfigMap дважды",
			append(moduleManifestsEntry(0, "a-kaname-module", "a.manifest.yaml"),
				moduleManifestsEntry(1, "a-kaname-module", "b.manifest.yaml")...),
			"a-kaname-module"},
		{"относительный каталог",
			append(append([]string{}, two...), "moduleManifests.dir=etc/kaname/manifests"),
			"moduleManifests.dir"},
		{"каталог поверх карты настроек",
			append(append([]string{}, two...), "moduleManifests.dir=/etc/kaname"),
			"moduleManifests.dir"},
		{"ручка доставки вторым адресом в env",
			append(append([]string{}, two...), "env.KANAME_MANIFESTS__DIR=/elsewhere"),
			"KANAME_MANIFESTS__DIR"},
		{"ручка доставки вторым адресом в secrets",
			append(append([]string{}, two...),
				"secrets.KANAME_MANIFESTS__REQUIRED.secretName=s", "secrets.KANAME_MANIFESTS__REQUIRED.secretKey=k"),
			"KANAME_MANIFESTS__REQUIRED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := renderChartAtAllowingFailure(t, ".", chartProfiles, tc.sets...)
			require.Errorf(t, err, "рендер принял вход, который том исполнил бы молча и неверно:\n%s", tc.sets)
			require.Containsf(t, out, tc.want, "отказ не называет %q:\n%s", tc.want, out)
			require.Containsf(t, out, "moduleManifests", "отказ не называет блок значений доставки:\n%s", out)
		})
	}
	// Положительный близнец всех случаев: два различных ConfigMap с различными
	// ключами рендерятся.
	out, err := renderChartAtAllowingFailure(t, ".", chartProfiles, two...)
	require.NoErrorf(t, err, "законный перечень отвергнут рендером:\n%s", out)
}
