// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// mail_key_files_mounted_test.go — ФАЙЛЫ КЛЮЧЕЙ ПОЧТОВОЙ ПОЛОСЫ ЛЕЖАТ В ПОДЕ, А НЕ
// ТОЛЬКО ЧИСЛЯТСЯ В НАСТРОЙКАХ; ФЛАГ ПОЧТЫ ОБЪЯВЛЕН ЯВНО (замысел NTF-2 З2, З18,
// CX2-13; приёмка NTF-2 Р4, NTF2-33 (а), (б)).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Страж старта судит у `authn.secrets.mail-window-key-file` и
// `authn.secrets.device-label-key-file` только НЕПУСТОТУ пути
// (`config.MailBounds`, вид «объявление»). Путь, названный настройками и не
// лежащий ни под одним монтированием, страж настройки пропускает, а процесс
// откажет уже в кластере — на чтении файла. Соседняя проба досягаемости
// (`renderedFilesAreMountable`) читает только ПЕРЕМЕННЫЕ окружения и пути из
// файла настроек не видит by construction. Поэтому здесь судится рендер: путь
// из карты настроек → монтирование контейнера службы → том → объект Secret и
// ключ в нём, а имя объекта — то, что объявил профиль.
//
// Отказ рендера на пустом имени — вторая половина: без неё «смонтировано»
// неотличимо от тома, который чарт собрал бы с пустым именем объекта.
//
// Флаг почты — третья: ключ без значения рендер обязан отвергнуть, назвав его
// (NTF2-33 (б)), `false` — законная величина и рендерится дословно (Р4).
//
// Вход собирается настоящим `helm template`; без helm проба — третья категория,
// а на объявленной полосе рендера (deploy/render-guard.sh) — отказ.
package deploy_test

import (
	"path"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// mailKeyFileKeys — ключи файла настроек, называющие файлы ключей. Популяция —
// строки таблицы границ вида «объявление» с путём (флаг путём не является);
// сверка с таблицей — в TestMailKeyFiles_PopulationIsTheBoundTable.
var mailKeyFileKeys = []string{
	"authn.secrets.mail-window-key-file",
	"authn.secrets.device-label-key-file",
}

// podVolumeSource — откуда том пода берёт содержимое: имя объекта Secret и
// отображение «ключ объекта → путь файла внутри тома».
type podVolumeSource struct {
	secretName string
	items      map[string]string // путь файла → ключ объекта
}

// renderedPod — монтирования контейнера службы и тома пода из рендера.
type renderedPod struct {
	mounts  map[string]string // каталог монтирования → имя тома
	volumes map[string]podVolumeSource
}

func readRenderedPod(t *testing.T, rendered string) renderedPod {
	t.Helper()
	pod := renderedPod{mounts: map[string]string{}, volumes: map[string]podVolumeSource{}}
	dec := yaml.NewDecoder(strings.NewReader(rendered))
	seen := false
	for {
		var doc map[string]any
		if err := dec.Decode(&doc); err != nil {
			break
		}
		if doc == nil || doc["kind"] != "Deployment" {
			continue
		}
		seen = true
		spec, _ := at(doc, "spec", "template", "spec").(map[string]any)
		containers, _ := spec["containers"].([]any)
		require.NotEmpty(t, containers, "развёртывание без контейнеров — судить монтирования не по чему")
		first, _ := containers[0].(map[string]any)
		mounts, _ := first["volumeMounts"].([]any)
		for _, raw := range mounts {
			m, _ := raw.(map[string]any)
			p, _ := m["mountPath"].(string)
			n, _ := m["name"].(string)
			pod.mounts[p] = n
		}
		vols, _ := spec["volumes"].([]any)
		for _, raw := range vols {
			v, _ := raw.(map[string]any)
			n, _ := v["name"].(string)
			src := podVolumeSource{items: map[string]string{}}
			if s, ok := v["secret"].(map[string]any); ok {
				src.secretName, _ = s["secretName"].(string)
				items, _ := s["items"].([]any)
				for _, it := range items {
					item, _ := it.(map[string]any)
					k, _ := item["key"].(string)
					p, _ := item["path"].(string)
					src.items[p] = k
				}
			}
			pod.volumes[n] = src
		}
	}
	require.True(t, seen, "в рендере нет развёртывания — вердикт был бы о пустоте")
	return pod
}

func TestMailKeyFiles_PopulationIsTheBoundTable(t *testing.T) {
	var fromTable []string
	for _, b := range config.MailBounds {
		if b.Kind == config.MailBoundDeclared && b.Key != config.NotificationsEnabledKey {
			fromTable = append(fromTable, b.Key)
		}
	}
	require.NotEmpty(t, fromTable, "таблица границ не дала ни одной строки ключа файла — обход пуст")
	require.ElementsMatch(t, fromTable, mailKeyFileKeys,
		"перечень ключей файлов пробы разошёлся с таблицей границ: строка, которой здесь нет, "+
			"не судится на монтирование вовсе")
}

func TestMailKeyFiles_ProdRenderMountsEachFromTheDeclaredSecret(t *testing.T) {
	rendered := renderStandaloneChart(t, chartProfiles)
	tree := renderedConfigTree(t, rendered)
	pod := readRenderedPod(t, rendered)
	declared, _ := at(mergeChartProfiles(t, chartProfiles), "authn", "secrets", "secretName").(string)
	require.NotEmpty(t, declared, "боевой профиль не называет authn.secrets.secretName — сверять том не с чем")

	for _, key := range mailKeyFileKeys {
		file := configString(tree, key)
		require.NotEmptyf(t, file, "%s не отрендерен в карту настроек", key)
		dir, base := path.Split(file)
		dir = strings.TrimSuffix(dir, "/")
		volume, mounted := pod.mounts[dir]
		require.Truef(t, mounted,
			"%s = %s, а каталога %s контейнер службы не монтирует (монтирования: %v) — процесс "+
				"откажет на чтении файла уже в кластере", key, file, dir, pod.mounts)
		src := pod.volumes[volume]
		require.Equalf(t, declared, src.secretName,
			"%s: том %s берётся не из объявленного объекта Secret", key, volume)
		require.NotEmptyf(t, src.items[base],
			"%s: том %s не кладёт файл %s — объект смонтирован, а файла по пути настроек нет", key, volume, base)
		t.Logf("%s = %s · том %s · Secret %s ключ %s", key, file, volume, src.secretName, src.items[base])
	}
	t.Logf("перепись: ключей файлов %d · монтирований контейнера %d · томов пода %d",
		len(mailKeyFileKeys), len(pod.mounts), len(pod.volumes))
}

func TestMailKeyFiles_EmptySecretNameRefusesTheRender(t *testing.T) {
	out, err := renderChartAtAllowingFailure(t, ".", chartProfiles, "authn.secrets.secretName=")
	requireRenderRefusal(t, out, err, "authn.secrets.secretName")
}

func TestNotificationsFlag_IsDeclaredByTheProfile(t *testing.T) {
	t.Run("боевой профиль объявляет флаг", func(t *testing.T) {
		tree := renderedConfigTree(t, renderStandaloneChart(t, chartProfiles))
		flag := at(tree, "notifications", "enabled")
		require.IsTypef(t, true, flag, "notifications.enabled в карте настроек не булево: %#v", flag)
	})
	t.Run("ключ снят — отказ рендера с именем ключа", func(t *testing.T) {
		out, err := renderChartAtAllowingFailure(t, ".", chartProfiles, "notifications.enabled=null")
		requireRenderRefusal(t, out, err, "notifications.enabled")
	})
	t.Run("false законен и рендерится дословно", func(t *testing.T) {
		out, err := renderChartAtAllowingFailure(t, ".", chartProfiles, "notifications.enabled=false")
		require.NoErrorf(t, err, "законное false отвергнуто рендером:\n%s", headOf(out))
		require.Equal(t, false, at(renderedConfigTree(t, out), "notifications", "enabled"))
	})
	t.Run("слово вместо булева — отказ рендера", func(t *testing.T) {
		out, err := renderChartAtAllowingFailure(t, ".", chartProfiles, "notifications.enabled=yes")
		requireRenderRefusal(t, out, err, "notifications.enabled")
	})
}
