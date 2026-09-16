// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// platform_manifests_test.go — манифесты модулей платформы, которые читают
// контейнерные пробы этого пакета: ОДИН читатель на пакет.
//
// # Почему корень называет ручка, а не подъём от модуля
//
// Три пробы пакета (применитель каталога, последовательность старта, полоса
// «применённая строка доезжает до вердикта») читают `services/<модуль>/manifest.yaml`.
// Корень они брали у `platformtree.Require(t)` — корня СВОЕГО модуля, — а каталога
// модулей в нём нет ни в одной посадке: после выноса службы отдельным
// репозиторием манифесты соседей в это дерево не входят by construction. Пока
// резолв пропускал такие пробы подъёмом, это молчало; когда пропуск сняли
// (#108), пробы покраснели «обход дерева не нашёл манифестов» — красным о
// посадке, а не о продукте.
//
// Корень поэтому берётся у ДЕРЕВА, НАЗВАННОГО СНАРУЖИ (`PLATFORM_TREE`), — тем же
// входом, что и пробы `modulecatalog`/`authzmapgen`: при пустой ручке проба
// пропускает себя с предпосылкой, у которой ЕСТЬ производитель, а условие в
// конвейере создаёт то же самое действие, что и заданию манифестов
// (`.github/actions/platform-tree`). Значит в конвейере эти пробы ИСПОЛНЯЮТСЯ, а
// не объявляют, что могли бы.
//
// # Почему координаты не литералы
//
// Каталог модулей и имя файла манифеста переобъявлены ссылкой на владельцев
// (`platformtree.SiblingsDir`, `manifest.TreeFileName()`): литерал в трёх файлах
// разошёлся бы с ними на первом же переименовании, и разошёлся бы молча.

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// platformManifestPath — манифест ОДНОГО модуля в названном дереве платформы.
func platformManifestPath(t *testing.T, module string) string {
	t.Helper()
	return filepath.Join(platformtree.RequireNamedPlatformTree(t),
		platformtree.SiblingsDir, module, manifest.TreeFileName())
}

// platformManifestPaths — манифесты ВСЕХ модулей названного дерева, обходом, в
// устойчивом порядке.
//
// Пустой обход — отказ, а не пустой перечень: ручка, указавшая в дерево без
// манифестов, отвергается ещё резолвом (каталог модулей обязан существовать), а
// каталог без единого манифеста дал бы пробе «применено 0, изменений 0» — вердикт
// ни о чём, неотличимый от зелёного.
func platformManifestPaths(t *testing.T) []string {
	t.Helper()
	root := platformtree.RequireNamedPlatformTree(t)
	paths, err := filepath.Glob(filepath.Join(root, platformtree.SiblingsDir, "*", manifest.TreeFileName()))
	require.NoError(t, err)
	require.NotEmptyf(t, paths,
		"обход %s не нашёл ни одного %s/*/%s: вердикт беспредметен",
		root, platformtree.SiblingsDir, manifest.TreeFileName())
	sort.Strings(paths)
	return paths
}

// readPlatformManifest — тело манифеста по пути, полученному обходом выше.
func readPlatformManifest(t *testing.T, path string) []byte {
	t.Helper()
	body, err := os.ReadFile(path) // #nosec G304 -- путь собран обходом названного дерева платформы
	require.NoError(t, err, "прочитать манифест %s", path)
	return body
}
