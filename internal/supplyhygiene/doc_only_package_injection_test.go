// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// doc_only_package_injection_test.go — доказательство того, что проверка
// описания без предмета СПОСОБНА упасть и СПОСОБНА смолчать.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ СИНТЕТИЧЕСКИЙ КОРЕНЬ, А НЕ ПРАВКА ДЕРЕВА
//
// Дерево службы читают и соседние сессии; внести в него дефект ради
// доказательства значило бы править общее состояние. Разбор поэтому вынесен в
// чистую функцию над ПРОИЗВОЛЬНЫМ корнем, а сюда подаётся корень, собранный в
// каталоге прогона.
//
// ─────────────────────────────────────────────────────────────────────────────
// КАЖДАЯ ИНЪЕКЦИЯ МЕНЯЕТ РОВНО ОДИН ФАКТ ПРОТИВ КОНТРОЛЯ
//
// Контроль стоит первым и обязан МОЛЧАТЬ. Дальше меняется по одному факту:
// иначе красное могло бы прийти от соседа, а проверка осталась бы вакуумной.
//
// Пара осей несущая, и вторая половина здесь не менее важна первой: признак
// «каталог несёт doc.go» без неё отключил бы девять законных мест дерева. Поэтому
// у каждой находки стоит близнец, отличающийся РОВНО ОДНИМ файлом — тем, который
// делает описание правдой.
package supplyhygiene

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// docOnlyRootWith собирает корень из перечисленных файлов. Файлов ровно столько,
// сколько подано: перепись тогда прямо называет, что прочитано ровно поданное.
func docOnlyRootWith(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		full := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o750))
		require.NoError(t, os.WriteFile(full, []byte(body), 0o600))
	}
	return root
}

// docOnlySoundTree — законный близнец дерева службы в миниатюре: один каталог
// несёт `doc.go` РЯДОМ с объявлениями, второй объявлений полон и шапки не имеет.
// Проверка обязана молчать на обоих.
func docOnlySoundTree() map[string]string {
	return map[string]string{
		"internal/service/doc.go":     "// Package service — шапка рядом с кодом.\npackage service\n",
		"internal/service/service.go": "package service\n\ntype Service struct{}\n",
		"internal/domain/id.go":       "package domain\n\ntype ID string\n",
	}
}

// ── Контроль: годный корень молчит ──────────────────────────────────────────

func TestDocOnlyInjectionControl_SoundRootIsSilent(t *testing.T) {
	census, findings, err := scanDocOnlyPackages(syntheticCorpus(t, docOnlyRootWith(t, docOnlySoundTree())))
	require.NoError(t, err)
	require.Empty(t, findings,
		"годный корень объявлен нарушением: проверка ловит наличие шапки, а не отсутствие предмета")
	require.Equal(t, 3, census.goFiles, "контроль беспредметен: прочитано не то число файлов Go")
	require.Equal(t, 2, census.dirs)
	require.Equal(t, 1, census.dirsWithDoc)
	require.Equal(t, 1, census.dirsDocPlus,
		"контроль беспредметен: законного близнеца — шапки РЯДОМ с объявлениями — в корне нет")
	require.Zero(t, census.dirsDocOnly)
}

// ── Ось 1: описание без предмета — НАХОДКА, и она называет координату ───────

func TestDocOnlyInjection_PackageWithoutDeclarationsIsFound(t *testing.T) {
	files := docOnlySoundTree()
	files["internal/repo/repomock/doc.go"] = "// Package repomock — моки, которых здесь нет.\npackage repomock\n"

	census, findings, err := scanDocOnlyPackages(syntheticCorpus(t, docOnlyRootWith(t, files)))
	require.NoError(t, err)
	require.Equal(t, []string{"internal/repo/repomock"}, findings,
		"пакет из одного описания не найден — проверка молчит там, где обязана назвать координату")
	require.Equal(t, 1, census.dirsDocOnly)
	require.Equal(t, 1, census.dirsDocPlus,
		"законный близнец пропал из корня — красное могло прийти от него, а не от инъекции")
}

// TestDocOnlyInjection_SecondPackageIsNamedToo — находки НЕ схлопываются в одну.
//
// Проверка, называющая первую координату и умалчивающая о второй, чинилась бы по
// одному месту за прогон, и второе пережило бы правку молча.
func TestDocOnlyInjection_SecondPackageIsNamedToo(t *testing.T) {
	files := docOnlySoundTree()
	files["internal/repo/repomock/doc.go"] = "// Package repomock\npackage repomock\n"
	files["internal/repo/kaname/pg/dto/doc.go"] = "// Package dto\npackage dto\n"

	_, findings, err := scanDocOnlyPackages(syntheticCorpus(t, docOnlyRootWith(t, files)))
	require.NoError(t, err)
	require.Equal(t, []string{"internal/repo/kaname/pg/dto", "internal/repo/repomock"}, findings,
		"названа не каждая координата — правка пошла бы по одному месту за прогон")
}

// ── Ось 2: тот же каталог с объявлением рядом — МОЛЧАНИЕ ────────────────────
//
// Отличается от оси 1 РОВНО ОДНИМ файлом. Без этой половины признак отключил бы
// девять законных каталогов дерева, и его сняли бы первым же прогоном.

func TestDocOnlyInjection_SameDirWithOneDeclarationIsSilent(t *testing.T) {
	files := docOnlySoundTree()
	files["internal/repo/repomock/doc.go"] = "// Package repomock — моки, и они здесь есть.\npackage repomock\n"
	files["internal/repo/repomock/repository.go"] = "package repomock\n\nfunc NewRepository() any { return nil }\n"

	census, findings, err := scanDocOnlyPackages(syntheticCorpus(t, docOnlyRootWith(t, files)))
	require.NoError(t, err)
	require.Empty(t, findings,
		"шапка рядом с объявлением объявлена нарушением — признак судит наличие шапки, "+
			"а предмет его в отсутствии объявлений")
	require.Equal(t, 2, census.dirsDocPlus)
	require.Zero(t, census.dirsDocOnly)
}

// TestDocOnlyInjection_DirWithoutDocIsSilent — каталог без шапки вовсе тоже
// молчит: предмет проверки — описание без предмета, а не отсутствие описания.
func TestDocOnlyInjection_DirWithoutDocIsSilent(t *testing.T) {
	files := docOnlySoundTree()
	files["internal/lonely/only.go"] = "package lonely\n\ntype T struct{}\n"

	census, findings, err := scanDocOnlyPackages(syntheticCorpus(t, docOnlyRootWith(t, files)))
	require.NoError(t, err)
	require.Empty(t, findings, "каталог без шапки объявлен нарушением — проверка меряет не то")
	require.Equal(t, 3, census.dirs)
	require.Equal(t, 1, census.dirsWithDoc)
}

// TestDocOnlyInjection_NonGoNeighbourDoesNotRescueTheDescription — сосед НЕ на Go
// предметом шапки пакета не является.
//
// Каталог с `doc.go` и, скажем, схемой или образцом настройки по-прежнему не
// содержит ни одного объявления; принять такой файл за предмет значило бы
// оправдать ровно то место, ради которого проверка заведена.
func TestDocOnlyInjection_NonGoNeighbourDoesNotRescueTheDescription(t *testing.T) {
	files := docOnlySoundTree()
	files["internal/repo/repomock/doc.go"] = "// Package repomock\npackage repomock\n"
	files["internal/repo/repomock/README.md"] = "# repomock\n"
	files["internal/repo/repomock/fixture.json"] = "{}\n"

	_, findings, err := scanDocOnlyPackages(syntheticCorpus(t, docOnlyRootWith(t, files)))
	require.NoError(t, err)
	require.Equal(t, []string{"internal/repo/repomock"}, findings,
		"сосед не на Go зачтён за предмет шапки пакета — объявлений в каталоге по-прежнему ноль")
}

// ── Ось 3: пустой обход — ОТКАЗ, а не зелёное ───────────────────────────────
//
// Обход, не нашедший ни одного файла Go, находок тоже не находит. Зелёное здесь
// означало бы «проверено» там, где не прочитано ничего, — то есть всеразрешение.

func TestDocOnlyInjection_EmptyWalkIsRefusedNotGreen(t *testing.T) {
	root := docOnlyRootWith(t, map[string]string{"README.md": "# пусто\n"})
	census, findings, err := scanDocOnlyPackages(syntheticCorpus(t, root))
	require.Error(t, err, "пустой обход дал вердикт вместо отказа — «ноль находок» стало бы "+
		"неотличимо от «ноль прочитанного»")
	require.Contains(t, err.Error(), "вердикт беспредметен")
	require.Empty(t, findings)
	require.Zero(t, census.goFiles)
}
