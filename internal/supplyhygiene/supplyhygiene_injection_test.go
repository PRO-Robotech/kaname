// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// supplyhygiene_injection_test.go — доказательство того, что соседние проверки
// СПОСОБНЫ упасть, и того, что они молчат на законном близнеце.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ СИНТЕТИЧЕСКИЙ КОРЕНЬ, А НЕ ПРАВКА ДЕРЕВА
//
// Обе проверки читают дерево службы. Внести в него дефект ради доказательства
// значило бы править общее состояние, которое читают соседние сессии. Поэтому
// разбор вынесен в чистые функции над ПРОИЗВОЛЬНЫМ корнем, а сюда подаётся
// корень, собранный в каталоге прогона.
//
// ─────────────────────────────────────────────────────────────────────────────
// ИНЪЕКЦИЯ МЕНЯЕТ РОВНО ОДИН ФАКТ ПРОТИВ СВОЕГО ПОЛОЖИТЕЛЬНОГО БЛИЗНЕЦА
//
// У каждой пробы-инъекции есть близнец, отличающийся ОДНИМ названным фактом:
// иначе красное могло бы прийти от соседа, а новая проверка осталась бы
// вакуумной, не показав этого ничем. Контроль («всё цело — молчат обе») стоит
// первым.
package supplyhygiene

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/treecorpus"
	"github.com/stretchr/testify/require"
)

// syntheticCorpus — состав СИНТЕТИЧЕСКОГО корня. Индекса у него нет by
// construction (это каталог прогона, а не репозиторий), поэтому обход диска
// здесь — единственный возможный авторитет, и выбран он ЯВНО: настоящее дерево
// службы берёт состав у индекса, и подмена одного другим была бы невидима.
func syntheticCorpus(t *testing.T, root string) *treecorpus.Tree {
	t.Helper()
	tree, err := treecorpus.SyntheticTree(root)
	require.NoError(t, err, "состав синтетического корня не собран — инъекция беспредметна")
	return tree
}

// syntheticServiceRoot — годный корень службы: свой go.mod, требование
// платформы по версии и один файл, импортирующий покрытый пакет платформы.
// Всякая проба ниже строит СВОЙ корень из этого и меняет ровно один факт.
func syntheticServiceRoot(t *testing.T, goMod, goFile, dockerfile string) string {
	t.Helper()

	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "go.mod"), []byte(goMod), 0o600))

	pkgDir := filepath.Join(root, "internal", "sample")
	require.NoError(t, os.MkdirAll(pkgDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(pkgDir, "sample.go"), []byte(goFile), 0o600))

	if dockerfile != "" {
		require.NoError(t, os.WriteFile(filepath.Join(root, dockerfileName), []byte(dockerfile), 0o600))
	}
	return root
}

const goodGoMod = `module github.com/PRO-Robotech/kacho-iam

go 1.26.0

require github.com/PRO-Robotech/kacho v0.0.0-20260904231955-a30d906b8edf
`

// goodGoFile — законный близнец: импорт платформы, ПОКРЫТЫЙ требованием, плюс
// собственный импорт службы. Оба обязаны молчать.
const goodGoFile = `package sample

import (
	_ "github.com/PRO-Robotech/kacho-iam/internal/other"
	_ "github.com/PRO-Robotech/kacho/pkg/ids"
)
`

// goodDockerfile — законный близнец шапки: обе названные координаты в корне
// существуют (каталог пакета и сам go.mod).
const goodDockerfile = `FROM mirror.gcr.io/library/golang:1.26-alpine
# сборка идёт из internal/sample, объявление зависимостей — рядом
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod go build ./internal/sample
`

// ── Контроль: годный корень молчит у ОБЕИХ проверок ─────────────────────────

func TestInjectionControl_SoundRootIsSilentInBothChecks(t *testing.T) {
	root := syntheticServiceRoot(t, goodGoMod, goodGoFile, goodDockerfile)

	census, findings, err := scanServiceModule(syntheticCorpus(t, root))
	require.NoError(t, err)
	require.Empty(t, findings, "годный корень объявлен нарушением: проверка ловит форму, а не существо")
	require.NotZero(t, census.filesParsed, "контроль беспредметен: файлов не разобрано")
	require.Equal(t, "github.com/PRO-Robotech/kacho-iam", census.modulePath)

	dcensus, dfindings, derr := scanDockerfileCoordinates(root)
	require.NoError(t, derr)
	require.Empty(t, dfindings, "годная шапка объявлена нарушением")
	require.NotZero(t, dcensus.coordinates, "контроль беспредметен: координат не распознано")
	require.Equal(t, dcensus.coordinates, dcensus.resolved)
}

// ── Проверка модуля: инъекция по каждой оси отдельно ────────────────────────

func TestInjection_MissingGoModIsAFinding(t *testing.T) {
	root := t.TempDir()
	_, _, err := scanServiceModule(syntheticCorpus(t, root))
	require.Error(t, err, "корень без go.mod принят: именно его отсутствие и есть предмет проверки")
}

func TestInjection_ReplaceOnThePlatformIsFound(t *testing.T) {
	badMod := goodGoMod + "\nreplace github.com/PRO-Robotech/kacho => ../..\n"
	root := syntheticServiceRoot(t, badMod, goodGoFile, goodDockerfile)

	_, findings, err := scanServiceModule(syntheticCorpus(t, root))
	require.NoError(t, err)
	require.Len(t, findings, 1, "директива замены на модуль платформы не найдена")
	require.Equal(t, "github.com/PRO-Robotech/kacho", findings[0].path)
	require.Contains(t, findings[0].reason, "replace")
}

func TestInjection_UncoveredPlatformImportIsFound(t *testing.T) {
	badFile := `package sample

import _ "github.com/PRO-Robotech/kacho-nowhere/pkg/thing"
`
	root := syntheticServiceRoot(t, goodGoMod, badFile, goodDockerfile)

	_, findings, err := scanServiceModule(syntheticCorpus(t, root))
	require.NoError(t, err)
	require.Len(t, findings, 1, "импорт платформы вне require и вне своего модуля не найден")
	require.Equal(t, "github.com/PRO-Robotech/kacho-nowhere/pkg/thing", findings[0].path)
}

func TestInjection_CoveredPlatformImportIsSilent(t *testing.T) {
	// Тот же файл, что в инъекции выше, с ЕДИНСТВЕННЫМ отличием: путь покрыт
	// требованием. Без этой пробы красное соседки ничего не доказывало бы.
	okFile := `package sample

import _ "github.com/PRO-Robotech/kacho/pkg/thing"
`
	root := syntheticServiceRoot(t, goodGoMod, okFile, goodDockerfile)

	_, findings, err := scanServiceModule(syntheticCorpus(t, root))
	require.NoError(t, err)
	require.Empty(t, findings, "покрытый импорт объявлен нарушением: проверка судит форму пути, а не покрытие")
}

func TestInjection_ImportInsideAStringLiteralIsNotAnImport(t *testing.T) {
	// Законный близнец из этого же дерева: соседние гейты держат путь пакета
	// внутри СТРОКИ синтетической фикстуры. Проверка обязана молчать — иначе
	// она считает объяснение предметом.
	fixtureFile := "package sample\n\nconst fixture = `import \"github.com/PRO-Robotech/kacho-nowhere/pkg/thing\"`\n"
	root := syntheticServiceRoot(t, goodGoMod, fixtureFile, goodDockerfile)

	_, findings, err := scanServiceModule(syntheticCorpus(t, root))
	require.NoError(t, err)
	require.Empty(t, findings, "путь внутри строкового литерала принят за импорт: проверка читает текст, а не разбор")
}

func TestInjection_EmptyWalkIsDistinguishableFromZeroFindings(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "go.mod"), []byte(goodGoMod), 0o600))

	census, findings, err := scanServiceModule(syntheticCorpus(t, root))
	require.NoError(t, err)
	require.Empty(t, findings)
	require.Zero(t, census.platformImports,
		"обход без единого файла обязан быть виден переписью: именно на этом числе тест верхнего уровня отказывает")
}

// ── Проверка шапки: инъекция по каждой оси отдельно ─────────────────────────

func TestInjection_DockerfileNamingAMissingPathIsFound(t *testing.T) {
	bad := goodDockerfile + "# несёт стабы контрактов локально (proto/gen)\n"
	root := syntheticServiceRoot(t, goodGoMod, goodGoFile, bad)

	_, findings, err := scanDockerfileCoordinates(root)
	require.NoError(t, err)
	require.Len(t, findings, 1, "координата, которой в контексте нет, не найдена")
	require.Equal(t, "proto/gen", findings[0].token)
}

func TestInjection_DockerfileNamingAnExistingPathIsSilent(t *testing.T) {
	// Отличие от инъекции выше — ОДНО: названная координата существует.
	ok := goodDockerfile + "# разбор живёт рядом, в internal/sample\n"
	root := syntheticServiceRoot(t, goodGoMod, goodGoFile, ok)

	_, findings, err := scanDockerfileCoordinates(root)
	require.NoError(t, err)
	require.Empty(t, findings, "существующая координата объявлена находкой: проверка ловит форму записи")
}

func TestInjection_DockerfileBuildPathWithLeadingDotIsRecognised(t *testing.T) {
	// Слепая зона первой редакции: ведущая точка снималась вместе с прочей
	// пунктуацией, путь становился абсолютным и отбрасывался как принадлежащий
	// файловой системе контейнера. Обе строки сборки проходили мимо наблюдения.
	bad := goodDockerfile + "RUN go build ./services/iam/cmd/kacho-iam\n"
	root := syntheticServiceRoot(t, goodGoMod, goodGoFile, bad)

	_, findings, err := scanDockerfileCoordinates(root)
	require.NoError(t, err)
	require.Len(t, findings, 1, "путь сборки, записанный через ./, не распознан как координата")
	require.Equal(t, "services/iam/cmd/kacho-iam", findings[0].token)
}

func TestInjection_DockerfileNonCoordinateTokensStaySilent(t *testing.T) {
	// Разграничение распознавателя: путь контейнера, образ реестра, параметр
	// монтирования и путь модуля координатами дерева НЕ являются. Ни один из
	// них в корне не существует, поэтому ложное распознавание немедленно дало
	// бы находку.
	noise := goodDockerfile + `COPY --from=builder /nowhere/kacho-iam /usr/local/bin/kacho-iam
# образ mirror.gcr.io/library/alpine:3.24, монтирование target=/go/pkg/mod
# модуль github.com/PRO-Robotech/kacho-nowhere/pkg/thing
`
	root := syntheticServiceRoot(t, goodGoMod, goodGoFile, noise)

	_, findings, err := scanDockerfileCoordinates(root)
	require.NoError(t, err)
	require.Empty(t, findings, "не-координата принята за координату дерева: находки будут ложными, и проверку отключат")
}

func TestInjection_DockerfileWithoutCoordinatesIsDistinguishableFromClean(t *testing.T) {
	bare := "FROM mirror.gcr.io/library/alpine:3.24\nUSER 65532\n"
	root := syntheticServiceRoot(t, goodGoMod, goodGoFile, bare)

	census, findings, err := scanDockerfileCoordinates(root)
	require.NoError(t, err)
	require.Empty(t, findings)
	require.Zero(t, census.coordinates,
		"шапка без единой координаты обязана быть видна переписью: на этом числе тест верхнего уровня отказывает")
}
