// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// build_stamp_injection_test.go — доказательство того, что проверка штампа
// СПОСОБНА упасть, и того, что она молчит на законном близнеце.
//
// ─────────────────────────────────────────────────────────────────────────────
// ОДИН ФАКТ ПРОТИВ БЛИЗНЕЦА
//
// Годный корень собран один раз; каждая проба меняет в нём РОВНО ОДНУ вещь.
// Инъекция вида «добавить ещё один файл» здесь не годится: новый файл нарушал бы
// всё, что требуется от файлов вообще, и красное приходило бы от соседа.
// Контроль («всё цело — находок ноль») стоит первым.
//
// ─────────────────────────────────────────────────────────────────────────────
// ГЛАВНАЯ ИЗ ПРОБ — «ОБЕЩАНИЕ В КОММЕНТАРИИ»
//
// Она подаёт файл сборки, где `-ldflags` стоит в комментарии, объясняющем
// подстановку, а исполняемая строка её не делает. Ровно так выглядит сегодня
// четыре соседних сервиса дерева, и проверка по подстроке над сырым файлом
// осталась бы на этом входе зелёной — найдя своё же объяснение.
package supplyhygiene

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// stampGoodDockerfile — годный файл сборки: аргументы объявлены в ступени
// сборки, оба символа проставлены из них.
const stampGoodDockerfile = `FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY . .
ARG KACHO_IMAGE_REVISION=""
ARG KACHO_IMAGE_VERSION=""
RUN go build -ldflags "-X main.buildVersion=$KACHO_IMAGE_VERSION -X main.buildRevision=$KACHO_IMAGE_REVISION" -o /kaname ./cmd/kaname \
 && go build -o /kaname-migrator ./cmd/migrator

FROM alpine:3.24
ARG KACHO_IMAGE_REVISION=""
ARG KACHO_IMAGE_VERSION=""
COPY --from=builder /kaname /usr/local/bin/kaname
`

// stampGoodMain — годный композиционный корень: оба символа объявлены
// переменными уровня пакета.
const stampGoodMain = `package main

var (
	buildVersion  = ""
	buildRevision = ""
)

func main() {}
`

// syntheticStampRoot — корень службы для проверки штампа: файл сборки плюс
// композиционный корень. Всякая проба ниже строит СВОЙ из этой пары и меняет
// ровно один факт.
func syntheticStampRoot(t *testing.T, dockerfile, mainGo string) string {
	t.Helper()

	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, dockerfileName), []byte(dockerfile), 0o600))

	cmdDir := filepath.Join(root, "cmd", "kaname")
	require.NoError(t, os.MkdirAll(cmdDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(cmdDir, "main.go"), []byte(mainGo), 0o600))
	return root
}

// requireStampFinding — находка с названной подстрокой есть, и перепись непуста.
func requireStampFinding(t *testing.T, root, want string) {
	t.Helper()
	census, findings, err := scanBuildStamp(root)
	require.NoError(t, err)
	require.NotZero(t, census.instructions, "инъекция беспредметна: инструкций не распознано")
	joined := strings.Join(findings, "\n")
	require.Containsf(t, joined, want,
		"проверка НЕ упала на внесённом дефекте — она вакуумна.\nнаходки:\n%s", joined)
}

// TestBuildStampInjection_ControlIsSilent — КОНТРОЛЬ: всё цело, находок ноль.
func TestBuildStampInjection_ControlIsSilent(t *testing.T) {
	t.Parallel()
	root := syntheticStampRoot(t, stampGoodDockerfile, stampGoodMain)

	census, findings, err := scanBuildStamp(root)
	require.NoError(t, err)
	require.Empty(t, findings, "проверка краснеет на ГОДНОМ входе — она ловит форму, а не существо")
	require.Equal(t, 1, census.buildCommands, "распознана не та строка сборки")
	require.Equal(t, 2, census.goVarsDeclared, "символы не сопоставлены с объявлениями")
}

// TestBuildStampInjection_LdflagsOnlyInAComment — обещание подстановки стоит в
// КОММЕНТАРИИ, исполняемая строка её не делает.
func TestBuildStampInjection_LdflagsOnlyInAComment(t *testing.T) {
	t.Parallel()
	broken := strings.Replace(stampGoodDockerfile,
		`RUN go build -ldflags "-X main.buildVersion=$KACHO_IMAGE_VERSION -X main.buildRevision=$KACHO_IMAGE_REVISION" -o /kaname ./cmd/kaname \`,
		"# версия инжектится через -ldflags \"-X main.buildVersion=… -X main.buildRevision=…\"\n"+
			`RUN go build -o /kaname ./cmd/kaname \`, 1)
	require.NotEqual(t, stampGoodDockerfile, broken, "инъекция не применилась")

	requireStampFinding(t, syntheticStampRoot(t, broken, stampGoodMain),
		"строка сборки не проставляет main.buildVersion")
}

// TestBuildStampInjection_SymbolRenamedInGo — подстановка есть, ЦЕЛИ у неё нет.
//
// Компоновщик о промахе `-X` молчит, поэтому без этой полосы переименование
// переменной отвязало бы штамп, не проявившись ничем.
func TestBuildStampInjection_SymbolRenamedInGo(t *testing.T) {
	t.Parallel()
	broken := strings.Replace(stampGoodMain, "buildRevision", "buildRev", 1)
	require.NotEqual(t, stampGoodMain, broken, "инъекция не применилась")

	requireStampFinding(t, syntheticStampRoot(t, stampGoodDockerfile, broken),
		"символ main.buildRevision НЕ ОБЪЯВЛЕН")
}

// TestBuildStampInjection_ArgDeclaredInAnotherStage — аргумент объявлен только в
// конечной ступени: в ступени сборки он не виден, подстановка даст пустое.
func TestBuildStampInjection_ArgDeclaredInAnotherStage(t *testing.T) {
	t.Parallel()
	broken := strings.Replace(stampGoodDockerfile,
		"ARG KACHO_IMAGE_REVISION=\"\"\nARG KACHO_IMAGE_VERSION=\"\"\nRUN go build",
		"RUN go build", 1)
	require.NotEqual(t, stampGoodDockerfile, broken, "инъекция не применилась")

	requireStampFinding(t, syntheticStampRoot(t, broken, stampGoodMain),
		"аргумент KACHO_IMAGE_VERSION не объявлен в ступени сборки")
}

// TestBuildStampInjection_ValueFromAForeignArg — подстановка берёт значение не из
// того аргумента, которым клеймится образ.
func TestBuildStampInjection_ValueFromAForeignArg(t *testing.T) {
	t.Parallel()
	broken := strings.Replace(stampGoodDockerfile,
		"-X main.buildRevision=$KACHO_IMAGE_REVISION", "-X main.buildRevision=$SOME_OTHER_ARG", 1)
	require.NotEqual(t, stampGoodDockerfile, broken, "инъекция не применилась")

	requireStampFinding(t, syntheticStampRoot(t, broken, stampGoodMain),
		"берётся не из аргумента KACHO_IMAGE_REVISION")
}

// TestBuildStampInjection_NoServiceBuildLine — сборки служебного двоичного файла
// в файле нет вовсе: «находок ноль» здесь означало бы «нечего было искать».
func TestBuildStampInjection_NoServiceBuildLine(t *testing.T) {
	t.Parallel()
	broken := strings.Replace(stampGoodDockerfile, "-o /kaname ./cmd/kaname", "-o /other ./cmd/other", 1)
	require.NotEqual(t, stampGoodDockerfile, broken, "инъекция не применилась")

	requireStampFinding(t, syntheticStampRoot(t, broken, stampGoodMain), "разбор беспредметен")
}

// TestBuildStampInjection_EmptyDockerfileLeavesTheCensusEmpty — предпосылка самой
// проверки: на пустом файле сборки перепись ПУСТА, и проба дерева отказывает по
// ней, а не молчит «находок ноль».
func TestBuildStampInjection_EmptyDockerfileLeavesTheCensusEmpty(t *testing.T) {
	t.Parallel()
	root := syntheticStampRoot(t, "", stampGoodMain)

	census, _, err := scanBuildStamp(root)
	require.NoError(t, err)
	require.Zero(t, census.instructions,
		"пустой файл сборки дал непустую перепись — тогда «ноль находок» неотличимо от «ноль прочитанного»")
	require.Zero(t, census.executableLines)
}
