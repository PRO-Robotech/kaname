// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// dockerfile_claims_test.go — Dockerfile службы не называет того, чего в его
// контексте сборки нет.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Шапка Dockerfile объявляла сборку самодостаточной: «kacho-iam несёт
// proto-stubs локально (proto/gen) и подключает kacho-corelib как
// versioned-модуль». Ни одного из двух в дереве не существовало: каталога
// `proto/gen` у службы нет, модуля с таким именем нет нигде, а сам образ
// собирался с контекстом в КОРНЕ монорепо и путями `./services/iam/cmd/...`.
// Утверждение пережило прежнее полирепо и читалось как факт — тот же класс, что
// корпус ловит в правилах: утверждение, пережившее свой предмет.
//
// Цена не косметическая. Читающий шапку заключает, что образ уже собирается из
// каталога службы, и не заводит того, чем это держится; следующий, кто попробует
// собрать службу отдельно, узнаёт правду отказом сборки.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ИМЕННО УТВЕРЖДАЕТСЯ
//
// Всякая КООРДИНАТА, названная в Dockerfile — и в исполняемой строке, и в
// комментарии, — существует относительно каталога службы, то есть относительно
// объявленного контекста сборки. Координатой считается токен формы пути:
// ASCII-буквы, цифры, точка, дефис, подчёркивание и косая черта; не меньше двух
// сегментов; не абсолютный (те принадлежат файловой системе контейнера);
// без двоеточия и знака равенства (образы реестра и параметры монтирования);
// первый сегмент без точки (доменные имена и пути модулей — не координаты
// дерева).
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ЭТА ПРОВЕРКА НЕ ЗАКРЫВАЕТ — сказано прямо
//
// Утверждение, написанное БЕЗ координаты («подключает такой-то модуль»,
// «siblings не нужны»), машинного предиката не имеет: судить его — значит судить
// смысл прозы. Тот же предел, что у машинного чтения вердикта приёмки. Здесь
// удержан ровно класс координат; остальное держится вниманием и обзором.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗАКОННЫЙ БЛИЗНЕЦ УЖЕ В ДЕРЕВЕ
//
// Та же шапка называет `internal/handler/jwksproxyhttp` — координату
// существующую и уместную. Проверка обязана на ней МОЛЧАТЬ, иначе она ловит
// форму записи, а не существо; это и проверяется инъекцией.
package supplyhygiene

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// dockerfileName — имя файла сборки службы относительно её корня.
const dockerfileName = "Dockerfile"

// pathShape — форма координаты дерева.
var pathShape = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)

// wrappingRunes — обрамление, снимаемое с ОБЕИХ сторон: кавычки и скобки прозы.
const wrappingRunes = "`'\"()[]{}*"

// trailingRunes — знаки препинания, снимаемые ТОЛЬКО справа. Слева их снимать
// нельзя: ведущая точка принадлежит самой координате (`./cmd/kacho-iam`), и
// симметричная обрезка превращала её в абсолютный путь, после чего разбор
// отбрасывал координату как принадлежащую файловой системе контейнера. Так и
// вышло в первой редакции: обе строки сборки, называвшие пути монорепо, прошли
// мимо наблюдения — распознано было 4 координаты вместо 6.
const trailingRunes = ".,;:"

// missingCoordinate — одно попадание: строка Dockerfile и названная в ней
// координата, которой в контексте нет.
type missingCoordinate struct {
	line  int
	token string
}

// coordinateCandidate приводит токен к координате дерева и говорит, координата
// ли это вообще. Отбрасывание объявлено здесь целиком, чтобы разбор читался в
// одном месте.
func coordinateCandidate(token string) (string, bool) {
	token = strings.Trim(token, wrappingRunes)
	token = strings.TrimRight(token, trailingRunes)
	if token == "" {
		return "", false
	}
	// Параметр монтирования, присваивание, клеймо: `target=/go/pkg/mod`.
	if strings.ContainsAny(token, "=") {
		return "", false
	}
	// Образ реестра и тег: `mirror.gcr.io/library/golang:1.26-alpine`.
	if strings.Contains(token, ":") {
		return "", false
	}
	// Абсолютный путь принадлежит файловой системе контейнера, а не контексту.
	if strings.HasPrefix(token, "/") {
		return "", false
	}
	token = strings.TrimPrefix(token, "./")
	if token == "" || strings.HasSuffix(token, "/") {
		return "", false
	}
	if !strings.Contains(token, "/") {
		return "", false
	}
	if !pathShape.MatchString(token) {
		return "", false
	}
	segments := strings.Split(token, "/")
	if len(segments) < 2 {
		return "", false
	}
	// Доменное имя и путь модуля: первый сегмент несёт точку.
	if strings.Contains(segments[0], ".") {
		return "", false
	}
	return token, true
}

// dockerfileCensus — объём осмотренного одним обходом Dockerfile.
type dockerfileCensus struct {
	linesScanned int
	tokensSeen   int
	coordinates  int
	resolved     int
}

// scanDockerfileCoordinates — разбор над ПРОИЗВОЛЬНЫМ корнем: и Dockerfile, и
// проверка существования берутся оттуда же. Вынесено из теста затем, чтобы
// способность гейта упасть доказывалась подачей входа, а не чтением.
func scanDockerfileCoordinates(root string) (dockerfileCensus, []missingCoordinate, error) {
	var census dockerfileCensus

	raw, err := os.ReadFile(filepath.Join(root, dockerfileName))
	if err != nil {
		return census, nil, err
	}

	var findings []missingCoordinate

	for idx, line := range strings.Split(string(raw), "\n") {
		census.linesScanned++

		body := line
		if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "#") {
			body = strings.TrimPrefix(trimmed, "#")
		}

		for _, token := range strings.Fields(body) {
			census.tokensSeen++

			candidate, ok := coordinateCandidate(token)
			if !ok {
				continue
			}
			census.coordinates++

			if _, statErr := os.Stat(filepath.Join(root, candidate)); statErr == nil {
				census.resolved++
				continue
			}
			findings = append(findings, missingCoordinate{line: idx + 1, token: candidate})
		}
	}

	return census, findings, nil
}

func TestDockerfileNamesOnlyCoordinatesItsContextCarries(t *testing.T) {
	census, findings, err := scanDockerfileCoordinates(serviceRoot)
	require.NoErrorf(t, err, "Dockerfile службы не читается: %s", filepath.Join(serviceRoot, dockerfileName))

	t.Logf(
		"перепись: строк осмотрено %d · токенов %d · координат распознано %d · из них резолвится %d · находок %d",
		census.linesScanned, census.tokensSeen, census.coordinates, census.resolved, len(findings),
	)

	// Пустой обход — находка: «ноль несуществующих координат» обязано быть
	// отличимо от «ноль прочитанного», а «ноль распознанных координат» — от
	// «распознаватель ослеп».
	require.NotZero(t, census.linesScanned, "обход пуст: строк Dockerfile не осмотрено ни одной — вердикт беспредметен")
	require.NotZero(t, census.tokensSeen, "обход пуст: токенов не осмотрено ни одного — вердикт беспредметен")
	require.NotZero(t, census.coordinates, "обход пуст: координат не распознано ни одной — распознаватель ослеп, вердикт беспредметен")

	for _, f := range findings {
		t.Errorf(
			"%s:%d — названа координата %q, которой в контексте сборки (каталог службы) НЕТ. "+
				"Исходов два: назвать существующее либо завести названное; оставить как есть нельзя — "+
				"шапка читается как факт",
			filepath.ToSlash(filepath.Join(serviceRoot, dockerfileName)), f.line, f.token,
		)
	}
}
