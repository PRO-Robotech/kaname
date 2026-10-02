// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// image_published_revision_test.go — ЗАДАНИЕ ОБРАЗА СПРАШИВАЕТ РЕЕСТР, ЧТО ОНО
// ОПУБЛИКОВАЛО (задача PRO-Robotech/kaname#429, п.1 предиката).
//
// Предмет и свойства провязки — в шапке `image_published_revision.go`, работа
// сверки — в шапке самой сверки; здесь они не пересказываются.
//
// Здесь два несущих утверждения. Первое — о ДЕРЕВЕ: провязка цела, находок
// ноль, и перепись называет, что осмотрено. Второе — о САМОЙ СВЕРКЕ: её
// самопроверка исполняется этой пробой и проходит. Самопроверку зовёт и
// конвейер, но только там; здесь она исполняется затем, чтобы сверка,
// потерявшая способность упасть, краснела уже у отправки, а не после вливания
// в линию. Способность обоих упасть — `image_published_revision_injection_test.go`.
package check_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// publishedSelfTestTimeout — срок самопроверки. Она ходит только к двойнику и
// укладывается в доли секунды; срок нужен, чтобы зависшая оболочка дала отказ
// пробы с координатой, а не таймаут всего пакета.
const publishedSelfTestTimeout = 60 * time.Second

// publishedSelfTestProbes — сколько проб самопроверки обязано исполниться.
// Число — ТОЧНОЕ по ведомости проб сверки, а не порог: проба, выпавшая из
// перечня молча, иначе осталась бы незамеченной.
const publishedSelfTestProbes = 21

// publishedSelfTestTally — итоговая строка самопроверки сверки.
var publishedSelfTestTally = regexp.MustCompile(`--self-test: проб исполнено (\d+), провалов (\d+)`)

// treeRoot — корень дерева этого модуля.
func treeRoot(t *testing.T) string {
	t.Helper()
	root, prefix := platformtree.RequireCorpus(t)
	if prefix != "" {
		root = filepath.Join(root, filepath.FromSlash(prefix))
	}
	return root
}

// runPublishedSelfTest — исполняет самопроверку сверки, лежащей по `script`.
// Возвращает код, вывод и сводку: исполнено/провалов (-1, если строки сводки нет).
func runPublishedSelfTest(t *testing.T, script string) (int, string, int, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), publishedSelfTestTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", script, "--self-test") // #nosec G204 -- путь из дерева либо из t.TempDir()
	// HOME передаётся: инструменты, которые зовёт сверка, вправе от него
	// зависеть (обёртка в PATH находит по нему настоящий файл), и без него отказ
	// инструмента читался бы как отказ сверки.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "TMPDIR=" + t.TempDir()}
	out, err := cmd.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: самопроверка не завершилась за %s", publishedSelfTestTimeout)
	}
	rc := 0
	if err != nil {
		var exitErr *exec.ExitError
		require.Truef(t, errors.As(err, &exitErr), "проверка НЕ ИСПОЛНЯЛАСЬ: самопроверка не запущена: %v", err)
		rc = exitErr.ExitCode()
	}
	ran, failed := -1, -1
	if m := publishedSelfTestTally.FindStringSubmatch(string(out)); m != nil {
		ran, _ = strconv.Atoi(m[1])
		failed, _ = strconv.Atoi(m[2])
	}
	return rc, string(out), ran, failed
}

// TestImageProducerAsksTheRegistryWhatItPublished — НЕСУЩЕЕ утверждение о
// провязке в дереве.
func TestImageProducerAsksTheRegistryWhatItPublished(t *testing.T) {
	t.Parallel()
	raw, ok := trunkCorpusSource(t)[imageInjectRel]
	require.Truef(t, ok, "проверка НЕ ИСПОЛНЯЛАСЬ: %s не прочитан", imageInjectRel)

	findings, census, err := check.AuditImagePublishedRevision(raw)
	require.NoError(t, err)
	t.Logf("перепись: %s · находок %d", census, len(findings))
	require.Emptyf(t, findings, "на дереве как есть гейт нашёл %d: %v", len(findings), findings)

	// Перепись отдельно от находок: «ноль находок» на задании, где сверки нет
	// вовсе, выше уже названо находкой, а здесь — что осмотрено ровно то, о чём
	// утверждение.
	require.GreaterOrEqual(t, census.Checks, 1)
	require.GreaterOrEqual(t, census.SelfTests, 1)
	require.Equal(t, 3*census.Checks, census.EnvCompared,
		"сверено со сборкой не по три величины на шаг сверки — молчание о расхождении ничего не стоит")
}

// TestImagePublishedRevisionCheckProvesItself — НЕСУЩЕЕ утверждение о сверке:
// её самопроверка исполняется и проходит, и проб в ней ровно столько, сколько
// объявлено.
func TestImagePublishedRevisionCheckProvesItself(t *testing.T) {
	t.Parallel()
	script := filepath.Join(treeRoot(t), filepath.FromSlash(check.ImagePublishedRevisionScript))
	_, err := os.Stat(script)
	require.NoErrorf(t, err, "сверки %s в дереве нет — п.1 предиката #429 держится вниманием",
		check.ImagePublishedRevisionScript)

	rc, out, ran, failed := runPublishedSelfTest(t, script)
	require.Equalf(t, 0, rc, "самопроверка сверки отказала кодом %d:\n%s", rc, out)
	require.Equalf(t, publishedSelfTestProbes, ran,
		"проб самопроверки исполнено %d, а в ведомости %d — проба выпала либо добавлена без записи:\n%s",
		ran, publishedSelfTestProbes, out)
	require.Equal(t, 0, failed)
}
