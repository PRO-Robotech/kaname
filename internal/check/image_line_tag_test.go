// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// image_line_tag_test.go — ОБРАЗ ГОЛОВЫ ЛИНИИ ТЕГУЕТСЯ ТЕМ ЖЕ ПРАВИЛОМ, ЧТО
// СТВОЛ: `<ветка>-<8 знаков ревизии>`, публикуется по `push`, движущегося тега
// нет (задача PRO-Robotech/kaname#429).
//
// Проба ИСПОЛНЯЕТ тела шагов `subject` и `gate` задания `image` из объявления в
// дереве той оболочкой, какой их исполняет провайдер при `defaults.run.shell:
// bash` (`bash --noprofile --norc -eo pipefail`), на синтетическом событии, и
// читает то, что шаги записали в `GITHUB_OUTPUT`: судится то, что шаг делает,
// а не шапка объявления. Шаг сборки не исполняется — ему нужен builder, — и о
// нём судится запись: тело несёт ровно один `-t`, и значение его — тег шага
// `subject`.
//
// ЧЕГО ПРОБА НЕ СУДИТ — сказано прямо. Выражения `${{ … }}` в `env:` шага
// провайдер вычисляет ДО оболочки, и здесь значения подаются такими, какие он
// даёт для события: на `push` `github.head_ref` пуст и имя берётся у
// `github.ref_name`. Фильтр веток `push` — пойдёт ли процесс на ветку линии
// вообще — судит ось 2 гейта триггеров (review_trigger_scope.go), а не эта
// проба. Что тег ДОЕХАЛ до реестра, дерево не знает: это прогон по `push` после
// вливания.
package check_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// imageStepTimeout — срок одного шага. Шаги вычисляют имя и не ходят наружу;
// срок нужен затем, чтобы зависшая оболочка дала отказ пробы, а не таймаут
// всего пакета без координаты.
const imageStepTimeout = 30 * time.Second

// imageJob — задание, производящее образ.
const imageJob = "image"

// Ревизии синтетических событий: полные, как их отдаёт провайдер.
const (
	lineHeadSHA  = "fc9f5aff1d0e6b6a3a4c0e0b6f1a2b3c4d5e6f70"
	trunkHeadSHA = "cbbac984b1a2c3d4e5f60718293a4b5c6d7e8f90"
)

type imageStep struct {
	ID   string            `yaml:"id"`
	Name string            `yaml:"name"`
	Run  string            `yaml:"run"`
	Env  map[string]string `yaml:"env"`
}

type imageWorkflow struct {
	Defaults struct {
		Run struct {
			Shell string `yaml:"shell"`
		} `yaml:"run"`
	} `yaml:"defaults"`
	Env  map[string]string `yaml:"env"`
	Jobs map[string]struct {
		Steps []imageStep `yaml:"steps"`
	} `yaml:"jobs"`
}

// imageProducer — объявление образа службы из дерева, разобранное, с
// проверенными предпосылками: оболочка названа, шаги на месте.
func imageProducer(t *testing.T) (imageWorkflow, map[string]imageStep) {
	t.Helper()
	raw, ok := trunkCorpusSource(t)[imageInjectRel]
	require.Truef(t, ok, "проверка НЕ ИСПОЛНЯЛАСЬ: %s не прочитан", imageInjectRel)
	var wf imageWorkflow
	require.NoError(t, yaml.Unmarshal([]byte(raw), &wf), "проверка НЕ ИСПОЛНЯЛАСЬ: объявление не разобрано")

	// ПРЕДПОСЫЛКА: оболочка по умолчанию — `bash`. Иначе провайдер исполнял бы
	// шаг другой оболочкой, и вердикт этой пробы относился бы не к нему.
	require.Equal(t, "bash", wf.Defaults.Run.Shell,
		"предпосылка ложна: `defaults.run.shell` не `bash` — проба исполняет шаг не той оболочкой")
	job, ok := wf.Jobs[imageJob]
	require.Truef(t, ok, "предпосылка ложна: задания %q нет", imageJob)

	steps := map[string]imageStep{}
	for _, s := range job.Steps {
		if s.ID != "" {
			steps[s.ID] = s
		}
		if strings.Contains(s.Run, "docker buildx build") {
			steps["build"] = s
		}
	}
	for _, id := range []string{"subject", "gate", "build"} {
		require.Containsf(t, steps, id, "предпосылка ложна: шага %q в задании %q нет", id, imageJob)
		require.NotEmptyf(t, steps[id].Run, "предпосылка ложна: у шага %q пустое тело", id)
	}
	return wf, steps
}

// execImageStep — исполняет тело шага и возвращает записанное в GITHUB_OUTPUT.
func execImageStep(dir, script string, env map[string]string) (map[string]string, error) {
	path := filepath.Join(dir, "step.sh")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		return nil, fmt.Errorf("тело шага не записано: %w", err)
	}
	outPath := filepath.Join(dir, "github_output")
	if err := os.WriteFile(outPath, nil, 0o600); err != nil {
		return nil, fmt.Errorf("файл выходов не заведён: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), imageStepTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "--noprofile", "--norc", "-eo", "pipefail", path) // #nosec G204 -- путь из t.TempDir()
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "GITHUB_OUTPUT=" + outPath}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("шаг не завершился за %s: %w", imageStepTimeout, ctx.Err())
		}
		return nil, fmt.Errorf("шаг завершился отказом: %w; вывод: %s", err, out)
	}

	f, err := os.Open(outPath) // #nosec G304 -- путь из t.TempDir()
	if err != nil {
		return nil, fmt.Errorf("файл выходов не прочитан: %w", err)
	}
	defer func() { _ = f.Close() }()
	outputs := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			return nil, fmt.Errorf("строка выхода без `=`: %q", sc.Text())
		}
		outputs[k] = v
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("файл выходов не дочитан: %w", err)
	}
	return outputs, nil
}

// subjectFinding — что не так с именем образа ветки `branch` на ревизии `sha`;
// пусто — имя по правилу ствола.
func subjectFinding(outputs map[string]string, branch, sha string) string {
	var why []string
	if want := branch + "-" + sha[:8]; outputs["tag"] != want {
		why = append(why, fmt.Sprintf("тег %q, а по правилу ствола %q", outputs["tag"], want))
	}
	if outputs["tag"] == "latest" {
		why = append(why, "тег движущийся (`latest`): вердикт вчерашнего прогона относился бы к другому образу")
	}
	if outputs["version"] != branch {
		why = append(why, fmt.Sprintf("версия %q, а не имя ветки %q", outputs["version"], branch))
	}
	if outputs["revision"] != sha {
		why = append(why, fmt.Sprintf("ревизия %q, а не полная %q", outputs["revision"], sha))
	}
	return strings.Join(why, "; ")
}

// gateEnv — окружение шага `gate`: событие, пространство имён по умолчанию и
// учётные данные реестра, если они объявлены.
func gateEnv(event, fallbackNS string, creds bool) map[string]string {
	env := map[string]string{"EVENT": event, "FALLBACK_NS": fallbackNS}
	if creds {
		env["DH_USER"] = "owner"
		env["DH_TOKEN"] = "token"
	}
	return env
}

// gateFinding — что не так с решением о публикации; пусто — решение то, что ждали.
func gateFinding(outputs map[string]string, push, ns string) string {
	var why []string
	if outputs["push"] != push {
		why = append(why, fmt.Sprintf("публикация %q, а ждали %q", outputs["push"], push))
	}
	if outputs["ns"] != ns {
		why = append(why, fmt.Sprintf("пространство имён %q, а ждали %q", outputs["ns"], ns))
	}
	return strings.Join(why, "; ")
}

// pushSubject — окружение шага `subject` на событии `push` в ветку.
func pushSubject(branch, sha string) map[string]string {
	return map[string]string{"REF_NAME": branch, "REF_TYPE": "branch", "HEAD_SHA": sha}
}

// TestImageProducerTagsALineHeadLikeTheTrunk — НЕСУЩЕЕ утверждение о форме
// тега и о публикации; способность упасть — половина «краснеет» ниже.
func TestImageProducerTagsALineHeadLikeTheTrunk(t *testing.T) {
	t.Parallel()
	wf, steps := imageProducer(t)

	for _, tc := range []struct{ what, branch, sha string }{
		{"голова ветки эпика", "357", lineHeadSHA},
		{"голова ветки волны", "366", lineHeadSHA},
		{"ствол — близнец того же правила", "main", trunkHeadSHA},
	} {
		t.Run("имя: "+tc.what, func(t *testing.T) {
			t.Parallel()
			out, err := execImageStep(t.TempDir(), steps["subject"].Run, pushSubject(tc.branch, tc.sha))
			require.NoError(t, err)
			require.Emptyf(t, subjectFinding(out, tc.branch, tc.sha), "шаг `subject` дал %v", out)
		})
	}

	ns := wf.Env["FALLBACK_NS"]
	require.NotEmpty(t, ns, "предпосылка ложна: `env.FALLBACK_NS` не объявлен")
	for _, tc := range []struct {
		what, event, push, ns string
		creds                 bool
	}{
		{"push с учётными данными публикует", "push", "true", "owner", true},
		{"запрос не публикует и с учётными данными", "pull_request", "false", "owner", true},
		{"push без учётных данных только собирает", "push", "false", ns, false},
	} {
		t.Run("публикация: "+tc.what, func(t *testing.T) {
			t.Parallel()
			out, err := execImageStep(t.TempDir(), steps["gate"].Run, gateEnv(tc.event, ns, tc.creds))
			require.NoError(t, err)
			require.Emptyf(t, gateFinding(out, tc.push, tc.ns), "шаг `gate` дал %v", out)
		})
	}

	// Тег у сборки ОДИН, и это вычисленный `subject`: второго `-t` — например,
	// движущегося — нет.
	t.Run("сборка несёт один тег, и он из `subject`", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, 1, strings.Count(steps["build"].Run, " -t "), "тегов у сборки не один")
		require.Contains(t, steps["build"].Run, `-t "$IMAGE_REF"`)
		require.True(t, strings.HasSuffix(steps["build"].Env["IMAGE_REF"], ":${{ steps.subject.outputs.tag }}"),
			"тег образа взят не у шага `subject`: %q", steps["build"].Env["IMAGE_REF"])
	})
}

// TestImageProducerTagProbeCanFail — половина «КРАСНЕЕТ»: дефект вносится в
// КОПИЮ тела шага из дерева, по одному факту.
func TestImageProducerTagProbeCanFail(t *testing.T) {
	t.Parallel()
	_, steps := imageProducer(t)

	t.Run("имя ветки заменено движущимся тегом", func(t *testing.T) {
		t.Parallel()
		script := injectOnce(t, steps["subject"].Run, `image_tag="$slug-${HEAD_SHA:0:8}"`, `image_tag="latest"`)
		out, err := execImageStep(t.TempDir(), script, pushSubject("357", lineHeadSHA))
		require.NoError(t, err)
		got := subjectFinding(out, "357", lineHeadSHA)
		require.Contains(t, got, "движущийся (`latest`)")
		require.Contains(t, got, `а по правилу ствола "357-fc9f5aff"`)
	})

	t.Run("push перестал публиковать", func(t *testing.T) {
		t.Parallel()
		script := injectOnce(t, steps["gate"].Run,
			"else\n  echo \"push=true\"", "else\n  echo \"push=false\"")
		out, err := execImageStep(t.TempDir(), script, gateEnv("push", "local", true))
		require.NoError(t, err)
		require.Contains(t, gateFinding(out, "true", "owner"), `публикация "false", а ждали "true"`)
	})

	t.Run("шаг, упавший в оболочке, — отказ, а не пустой выход", func(t *testing.T) {
		t.Parallel()
		_, err := execImageStep(t.TempDir(), "false\n"+steps["subject"].Run, pushSubject("357", lineHeadSHA))
		require.Error(t, err)
		require.Contains(t, err.Error(), "шаг завершился отказом")
	})
}
