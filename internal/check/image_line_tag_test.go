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
// ЛИНИЯ ИЛИ ЗАДАЧА — ПРЕДМЕТ ЭТОЙ ПРОБЫ, а не фильтра. Ветки задач названы
// номером так же, как линии, и фильтр `push` пропускает обе; публикацию решает
// шаг `gate` переписью запросов с базой этой ветки. Провайдер подменён
// двойником CLI (ghStub), отвечающим так, как отвечает API: ветка задачи —
// голова запроса в волну и база ни одного, линия — база, в том числе когда все
// запросы в неё уже влиты. Законный близнец линии — push в задачу 429 с тем же
// видом имени: сборка есть, публикации нет.
//
// ЧЕГО ПРОБА НЕ СУДИТ — сказано прямо. Выражения `${{ … }}` в `env:` шага
// провайдер вычисляет ДО оболочки, и здесь значения подаются такими, какие он
// даёт для события: на `push` `github.head_ref` пуст и имя берётся у
// `github.ref_name`. Фильтр веток `push` — пойдёт ли процесс на ветку вообще —
// судит ось 2 гейта триггеров (review_trigger_scope.go), а не эта проба. Что
// настоящий API отвечает так, как двойник, дерево не знает: форма обращения
// судится двойником, ответ — прогоном по `push`. Что тег ДОЕХАЛ до реестра,
// дерево тоже не знает: это прогон по `push` после вливания.
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

// ghStub — ДВОЙНИК CLI провайдера для шага `gate`: отвечает на перепись
// запросов по базе (`api repos/<репозиторий>/pulls?base=…&state=…&per_page=…`)
// так, как отвечает API. Записи — `GH_STUB_PULLS`: «<база>:<open|closed> …»;
// влитый запрос у провайдера имеет состояние `closed`. Умолчание `state` —
// `open`, как у провайдера: перепись без `state=all` не видит линии, все
// запросы в которую уже влиты. Каждое обращение пишется в `GH_STUB_LOG` —
// проба судит и то, КОГО шаг спросил, и то, что ствол не спрашивает никого.
// Незнакомая форма обращения — отказ двойника, а не ответ «ноль».
const ghStub = `#!/usr/bin/env bash
printf '%s\n' "$*" >> "$GH_STUB_LOG"
if [ -n "$GH_STUB_FAIL" ]; then echo "HTTP 502: Bad Gateway" >&2; exit 1; fi
[ "$1" = api ] || { echo "двойник знает только api: $*" >&2; exit 64; }
url=$2; shift 2
case "$url" in */pulls\?*) ;; *) echo "двойник знает только перепись запросов: $url" >&2; exit 64 ;; esac
base='' state=open per=30
IFS='&' read -ra kv <<<"${url#*\?}"
for p in "${kv[@]}"; do
  case "$p" in base=*) base=${p#base=} ;; state=*) state=${p#state=} ;; per_page=*) per=${p#per_page=} ;; esac
done
n=0
for rec in $GH_STUB_PULLS; do
  [ "${rec%%:*}" = "$base" ] || continue
  case "$state" in
    all) ;;
    open) [ "${rec#*:}" = open ] || continue ;;
    closed) [ "${rec#*:}" = closed ] || continue ;;
    *) echo "state=$state провайдер не знает" >&2; exit 22 ;;
  esac
  n=$((n + 1))
done
[ "$n" -gt "$per" ] && n=$per
if [ "$*" = "--jq length" ]; then echo "$n"; exit 0; fi
printf '['; for ((i = 0; i < n; i++)); do [ "$i" -gt 0 ] && printf ','; printf '{}'; done; echo ']'
`

// gateWorld — событие для шага `gate` и то, что о нём знает трекер.
type gateWorld struct {
	event, refType, refName string
	creds                   bool
	// pulls — запросы по базам, как их видит провайдер: «<база>:<состояние> …».
	pulls string
	// apiFails — провайдер отказал на обращении.
	apiFails bool
}

// gateEnv — окружение шага `gate` и путь журнала обращений двойника: событие,
// ссылка, пространство имён по умолчанию, учётные данные реестра, если они
// объявлены, и двойник CLI провайдера первым в PATH.
func gateEnv(t *testing.T, dir, fallbackNS string, w gateWorld) (map[string]string, string) {
	t.Helper()
	bin := filepath.Join(dir, "bin")
	require.NoError(t, os.MkdirAll(bin, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(bin, "gh"), []byte(ghStub), 0o700)) // #nosec G306 -- двойник обязан исполняться
	logPath := filepath.Join(dir, "gh.log")
	require.NoError(t, os.WriteFile(logPath, nil, 0o600))
	env := map[string]string{
		"PATH":          bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"EVENT":         w.event,
		"REF_TYPE":      w.refType,
		"REF_NAME":      w.refName,
		"REPO":          "PRO-Robotech/kaname",
		"GH_TOKEN":      "token",
		"FALLBACK_NS":   fallbackNS,
		"GH_STUB_LOG":   logPath,
		"GH_STUB_PULLS": w.pulls,
	}
	if w.creds {
		env["DH_USER"] = "owner"
		env["DH_TOKEN"] = "token"
	}
	if w.apiFails {
		env["GH_STUB_FAIL"] = "1"
	}
	return env, logPath
}

// runGate — исполняет тело шага `gate` в мире `w`; второе значение — журнал
// обращений к провайдеру.
func runGate(t *testing.T, script, fallbackNS string, w gateWorld) (map[string]string, string, error) {
	t.Helper()
	dir := t.TempDir()
	env, logPath := gateEnv(t, dir, fallbackNS, w)
	out, err := execImageStep(dir, script, env)
	calls, rerr := os.ReadFile(logPath) // #nosec G304 -- путь из t.TempDir()
	require.NoError(t, rerr)
	return out, string(calls), err
}

// Миры шага `gate`. Ветка задачи — ГОЛОВА запроса в волну, а не его база:
// у провайдера база 366 знает запрос, база 429 — ни одного.
var (
	trunkPush = gateWorld{event: "push", refType: "branch", refName: "main", creds: true, pulls: "main:open"}
	linePush  = gateWorld{event: "push", refType: "branch", refName: "366", creds: true,
		pulls: "366:closed 366:open 357:closed"}
	landedLinePush = gateWorld{event: "push", refType: "branch", refName: "357", creds: true,
		pulls: "357:closed 366:open"}
	taskPush = gateWorld{event: "push", refType: "branch", refName: "429", creds: true,
		pulls: "366:closed 366:open 357:closed"}
	// Вторая форма имени линии (Д36/Д59 эпика kacho#2914): номер, дефис, суть.
	// Ветка эпика `484-notify` — база запроса волны; ветка полосы той же формы
	// `484-ci-branch-name-suffix` — голова запроса, а не его база.
	suffixLinePush = gateWorld{event: "push", refType: "branch", refName: "484-notify", creds: true,
		pulls: "484-notify:open 484-notify:closed main:open"}
	suffixTaskPush = gateWorld{event: "push", refType: "branch", refName: "484-ci-branch-name-suffix", creds: true,
		pulls: "484-notify:open main:open"}
)

// gateLineCond — запись условия «ветка названа как линия» в шаге `gate`: две
// формы имени, из цифр и `<номер>-<суть>` (Д59). Инъекции ниже меняют именно её.
const gateLineCond = `elif [[ "$REF_NAME" =~ ^[0-9]+$ || "$REF_NAME" =~ ^[0-9]+-[a-z0-9][a-z0-9-]*$ ]]; then`

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
		{"голова ветки эпика второй формы", "484-notify", lineHeadSHA},
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
		what     string
		w        gateWorld
		push, ns string
		// asks — о какой базе шаг обязан спросить трекер; пусто — не спрашивает вовсе.
		asks string
	}{
		{"push в ствол публикует, трекер не спрашивается", trunkPush, "true", "owner", ""},
		{"push в ветку линии публикует — она база запроса", linePush, "true", "owner", "366"},
		{"линия, все запросы в которую влиты, публикует", landedLinePush, "true", "owner", "357"},
		// ЗАКОННЫЙ БЛИЗНЕЦ ЛИНИИ той же формы имени: фильтр `push` его пропускает,
		// а посаженного состояния у него нет.
		{"push в ветку задачи НЕ публикует — имя той же формы, состояние не посажено", taskPush, "false", "owner", "429"},
		{"push в ветку эпика второй формы публикует — она база запроса", suffixLinePush, "true", "owner", "484-notify"},
		{"push в ветку полосы второй формы НЕ публикует — база ни одного запроса", suffixTaskPush, "false", "owner", "484-ci-branch-name-suffix"},
		// ЗАКОННЫЙ БЛИЗНЕЦ ФОРМЫ: имя с прописной и подчёркиванием вне обеих
		// форм — трекер не спрашивается, публикации нет.
		{"ветка вне обеих форм имени не публикует и трекер не спрашивает",
			gateWorld{event: "push", refType: "branch", refName: "484_Notify", creds: true, pulls: "484_Notify:open"}, "false", "owner", ""},
		{"ссылка на версию публикует", gateWorld{event: "push", refType: "tag", refName: "v1.2.3", creds: true}, "true", "owner", ""},
		{"ручной запуск на ветке полосы не публикует",
			gateWorld{event: "workflow_dispatch", refType: "branch", refName: "lane/kn-api", creds: true}, "false", "owner", ""},
		{"запрос не публикует и с учётными данными",
			gateWorld{event: "pull_request", refType: "branch", refName: "437/merge", creds: true, pulls: "366:open"}, "false", "owner", ""},
		{"push без учётных данных только собирает", gateWorld{event: "push", refType: "branch", refName: "366", pulls: "366:open"}, "false", ns, ""},
	} {
		t.Run("публикация: "+tc.what, func(t *testing.T) {
			t.Parallel()
			out, calls, err := runGate(t, steps["gate"].Run, ns, tc.w)
			require.NoError(t, err)
			require.Emptyf(t, gateFinding(out, tc.push, tc.ns), "шаг `gate` дал %v", out)
			if tc.asks == "" {
				require.Emptyf(t, calls, "решение не зависит от трекера, а шаг его спросил: %s", calls)
				return
			}
			require.Containsf(t, calls, "repos/PRO-Robotech/kaname/pulls?base="+tc.asks+"&",
				"шаг спросил не о своей ветке: %q", calls)
		})
	}

	// «Линия или задача» не установлено — это НЕ ВЫПОЛНИЛОСЬ, а не «задача»:
	// тихое `push=false` на отказе провайдера вернуло бы дефект #429 (голова
	// линии без образа) без единого красного.
	t.Run("публикация: трекер отказал — шаг не исполнился, а не решил «задача»", func(t *testing.T) {
		t.Parallel()
		w := linePush
		w.apiFails = true
		out, _, err := runGate(t, steps["gate"].Run, ns, w)
		require.Errorf(t, err, "отказ провайдера прочитан как решение: %v", out)
		require.Contains(t, err.Error(), "не установлено")
	})

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

	t.Run("push в ствол перестал публиковать", func(t *testing.T) {
		t.Parallel()
		script := injectOnce(t, steps["gate"].Run, `landed=true; why="ствол`, `landed=false; why="ствол`)
		out, _, err := runGate(t, script, "local", trunkPush)
		require.NoError(t, err)
		require.Contains(t, gateFinding(out, "true", "owner"), `публикация "false", а ждали "true"`)
	})

	// ДЕФЕКТ РЕВЬЮ #429: линию «распознаёт» фильтр — ветка из цифр публикуется
	// без переписи, и ветка задачи идёт в реестр под именем линии.
	t.Run("линию распознаёт форма имени, а не перепись — задача публикуется", func(t *testing.T) {
		t.Parallel()
		script := injectOnce(t, steps["gate"].Run, gateLineCond,
			gateLineCond+` landed=true; why="ветка из цифр"; elif false; then`)
		out, _, err := runGate(t, script, "local", taskPush)
		require.NoError(t, err)
		require.Contains(t, gateFinding(out, "false", "owner"), `публикация "true", а ждали "false"`)
	})

	// Д59: шаг, знающий только форму из цифр, оставляет голову ветки эпика
	// `484-notify` без образа — тот же дефект #429 для второй формы имени.
	t.Run("вторая форма имени не распознана — голова `484-notify` без образа", func(t *testing.T) {
		t.Parallel()
		script := injectOnce(t, steps["gate"].Run, gateLineCond, `elif [[ "$REF_NAME" =~ ^[0-9]+$ ]]; then`)
		out, calls, err := runGate(t, script, "local", suffixLinePush)
		require.NoError(t, err)
		require.Contains(t, gateFinding(out, "true", "owner"), `публикация "false", а ждали "true"`)
		require.Empty(t, calls, "форма не распознана — трекер не спрошен")
	})

	t.Run("перепись только открытых запросов — влитая линия без образа", func(t *testing.T) {
		t.Parallel()
		script := injectOnce(t, steps["gate"].Run, "&state=all&", "&state=open&")
		out, _, err := runGate(t, script, "local", landedLinePush)
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
