// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// image_review_duplicate_test.go — ЗАПРОС НЕ ПЕРЕСОБИРАЕТ ДЕРЕВО, КОТОРОЕ УЖЕ
// СОБИРАЕТ ОТПРАВКА ЕГО ГОЛОВЫ (задача PRO-Robotech/kaname#847).
//
// # ПРЕДМЕТ
//
// Отправка в ветку-номер и прогон запроса с этой головой собирают образ дважды:
// замер 2026-10-16…23 — прогонов `push` 221, запроса 91, из них с прогоном
// `push` той же ревизии 83. Сборку по `push` снять нельзя: у неё есть
// потребитель — голова линии публикуется под `<номер>-<ревизия>` (её пинит зонт
// монорепо), ветка задачи под `task-<ветка>-<ревизия>` (её ставит стенд проб
// платформы, kaname#916, kacho#3312). Запрос не публикует никогда, значит
// двойник — его сборка, и ровно тогда, когда она собирает ТО ЖЕ дерево:
//
//  1. голова — ветка этого репозитория, и фильтр `push` её пропускает
//     (`main` либо номер): иначе прогона по `push` нет вовсе;
//  2. голова не отстаёт от базы: тогда дерево слияния, которое собирает запрос,
//     равно дереву головы. Отстающая голова — законный близнец: слияние с
//     новой базой не собирает больше никто;
//  3. прогон `push` этой ревизии в этой ветке идёт либо завершён успехом или
//     отказом. Снятый (`cancelled`) не собрал ничего; отказ виден на ревизии.
//
// Всё прочее — сборка как прежде, и отказ провайдера тоже: шаг решает
// «собирать», вслух, а не «пропустить» молча.
//
// Проба ИСПОЛНЯЕТ тело шага из дерева той оболочкой, какой его исполняет
// провайдер, с двойником CLI провайдера и настоящим `jq`, и судит выход. О
// задании `image` судится запись: его условие читает этот выход, выход задания
// `changes` назван, и окружение шага взято из тех полей события, которые
// названы в шапке.
//
// ЧЕГО ПРОБА НЕ СУДИТ: что настоящий API отвечает так, как двойник (форма
// обращения судится журналом двойника, ответ — прогоном запроса), и что
// снятый здесь прогон `push` после решения не сняли — это свойство провайдера.
package check_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/PRO-Robotech/kaname/internal/testsupport/execstub"
)

// reviewDupStepID — шаг задания `changes`, решающий, двойник ли сборка запроса.
const reviewDupStepID = "duplicate"

type reviewDupJob struct {
	If      string            `yaml:"if"`
	Outputs map[string]string `yaml:"outputs"`
	Steps   []imageStep       `yaml:"steps"`
}

// reviewDupProducer — шаг `duplicate` и задания `changes`, `image` из дерева.
func reviewDupProducer(t *testing.T) (step imageStep, changes, image reviewDupJob) {
	t.Helper()
	raw, ok := trunkCorpusSource(t)[imageInjectRel]
	require.Truef(t, ok, "проверка НЕ ИСПОЛНЯЛАСЬ: %s не прочитан", imageInjectRel)
	var wf struct {
		Jobs map[string]reviewDupJob `yaml:"jobs"`
	}
	require.NoError(t, yaml.Unmarshal([]byte(raw), &wf), "проверка НЕ ИСПОЛНЯЛАСЬ: объявление не разобрано")
	changes, ok = wf.Jobs["changes"]
	require.True(t, ok, "предпосылка ложна: задания `changes` нет")
	image, ok = wf.Jobs[imageJob]
	require.Truef(t, ok, "предпосылка ложна: задания %q нет", imageJob)
	for _, s := range changes.Steps {
		if s.ID == reviewDupStepID {
			step = s
		}
	}
	require.NotEmptyf(t, step.Run, "шага %q в задании `changes` нет либо у него пустое тело: запрос "+
		"пересобирает дерево, которое уже собирает отправка его головы", reviewDupStepID)
	return step, changes, image
}

// reviewDupStub — двойник CLI провайдера. Знает два обращения:
//
//	api repos/<р>/compare/<база>...<ревизия> --jq .behind_by — печатает GH_STUB_BEHIND;
//	api repos/<р>/actions/workflows/<файл>/runs?<ключи> — массив прогонов формы API.
//
// Записи GH_STUB_RUNS — «<событие>:<ветка>:<ревизия>:<status>:<conclusion> …»,
// пустой conclusion — null. Фильтр — по каждому ключу, который шаг назвал:
// ключ, которого шаг не назвал, не сужает ничего, как у провайдера.
// GH_STUB_FAIL — «compare» либо «runs»: это обращение отказывает.
const reviewDupStub = `#!/usr/bin/env bash
printf '%s\n' "$*" >> "$GH_STUB_LOG"
[ "$1" = api ] || { echo "двойник знает только api: $*" >&2; exit 64; }
url=$2; shift 2
case "$url" in
  repos/PRO-Robotech/kaname/compare/*...*)
    [ "$GH_STUB_FAIL" = compare ] && { echo "HTTP 502: Bad Gateway" >&2; exit 1; }
    [ "$*" = "--jq .behind_by" ] || { echo "двойник не знает ключей сверки: $*" >&2; exit 64; }
    echo "$GH_STUB_BEHIND"; exit 0 ;;
  repos/PRO-Robotech/kaname/actions/workflows/docker-build.yml/runs\?*) ;;
  *) echo "двойник не знает обращения: $url" >&2; exit 22 ;;
esac
[ "$GH_STUB_FAIL" = runs ] && { echo "HTTP 502: Bad Gateway" >&2; exit 1; }
[ "$#" -eq 0 ] || { echo "двойник не знает ключей переписи: $*" >&2; exit 64; }
event='' branch='' sha=''
IFS='&' read -ra kv <<<"${url#*\?}"
for p in "${kv[@]}"; do
  case "$p" in event=*) event=${p#event=} ;; branch=*) branch=${p#branch=} ;; head_sha=*) sha=${p#head_sha=} ;; esac
done
out=()
for rec in $GH_STUB_RUNS; do
  IFS=: read -r e b s st co <<<"$rec"
  [ -z "$event" ] || [ "$e" = "$event" ] || continue
  [ -z "$branch" ] || [ "$b" = "$branch" ] || continue
  [ -z "$sha" ] || [ "$s" = "$sha" ] || continue
  [ -n "$co" ] && co="\"$co\"" || co=null
  out+=("{\"event\":\"$e\",\"head_branch\":\"$b\",\"head_sha\":\"$s\",\"status\":\"$st\",\"conclusion\":$co}")
done
(IFS=,; echo "{\"total_count\":${#out[@]},\"workflow_runs\":[${out[*]}]}")
`

// reviewDupWorld — событие запроса и то, что о нём знает провайдер.
type reviewDupWorld struct {
	event, headRepo, headRef, behind, runs, fail string
}

const (
	dupHeadSHA  = "fc9f5aff1d0e6b6a3a4c0e0b6f1a2b3c4d5e6f70"
	dupOtherSHA = "0b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3d4"
	dupRepo     = "PRO-Robotech/kaname"
)

func runReviewDup(t *testing.T, script string, w reviewDupWorld) (map[string]string, string, error) {
	t.Helper()
	// ПРЕДПОСЫЛКА: `jq` исполним в окружении шага. Без неё шаг уходит в ветвь
	// «не установлено — собираем», и каждый мир с ответом «false» зеленел бы
	// беспредметно.
	jq := exec.Command("jq", "-n", "1")
	jq.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	if out, err := jq.CombinedOutput(); err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: `jq` не исполняется, а шаг на раннере его зовёт: %v; %s", err, out)
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	execstub.Write(t, filepath.Join(bin, "gh"), reviewDupStub)
	logPath := filepath.Join(dir, "gh.log")
	require.NoError(t, os.WriteFile(logPath, nil, 0o600))
	env := map[string]string{
		"PATH":           bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME":           os.Getenv("HOME"),
		"GH_TOKEN":       "token",
		"EVENT":          w.event,
		"REPO":           dupRepo,
		"HEAD_REPO":      w.headRepo,
		"HEAD_REF":       w.headRef,
		"HEAD_SHA":       dupHeadSHA,
		"BASE_REF":       "942",
		"WORKFLOW_REF":   dupRepo + "/.github/workflows/docker-build.yml@refs/pull/12/merge",
		"GH_STUB_LOG":    logPath,
		"GH_STUB_BEHIND": w.behind,
		"GH_STUB_RUNS":   w.runs,
		"GH_STUB_FAIL":   w.fail,
	}
	out, err := execImageStep(dir, script, env)
	calls, rerr := os.ReadFile(logPath) // #nosec G304 -- путь из t.TempDir()
	require.NoError(t, rerr)
	return out, string(calls), err
}

// Миры. Голова 847 — ветка задачи этого репозитория, запрос в ветку эпика 942.
var (
	pushRunning = "push:847:" + dupHeadSHA + ":in_progress:"
	pushOther   = "push:847:" + dupOtherSHA + ":completed:success"

	reviewOverPush = reviewDupWorld{event: "pull_request", headRepo: dupRepo, headRef: "847", behind: "0",
		runs: pushOther + " " + pushRunning}
	reviewBehind = reviewDupWorld{event: "pull_request", headRepo: dupRepo, headRef: "847", behind: "3",
		runs: pushRunning}
	reviewPushCancelled = reviewDupWorld{event: "pull_request", headRepo: dupRepo, headRef: "847", behind: "0",
		runs: "push:847:" + dupHeadSHA + ":completed:cancelled"}
	reviewOnlyOtherSHA = reviewDupWorld{event: "pull_request", headRepo: dupRepo, headRef: "847", behind: "0",
		runs: pushOther}
	reviewFromFork = reviewDupWorld{event: "pull_request", headRepo: "someone/kaname", headRef: "847", behind: "0",
		runs: pushRunning}
	reviewOffPushFilter = reviewDupWorld{event: "pull_request", headRepo: dupRepo, headRef: "lane-kn-api", behind: "0",
		runs: "push:lane-kn-api:" + dupHeadSHA + ":in_progress:"}
)

// TestImageReviewBuildIsSkippedWhenThePushRunBuildsTheSameTree — несущее утверждение.
func TestImageReviewBuildIsSkippedWhenThePushRunBuildsTheSameTree(t *testing.T) {
	t.Parallel()
	step, changes, image := reviewDupProducer(t)

	t.Run("задание `changes` отдаёт решение, `image` его читает, окружение — из события", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "${{ steps.duplicate.outputs.duplicate }}", strings.TrimSpace(changes.Outputs["duplicate"]),
			"выход `duplicate` задания `changes` не назван — условие `image` прочитало бы пустое")
		require.Contains(t, image.If, "needs.changes.outputs.duplicate != 'true'",
			"условие задания `image` решения не читает — двойник собирается по-прежнему")
		for k, want := range map[string]string{
			"EVENT":        "${{ github.event_name }}",
			"REPO":         "${{ github.repository }}",
			"HEAD_REPO":    "${{ github.event.pull_request.head.repo.full_name }}",
			"HEAD_REF":     "${{ github.event.pull_request.head.ref }}",
			"HEAD_SHA":     "${{ github.event.pull_request.head.sha }}",
			"BASE_REF":     "${{ github.event.pull_request.base.ref }}",
			"WORKFLOW_REF": "${{ github.workflow_ref }}",
			"GH_TOKEN":     "${{ github.token }}",
		} {
			require.Equalf(t, want, strings.TrimSpace(step.Env[k]),
				"окружение шага: %s берётся не из того поля события — проба судила бы не тот вход", k)
		}
	})

	for _, tc := range []struct {
		what, want string
		w          reviewDupWorld
		// asks — подстроки обращений, которые шаг обязан сделать; пустой — не спрашивает никого.
		asks []string
	}{
		{"голова не отстаёт, прогон push её ревизии идёт — сборка запроса снята", "true", reviewOverPush,
			[]string{"compare/942..." + dupHeadSHA + " --jq .behind_by",
				"actions/workflows/docker-build.yml/runs?event=push&branch=847&head_sha=" + dupHeadSHA}},
		{"прогон push завершён отказом — отказ виден на ревизии, снимаем", "true",
			reviewDupWorld{event: "pull_request", headRepo: dupRepo, headRef: "847", behind: "0",
				runs: "push:847:" + dupHeadSHA + ":completed:failure"}, nil},
		// ЗАКОННЫЙ БЛИЗНЕЦ: та же голова, тот же прогон push, но дерево слияния другое.
		{"голова отстаёт от базы — слияние не собирает больше никто", "false", reviewBehind,
			[]string{"compare/942..."}},
		{"прогон push снят — он не собрал ничего", "false", reviewPushCancelled, nil},
		{"прогон push есть лишь у другой ревизии", "false", reviewOnlyOtherSHA, nil},
		{"голова из другого репозитория — отправки сюда нет", "false", reviewFromFork, []string{}},
		{"голова вне фильтра push — отправки не было", "false", reviewOffPushFilter, []string{}},
		{"отправка не спрашивает никого", "false", reviewDupWorld{event: "push", headRef: "847"}, []string{}},
		{"ручной запуск не спрашивает никого", "false", reviewDupWorld{event: "workflow_dispatch"}, []string{}},
		{"сверка отказала — собираем", "false",
			reviewDupWorld{event: "pull_request", headRepo: dupRepo, headRef: "847", behind: "0", runs: pushRunning,
				fail: "compare"}, nil},
		{"ответ сверки не разобран — собираем", "false",
			reviewDupWorld{event: "pull_request", headRepo: dupRepo, headRef: "847", behind: "null", runs: pushRunning}, nil},
		{"перепись прогонов отказала — собираем", "false",
			reviewDupWorld{event: "pull_request", headRepo: dupRepo, headRef: "847", behind: "0", runs: pushRunning,
				fail: "runs"}, nil},
	} {
		t.Run(tc.what, func(t *testing.T) {
			t.Parallel()
			out, calls, err := runReviewDup(t, step.Run, tc.w)
			require.NoError(t, err)
			require.Equalf(t, tc.want, out["duplicate"], "шаг `duplicate` дал %v; обращения: %s", out, calls)
			if tc.asks != nil && len(tc.asks) == 0 {
				require.Emptyf(t, calls, "решение не зависит от провайдера, а шаг его спросил: %s", calls)
			}
			for _, a := range tc.asks {
				require.Containsf(t, calls, "repos/"+dupRepo+"/"+a, "шаг не спросил %q: %s", a, calls)
			}
		})
	}
}

// TestImageReviewDuplicateProbeCanFail — половина «КРАСНЕЕТ»: дефект — в копию тела.
func TestImageReviewDuplicateProbeCanFail(t *testing.T) {
	t.Parallel()
	step, _, _ := reviewDupProducer(t)
	for _, tc := range []struct {
		what, old, repl string
		w               reviewDupWorld
	}{
		{"сверка с базой снята — отстающая голова теряет сборку слияния",
			`[ "$behind" = 0 ] ||`, `true ||`, reviewBehind},
		{"снятый прогон push засчитан", `.conclusion == "success" or .conclusion == "failure"`, `true`,
			reviewPushCancelled},
		{"ревизия не названа в переписи — засчитан прогон другой ревизии", `&head_sha=$HEAD_SHA`, ``,
			reviewOnlyOtherSHA},
		{"признак своего репозитория снят — голова из другого засчитана", `[ "$HEAD_REPO" = "$REPO" ] ||`,
			`true ||`, reviewFromFork},
		{"фильтр push снят — голова вне фильтра засчитана", `[[ "$HEAD_REF" =~ ^(main|[0-9]+)$ ]] ||`,
			`true ||`, reviewOffPushFilter},
	} {
		t.Run(tc.what, func(t *testing.T) {
			t.Parallel()
			out, _, err := runReviewDup(t, injectOnce(t, step.Run, tc.old, tc.repl), tc.w)
			require.NoError(t, err)
			require.Equal(t, "true", out["duplicate"], "инъекция не изменила решения — проба слепа к ней")
		})
	}
}
