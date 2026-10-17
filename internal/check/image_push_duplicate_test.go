// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// image_push_duplicate_test.go — ОТПРАВКА В ВЕТКУ ЗАДАЧИ НЕ ПЕРЕСОБИРАЕТ ТО, ЧТО
// СОБИРАЕТ ЕЁ ЗАПРОС (задача PRO-Robotech/kaname#847).
//
// # ПРЕДМЕТ
//
// Фильтр `push` образа пропускает ветки-номера, а среди них — ветки задач: имя
// той же формы, что у линии. Ветка задачи не публикуется (шаг `gate`), то есть
// её прогон по `push` — сборка без потребителя, и на том же коммите её уже
// собирает прогон запроса. Замер 2026-10-02…16: дублей «push + запрос» на одном
// коммите 233, из них на ветках задач 204; push в ветки задач — 488 прогонов,
// 1214 минут прогона.
//
// Снимать `push` с веток-номеров НЕЛЬЗЯ: тег головы линии пинит зонт
// (`deploy/helm/umbrella/values.yaml` монорепо — `296-…`), и публикует его
// только `push`. Поэтому решает шаг `duplicate` задания `changes`: прогон по
// `push` пропускает сборку ровно тогда, когда (1) ветка-номер — задача, база ни
// одного запроса (тот же признак, что у шага `gate`), и (2) у неё есть ОТКРЫТЫЙ
// НЕ-ЧЕРНОВОЙ запрос в базу из фильтра `pull_request` — его прогон эту голову
// соберёт. Черновой не в счёт: на черновике образ выбирает карта путей и может
// не выбрать. Всё прочее — сборка как прежде, и отказ провайдера тоже: шаг
// решает «собирать», громко, а не «пропустить» молча.
//
// Проба ИСПОЛНЯЕТ тело шага из дерева той оболочкой, какой его исполняет
// провайдер, с двойником CLI провайдера и настоящим `jq`, и судит выход. О
// задании `image` судится запись: его условие читает этот выход, а выход
// задания `changes` назван.
//
// ЧЕГО ПРОБА НЕ СУДИТ: что настоящий API отвечает так, как двойник (форма
// обращения судится журналом двойника, ответ — прогоном по `push`), и что
// прогон запроса действительно стартовал — это свойство провайдера.
package check_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// dupStepID — шаг задания `changes`, решающий, двойник ли эта сборка.
const dupStepID = "duplicate"

type dupJob struct {
	If      string            `yaml:"if"`
	Outputs map[string]string `yaml:"outputs"`
	Steps   []imageStep       `yaml:"steps"`
}

// dupProducer — тело шага `duplicate` и задания `changes`, `image` из дерева.
func dupProducer(t *testing.T) (step string, changes, image dupJob) {
	t.Helper()
	raw, ok := trunkCorpusSource(t)[imageInjectRel]
	require.Truef(t, ok, "проверка НЕ ИСПОЛНЯЛАСЬ: %s не прочитан", imageInjectRel)
	var wf struct {
		Jobs map[string]dupJob `yaml:"jobs"`
	}
	require.NoError(t, yaml.Unmarshal([]byte(raw), &wf), "проверка НЕ ИСПОЛНЯЛАСЬ: объявление не разобрано")
	changes, ok = wf.Jobs["changes"]
	require.True(t, ok, "предпосылка ложна: задания `changes` нет")
	image, ok = wf.Jobs[imageJob]
	require.Truef(t, ok, "предпосылка ложна: задания %q нет", imageJob)
	for _, s := range changes.Steps {
		if s.ID == dupStepID {
			step = s.Run
		}
	}
	require.NotEmptyf(t, step, "шага %q в задании `changes` нет либо у него пустое тело: отправка "+
		"в ветку задачи пересобирает голову, которую уже собирает её запрос", dupStepID)
	return step, changes, image
}

// dupStub — двойник CLI провайдера: `api repos/<р>/pulls?base=…|head=<владелец>:<ветка>&state=…&per_page=…`.
// Записи `GH_STUB_PULLS` — «<голова>><база>:<open|closed>:<draft true|false> …».
// С `--jq length` печатает число, без него — массив запросов формы API.
const dupStub = `#!/usr/bin/env bash
printf '%s\n' "$*" >> "$GH_STUB_LOG"
if [ -n "$GH_STUB_FAIL" ]; then echo "HTTP 502: Bad Gateway" >&2; exit 1; fi
[ "$1" = api ] || { echo "двойник знает только api: $*" >&2; exit 64; }
url=$2; shift 2
case "$url" in */pulls\?*) ;; *) echo "двойник знает только перепись запросов: $url" >&2; exit 64 ;; esac
base='' head='' state=open per=30
IFS='&' read -ra kv <<<"${url#*\?}"
for p in "${kv[@]}"; do
  case "$p" in base=*) base=${p#base=} ;; head=*) head=${p#head=} ;; state=*) state=${p#state=} ;; per_page=*) per=${p#per_page=} ;; esac
done
if [ -n "$head" ]; then
  [ "${head%%:*}" = PRO-Robotech ] || { echo "head без владельца: $head" >&2; exit 22; }
  head=${head#*:}
fi
out=() n=0
for rec in $GH_STUB_PULLS; do
  h=${rec%%>*} rest=${rec#*>}; b=${rest%%:*} rest=${rest#*:}; st=${rest%%:*} dr=${rest#*:}
  [ -z "$base" ] || [ "$b" = "$base" ] || continue
  [ -z "$head" ] || [ "$h" = "$head" ] || continue
  case "$state" in all) ;; open|closed) [ "$st" = "$state" ] || continue ;; *) exit 22 ;; esac
  [ "$n" -lt "$per" ] || break
  out+=("{\"state\":\"$st\",\"draft\":$dr,\"head\":{\"ref\":\"$h\"},\"base\":{\"ref\":\"$b\"}}")
  n=$((n + 1))
done
if [ "$*" = "--jq length" ]; then echo "$n"; exit 0; fi
[ "$#" -eq 0 ] || { echo "двойник не знает ключей: $*" >&2; exit 64; }
(IFS=,; echo "[${out[*]}]")
`

type dupWorld struct {
	event, refType, refName, pulls string
	apiFails                       bool
}

func runDup(t *testing.T, script string, w dupWorld) (map[string]string, string, error) {
	t.Helper()
	// ПРЕДПОСЫЛКА: `jq` исполним в окружении шага. Без неё шаг уходит в ветвь
	// «не установлено — собираем», и каждый мир с ответом «false» зеленел бы
	// беспредметно.
	jq := exec.Command("jq", "-n", "1")
	jq.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	if out, err := jq.CombinedOutput(); err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: `jq` не исполняется, а шаг на раннере его зовёт: %v; %s", err, out)
	}
	// Двойник подставлен ФУНКЦИЕЙ оболочки из окружения, а не исполняемым
	// файлом в PATH: свежезаписанный исполняемый файл под параллельными пробами
	// пакета ловит ETXTBSY (дескриптор записи унаследован чужим fork до exec),
	// шаг уходит в ветвь «не установлено — собираем», и мир с ответом «false»
	// зеленел бы беспредметно — замер: хук отправки @7f07ddbd9, мир линии, журнал
	// обращений пуст. Файл двойника здесь только читается оболочкой.
	dir := t.TempDir()
	stub := filepath.Join(dir, "gh-stub.sh")
	require.NoError(t, os.WriteFile(stub, []byte(dupStub), 0o600))
	logPath := filepath.Join(dir, "gh.log")
	require.NoError(t, os.WriteFile(logPath, nil, 0o600))
	env := map[string]string{
		"BASH_FUNC_gh%%": `() { bash "$GH_STUB_SCRIPT" "$@"; }`,
		"GH_STUB_SCRIPT": stub,
		"PATH":           os.Getenv("PATH"),
		"EVENT":          w.event,
		"REF_TYPE":       w.refType,
		"REF_NAME":       w.refName,
		"REPO":           "PRO-Robotech/kaname",
		"GH_TOKEN":       "token",
		"HOME":           os.Getenv("HOME"),
		"GH_STUB_LOG":    logPath,
		"GH_STUB_PULLS":  w.pulls,
	}
	if w.apiFails {
		env["GH_STUB_FAIL"] = "1"
	}
	out, err := execImageStep(dir, script, env)
	calls, rerr := os.ReadFile(logPath) // #nosec G304 -- путь из t.TempDir()
	require.NoError(t, rerr)
	return out, string(calls), err
}

// Мир: линия 296 (база запросов), задача 847 — голова запроса в 296.
const dupPulls = "296>main:open:false 801>296:closed:false"

var (
	taskWithReview = dupWorld{event: "push", refType: "branch", refName: "847",
		pulls: dupPulls + " 847>296:open:false"}
	linePushDup = dupWorld{event: "push", refType: "branch", refName: "296",
		pulls: dupPulls + " 847>296:open:false"}
	taskNoReview  = dupWorld{event: "push", refType: "branch", refName: "847", pulls: dupPulls}
	taskDraft     = dupWorld{event: "push", refType: "branch", refName: "847", pulls: dupPulls + " 847>296:open:true"}
	taskClosed    = dupWorld{event: "push", refType: "branch", refName: "847", pulls: dupPulls + " 847>296:closed:false"}
	taskOffFilter = dupWorld{event: "push", refType: "branch", refName: "847", pulls: dupPulls + " 847>lane-x:open:false"}
)

// TestImagePushOnATaskBranchIsNotRebuiltWhenItsReviewBuildsIt — несущее утверждение.
func TestImagePushOnATaskBranchIsNotRebuiltWhenItsReviewBuildsIt(t *testing.T) {
	t.Parallel()
	step, changes, image := dupProducer(t)

	t.Run("задание `changes` отдаёт решение, `image` его читает", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "${{ steps.duplicate.outputs.duplicate }}", strings.TrimSpace(changes.Outputs["duplicate"]),
			"выход `duplicate` задания `changes` не назван — условие `image` прочитало бы пустое")
		require.Contains(t, image.If, "needs.changes.outputs.duplicate != 'true'",
			"условие задания `image` решения не читает — двойник собирается по-прежнему")
	})

	for _, tc := range []struct {
		what, want string
		w          dupWorld
		// asks — подстроки обращений, которые шаг обязан сделать; nil — не спрашивает никого.
		asks []string
	}{
		{"задача с открытым запросом в линию — сборку несёт запрос", "true", taskWithReview,
			[]string{"pulls?base=847&state=all&", "pulls?head=PRO-Robotech:847&state=open&"}},
		// ЗАКОННЫЙ БЛИЗНЕЦ той же формы имени: линия публикует, её сборку не снять.
		{"линия — база запроса, публикует", "false", linePushDup, []string{"pulls?base=296&state=all&"}},
		{"задача без запроса — сборка по push единственная", "false", taskNoReview, nil},
		{"задача с черновым запросом — карта путей может образ не выбрать", "false", taskDraft, nil},
		{"задача с одним лишь закрытым запросом", "false", taskClosed, nil},
		{"задача с запросом в базу вне фильтра — прогона запроса нет", "false", taskOffFilter, nil},
		{"ствол не спрашивает никого", "false", dupWorld{event: "push", refType: "branch", refName: "main"}, []string{}},
		{"метка версии не спрашивает никого", "false", dupWorld{event: "push", refType: "tag", refName: "v1.2.3"}, []string{}},
		{"запрос не спрашивает никого", "false", dupWorld{event: "pull_request", refType: "branch", refName: "12/merge"}, []string{}},
		{"ручной запуск не спрашивает никого", "false", dupWorld{event: "workflow_dispatch", refType: "branch", refName: "847"}, []string{}},
		{"провайдер отказал — собираем, а не пропускаем", "false", dupWorld{event: "push", refType: "branch",
			refName: "847", pulls: taskWithReview.pulls, apiFails: true}, nil},
	} {
		t.Run(tc.what, func(t *testing.T) {
			t.Parallel()
			out, calls, err := runDup(t, step, tc.w)
			require.NoError(t, err)
			require.Equalf(t, tc.want, out["duplicate"], "шаг `duplicate` дал %v; обращения: %s", out, calls)
			if tc.asks != nil && len(tc.asks) == 0 {
				require.Emptyf(t, calls, "решение не зависит от трекера, а шаг его спросил: %s", calls)
			}
			for _, a := range tc.asks {
				require.Containsf(t, calls, "repos/PRO-Robotech/kaname/"+a, "шаг не спросил %q: %s", a, calls)
			}
		})
	}
}

// TestImagePushDuplicateProbeCanFail — половина «КРАСНЕЕТ»: дефект — в копию тела.
func TestImagePushDuplicateProbeCanFail(t *testing.T) {
	t.Parallel()
	step, _, _ := dupProducer(t)
	for _, tc := range []struct {
		what, old, repl string
		w               dupWorld
	}{
		{"признак линии снят — линия теряет публикуемую сборку",
			`[ "$bases" = 0 ] ||`, `false &&`, linePushDup},
		{"фильтр баз снят — запрос в базу вне фильтра «соберёт»",
			`(.base.ref == "main" or (.base.ref | test("^[0-9]+$")))`, `true`, taskOffFilter},
		{"черновой засчитан", `.draft == false and `, ``, taskDraft},
	} {
		t.Run(tc.what, func(t *testing.T) {
			t.Parallel()
			out, _, err := runDup(t, injectOnce(t, step, tc.old, tc.repl), tc.w)
			require.NoError(t, err)
			require.Equal(t, "true", out["duplicate"], "инъекция не изменила решения — проба слепа к ней")
		})
	}
}
