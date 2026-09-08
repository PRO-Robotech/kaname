// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// prod_profile_render_test.go — АВТОРИТЕТНЫЙ вердикт о боевом профиле: вход
// собирается НАСТОЯЩИМ рендером чарта, а не переложением (задача #2334).
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗАЧЕМ ВТОРОЙ ПРОИЗВОДИТЕЛЬ ВХОДА, ЕСЛИ ОДИН УЖЕ ЕСТЬ
//
// Прежняя проба боевого профиля собирала вход ПЕРЕЛОЖЕНИЕМ `configBridge` —
// повторением шаблона на Go. Предпосылка переложения проверялась в ОДНУ
// сторону: каждый ключ переложения обязан встречаться в шаблоне. Обратного
// требования не было, поэтому ключ, который шаблон рендерит, а переложение не
// несёт, оказывался ВНЕ НАБЛЮДЕНИЯ — не находкой и не зелёным, а молчанием.
//
// Замер, из которого проба выведена: ключей-листьев в отрендеренной
// конфигурации 18, записей переложения 16. Невидимы были ровно два —
// `api-server.rest-endpoint` и `api-server.internal-rest-endpoint`, — и первый
// из них нёс отказ стража старта. То есть гейт, заведённый ради вопроса
// «поднимется ли боевой профиль», отвечал о входе, которого процесс не увидит.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ ЕСТЬ, И ЧЕГО ЗДЕСЬ НЕТ
//
//	Р1  вход РЕНДЕРА проходит стража старта — несущая проба;
//	Р2  отрицательный контроль: без боевого профиля страж ОБЯЗАН отказать;
//	Р3  переложение покрывает КАЖДЫЙ ключ, который рендерит чарт, — перепись
//	    в обе стороны, с именем недостающего;
//	Р4  файл, названный ручкой, лежит под каталогом, который под МОНТИРУЕТ —
//	    судится по рендеру, а не по значениям.
//
// Пода проба НЕ поднимает и об установке в кластере не утверждает ничего: это
// «не выполнилось», третья категория, а не зелёное. Она доказывает ровно одно —
// что вход, который чарт отдаёт процессу, страж старта принимает.
//
// ─────────────────────────────────────────────────────────────────────────────
// ГДЕ ЭТИ ПРОБЫ ИСПОЛНЯЮТСЯ, И ПОЧЕМУ УСЛОВИЕ ОТКАЗА НЕ «CI»
//
// helm пришпилен ровно к ОДНОЙ job конвейера (`helm` в ci.yaml); job, гоняющая
// юниты модуля службы, его не несёт. Условие «в CI отсутствие helm — отказ»
// покрасило бы её по причине, к дереву отношения не имеющей, а условие «везде
// пропуск» сделало бы гейт инертным именно там, где он гейтит мёрж.
//
// Поэтому вердикт производит ОБЪЯВИВШАЯ СЕБЯ полоса — deploy/render-guard.sh,
// который зовётся из job `helm` через `make -C services/iam helm-render-guard` и
// ставит HELM_RENDER_GUARD_LANE=1:
//
//	helm есть                       → пробы идут ВСЕГДА (в том числе локально);
//	helm нет, полоса объявлена      → ОТКАЗ: обещала вердикт и дать не может;
//	helm нет, полоса не объявлена   → пропуск, и он назван третьей категорией —
//	                                  не зелёным.
//
// Провязку из конвейера держит гейт класса
// internal/repohygiene/artifactgates/renderguard_test.go: страж рендера, не
// вызываемый ниоткуда, — ровно тот дефект, против которого он написан.
package deploy_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/multierr"
	"gopkg.in/yaml.v3"
)

// renderedInput — ровно тот вход, который чарт отдаёт процессу.
type renderedInput struct {
	// ConfigBody — тело `config.yaml` карты настроек, дословно.
	ConfigBody string
	// Envs — переменные окружения контейнера; величины, приезжающие из
	// объекта Secret, заменены годными по форме заменителями.
	Envs map[string]string
	// FromSecret — имена переменных, которые профиль объявил приезжающими из
	// секрета. Нужны, чтобы заменитель жил, пока у него есть предмет.
	FromSecret []string
	// Mounts — пути монтирования томов контейнера. Ими судится досягаемость
	// файлов, названных ручками.
	Mounts []string
	// Docs — сколько документов прочитано в рендере. Объём осмотренного.
	Docs int
}

// renderGuardLaneEnv — переменная, которой полоса рендера ОБЪЯВЛЯЕТ СЕБЯ.
//
// Объявление, а не догадка по окружению: «мы в CI» не отвечает на вопрос
// «обязан ли здесь быть helm», и на нём гейт краснел бы в чужой job.
//
// ИМЯ БЕЗ ПРИСТАВКИ ПРОДУКТА, и обе приставки отвергнуты по своей причине.
//
// Приставка ПЛАТФОРМЫ в файлах отдельно поставляемой службы есть тот самый
// остаток, который снимает линия дебрендинга (держатель — internal/repohygiene,
// ведомость полосы «переменная окружения»); на первой редакции она и покраснела.
// Приставка КОНФИГУРАЦИИ службы целиком зарезервирована requireCleanEnv: любая
// переменная этой формы в окружении прогона делает вердикт свойством машины, а
// не профиля, — то есть переменная объявления полосы роняла бы каждую пробу
// посадки.
//
// Ни та, ни другая приставка здесь НЕ ВОСПРОИЗВОДЯТСЯ дословно намеренно:
// ведомость читает текст и прозу о приставке от приставки не отличает — гейт
// покраснел бы на собственном объяснении.
const renderGuardLaneEnv = "HELM_RENDER_GUARD_LANE"

// renderedSecretStandIns — заменители ВСЕХ переменных, которые рендер объявляет
// приезжающими из объекта Secret.
//
// Шире, чем `secretStandIns`, и это не второе место об одном предмете: та карта
// покрывает секцию `secrets:` профиля, а рендер видит СВЕРХ неё пароль базы —
// он объявляется отдельной парой ключей (`db.passwordSecretName` /
// `db.passwordSecretKey`), а имя переменной ему даёт шаблон развёртывания, а не
// профиль. Общие записи БЕРУТСЯ из `secretStandIns`, а не переписываются.
//
// Следствие, названное вслух: производитель, видящий не все объявления, не
// вправе судить, пережил ли заменитель свой предмет. Осиротевший заменитель
// ищет ТОЛЬКО эта проба — у неё полная картина.
var renderedSecretStandIns = func() map[string]string {
	out := map[string]string{
		// Пароль к базе. Форма произвольна: страж старта его не разбирает, а
		// читается он лениво, уже соединением.
		"KANAME_DB_PASSWORD": "stand-in-not-a-secret",
	}
	for k, v := range secretStandIns {
		out[k] = v
	}
	return out
}()

// minimalOperatorCoordinates — координаты, которые чарт требует НАЗВАТЬ и
// умолчаний которым не даёт намеренно: без них рендер отказывает целиком.
//
// Нужны отрицательному контролю: он ставит службу БЕЗ боевого профиля, а без
// этих четырёх шаблон не рендерится вовсе — и «не выполнилось» подменило бы
// вердикт стража, которого контроль как раз и добивается.
var minimalOperatorCoordinates = []string{
	"image=registry.example.invalid/pro-robotech/kaname:0.1.0",
	"db.host=postgres.example.invalid",
	"db.passwordSecretName=kaname-db",
	"db.passwordSecretKey=password",
}

// renderStandaloneChart зовёт `helm template` на ЭТОМ чарте с названной
// цепочкой профилей.
func renderStandaloneChart(t *testing.T, valueFiles []string, sets ...string) string {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		if os.Getenv(renderGuardLaneEnv) != "" {
			t.Fatalf("helm не в PATH, а полоса рендера объявлена (%s задан) — она обещала "+
				"вердикт и дать его не может: инертный гейт на джобе, гейтящей мёрж, гейтом "+
				"не является", renderGuardLaneEnv)
		}
		t.Skipf("helm не в PATH — вердикта НЕТ ни у одной пробы этого файла: третья категория, "+
			"не зелёное и не красное. Вердикт производит полоса deploy/render-guard.sh "+
			"(%s=1), которую конвейер зовёт из job `helm`", renderGuardLaneEnv)
	}
	args := []string{"template", "kaname", ".", "--namespace", "kaname"}
	for _, f := range valueFiles {
		args = append(args, "-f", f)
	}
	for _, kv := range sets {
		args = append(args, "--set", kv)
	}
	out, err := exec.Command("helm", args...).CombinedOutput() // #nosec G204 -- фиксированный бинарь, аргументы из дерева
	require.NoErrorf(t, err,
		"чарт не отрендерился цепочкой %v: это НЕ вердикт стража, а «не выполнилось» — "+
			"третья категория, и в успех она не засчитывается\n%s", valueFiles, out)
	return string(out)
}

// readRenderedInput разбирает рендер и достаёт из него ровно то, что увидит
// процесс: тело настроек, окружение контейнера и пути монтирования.
//
// Проба ПРЕДПОСЫЛКИ здесь же: рендер без карты настроек либо без развёртывания
// — отказ, а не пустой вход. Пустой вход дал бы стражу нечего отвергать, и
// «ноль находок» стало бы неотличимо от «ноль прочитанного».
func readRenderedInput(t *testing.T, rendered string) renderedInput {
	t.Helper()
	in := renderedInput{Envs: map[string]string{}}

	dec := yaml.NewDecoder(strings.NewReader(rendered))
	for {
		var doc map[string]any
		if err := dec.Decode(&doc); err != nil {
			break
		}
		if doc == nil {
			continue
		}
		in.Docs++
		kind, _ := doc["kind"].(string)
		switch kind {
		case "ConfigMap":
			data, _ := doc["data"].(map[string]any)
			if body, ok := data["config.yaml"].(string); ok {
				in.ConfigBody = body
			}
		case "Deployment":
			readContainerInput(&in, doc)
		}
	}

	require.NotEmpty(t, in.Docs, "рендер не дал ни одного документа — вердикт был бы о пустоте")
	require.NotEmpty(t, in.ConfigBody,
		"в рендере нет `config.yaml` карты настроек — процессу нечего читать, и страж, "+
			"которому не подали ничего, отвергал бы пустоту, а не профиль")
	require.NotEmpty(t, in.Envs,
		"в рендере нет ни одной переменной окружения контейнера — половина входа процесса потеряна")
	return in
}

// readContainerInput забирает окружение и монтирования ПЕРВОГО контейнера
// развёртывания.
func readContainerInput(in *renderedInput, doc map[string]any) {
	spec, _ := doc["spec"].(map[string]any)
	tpl, _ := spec["template"].(map[string]any)
	pod, _ := tpl["spec"].(map[string]any)
	containers, _ := pod["containers"].([]any)
	for _, raw := range containers {
		c, _ := raw.(map[string]any)
		entries, _ := c["env"].([]any)
		for _, e := range entries {
			entry, _ := e.(map[string]any)
			name, _ := entry["name"].(string)
			if name == "" {
				continue
			}
			if v, ok := entry["value"].(string); ok {
				in.Envs[name] = v
				continue
			}
			in.FromSecret = append(in.FromSecret, name)
		}
		mounts, _ := c["volumeMounts"].([]any)
		for _, m := range mounts {
			mount, _ := m.(map[string]any)
			if p, _ := mount["mountPath"].(string); p != "" {
				in.Mounts = append(in.Mounts, p)
			}
		}
		break
	}
	sort.Strings(in.FromSecret)
	sort.Strings(in.Mounts)
}

// substituteRenderedSecrets кладёт заменители тех переменных, что рендер
// объявил приезжающими из объекта Secret, и судит САМО объявление.
//
// Заменитель живёт, пока у него есть предмет: запись, которой больше нечего
// заменять, — находка, а не безобидный остаток.
func substituteRenderedSecrets(in renderedInput) error {
	var errs error
	seen := map[string]bool{}
	for _, name := range in.FromSecret {
		standIn, ok := renderedSecretStandIns[name]
		if !ok {
			errs = multierr.Append(errs, fmt.Errorf(
				"рендер объявляет переменную %s приезжающей из секрета, а у пробы нет для неё "+
					"заменителя — вердикт о полноте профиля вынести не с чем", name))
			continue
		}
		if _, clash := in.Envs[name]; clash {
			errs = multierr.Append(errs, fmt.Errorf(
				"переменная %s объявлена и значением, и ссылкой на секрет — величина выразима "+
					"двумя способами, и какой действует, решает шаблон, а не оператор", name))
			continue
		}
		in.Envs[name] = standIn
		seen[name] = true
	}
	for name := range renderedSecretStandIns {
		if !seen[name] {
			errs = multierr.Append(errs, fmt.Errorf(
				"у пробы есть заменитель для %s, но рендер такой переменной из секрета не "+
					"объявляет — запись пережила свой предмет", name))
		}
	}
	return errs
}

// renderedFilesAreMountable — каждый путь, названный ручкой окружения, лежит
// под каталогом, который контейнер МОНТИРУЕТ.
//
// Судится по рендеру, а не по значениям чарта: монтирования объявляет
// развёртывание, и значения о них знают лишь постольку, поскольку шаблон их
// читает. Ручка, называющая путь, которого под не несёт, — объявленная и
// неисполнимая возможность: процесс отказывает в пуске на нечитаемом файле, а
// профиль читается как настроенный.
func renderedFilesAreMountable(in renderedInput) error {
	if len(in.Mounts) == 0 {
		return fmt.Errorf("контейнер не монтирует ни одного тома — судить досягаемость файлов не по чему")
	}
	var errs error
	for _, name := range sortedKeys(in.Envs) {
		value := in.Envs[name]
		if !strings.HasPrefix(value, "/") {
			continue
		}
		for _, path := range strings.Split(value, ",") {
			path = strings.TrimSpace(path)
			if path == "" {
				continue
			}
			under := false
			for _, mount := range in.Mounts {
				if path == mount || strings.HasPrefix(path, strings.TrimSuffix(mount, "/")+"/") {
					under = true
					break
				}
			}
			if !under {
				errs = multierr.Append(errs, fmt.Errorf(
					"%s называет файл %s, а контейнер монтирует только %s — процесс откажет в "+
						"пуске на нечитаемом файле, при том что профиль читается как настроенный",
					name, path, strings.Join(in.Mounts, ", ")))
			}
		}
	}
	return errs
}

// renderedVerdict — сводный вердикт стражей о входе, собранном рендером.
func renderedVerdict(t *testing.T, in renderedInput) error {
	t.Helper()
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(in.ConfigBody), 0o600))

	errs := multierr.Append(substituteRenderedSecrets(in), renderedFilesAreMountable(in))
	return multierr.Append(errs, bootGuardVerdict(t, cfgPath, in.Envs))
}

// ── Р1: несущая проба ────────────────────────────────────────────────────────

func TestProdProfile_RenderedByHelmSatisfiesTheBootGuard(t *testing.T) {
	in := readRenderedInput(t, renderStandaloneChart(t, chartProfiles))

	verdict := renderedVerdict(t, in)
	require.NoError(t, verdict,
		"боевой профиль ОТРЕНДЕРЕН и не удовлетворяет стражу старта: под с этим входом не "+
			"поднимется — процесс откажет в пуске ещё до первого слушателя. Профиль поставляется "+
			"как боевой и не даёт поднятой службы ни у одного, кто поставит по нему (ban #16: "+
			"values.prod ОБЯЗАН реально boots, не только render-иться)")

	t.Logf("перепись: профилей в цепочке %d · документов рендера %d · байт конфигурации %d · "+
		"переменных окружения %d (из них из секрета %d) · монтирований %d",
		len(chartProfiles), in.Docs, len(in.ConfigBody), len(in.Envs), len(in.FromSecret), len(in.Mounts))
}

// ── Р2: отрицательный контроль ───────────────────────────────────────────────

// TestProdProfile_RenderedGuardIsLiveWithoutTheProfile — без боевого профиля
// страж ОБЯЗАН отказать.
//
// Без этой половины зелёное выше не значит ничего: страж, разучившийся падать,
// на любом входе выглядит довольным.
func TestProdProfile_RenderedGuardIsLiveWithoutTheProfile(t *testing.T) {
	in := readRenderedInput(t, renderStandaloneChart(t, []string{"values.yaml"}, minimalOperatorCoordinates...))

	verdict := renderedVerdict(t, in)
	require.Error(t, verdict,
		"одни базовые значения чарта прошли стража боевой посадки — значит зелёное боевого "+
			"профиля не доказывает ничего: падать стражу не на чем")
	t.Logf("отрицательный контроль: без боевого профиля страж отказал — %d упрёк(ов)",
		len(multierr.Errors(verdict)))
}

// ── Р3: переложение не уже чарта ─────────────────────────────────────────────

// TestConfigBridge_CoversEveryKeyTheChartRenders — перепись В ОБЕ СТОРОНЫ.
//
// `TestConfigBridge_MirrorsTheChartTemplate` требует, чтобы каждый ключ
// переложения встречался в шаблоне. Обратного требования не было, и ключ,
// который шаблон рендерит, а переложение не несёт, уходил из-под наблюдения
// молча — вместе со всяким отказом стража, который он несёт.
//
// Класс, а не экземпляр: всякий ключ, который добавят в шаблон и не добавят в
// переложение, ушёл бы так же. Поэтому сверяется не перечень имён, а ЧИСЛА и
// разность множеств.
func TestConfigBridge_CoversEveryKeyTheChartRenders(t *testing.T) {
	in := readRenderedInput(t, renderStandaloneChart(t, chartProfiles))

	rendered := configLeafKeys(t, in.ConfigBody)
	missing, extra, census := bridgeCoverageOf(configBridge, rendered)

	require.Emptyf(t, missing,
		"чарт рендерит ключи, которых переложение не несёт: %s\n"+
			"    вход, собранный переложением, УЖЕ того, что увидит процесс, — и уже ровно там, "+
			"где расхождение не видно: проба боевого профиля осталась бы зелёной при стражe, "+
			"отвергающем настоящий рендер (задача #2334)", strings.Join(missing, ", "))
	require.Emptyf(t, extra,
		"переложение несёт ключи, которых в рендере боевого профиля нет: %s\n"+
			"    вход ШИРЕ действительного: проба стережёт величину, которой процесс не получит",
		strings.Join(extra, ", "))

	t.Logf("перепись: %s", census)
}

// bridgeCoverage — объём осмотренного переписью покрытия.
type bridgeCoverage struct {
	RenderKeys int
	BridgeKeys int
	Common     int
}

func (c bridgeCoverage) String() string {
	return fmt.Sprintf("ключей-листьев в рендере %d · записей переложения %d · общих %d",
		c.RenderKeys, c.BridgeKeys, c.Common)
}

// bridgeCoverageOf сверяет НАЗВАННОЕ переложение с ключами рендера.
//
// Переложение приходит параметром, чтобы способность переписи упасть
// доказывалась инъекцией, а не прочтением.
func bridgeCoverageOf(bridge []bridged, rendered []string) (missing, extra []string, census bridgeCoverage) {
	inBridge := map[string]bool{}
	for _, b := range bridge {
		inBridge[b.configKey] = true
	}
	inRender := map[string]bool{}
	for _, k := range rendered {
		inRender[k] = true
	}
	census = bridgeCoverage{RenderKeys: len(inRender), BridgeKeys: len(inBridge)}
	for _, k := range rendered {
		if inBridge[k] {
			census.Common++
			continue
		}
		missing = append(missing, k)
	}
	for k := range inBridge {
		if !inRender[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return missing, extra, census
}

// configLeafKeys — точечные пути ЛИСТЬЕВ отрендеренной конфигурации.
//
// ЕДИНИЦА СЧЁТА — ключ-лист: скаляр либо список. Список считается ОДНИМ листом,
// а не по элементу: переложение кладёт его одной записью, и счёт по элементам
// сделал бы перепись функцией содержимого профиля, а не его формы.
func configLeafKeys(t *testing.T, body string) []string {
	t.Helper()
	var tree map[string]any
	require.NoError(t, yaml.Unmarshal([]byte(body), &tree),
		"тело настроек из рендера не разбирается как YAML")
	require.NotEmpty(t, tree, "отрендеренная конфигурация пуста — сверять переложение не с чем")

	var out []string
	var walk func(node map[string]any, prefix []string)
	walk = func(node map[string]any, prefix []string) {
		for key, val := range node {
			path := append(append([]string{}, prefix...), key)
			if child, ok := val.(map[string]any); ok && len(child) > 0 {
				walk(child, path)
				continue
			}
			out = append(out, strings.Join(path, "."))
		}
	}
	walk(tree, nil)
	sort.Strings(out)
	return out
}
