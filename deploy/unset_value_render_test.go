// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// unset_value_render_test.go — НЕЗАДАННОЕ ДОЕЗЖАЕТ ДО СТРАЖА НЕЗАДАННЫМ, и это
// утверждается НАСТОЯЩИМ рендером чарта, а не переложением.
//
// ─────────────────────────────────────────────────────────────────────────────
// ДВА ВОПРОСА, И ОБА ЗАДАЁТ ЧАРТ, А НЕ ПРОЦЕСС
//
//  1. ПОДСТАНОВКА. Накладка оператора, промолчавшая о сроке ключа подписи,
//     обязана давать отказ старта С ИМЕНЕМ КЛЮЧА — тем текстом, что объявлен в
//     таблице стража. Так было не всегда (#321): умолчание процесса сняли, а
//     базовые значения чарта продолжали выбирать срок, и отказа не наступало ни
//     при какой накладке. Проба-переложение этого не видела: ручку она снимает
//     из СЛИТОГО дерева, то есть вместе с базовым значением, — а `helm` сливает
//     базовые значения с накладкой, и молчание накладки базовое значение не
//     снимает.
//
//  2. ПУТЬ ОТКАЗА. Пустая строка — не срок. Отданная шаблоном «как есть», она
//     отвергается РАЗБОРОМ настроек (`time: invalid duration`), и до стража пуск
//     не доезжает: отказ называет ключ, но не причину, и закрывает собой все
//     прочие отказы стража, которые тот сложил бы в один ответ. Законный путь —
//     тот, которым чарт уже отдаёт каждый срок полосы входа и окно свежести:
//     ВЕТВЬ, а не сквозная подстановка. Незаданный срок в файл настроек не
//     попадает вовсе, и страж отказывает сам, называя ключ.
//
// Второй вопрос — о КЛАССЕ, а не об экземпляре: проба рендерит базовые значения
// с поднятым выключателем КАЖДОГО блока, о котором знает переложение, и требует,
// чтобы разбор настроек не отверг ничего. Выключатели выводятся из переложения,
// а не выписываются: новый блок за выключателем попадает в пробу сам.
//
// ─────────────────────────────────────────────────────────────────────────────
// ГДЕ ИСПОЛНЯЕТСЯ
//
// Обе рендер-пробы требуют helm и называются с приставки `TestProdProfile_Rendered`,
// поэтому их берёт полоса `deploy/render-guard.sh`; без helm и без объявленной
// полосы — пропуск третьей категорией, не зелёное. Предпосылку второго вопроса
// («разбор отвергает пустой срок, и отвергает его ДО стража») проба ниже
// доказывает без helm — на синтетическом теле настроек.
package deploy_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// keyLifetimeSetting — ключ стража, о котором первый вопрос.
const keyLifetimeSetting = "authn.token-signing.key-lifetime"

// overlayWithout пишет боевую накладку во временный файл, сняв в ней ОДИН лист
// (пустой путь — не снимая ничего). Близнец и отрицание проходят ОДНИМ путём
// записи: иначе разница вердиктов могла бы прийти от пересборки YAML, а не от
// снятого листа.
func overlayWithout(t *testing.T, path []string) string {
	t.Helper()
	overlay := readChartProfile(t, "values.prod.yaml")
	if len(path) > 0 {
		require.NotNilf(t, at(overlay, path...),
			"фикстура беспредметна: боевая накладка не объявляет %s — снимать нечего",
			strings.Join(path, "."))
		removeAt(overlay, path)
	}
	raw, err := yaml.Marshal(overlay)
	require.NoError(t, err)
	file := filepath.Join(t.TempDir(), "values.overlay.yaml")
	require.NoError(t, os.WriteFile(file, raw, 0o600))
	return file
}

// TestProdProfile_RenderedWithoutAKeyLifetimeRefusesStartNamingIt — накладка,
// промолчавшая о сроке ключа подписи, даёт отказ старта с текстом таблицы.
//
// Положительный близнец — та же накладка, записанная тем же путём, с ключом: она
// обязана не давать этого отказа. Отличие ровно одно — снятый лист.
func TestProdProfile_RenderedWithoutAKeyLifetimeRefusesStartNamingIt(t *testing.T) {
	row := requiredSettingByKey(t, keyLifetimeSetting)
	valuePath := bridgedByKey(t, keyLifetimeSetting).valuePath
	require.NotEmpty(t, valuePath, "переложение не называет пути значения срока ключа — снимать нечего")

	t.Run("близнец: накладка называет срок", func(t *testing.T) {
		in := readRenderedInput(t, renderStandaloneChart(t, []string{chartDefaultsFile, overlayWithout(t, nil)}))
		verdict := renderedVerdict(t, in)
		require.NoError(t, verdict,
			"боевая накладка, пересобранная тем же путём, что и отрицание, не прошла стража — "+
				"отрицание ниже ничего не доказало бы: падать было бы не на снятом листе")
	})

	t.Run("накладка о сроке молчит", func(t *testing.T) {
		in := readRenderedInput(t, renderStandaloneChart(t, []string{chartDefaultsFile, overlayWithout(t, valuePath)}))
		verdict := renderedVerdict(t, in)
		require.Error(t, verdict,
			"накладка без %s отрендерена и ПРИНЯТА стражем — срок ключа подписи выбран за "+
				"оператора самим чартом, и отказа не бывает ни при какой накладке (#321). "+
				"Тело настроек рендера:\n%s", strings.Join(valuePath, "."), in.ConfigBody)
		require.Containsf(t, verdict.Error(), row.Refusal,
			"отказ наступил, но не тем текстом, что объявлен в таблице стража (%q): до стража "+
				"незаданное не доехало — его отверг кто-то раньше, и оператор не узнает причины", row.Refusal)
	})
}

// blockSwitchSets — `--set` для выключателя КАЖДОГО блока, о котором знает
// переложение. Выводится, а не выписывается.
func blockSwitchSets(t *testing.T) []string {
	t.Helper()
	seen := map[string]bool{}
	var out []string
	for _, b := range configBridge {
		if len(b.gate) == 0 {
			continue
		}
		joined := strings.Join(b.gate, ".")
		if seen[joined] {
			continue
		}
		seen[joined] = true
		out = append(out, joined+"=true")
	}
	sort.Strings(out)
	require.NotEmpty(t, out, "переложение не знает ни одного выключателя блока — "+
		"проба судила бы базовые значения без единого блока, и молчание ничего не значило бы")
	return out
}

// renderedDecodeRefusal — отказ РАЗБОРА настроек на входе рендера: ровно тот,
// что наступает раньше стража.
func renderedDecodeRefusal(t *testing.T, body string, envs map[string]string) error {
	t.Helper()
	requireCleanEnv(t)
	for k, v := range envs {
		t.Setenv(k, v)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	_, err := config.Load(path)
	return err
}

// TestProdProfile_RenderedBaseValuesReachTheBootGuardUndecoded — базовые
// значения с поднятым выключателем каждого блока разбираются: ни одна
// незаданная величина не отвергнута разбором раньше стража.
func TestProdProfile_RenderedBaseValuesReachTheBootGuardUndecoded(t *testing.T) {
	switches := blockSwitchSets(t)
	sets := append(append([]string{}, minimalOperatorCoordinates...), switches...)
	in := readRenderedInput(t, renderStandaloneChart(t, []string{chartDefaultsFile}, sets...))

	err := renderedDecodeRefusal(t, in.ConfigBody, in.Envs)
	require.NoErrorf(t, err,
		"базовые значения с поднятыми выключателями %v не разбираются: незаданная величина "+
			"отвергнута РАЗБОРОМ, а не стражем — отказ называет ключ, но не причину, и закрывает "+
			"собой прочие отказы стража. Отдайте ключ ветвью (`with`), как соседние сроки: "+
			"незаданный он не попадёт в файл настроек, и страж откажет сам.\nТело настроек:\n%s",
		switches, in.ConfigBody)

	t.Logf("перепись: выключателей поднято %d (%s) · ключей-листьев в рендере %d · переменных окружения %d",
		len(switches), strings.Join(switches, ", "), len(configLeafKeys(t, in.ConfigBody)), len(in.Envs))
}

// TestEmptyDurationIsRefusedByTheDecoderBeforeTheGuard — ПРЕДПОСЫЛКА второго
// вопроса, без helm: пустая строка у срока отвергается разбором, и отказ этот —
// не отказ стража; тот же ключ, НЕ отданный вовсе, доезжает до стража, и страж
// отказывает текстом таблицы.
//
// Без неё рендер-проба выше молчала бы по другой причине: разбор, научившийся
// принимать пустую строку за ноль, сделал бы её зелёной на любом шаблоне.
func TestEmptyDurationIsRefusedByTheDecoderBeforeTheGuard(t *testing.T) {
	row := requiredSettingByKey(t, keyLifetimeSetting)
	const head = "authn:\n  token-signing:\n    enabled: true\n" +
		"    issuer: \"https://iam.example.invalid\"\n" +
		"    algorithm: \"ES256\"\n" +
		"    allowed-algorithms: \"ES256\"\n" +
		"    key-set-path: \"/.well-known/kaname/jwks.json\"\n"

	t.Run("пустая строка отвергается разбором", func(t *testing.T) {
		err := renderedDecodeRefusal(t, head+"    key-lifetime: \"\"\n", nil)
		require.Error(t, err, "разбор принял пустую строку за срок — рендер-проба судила бы пустоту")
		require.Contains(t, err.Error(), keyLifetimeSetting, "отказ разбора обязан назвать ключ")
		require.NotContains(t, err.Error(), row.Refusal,
			"отказ пустой строки пришёл текстом СТРАЖА — значит, разбор её пропускает, и "+
				"различать два пути отказа больше не на чем")
	})

	t.Run("близнец: ключ не отдан вовсе — отказывает страж", func(t *testing.T) {
		requireCleanEnv(t)
		path := filepath.Join(t.TempDir(), "config.yaml")
		require.NoError(t, os.WriteFile(path, []byte(head), 0o600))
		cfg, err := config.Load(path)
		require.NoError(t, err, "тело без ключа обязано разбираться")
		verdict := cfg.AuthN.TokenSigning.Validate()
		require.Error(t, verdict, "незаданный срок доехал до стража и принят")
		require.Contains(t, verdict.Error(), row.Refusal)
	})
}
