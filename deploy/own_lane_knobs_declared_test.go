// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// own_lane_knobs_declared_test.go — РУЧКА, КОТОРУЮ СТРАЖ ТРЕБУЕТ ПОД `own`,
// ОБЪЯВЛЕНА ЧАРТОМ; РУЧКА, КОТОРУЮ ЧАРТ РЕНДЕРИТ ПОЛОСЕ, ЧИТАЕТСЯ ПРОЦЕССОМ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ (задача #205, найдено имитацией клиента по ban #18)
//
// Страж старта под посадкой `own` требует величины без умолчания: полоса входа
// паролем (Ф3), темп заведения аккаунтов (Ф4), срок кода восстановления (Ф5),
// ключи обёртки второго фактора и окно свежести (Ф12). Документ установки
// говорит о каждой «перенос прежней величины объявляется профилем». Профиль —
// это значения ЧАРТА, и объявить он может только то, что шаблон рендерит.
//
// Замер, из которого проба выведена: три величины страж требовал, а шаблон карты
// настроек знал только блок `authn.login.{session-ttl … memory-reserve-bytes}`
// — ни `recovery-code-ttl`, ни блока `registration`. Оператор проходил отказ
// старта по трём именам подряд и угадывал карту переменных
// `KANAME_AUTHN__REGISTRATION__*` — цикл выкатки на ручку, при том что документ
// обещал профиль.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОПУЛЯЦИЯ БЕРЁТСЯ У СТРАЖА, А НЕ ВЫПИСЫВАЕТСЯ ЗДЕСЬ
//
// Перечень величин посадки `own` объявлен ОДИН раз — строками таблицы
// `config.RequiredSettings`, чьи полосы называют `own`. Таблица доказана
// прогоном (required_settings_test.go): каждая строка роняет старт незаданной.
// Выписанный здесь второй перечень разошёлся бы с ней молча: следующая фаза
// добавит строку коммитом в свой файл, проба не изменится, и расхождение увидит
// тот, кто в этот день переводит установку на `own`. Ровно так и было: проба
// зонтичного подчарта платформы (kacho#2699) перечень выписывала.
//
// ─────────────────────────────────────────────────────────────────────────────
// ДВА ПУТИ ПОДАЧИ, И ОБА — ОБЪЯВЛЕНИЕ ЧАРТА
//
// Величина доезжает до процесса либо ключом файла настроек, который рендерит
// `configmap.yaml`, либо переменной из объекта Secret через карту `secrets`
// поставляемого профиля (ключи обёртки). Третьего пути — «оператор допишет
// переменную сам в карту `env`» — проба не признаёт намеренно: карта `env`
// принимает что угодно, поэтому «объявлено» через неё ничего не значит, а сама
// величина остаётся ненайденной по имени в поставке.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПАРИТЕТ В ОБЕ СТОРОНЫ
//
//	страж → чарт   каждая строка таблицы с полосой `own` объявлена: рендерится
//	               ключом либо подаётся секретом;
//	чарт  → процесс каждый ключ, который шаблон рендерит в блоках полосы
//	               (`authn.login.*`, `authn.registration.*`, `authn.access-keys.*`),
//	               процесс читает ручкой перечня (`config.LoginLaneKnobs`,
//	               `config.RegistrationKnobs`, `config.AccessKeyKnobs`).
//	               Ключ вне перечня — ручка без читателя: оператор её правит,
//	               рендер зелёный, поведение прежнее.
//
// Обратная сторона судится по ПЕРЕЧНЮ РУЧЕК, а не по таблице стража: страж
// требует не всё, что процесс читает (`breach-check-url` обязателен только при
// включённой проверке утечек и в таблице не стоит), а рендерить чарт обязан
// ровно читаемое.
//
// Проба ДЕКЛАРАТИВНА: читает текст шаблона и профили, а не рендер. Она судит,
// ОБЪЯВЛЕНА ли величина, и не судит её значение — значение проверяет проба
// боевого профиля стражем.
package deploy_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// ownLaneBlockPrefixes — ключи блоков полосы: рендерятся только под `own`,
// и каждый обязан иметь читателя в перечне ручек процесса.
var ownLaneBlockPrefixes = []string{"authn.login.", "authn.registration.", "authn.access-keys."}

// ownLaneRequiredSettings — строки таблицы стража, применимые к посадке `own`
// ПОЛОСОЙ, а не любой посадке: у безусловных строк своя проба.
func ownLaneRequiredSettings() []config.RequiredSetting {
	var out []config.RequiredSetting
	for _, s := range config.RequiredSettings {
		for _, l := range s.Lanes {
			if l == config.IdentityProviderOwn {
				out = append(out, s)
				break
			}
		}
	}
	return out
}

// laneKnobKeys — ключи, которые процесс читает ручками полосы: перечни, по
// которым `Load` привязывает окружение и стражи называют ручку в отказе.
func laneKnobKeys() map[string]bool {
	keys := map[string]bool{}
	for _, k := range config.LoginLaneKnobs {
		keys[k.Key] = true
	}
	for _, k := range config.RegistrationKnobs {
		keys[k.Key] = true
	}
	for _, k := range config.AccessKeyKnobs {
		keys[k.Key] = true
	}
	return keys
}

// renderedConfigKey — ключ файла настроек, который рендерит шаблон карты.
type renderedConfigKey struct {
	line int
	leaf bool // строка несёт величину; иначе это узел, открывающий вложенные ключи
}

// collectRenderedConfigKeys — ВСЕ ключи блока `config.yaml` шаблона карты
// настроек, по дорожке (`authn.login.session-ttl`), с номером строки.
//
// В отличие от переписи подстановок (boot_guard_defaults_test.go) здесь
// считается и ключ с литералом (`enabled: true`): предмет — ОБЪЯВЛЕН ли ключ, а
// не откуда он берёт величину. Псевдоним контекста (`with $authn.login` → `.`)
// дорожку не меняет: дорожка собирается по ОТСТУПУ, как её видит процесс.
func collectRenderedConfigKeys(chartDir string) (keys map[string]renderedConfigKey, linesRead int, err error) {
	raw, err := os.ReadFile(filepath.Join(chartDir, templatesDir, configMapTemplate))
	if err != nil {
		return nil, 0, fmt.Errorf("шаблон карты настроек не читается: %w", err)
	}
	lines := strings.Split(string(raw), "\n")
	linesRead = len(lines)
	keys = map[string]renderedConfigKey{}

	type frame struct {
		indent int
		key    string
	}
	var stack []frame
	inBlock, baseIndent := false, 0
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !inBlock {
			if strings.Contains(trimmed, settingsBlockAnchor) {
				inBlock = true
				baseIndent = len(line) - len(strings.TrimLeft(line, " "))
			}
			continue
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "{{") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent <= baseIndent {
			break
		}
		key := yamlKeyOf(trimmed)
		if key == "" || strings.HasPrefix(trimmed, "-") {
			continue
		}
		for len(stack) > 0 && stack[len(stack)-1].indent >= indent {
			stack = stack[:len(stack)-1]
		}
		path := key
		for j := len(stack) - 1; j >= 0; j-- {
			path = stack[j].key + "." + path
		}
		value := strings.TrimSpace(trimmed[strings.Index(trimmed, ":")+1:])
		leaf := value != ""
		if !leaf {
			stack = append(stack, frame{indent, key})
		}
		if _, seen := keys[path]; !seen {
			keys[path] = renderedConfigKey{line: i + 1, leaf: leaf}
		}
	}
	return keys, linesRead, nil
}

// collectDeclaredSecretEnvs — имена переменных, которые поставляемая цепочка
// профилей объявляет приезжающими из объекта Secret (карта `secrets`), с именем
// профиля, где объявление стоит.
func collectDeclaredSecretEnvs(chartDir string, profiles []string) (map[string]string, error) {
	out := map[string]string{}
	for _, name := range profiles {
		raw, err := os.ReadFile(filepath.Join(chartDir, name))
		if err != nil {
			return nil, fmt.Errorf("профиль %s не читается: %w", name, err)
		}
		var tree map[string]any
		if err := yaml.Unmarshal(raw, &tree); err != nil {
			return nil, fmt.Errorf("профиль %s не разбирается: %w", name, err)
		}
		secrets, _ := tree["secrets"].(map[string]any)
		for env := range secrets {
			out[env] = name
		}
	}
	return out, nil
}

// auditOwnLaneKnobsDeclared — находки и перепись.
func auditOwnLaneKnobsDeclared(chartDir string) (findings []string, census string, err error) {
	required := ownLaneRequiredSettings()
	if len(required) == 0 {
		return nil, "", fmt.Errorf("обход пуст: таблица стража не дала ни одной строки посадки own — вердикт беспредметен")
	}
	rendered, linesRead, err := collectRenderedConfigKeys(chartDir)
	if err != nil {
		return nil, "", err
	}
	if len(rendered) == 0 {
		return nil, "", fmt.Errorf("обход пуст: шаблон карты настроек не дал ни одного ключа файла настроек — вердикт беспредметен")
	}
	secrets, err := collectDeclaredSecretEnvs(chartDir, chartProfiles)
	if err != nil {
		return nil, "", err
	}

	// страж → чарт
	var viaFile, viaSecret int
	for _, s := range required {
		if _, ok := rendered[s.Key]; ok {
			viaFile++
			continue
		}
		if profile, ok := secrets[s.Env]; ok {
			viaSecret++
			_ = profile
			continue
		}
		findings = append(findings, fmt.Sprintf(
			"  %s: ключ %s (%s) — страж старта под посадкой own требует его, а чарт не объявляет:\n"+
				"    шаблон карты настроек ключ не рендерит, и ни один поставляемый профиль не подаёт переменную\n"+
				"    секретом. Профиль на own проходит отказ старта по этому имени и не может его снять ни одним\n"+
				"    ключом значений. Рендерите ключ ветвью (`with`/`hasKey`, без умолчания) либо объявите\n"+
				"    переменную картой `secrets` поставляемого профиля.",
			configMapTemplate, s.Key, s.Env))
	}

	// чарт → процесс
	knobs := laneKnobKeys()
	var laneRendered, unread int
	for path, k := range rendered {
		if !k.leaf {
			continue
		}
		inLane := false
		for _, p := range ownLaneBlockPrefixes {
			if strings.HasPrefix(path, p) {
				inLane = true
				break
			}
		}
		if !inLane {
			continue
		}
		laneRendered++
		if knobs[path] {
			continue
		}
		unread++
		findings = append(findings, fmt.Sprintf(
			"  %s:%d: ключ %s рендерится в блоке полосы, а процесс не читает его ни одной ручкой перечня\n"+
				"    (config.LoginLaneKnobs, config.RegistrationKnobs, config.AccessKeyKnobs). Это ручка без читателя: оператор её\n"+
				"    правит, рендер зелёный, поведение прежнее. Снимите ключ с шаблона либо заведите ручку в перечне.",
			configMapTemplate, k.line, path))
	}

	sort.Strings(findings)
	census = fmt.Sprintf(
		"перепись: строк шаблона прочитано %d · ключей файла настроек %d · строк стража на посадке own %d "+
			"(рендерятся ключом %d · подаются секретом %d · не объявлены %d) · ключей блоков полосы %d "+
			"(без читателя %d) · профилей с картой секретов прочитано %d · находок %d",
		linesRead, len(rendered), len(required), viaFile, viaSecret, len(required)-viaFile-viaSecret,
		laneRendered, unread, len(chartProfiles), len(findings))
	return findings, census, nil
}

// TestChartDeclaresEveryKnobTheOwnLaneGuardRequires — паритет «страж под own
// требует ⇔ чарт объявляет» и «чарт рендерит полосе ⇒ процесс читает».
func TestChartDeclaresEveryKnobTheOwnLaneGuardRequires(t *testing.T) {
	chartDir := filepath.Join(serviceRoot(t), "deploy")

	findings, census, err := auditOwnLaneKnobsDeclared(chartDir)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(findings) > 0 {
		t.Fatalf("чарт расходится со стражем посадки own:\n%s\n\n%s", strings.Join(findings, "\n"), census)
	}
	t.Log(census)
}
