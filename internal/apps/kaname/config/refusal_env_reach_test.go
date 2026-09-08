// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// refusal_env_reach_test.go — ГЕЙТ КЛАССА: переменная окружения, НАЗВАННАЯ
// текстом отказа стража старта, обязана доезжать до поля.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Текст отказа и разбор настройки — ДВА МЕСТА ОБ ОДНОМ ПРЕДМЕТЕ, и расходятся
// они МОЛЧА. Отказ пишется как проза и не компилируется; привязка ключа к
// окружению живёт в `load.go` и не знает, что о ней написано. Расхождение видит
// только тот, кто в этот день ставит службу впервые, — и видит он его в самой
// дорогой форме: отказ ВЫГЛЯДИТ исчерпывающим, называет координату, оператор
// делает ровно названное и получает ТОТ ЖЕ отказ. Отличить свою ошибку от нашей
// он не может и упирается в цикл.
//
// Цена измерена, а не предположена. Замер на этом дереве (4 профиля посадки,
// разбор `Config.Validate`): отказов прочитано 22, переменных названо 7, из них
// НЕ ДОЕЗЖАЛО ДО ПОЛЯ 2 — `KANAME_AUTHN__TRUSTED_FORWARDER_SANS` (круг
// законных отправителей переданной личности) и
// `KANAME_AUTHN__TRUST_ANY_FORWARDER` (объявленный тем же отказом опт-ин
// стенда). Вторую из них задание не называло: она найдена этим разбором.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ОПЫТ, А НЕ ЧТЕНИЕ ИСХОДНИКА
//
// «Есть ли у ключа привязка» — вопрос о ТЕКСТЕ `load.go`, и ответ на него не
// равен вопросу оператора. Ключ бывает известен виперу тремя разными способами
// (умолчание, явная привязка, легаси-псевдоним), а часть величин читается вовсе
// не випером — прямым обращением к окружению в момент проверки. Разбор, который
// умеет только про привязку, объявил бы находкой каждую из вторых.
//
// Поэтому предикат ОДИН и он про ИСХОД: задать переменную и посмотреть,
// изменилось ли то, что видит оператор, — загруженная конфигурация либо набор
// отказов. Не изменилось ничего ни на одном годном значении — переменная
// инертна, сколько бы раз её ни задали.
//
// ─────────────────────────────────────────────────────────────────────────────
// ОБЛАСТЬ НАЗВАНА ЧЕСТНО
//
// Судятся ОТКАЗЫ СТРАЖА НАСТРОЙКИ (`Config.Validate`). Отказы двух других
// стадий — посадки (`pkg/servicecontract`) и сборки (`ValidateLaneWiring`) — сюда
// не приходят, и гейт о них не утверждает НИЧЕГО. Обратное («здесь весь старт»)
// было бы ложью, которую оператор обнаружит на стенде.
//
// И ещё уже: судятся только переменные ЭТОЙ службы — имя с префиксом
// `KANAME_`. Отказ докерной полосы называет заодно `KACHO_REGISTRY_SERVICE_AUD`
// — переменную СОСЕДА, и это правильно: величина у обеих сторон одна, и оператор
// обязан видеть оба имени. Судить её здесь нечем by construction — она не
// доезжает и не должна доезжать до полей iam, а её досягаемость есть свойство
// чужого процесса. Граница названа, чтобы её не приняли за пропуск.
//
// И ещё уже: судится ровно то, что НАЗВАНО ОТКАЗОМ. Имя переменной, встреченное
// в комментарии, в шапке функции или в строке самоотчёта, предметом этого гейта
// НЕ является — оно к оператору в момент отказа не обращено. Половина эта не
// декоративна: по дереву iam имён вида `KANAME_*` — 106, и 63 из них не
// меняют исход `Load`+`Validate`, потому что читаются другими механизмами
// (посадка mTLS, композиционный корень). Разбор, судящий исходный ТЕКСТ, выдал
// бы шесть десятков находок, из которых верны единицы, — и его отключили бы
// первым.
package config_test

import (
	"fmt"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// refusalEnvPattern — имя переменной этой службы в тексте отказа.
var refusalEnvPattern = regexp.MustCompile(`KANAME_[A-Z0-9_]*[A-Z0-9]`)

// refusalProfile — ОДИН профиль посадки, на котором спрашивают стража.
type refusalProfile struct {
	Name string
	Env  map[string]string
}

// refusalWorld — всё, что разбор знает о мире. Инъекция подменяет ЕГО, а не
// разбор: гейт обязан быть способен упасть, а падение подставного мира не
// должно ронять саму пробу способности падать.
type refusalWorld struct {
	// Refusals — тексты отказов стража на профиле.
	Refusals func(refusalProfile) []string
	// Reaches — ОПЫТ: задать переменную на этом профиле и сказать, изменился ли
	// исход. Вторым значением — чем именно установлено, для текста находки.
	Reaches func(prof refusalProfile, env string) (bool, string)
}

// refusalEnvCensus — объём осмотренного. Печатается ВСЕГДА: без него «находок 0»
// неотличимо от «не прочитано ничего».
type refusalEnvCensus struct {
	Profiles  int
	Refusals  int
	Named     int
	Reached   int
	NamedList []string
}

func (c refusalEnvCensus) String() string {
	return fmt.Sprintf(
		"профилей посадки %d · отказов прочитано %d · переменных названо %d · доезжает %d · инертных %d",
		c.Profiles, c.Refusals, c.Named, c.Reached, c.Named-c.Reached)
}

// auditRefusalNamedEnv — разбор. Возвращает находки и объём осмотренного.
//
// Обращения к `*testing.T` здесь нет намеренно: разбор, роняющий пробу изнутри,
// инъекции не поддаётся — падение подставного мира уронило бы саму пробу
// способности падать.
func auditRefusalNamedEnv(profiles []refusalProfile, world refusalWorld) ([]string, refusalEnvCensus) {
	var findings []string
	census := refusalEnvCensus{Profiles: len(profiles)}

	// Где переменная названа ВПЕРВЫЕ: на этом профиле её и пробуют. Профиль
	// значим — на стенде разработчика половина отказов не производится вовсе,
	// и проба на чужом профиле сказала бы «инертна» о живой величине.
	firstNamedOn := map[string]refusalProfile{}
	for _, prof := range profiles {
		texts := world.Refusals(prof)
		census.Refusals += len(texts)
		for _, text := range texts {
			for _, env := range refusalEnvPattern.FindAllString(text, -1) {
				if _, seen := firstNamedOn[env]; !seen {
					firstNamedOn[env] = prof
				}
			}
		}
	}

	for env := range firstNamedOn {
		census.NamedList = append(census.NamedList, env)
	}
	sort.Strings(census.NamedList)
	census.Named = len(census.NamedList)

	// ПУСТОЙ ОБХОД — находка, а не тишина. «Ноль находок» обязано быть отличимо
	// от «ноль прочитанного»: разбор, которому не дали ни одного профиля, ни
	// одного отказа или ни одного названного имени, о дереве не утверждает
	// ничего и зелёным быть не вправе.
	if census.Profiles == 0 {
		findings = append(findings, "обход пуст: стража не спросили НИ НА ОДНОМ профиле посадки")
	}
	if census.Profiles > 0 && census.Refusals == 0 {
		findings = append(findings,
			"обход пуст: страж не отказал ни на одном профиле — предмета у разбора нет")
	}
	if census.Refusals > 0 && census.Named == 0 {
		findings = append(findings,
			"обход пуст: ни один отказ не назвал переменной окружения — разбору нечего сверять")
	}

	for _, env := range census.NamedList {
		prof := firstNamedOn[env]
		reaches, how := world.Reaches(prof, env)
		if reaches {
			census.Reached++
			continue
		}
		findings = append(findings, fmt.Sprintf(
			"%s названа текстом отказа стража (профиль %q) и ДО ПОЛЯ НЕ ДОЕЗЖАЕТ: %s. "+
				"Оператор делает ровно то, что говорит отказ, и получает тот же отказ. "+
				"Объявите ключу привязку в load.go (v.BindEnv) либо умолчание в defaults.go — "+
				"либо не называйте эту переменную в отказе",
			env, prof.Name, how))
	}

	return findings, census
}

// ─────────────────────────────────────────────────────────────────────────────
// ЖИВОЙ МИР: профили и опыт.

// refusalProfilesUnderTest — профили, на которых спрашивают стража.
//
// Четыре, а не один: половина отказов производится только в боевом режиме, а
// часть — только на объявленной полосе посадки личности. Профиль, оставшийся вне
// обхода, унёс бы с собой все переменные, которые называют только его отказы.
func refusalProfilesUnderTest() []refusalProfile {
	return []refusalProfile{
		{Name: "боевой, ничего не объявлено", Env: map[string]string{}},
		{Name: "боевой, полоса external", Env: map[string]string{
			"KANAME_AUTHN__IDENTITY_PROVIDER": "external",
		}},
		{Name: "боевой, полоса own", Env: map[string]string{
			"KANAME_AUTHN__IDENTITY_PROVIDER": "own",
		}},
		{Name: "стенд разработчика", Env: map[string]string{
			"KANAME_AUTHN__MODE": "dev",
		}},
	}
}

// refusalProbeValues — значения, которыми пробуют досягаемость.
//
// Их несколько, потому что поле бывает разной формы: булев опт-ин не меняется
// от строки, а строка — от «true». Досягаемость доказывает ЛЮБОЕ из них: вопрос
// разбора не «годно ли значение», а «увидел ли его процесс вообще».
var refusalProbeValues = []string{"true", "spiffe://kacho.example/probe", "7m", "7"}

func applyRefusalProfile(prof refusalProfile) {
	clearOwnEnv()
	for k, v := range prof.Env {
		_ = os.Setenv(k, v)
	}
}

// liveRefusalWorld — мир, собранный из живого стража.
func liveRefusalWorld() refusalWorld {
	return refusalWorld{
		Refusals: func(prof refusalProfile) []string {
			applyRefusalProfile(prof)
			cfg, err := config.Load("")
			if err != nil {
				return []string{"загрузка отвергнута: " + err.Error()}
			}
			out := refusals(cfg)
			sort.Strings(out)
			return out
		},
		Reaches: func(prof refusalProfile, env string) (bool, string) {
			applyRefusalProfile(prof)
			base, err := config.Load("")
			if err != nil {
				// Профиль сам по себе не грузится — о переменной это не
				// утверждает ничего, и объявлять её инертной нельзя.
				return true, "профиль не загружается, досягаемость не спрашивалась"
			}
			baseRefusals := sortedCopy(refusals(base))

			for _, value := range refusalProbeValues {
				applyRefusalProfile(prof)
				_ = os.Setenv(env, value)
				got, err := config.Load("")
				if err != nil {
					return true, fmt.Sprintf("значение %q отвергнуто разбором настройки — то есть прочитано", value)
				}
				if !reflect.DeepEqual(base, got) {
					return true, fmt.Sprintf("значение %q изменило загруженную настройку", value)
				}
				if !reflect.DeepEqual(baseRefusals, sortedCopy(refusals(got))) {
					return true, fmt.Sprintf("значение %q изменило набор отказов стража", value)
				}
			}
			return false, fmt.Sprintf(
				"ни одно из %d пробных значений не изменило ни загруженную настройку, ни набор отказов",
				len(refusalProbeValues))
		},
	}
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// ГЕЙТ.

func TestRefusalNamedEnvVarReachesItsField(t *testing.T) {
	saved := snapshotEnv()
	defer restoreEnv(saved)

	findings, census := auditRefusalNamedEnv(refusalProfilesUnderTest(), liveRefusalWorld())

	t.Logf("объём осмотренного: %s", census)
	t.Logf("названы отказами: %s", strings.Join(census.NamedList, ", "))

	if len(findings) > 0 {
		t.Fatalf("находок %d:\n  • %s", len(findings), strings.Join(findings, "\n  • "))
	}
}

// ЗАКОННЫЙ БЛИЗНЕЦ, половина первая: имя, названное ПРОЗОЙ, а не отказом, —
// предметом гейта не является, и он о нём молчит.
//
// `KANAME_RECONCILE_DRAIN_INTERVAL_MS` встречается в дереве iam константой
// композиционного корня, читается им напрямую из окружения и потому исход
// `Load`+`Validate` не меняет. Разбор, судящий исходный текст, объявил бы её
// находкой; этот молчит — она не названа НИ ОДНИМ отказом стража настройки.
// Прав ли соседний текст, называя её, — предмет другого разбора; здесь
// утверждается только область.
//
// Прежде близнецом стояла `KANAME_METRICS_ADDR` — имя из текста самоотчёта о
// посадке. Оно перестало существовать в дереве вместе со своим предметом (#2042:
// самоотчёт называл четыре переменные, которых нет, и приведён к работающим
// ручкам), а близнец, взятый у снятого предмета, истекает вместе с ним и уносит
// доказательство области.
func TestRefusalEnvGate_SaysNothingAboutNamesMentionedOnlyInProse(t *testing.T) {
	saved := snapshotEnv()
	defer restoreEnv(saved)

	const proseOnly = "KANAME_RECONCILE_DRAIN_INTERVAL_MS"

	_, census := auditRefusalNamedEnv(refusalProfilesUnderTest(), liveRefusalWorld())
	for _, named := range census.NamedList {
		if named == proseOnly {
			t.Fatalf("%s объявлена названной отказом — значит близнец выбран неверно "+
				"и проба области больше ничего не утверждает", proseOnly)
		}
	}

	// Положительный контроль: имя, которое отказ действительно называет, в
	// перечне ЕСТЬ. Без него отрицание выше зеленело бы на пустом перечне.
	if !contains(census.NamedList, "KANAME_HOOK_TOKEN") {
		t.Fatalf("перечень названных отказами не содержит KANAME_HOOK_TOKEN — "+
			"обход не состоялся, и отрицание выше беспредметно: %s", census)
	}
}

func contains(list []string, needle string) bool {
	for _, s := range list {
		if s == needle {
			return true
		}
	}
	return false
}
