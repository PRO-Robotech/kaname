// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

// access_keys_test.go — ТРИ ВЕЛИЧИНЫ ПРИВЯЗКИ КЛЮЧЕЙ ДОСТУПА И ЧЕТВЁРТЫЙ
// ПОТОЛОК объявляет посадка (фаза Ф7, задача PRO-Robotech/kacho#1273; приёмка
// `docs/engineering/acceptance/access-keys-are-ours.md`, Р2, Р8; сценарии
// Ф7-13 и Ф7-38).
//
// # Ф7-13 — три исхода у каждой из трёх величин, и отказ называет СВОЮ ручку
//
//	имя доверяющей стороны   незаданное · пустое → отказ старта; непустое → работа
//	перечень происхождений   незаданный → отказ старта; пустой → «никого»;
//	                         непустой → работа
//	перечень алгоритмов      незаданный · пустой → отказ старта; непустой → работа
//
// Один текст на три величины оставил бы оператора гадать, которую он забыл, —
// поэтому проба требует, чтобы отказ каждой величины называл её ключ и её
// переменную и НЕ называл соседних.
//
// # Ф7-38 — три исхода величины потолка
//
//	не объявлена → отказ старта с именем ручки; ноль → «ключей не заводить»;
//	положительная → работа. Форма та же, что у трёх соседних потолков (Р8).

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/multierr"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify"
)

const (
	akKeyRPID   = "authn.access-keys.rp-id"
	akKeyOrig   = "authn.access-keys.origins"
	akKeyAlgs   = "authn.access-keys.algorithms"
	akEnvRPID   = "KANAME_AUTHN__ACCESS_KEYS__RP_ID"
	akEnvOrig   = "KANAME_AUTHN__ACCESS_KEYS__ORIGINS"
	akEnvAlgs   = "KANAME_AUTHN__ACCESS_KEYS__ALGORITHMS"
	akCeilKey   = "own-ceilings.access-keys-per-user"
	akCeilEnv   = "KANAME_OWN_CEILINGS__ACCESS_KEYS_PER_USER"
	akCeilKind  = domain.LimitKind("iam.user.accessKey")
	akSampleRP  = "access.example.invalid"
	akSampleOrg = "https://console.access.example.invalid"
)

// akGood — годная привязка: имя, одно происхождение под ним, весь словарь.
func akGood() config.AccessKeysConfig {
	return config.AccessKeysConfig{
		RPID:       akSampleRP,
		Origins:    []string{akSampleOrg},
		Algorithms: []int64{-7, -8, -257},
	}
}

// refusalsOf — тексты отказов стража по одному на строку.
func refusalsOf(err error) []string {
	var out []string
	for _, e := range multierr.Errors(err) {
		out = append(out, e.Error())
	}
	return out
}

// mentionsOnly — среди отказов ровно один называет ключ `own`, и ни один не
// называет чужих ключей.
func requireNamesItsOwnKnob(t *testing.T, refusals []string, own string, others ...string) {
	t.Helper()
	named := 0
	for _, r := range refusals {
		if strings.Contains(r, own) {
			named++
			for _, o := range others {
				require.NotContains(t, r, o, "отказ величины %s назвал чужую ручку %s: %q", own, o, r)
			}
		}
	}
	require.Equal(t, 1, named, "величину %s обязан называть ровно один отказ, получено %v", own, refusals)
}

// TestAccessKeys_F7_13_GoodBindingPasses — положительный контроль всего файла:
// без него отрицания ниже зеленели бы на страже, отвергающем всё.
func TestAccessKeys_F7_13_GoodBindingPasses(t *testing.T) {
	c := akGood()
	require.NoError(t, c.Validate())
	require.False(t, c.Nobody())
	b := c.Binding()
	require.Equal(t, akSampleRP, b.RPID)
	require.Equal(t, []string{akSampleOrg}, b.Origins)
	require.Equal(t, webauthnverify.KnownAlgorithms(), b.Algorithms)
}

// TestAccessKeys_F7_13_RPIDUnsetOrEmptyRefusesNamingItsKnob — у имени пустого
// значения не бывает: незаданное и пустое дают отказ оба.
func TestAccessKeys_F7_13_RPIDUnsetOrEmptyRefusesNamingItsKnob(t *testing.T) {
	for _, rp := range []string{"", "   "} {
		c := akGood()
		c.RPID = rp
		got := refusalsOf(c.Validate())
		require.NotEmpty(t, got, "имя %q обязано отвергаться", rp)
		requireNamesItsOwnKnob(t, got, akKeyRPID, akKeyOrig, akKeyAlgs)
		require.True(t, strings.Contains(strings.Join(got, "\n"), akEnvRPID), "отказ обязан назвать переменную: %v", got)
	}
}

// TestAccessKeys_F7_13_RPIDMustBeADomainName — имя доверяющей стороны есть
// доменное имя (WebAuthn L2 §5.1.3): литерал адреса, схема, порт, путь и
// заглавные буквы отвергаются с именем ручки; законные формы проходят.
func TestAccessKeys_F7_13_RPIDMustBeADomainName(t *testing.T) {
	for _, bad := range []string{"10.0.0.1", "[::1]", "https://access.example.invalid", "access.example.invalid:443",
		"access.example.invalid/", "Access.Example.Invalid", "-bad.example", "a..b", "под.example"} {
		c := akGood()
		c.RPID = bad
		got := refusalsOf(c.Validate())
		require.NotEmpty(t, got, "имя %q обязано отвергаться", bad)
		require.True(t, strings.Contains(strings.Join(got, "\n"), akKeyRPID), "отказ на %q обязан назвать ручку: %v", bad, got)
	}
	for _, ok := range []string{"localhost", "example", "a.b.c.example.invalid"} {
		c := akGood()
		c.RPID = ok
		c.Origins = []string{"https://" + ok}
		require.NoError(t, c.Validate(), "имя %q законно", ok)
	}
}

// TestAccessKeys_F7_13_OriginsUnsetRefusesNamingItsKnob — незаданный перечень
// происхождений роняет старт; отказ называет ручку и говорит, как выразить
// «никого» (иначе оператор, задавший пустую переменную, получает тот же отказ
// снова, не имея способа отличить свою ошибку от нашей).
func TestAccessKeys_F7_13_OriginsUnsetRefusesNamingItsKnob(t *testing.T) {
	c := akGood()
	c.Origins = nil
	got := refusalsOf(c.Validate())
	require.NotEmpty(t, got)
	requireNamesItsOwnKnob(t, got, akKeyOrig, akKeyRPID, akKeyAlgs)
	joined := strings.Join(got, "\n")
	require.Contains(t, joined, akEnvOrig)
	require.Contains(t, joined, config.AccessKeyOriginsNone, "отказ обязан назвать слово, которым объявляется «никого»")
}

// TestAccessKeys_F7_13_OriginsEmptyMeansNobody — пустой перечень (файлом — `[]`,
// переменной — слово `none`) стартует и означает «никого»: привязка отдаёт
// пустой перечень происхождений, и всякий результат церемонии и всякое
// утверждение будут отвергнуты (Ф7-44, Ф7-10).
func TestAccessKeys_F7_13_OriginsEmptyMeansNobody(t *testing.T) {
	for name, origins := range map[string][]string{
		"пустой список файла": {},
		"слово none":          {config.AccessKeyOriginsNone},
	} {
		t.Run(name, func(t *testing.T) {
			c := akGood()
			c.Origins = origins
			require.NoError(t, c.Validate())
			require.True(t, c.Nobody())
			require.Empty(t, c.Binding().Origins)
		})
	}
	// Слово `none` рядом с настоящим происхождением — противоречие, а не «никого».
	c := akGood()
	c.Origins = []string{config.AccessKeyOriginsNone, akSampleOrg}
	got := refusalsOf(c.Validate())
	require.NotEmpty(t, got)
	require.Contains(t, strings.Join(got, "\n"), akKeyOrig)
}

// TestAccessKeys_F7_13_OriginIsSchemeAndHost — происхождение записывается
// схемой и хостом (WebAuthn: `C.origin` сверяется побайтово); путь, запрос,
// пропущенная схема и незащищённая схема вне localhost отвергаются с именем
// ручки; порт умолчания снимается, хост приводится к строчным.
func TestAccessKeys_F7_13_OriginIsSchemeAndHost(t *testing.T) {
	for _, bad := range []string{
		"console.access.example.invalid",           // без схемы
		"https://console.access.example.invalid/",  // путь
		"https://console.access.example.invalid/x", // путь
		"https://console.access.example.invalid?a", // запрос
		"http://console.access.example.invalid",    // незащищённая схема
		"ftp://console.access.example.invalid",     // чужая схема
		"https://",                                 // без хоста
		"",                                         // пустая строка среди элементов
	} {
		c := akGood()
		c.Origins = []string{bad}
		got := refusalsOf(c.Validate())
		require.NotEmpty(t, got, "происхождение %q обязано отвергаться", bad)
		require.Contains(t, strings.Join(got, "\n"), akKeyOrig, "отказ на %q обязан назвать ручку", bad)
	}
	c := akGood()
	c.Origins = []string{"https://Console.Access.Example.Invalid:443", "https://console.access.example.invalid:8443"}
	require.NoError(t, c.Validate())
	require.Equal(t, []string{"https://console.access.example.invalid", "https://console.access.example.invalid:8443"}, c.Binding().Origins)

	local := config.AccessKeysConfig{RPID: "localhost", Origins: []string{"http://localhost:5173"}, Algorithms: []int64{-7}}
	require.NoError(t, local.Validate(), "localhost — защищённый контекст браузера и по http")
}

// TestAccessKeys_F7_13_OriginHostLiesUnderTheRPID — имя доверяющей стороны
// обязано быть регистрируемым суффиксом хоста каждого происхождения либо
// равняться ему (WebAuthn L2 §5.1.3): иначе ни одна церемония не выполнима,
// то есть объявлена не политика, а поломка — отказ старта, называющий обе ручки.
func TestAccessKeys_F7_13_OriginHostLiesUnderTheRPID(t *testing.T) {
	c := akGood()
	c.Origins = []string{"https://console.other.invalid"}
	got := refusalsOf(c.Validate())
	require.NotEmpty(t, got)
	joined := strings.Join(got, "\n")
	require.Contains(t, joined, akKeyOrig)
	require.Contains(t, joined, akKeyRPID)

	// Суффикс — по границе метки: `notaccess.example.invalid` не под `access.example.invalid`.
	c = akGood()
	c.Origins = []string{"https://notaccess.example.invalid"}
	require.Error(t, c.Validate())

	c = akGood()
	c.Origins = []string{"https://" + akSampleRP, "https://a.b." + akSampleRP}
	require.NoError(t, c.Validate())
}

// TestAccessKeys_F7_13_AlgorithmsUnsetOrEmptyRefuse — у перечня алгоритмов
// «никого» не бывает by construction: незаданный и пустой дают отказ оба;
// идентификатор вне словаря — отказ, называющий словарь.
func TestAccessKeys_F7_13_AlgorithmsUnsetOrEmptyRefuse(t *testing.T) {
	for name, algs := range map[string][]int64{"незаданный": nil, "пустой": {}} {
		t.Run(name, func(t *testing.T) {
			c := akGood()
			c.Algorithms = algs
			got := refusalsOf(c.Validate())
			require.NotEmpty(t, got)
			requireNamesItsOwnKnob(t, got, akKeyAlgs, akKeyRPID, akKeyOrig)
			require.Contains(t, strings.Join(got, "\n"), akEnvAlgs)
		})
	}
	c := akGood()
	c.Algorithms = []int64{-7, -35}
	got := refusalsOf(c.Validate())
	require.NotEmpty(t, got)
	joined := strings.Join(got, "\n")
	require.Contains(t, joined, akKeyAlgs)
	require.Contains(t, joined, "-257", "отказ обязан назвать словарь")
	require.Contains(t, joined, "-35", "отказ обязан назвать чужой идентификатор")
}

// TestAccessKeys_F7_13_EachRefusalNamesItsOwnKnob — все три незаданы: отказов
// три, и каждый называет свою ручку, не называя соседних.
func TestAccessKeys_F7_13_EachRefusalNamesItsOwnKnob(t *testing.T) {
	var c config.AccessKeysConfig
	got := refusalsOf(c.Validate())
	require.Len(t, got, 3, "по отказу на величину: %v", got)
	requireNamesItsOwnKnob(t, got, akKeyRPID, akKeyOrig, akKeyAlgs)
	requireNamesItsOwnKnob(t, got, akKeyOrig, akKeyRPID, akKeyAlgs)
	requireNamesItsOwnKnob(t, got, akKeyAlgs, akKeyRPID, akKeyOrig)
}

// TestAccessKeys_F7_13_EnvReachesTheFields — переменные, названные текстами
// отказов, ДОЕЗЖАЮТ до полей: перечни — через запятую, слово `none` — в поле
// как единственный элемент.
func TestAccessKeys_F7_13_EnvReachesTheFields(t *testing.T) {
	t.Setenv(akEnvRPID, akSampleRP)
	t.Setenv(akEnvOrig, akSampleOrg+",https://a."+akSampleRP)
	t.Setenv(akEnvAlgs, "-7, -257")
	cfg, err := config.Load("")
	require.NoError(t, err)
	require.Equal(t, akSampleRP, cfg.AuthN.AccessKeys.RPID)
	require.Equal(t, []string{akSampleOrg, "https://a." + akSampleRP}, cfg.AuthN.AccessKeys.Origins)
	require.Equal(t, []int64{-7, -257}, cfg.AuthN.AccessKeys.Algorithms, "перечень через запятую, пробелы сняты")
	require.NoError(t, cfg.AuthN.AccessKeys.Validate())

	// Не число среди элементов — отказ загрузки, называющий элемент, а не `[0]`.
	t.Setenv(akEnvAlgs, "-7,ES256")
	_, err = config.Load("")
	require.Error(t, err)
	require.Contains(t, err.Error(), "ES256")
	t.Setenv(akEnvAlgs, "-7,-257")

	t.Setenv(akEnvOrig, config.AccessKeyOriginsNone)
	cfg, err = config.Load("")
	require.NoError(t, err)
	require.True(t, cfg.AuthN.AccessKeys.Nobody())
}

// TestAccessKeys_F7_13_FileKeysArmTheFields — ключи файла доезжают до полей;
// пустой список файла — «никого».
func TestAccessKeys_F7_13_FileKeysArmTheFields(t *testing.T) {
	cfg, err := config.Load(writeConfig(t, `
authn:
  access-keys:
    rp-id: `+akSampleRP+`
    origins: []
    algorithms: [-7, -8]
`))
	require.NoError(t, err)
	require.Equal(t, akSampleRP, cfg.AuthN.AccessKeys.RPID)
	require.NotNil(t, cfg.AuthN.AccessKeys.Origins, "пустой список файла обязан доехать пустым, а не незаданным")
	require.True(t, cfg.AuthN.AccessKeys.Nobody())
	require.Equal(t, []int64{-7, -8}, cfg.AuthN.AccessKeys.Algorithms)

	// Отсутствующий ключ остаётся незаданным — отказ старта, а не «никого».
	cfg, err = config.Load(writeConfig(t, `
authn:
  access-keys:
    rp-id: `+akSampleRP+`
`))
	require.NoError(t, err)
	require.Nil(t, cfg.AuthN.AccessKeys.Origins)
	require.Error(t, cfg.AuthN.AccessKeys.Validate())
}

// TestAccessKeys_F7_13_KnobTableCarriesAllThree — перечень ручек привязки
// объявлен одним объявлением, и это его читают `Load` и стражи.
func TestAccessKeys_F7_13_KnobTableCarriesAllThree(t *testing.T) {
	want := map[string]string{akKeyRPID: akEnvRPID, akKeyOrig: akEnvOrig, akKeyAlgs: akEnvAlgs}
	require.Len(t, config.AccessKeyKnobs, len(want))
	for _, k := range config.AccessKeyKnobs {
		require.Equal(t, want[k.Key], k.Env, "переменная ручки %s", k.Key)
	}
}

// TestAccessKeys_F7_13_LaneRequirementOnOwn — привязка требуется полосой `own`
// стадии «настройка» и не предъявляется под `external`: там ключей нет (сессии
// нет, а регистрация и снятие ключа — действия в окне свежести, Р5).
func TestAccessKeys_F7_13_LaneRequirementOnOwn(t *testing.T) {
	const el = "привязка ключей доступа объявлена: имя доверяющей стороны, перечень происхождений, перечень алгоритмов"
	seen := false
	for _, r := range config.LaneRequirements {
		if r.Element != el {
			continue
		}
		seen = true
		require.Equal(t, config.LaneStageConfig, r.Stage)
		require.True(t, r.AppliesTo(config.IdentityProviderOwn))
		require.False(t, r.AppliesTo(config.IdentityProviderExternal))
	}
	require.True(t, seen, "в таблице требований нет строки %q", el)
}

// TestAccessKeys_F7_13_RequiredSettingsRowsExist — три строки таблицы
// обязательных величин порождены из перечня ручек, полоса `own`.
func TestAccessKeys_F7_13_RequiredSettingsRowsExist(t *testing.T) {
	want := map[string]bool{akKeyRPID: false, akKeyOrig: false, akKeyAlgs: false}
	for _, s := range config.RequiredSettings {
		if _, ok := want[s.Key]; !ok {
			continue
		}
		want[s.Key] = true
		require.Equal(t, []config.IdentityProvider{config.IdentityProviderOwn}, s.Lanes, "строка %s — полоса own", s.Key)
		require.Equal(t, config.SupplyEnv, s.Supply)
		require.NotEmpty(t, s.Env)
		require.Contains(t, s.Refusal, s.Key)
	}
	for k, ok := range want {
		require.True(t, ok, "нет строки %s", k)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Ф7-38 — четвёртый потолок.

// TestAccessKeys_F7_38_CeilingKnobIsTheFourthOfTheSameForm — ручка стоит в
// таблице величин рядом с тремя, тем же видом, что каталог и триггер.
func TestAccessKeys_F7_38_CeilingKnobIsTheFourthOfTheSameForm(t *testing.T) {
	require.Len(t, config.OwnCeilingKnobs, 4)
	var found bool
	for _, k := range config.OwnCeilingKnobs {
		if k.Kind != akCeilKind {
			continue
		}
		found = true
		require.Equal(t, akCeilKey, k.Key)
		require.Equal(t, akCeilEnv, k.Env)
		require.NotEmpty(t, k.Why)
	}
	require.True(t, found, "в таблице величин нет вида %s", akCeilKind)
	require.True(t, domain.IsPostureStatedKind(akCeilKind), "вид обязан быть в закрытом множестве посадки")
}

// TestAccessKeys_F7_38_ThreeOutcomesAreDistinct — незаданная величина — отказ с
// именем ручки; ноль — старт и «ключей не заводить» (Stated несёт 0);
// положительная — старт.
func TestAccessKeys_F7_38_ThreeOutcomesAreDistinct(t *testing.T) {
	full := config.OwnCeilingsConfig{
		AccountsPerIdentity:          ptrInt64(1),
		CredentialsPerUser:           ptrInt64(2),
		CredentialsPerServiceAccount: ptrInt64(2),
	}
	got := refusalsOf(full.Validate())
	require.Len(t, got, 1, "незаданный четвёртый потолок — ровно один отказ: %v", got)
	require.Contains(t, got[0], akCeilKey)
	require.Contains(t, got[0], akCeilEnv)
	require.Contains(t, got[0], string(akCeilKind))

	full.AccessKeysPerUser = ptrInt64(0)
	require.NoError(t, full.Validate())
	v, ok := full.Stated()[akCeilKind]
	require.True(t, ok)
	require.Equal(t, int64(0), v)

	full.AccessKeysPerUser = ptrInt64(-1)
	require.Error(t, full.Validate())

	full.AccessKeysPerUser = ptrInt64(3)
	require.NoError(t, full.Validate())
	require.Equal(t, int64(3), full.Stated()[akCeilKind])
}

// TestAccessKeys_F7_38_EnvReachesTheField — переменная доезжает до поля,
// включая явный ноль.
func TestAccessKeys_F7_38_EnvReachesTheField(t *testing.T) {
	t.Setenv(akCeilEnv, "0")
	cfg, err := config.Load("")
	require.NoError(t, err)
	require.NotNil(t, cfg.OwnCeilings.AccessKeysPerUser)
	require.Equal(t, int64(0), *cfg.OwnCeilings.AccessKeysPerUser)
}

// TestAccessKeys_F7_38_FileKeyReachesTheField — ключ файла доезжает до поля.
// Отдельной пробой, а не второй половиной предыдущей: переменная окружения
// старше файла, и поставленная там она перебила бы ключ файла молча.
func TestAccessKeys_F7_38_FileKeyReachesTheField(t *testing.T) {
	cfg, err := config.Load(writeConfig(t, "own-ceilings:\n  access-keys-per-user: 7\n"))
	require.NoError(t, err)
	require.NotNil(t, cfg.OwnCeilings.AccessKeysPerUser)
	require.Equal(t, int64(7), *cfg.OwnCeilings.AccessKeysPerUser)
}

// TestAccessKeys_F7_38_RequiredSettingsRowExists — строка документа оператора
// порождена из таблицы величин.
func TestAccessKeys_F7_38_RequiredSettingsRowExists(t *testing.T) {
	for _, s := range config.RequiredSettings {
		if s.Key == akCeilKey {
			require.Equal(t, akCeilEnv, s.Env)
			require.Empty(t, s.Lanes, "потолок — величина любой посадки, той же формы, что три соседних")
			return
		}
	}
	t.Fatalf("нет строки %s", akCeilKey)
}
