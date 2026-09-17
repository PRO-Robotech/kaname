// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

// access_keys.go — НАСТРОЙКА привязки ключей доступа (фаза Ф7, задача
// PRO-Robotech/kacho#1273; приёмка `docs/engineering/acceptance/access-keys-are-ours.md`,
// решение Р2; сценарий Ф7-13).
//
// # Три величины контракта, и все три объявляет профиль
//
// Церемония WebAuthn привязывает ключ к ИМЕНИ ДОВЕРЯЮЩЕЙ СТОРОНЫ (RP ID) и к
// ПРОИСХОЖДЕНИЮ (origin), а открытый ключ принимается только в АЛГОРИТМЕ из
// объявленного перечня. Все три — величины ПОСАДКИ: продукт не знает, на каком
// имени и по какому адресу его установили. Обязанность объявить принадлежит
// контракту, значение — профилю; незаданное роняет старт, называя СВОЮ ручку
// (Ф1 §7 инв. 4). Умолчания нет ни здесь, ни в `defaults.go`: величина, которую
// подставляет построение, предметом стража быть не может.
//
// # Пустое и незаданное различаются, и различие несущее (Ф7-13)
//
//	имя доверяющей стороны   незаданное · пустое → отказ; непустое → работа
//	перечень происхождений   незаданный → отказ; пустой → «НИКОГО»; непустой → работа
//	перечень алгоритмов      незаданный · пустой → отказ; непустой → работа
//
// «Никого» у перечня происхождений — политика: посадка, которой ключи не нужны
// (например, без доменного имени, §1.3 приёмки), объявляет пустой перечень и
// стартует; всякий результат церемонии и всякое утверждение отвергаются (Ф7-44,
// Ф7-10). Переменная окружения пустой быть не может — загрузчик читает пустую
// переменную как незаданную, — поэтому «никого» объявляется СЛОВОМ `none`, как
// у домена печенья (`CookieDomainNone`); в файле настроек — пустым списком.
//
// У перечня алгоритмов «никого» не бывает by construction: перечень, не
// допускающий ни одного алгоритма, делает церемонию невыполнимой, то есть
// объявляет не политику, а поломку.
//
// # Форма величин — норма протокола, а не вкус
//
// Имя доверяющей стороны — доменное имя (WebAuthn L2 §5.1.3): литерал адреса,
// схема, порт и путь отвергаются. Происхождение — `схема://хост[:порт]` без пути
// (сверка `C.origin` побайтовая, §7.1/§7.2), схема защищённая (браузер отдаёт
// ключ только в защищённом контексте; `localhost` — исключение самого браузера).
// Хост каждого происхождения обязан лежать ПОД именем доверяющей стороны или
// равняться ему: иначе ни одна церемония не выполнима — отказ старта, называющий
// обе ручки.

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	"go.uber.org/multierr"

	"github.com/PRO-Robotech/kaname/internal/webauthnverify"
)

// AccessKeysConfig — ручки привязки; все под `authn.access-keys.*`.
type AccessKeysConfig struct {
	// RPID — имя доверяющей стороны: доменное имя, строчными.
	RPID string `mapstructure:"rp-id"`
	// Origins — перечень происхождений `схема://хост[:порт]`. nil — не задан;
	// пустой либо `[none]` — «никого».
	Origins []string `mapstructure:"origins"`
	// Algorithms — перечень идентификаторов COSE (словарь — `webauthnverify.KnownAlgorithms`).
	Algorithms []int64 `mapstructure:"algorithms"`
}

// AccessKeyOriginsNone — слово, которым перечень происхождений объявляется
// пустым («никого») там, где пустое значение не выразимо (переменная окружения).
const AccessKeyOriginsNone = "none"

// accessKeyKnob — пара «ключ настройки ↔ переменная среды» одной ручки.
type accessKeyKnob struct {
	Key string
	Env string
}

const accessKeyKeyPrefix = "authn.access-keys."

// AccessKeyKnobs — перечень ручек привязки одним объявлением. Читается `Load`
// (привязка окружения), документом оператора и стражами (имя в отказе).
var AccessKeyKnobs = []accessKeyKnob{
	{accessKeyKeyPrefix + "rp-id", "KANAME_AUTHN__ACCESS_KEYS__RP_ID"},
	{accessKeyKeyPrefix + "origins", "KANAME_AUTHN__ACCESS_KEYS__ORIGINS"},
	{accessKeyKeyPrefix + "algorithms", "KANAME_AUTHN__ACCESS_KEYS__ALGORITHMS"},
}

func accessKeyEnv(key string) string {
	for _, k := range AccessKeyKnobs {
		if k.Key == key {
			return k.Env
		}
	}
	return ""
}

func accessKeyMissing(key, why string) error {
	return fmt.Errorf("%s не задан (%s): %s", key, accessKeyEnv(key), why)
}

func accessKeyBad(key string, value any, why string) error {
	return fmt.Errorf("%s = %v (%s): %s", key, value, accessKeyEnv(key), why)
}

// reDNSLabel — метка доменного имени: строчные буквы, цифры, дефис не по краям.
var reDNSLabel = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// validRPID — доменное имя строчными: метки через точку, без схемы, порта,
// пути и без литерала адреса.
func validRPID(s string) bool {
	if s == "" || len(s) > 253 || net.ParseIP(s) != nil {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if !reDNSLabel.MatchString(label) {
			return false
		}
	}
	return true
}

// ValidateRPID — имя доверяющей стороны объявлено и есть доменное имя.
func (c AccessKeysConfig) ValidateRPID() error {
	key := accessKeyKeyPrefix + "rp-id"
	rp := strings.TrimSpace(c.RPID)
	if rp == "" {
		return accessKeyMissing(key, "имя доверяющей стороны (RP ID) — доменное имя установки, к которому браузер "+
			"привязывает каждый ключ; пустого значения у него не бывает. Задайте доменное имя строчными, "+
			"без схемы, порта и пути (WebAuthn L2 §5.1.3)")
	}
	if !validRPID(rp) {
		return accessKeyBad(key, rp, "имя доверяющей стороны обязано быть доменным именем строчными — метки через "+
			"точку, без схемы, порта, пути и без литерала адреса (у него доменного имени нет by construction; "+
			"посадка без имени объявляет перечень происхождений пустым — «никого»)")
	}
	return nil
}

// originsAreNone — перечень объявлен «никого»: пустой список либо одно слово.
func (c AccessKeysConfig) originsAreNone() bool {
	if c.Origins == nil {
		return false
	}
	if len(c.Origins) == 0 {
		return true
	}
	return len(c.Origins) == 1 && strings.TrimSpace(c.Origins[0]) == AccessKeyOriginsNone
}

// Nobody — перечень происхождений объявлен пустым: ключи выключены политикой,
// всякий результат церемонии и всякое утверждение отвергаются.
func (c AccessKeysConfig) Nobody() bool { return c.originsAreNone() }

// normalizeOrigin приводит происхождение к форме, в которой его присылает
// браузер: схема и хост строчными, порт умолчания снят. Отказ — текст причины.
func normalizeOrigin(raw string) (string, string) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "пустая строка среди элементов перечня"
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Opaque != "" {
		return "", "ожидается `схема://хост[:порт]`"
	}
	if u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", "происхождение — только схема и хост: без пути, запроса, фрагмента и учётных данных"
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	switch scheme {
	case "https":
		if port == "443" {
			port = ""
		}
	case "http":
		if host != "localhost" {
			return "", "схема http допустима только для localhost — браузер отдаёт ключ лишь в защищённом контексте"
		}
		if port == "80" {
			port = ""
		}
	default:
		return "", "схема обязана быть https (http — только для localhost)"
	}
	if host == "" {
		return "", "хост не назван"
	}
	if port != "" {
		return scheme + "://" + host + ":" + port, ""
	}
	return scheme + "://" + host, ""
}

// hostUnderRPID — хост равен имени доверяющей стороны либо лежит под ним по
// границе метки.
func hostUnderRPID(host, rpID string) bool {
	return host == rpID || strings.HasSuffix(host, "."+rpID)
}

// ValidateOrigins — перечень происхождений объявлен; пустой — «никого»;
// непустой — каждое элемент годной формы под именем доверяющей стороны.
func (c AccessKeysConfig) ValidateOrigins() error {
	key := accessKeyKeyPrefix + "origins"
	if c.Origins == nil {
		return accessKeyMissing(key, "перечень происхождений (origin) консоли, которым браузер привязывает ключ; "+
			"незаданный — отказ, потому что «принимаем любое» здесь не политика, а отсутствие привязки. "+
			"Задайте перечень `https://хост[:порт]` через запятую либо слово «"+AccessKeyOriginsNone+"» — "+
			"«никого»: служба стартует и отвергает всякий ключ (в файле настроек — пустой список)")
	}
	if c.originsAreNone() {
		return nil
	}
	rp := strings.TrimSpace(c.RPID)
	var errs error
	for _, raw := range c.Origins {
		if strings.TrimSpace(raw) == AccessKeyOriginsNone {
			errs = multierr.Append(errs, accessKeyBad(key, raw, "слово «"+AccessKeyOriginsNone+"» означает «никого» и "+
				"стоит в перечне одно; рядом с настоящим происхождением оно противоречие, а не элемент"))
			continue
		}
		norm, why := normalizeOrigin(raw)
		if why != "" {
			errs = multierr.Append(errs, accessKeyBad(key, raw, why))
			continue
		}
		host := strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(norm, "https://"), "http://"))
		if i := strings.LastIndexByte(host, ':'); i >= 0 {
			host = host[:i]
		}
		if validRPID(rp) && !hostUnderRPID(host, rp) {
			errs = multierr.Append(errs, fmt.Errorf("%s = %v (%s): хост происхождения не лежит под именем доверяющей стороны "+
				"%s = %q (%s) — ни одна церемония на таком происхождении не выполнима (WebAuthn L2 §5.1.3): "+
				"объявлена не политика, а поломка",
				key, raw, accessKeyEnv(key), accessKeyKeyPrefix+"rp-id", rp, accessKeyEnv(accessKeyKeyPrefix+"rp-id")))
		}
	}
	return errs
}

// ValidateAlgorithms — перечень алгоритмов объявлен непустым и целиком в словаре.
func (c AccessKeysConfig) ValidateAlgorithms() error {
	key := accessKeyKeyPrefix + "algorithms"
	if len(c.Algorithms) == 0 {
		return accessKeyMissing(key, "перечень алгоритмов открытого ключа (COSE), в которых принимаются ключи; "+
			"пустого «никого» у него не бывает: перечень без единого алгоритма делает церемонию невыполнимой. "+
			"Словарь: "+knownAlgorithmsText())
	}
	if _, err := webauthnverify.ParseAlgorithms(c.Algorithms); err != nil {
		return accessKeyBad(key, c.Algorithms, err.Error()+"; словарь: "+knownAlgorithmsText())
	}
	return nil
}

func knownAlgorithmsText() string {
	parts := make([]string, 0, 3)
	for _, a := range webauthnverify.KnownAlgorithms() {
		parts = append(parts, fmt.Sprintf("%d (%s)", int64(a), a.Name()))
	}
	return strings.Join(parts, ", ")
}

// Validate — все три стража разом; отказ по каждой величине сразу, и каждый
// называет свою ручку (Ф7-13).
func (c AccessKeysConfig) Validate() error {
	return multierr.Combine(c.ValidateRPID(), c.ValidateOrigins(), c.ValidateAlgorithms())
}

// Binding — привязка в форме проверяющего: имя, нормализованные происхождения
// (пустые при «никого»), разобранный перечень алгоритмов. Страж выше не
// допускает негодных величин; здесь негодное отбрасывается, а не подставляется.
func (c AccessKeysConfig) Binding() webauthnverify.Binding {
	b := webauthnverify.Binding{RPID: strings.TrimSpace(c.RPID)}
	if !c.originsAreNone() {
		for _, raw := range c.Origins {
			if norm, why := normalizeOrigin(raw); why == "" {
				b.Origins = append(b.Origins, norm)
			}
		}
	}
	if algs, err := webauthnverify.ParseAlgorithms(c.Algorithms); err == nil {
		b.Algorithms = algs
	}
	return b
}
