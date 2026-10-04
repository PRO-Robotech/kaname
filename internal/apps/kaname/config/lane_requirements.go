// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// lane_requirements.go — ТРЕБОВАНИЯ ПОЛОСЫ своего входа и своей чеканки,
// объявленные таблицей (задача #1125, подфаза Ф4д эпика #896; ось посадки снята
// в kaname#363).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ТАБЛИЦА, А НЕ ЦЕПОЧКА `if`
//
// Каждое требование обязано быть покрыто пробой отказа старта, и держаться это
// должно ПОСТРОЕНИЕМ, а не переписью: проба ходит по ЭТОЙ ЖЕ таблице и порождает
// по случаю на строку, поэтому непокрытой строки не бывает by construction.
// Чтобы завести требование, его придётся вписать сюда — то есть туда, где его
// увидит проба.
//
// Второй рукописный перечень строк рядом — находка гейта: два места об одном
// предмете разошлись бы молча, и разошлись бы именно там, где расхождение не
// видно (на строке, которую забыли дописать во второй перечень).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЛОСА ОДНА, И ВЫБИРАТЬ ЕЁ НЕЧЕМ (kaname#363)
//
// Прежде строки называли полосу посадки — `external` либо `own`, — и старт
// предъявлял только строки той, что объявил ключ посадки. Внешнего поставщика
// удостоверений у службы больше нет, ключ снят, и строки предъявляются ВСЯКОМУ
// боевому старту. Снятие оси не должно было выродить стражей в вакуумные:
// раннего возврата «посадка не объявлена — судить нечего» здесь больше нет, и
// обе стадии исполняют все свои строки (lane_axis_withdrawn_test.go).
//
// ─────────────────────────────────────────────────────────────────────────────
// ИНВАРИАНТ, РАДИ КОТОРОГО ВСЁ ОСТАЛЬНОЕ
//
// НИ ОДНА стадия не пуста. Стадия без требований означала бы старт, поднимающийся
// без проверки того, чем служба удостоверяет человека и чем она чеканит, — то
// есть ровно то, что запрещает ban #16. Свойство проверяется по этой таблице
// (lane_gates_test.go), и гейт печатает, сколько строк на какой стадии.
//
// ─────────────────────────────────────────────────────────────────────────────
// ДВЕ СТАДИИ, И ОНИ НЕ ВЗАИМОЗАМЕНЯЕМЫ
//
//   - LaneStageConfig  — читает ЗНАЧЕНИЯ настройки. Исполняется Config.Validate().
//   - LaneStageWiring  — читает ПРОВЯЗАННЫЕ ОБЪЕКТЫ. Настройка их не видит и
//     выразить их отсутствие не может, поэтому эти строки исполняет
//     композиционный корень через ValidateLaneWiring.
//
// Половины не смягчают друг друга: проверка настройки НЕ заменяет проверку
// полноты провязки, и наоборот. Включённость своей чеканки обе читают ОДНИМ
// аксессором (TokenSigningConfig.Enabled) — разойтись во мнении о ней они не
// могут.
//
// ─────────────────────────────────────────────────────────────────────────────
// ВЕЛИЧИНА ПОДАЁТСЯ ПАРАМЕТРОМ, А НЕ ЧИТАЕТСЯ СТРАЖЕМ ИЗ ВСТРОЕННОГО ФАЙЛА
//
// Требование «полоса умеет предъявить каждый уровень доверия, которого требует
// каталог прав» берёт величину ИЗ КАТАЛОГА, а не из константы. Каталог подаётся
// в стража композиционным корнем (LaneWiring.CatalogFloors) ровно так, как его
// подаёт композиционный корень края. Иначе «подмена каталога на набор без
// записей уровня 2» — состояние, которого проба создать не может, и сценарий
// стал бы описываемым, но не вызываемым.
package config

import (
	"fmt"
	"sort"
	"strings"

	"go.uber.org/multierr"

	"github.com/PRO-Robotech/corelib/acrlevel"
)

// LaneStage — на какой стадии старта требование проверяется.
type LaneStage int

const (
	// LaneStageConfig — требование выразимо значениями настройки.
	LaneStageConfig LaneStage = iota
	// LaneStageWiring — требование выразимо только собранными объектами.
	LaneStageWiring
)

// String — имя стадии для текстов переписи и отказов.
func (s LaneStage) String() string {
	switch s {
	case LaneStageConfig:
		return "настройка"
	case LaneStageWiring:
		return "сборка"
	default:
		return fmt.Sprintf("stage(%d)", int(s))
	}
}

// CatalogFloors — сколько записей каталога прав требуют каждого уровня
// доверия.
//
// Readable отделяет «каталог не прочитан» от «каталог не требует ничего».
// Нечитанный и пустой дают ОДНО И ТО ЖЕ число записей, и различает их только
// это поле: неизвестность не есть ноль.
type CatalogFloors struct {
	// Readable — удалось ли прочитать каталог вообще.
	Readable bool
	// ByLevel — требуемый уровень → сколько записей его требуют. Уровни, не
	// известные платформе, сюда попадать могут: ранжирование решает, требование
	// это или нет, и решает ЕДИНСТВЕННОЙ функцией платформы.
	ByLevel map[string]int
}

// LaneWiring — факты о ПРОВЯЗКЕ, которых проверка настройки не видит.
//
// Заполняется композиционным корнем ПОСЛЕ сборки объектов и ДО старта
// листенеров. Каждое поле обязано отражать собранную проводку, а не намерение
// профиля, — иначе страж отчитывался бы о намерении вместо исхода.
type LaneWiring struct {
	// OwnMintSignerWired — подписант своей чеканки и состав утверждений
	// провязаны.
	OwnMintSignerWired bool
	// HumanCredentialsWired — хранилище СВОИХ способов входа человека доступно.
	HumanCredentialsWired bool
	// HumanSessionsWired — хранилище СВОЕЙ сессии человека доступно.
	HumanSessionsWired bool
	// PresentableACRs — уровни доверия, которые полоса УМЕЕТ предъявить
	// человеку. Пустой перечень означает «полоса не предъявляет ни одного»; это
	// законное наблюдаемое состояние, а не «не заполнено».
	PresentableACRs []string
	// CatalogFloors — что требует каталог прав. Подаётся параметром, чтобы
	// сценарий подмены каталога был не описываемым, а вызываемым.
	CatalogFloors CatalogFloors
}

// LaneRequirement — ОДНО требование, без которого боевой старт не проходит.
type LaneRequirement struct {
	// Element — обязательный элемент, человеческим именем. Попадает в перепись
	// гейта и в имя порождённого пробой случая.
	Element string
	// Stage — стадия, на которой требование проверяется.
	Stage LaneStage
	// Check — отказ, называющий элемент. Возвращает nil, когда требование
	// выполнено. Строки стадии «настройка» LaneWiring НЕ читают.
	Check func(Config, LaneWiring) error
}

// LaneRequirements — ТАБЛИЦА требований. Единственное объявление.
//
// Ни один текст отказа не называет снятого ключа посадки: совет объявить ключ,
// которого нет, послал бы оператора за вторым отказом — от загрузчика
// (retired_settings.go).
var LaneRequirements = []LaneRequirement{
	{
		Element: "своя чеканка токенов включена",
		Stage:   LaneStageConfig,
		Check: func(c Config, _ LaneWiring) error {
			if c.AuthN.TokenSigning.Enabled {
				return nil
			}
			return fmt.Errorf(
				"production mode: authn.token-signing.enabled is false — the service has no " +
					"identity provider to fall back to, so with our own minting off the process " +
					"would start and be unable to issue a single token. Enable it")
		},
	},
	// СТРОКА КОНТУРА ВЫДАЧИ КЛЮЧЕЙ СЛУЖЕБНЫХ УЧЁТОК (задача #337). Ключ
	// служебной учётки обменивается на токен токен-эндпоинтом платформы, и
	// другого исполнителя выдачи у службы нет: процесс поднимался бы и отказывал
	// на всякой выдаче ключа. Предикат «переведён» один на всех читателей
	// (Config.SAKeyIssuanceIsOurs): копия условия здесь разошлась бы со сборкой.
	{
		Element: "контур выдачи ключей служебных учёток переведён на свою чеканку",
		Stage:   LaneStageConfig,
		Check: func(c Config, _ LaneWiring) error {
			if c.SAKeyIssuanceIsOurs() {
				return nil
			}
			return fmt.Errorf(
				"production mode: authn.client-token.enabled is false — a service-account key is " +
					"exchanged on the platform token endpoint, and the service has no other executor " +
					"of key issuance: the process would start and refuse every key issuance. " +
					"Enable authn.client-token (env KANAME_AUTHN__CLIENT_TOKEN__ENABLED)")
		},
	},
	// ЗДЕСЬ СТОЯЛА СТРОКА «приём предъявленного удостоверения включён», и она
	// ПЕРЕЕХАЛА, а не исчезла: PresentedCredentialConfig.ValidateBinding. У
	// требования один предмет, и два стража о нём разошлись бы молча.
	//
	// ШЕСТЬ СТРОК ПОЛОСЫ ВХОДА (Ф3, kacho#1269; шестая — Ф5, kacho#1271):
	// величины, без которых полоса входа паролем и восстановления не
	// собирается, объявляет профиль; незаданная — отказ старта с именем ручки
	// (Ф1 §7 инв. 4; Ф3-28, Ф3-33, Ф3-41, Ф3-42, Ф5-06).
	{
		Element: "срок сессии и домен печенья объявлены",
		Stage:   LaneStageConfig,
		Check: func(c Config, _ LaneWiring) error {
			return c.AuthN.Login.ValidateSessionAndCookie()
		},
	},
	{
		Element: "предел частоты неверных предъявлений объявлен по обеим осям",
		Stage:   LaneStageConfig,
		Check: func(c Config, _ LaneWiring) error {
			return c.AuthN.Login.ValidateRateLimits()
		},
	},
	{
		Element: "правило пароля объявлено: длина, состояние и адрес проверки утечек",
		Stage:   LaneStageConfig,
		Check: func(c Config, _ LaneWiring) error {
			return c.AuthN.Login.ValidatePasswordPolicy()
		},
	},
	{
		Element: "ручка «что писать» объявлена и в перечне записываемых",
		Stage:   LaneStageConfig,
		Check: func(c Config, _ LaneWiring) error {
			return c.AuthN.Login.ValidateHasher()
		},
	},
	{
		Element: "ёмкость проверяющего и резерв памяти объявлены",
		Stage:   LaneStageConfig,
		Check: func(c Config, _ LaneWiring) error {
			return c.AuthN.Login.ValidateCapacity()
		},
	},
	// СТРОКА РЕГИСТРАЦИИ (Ф4, kacho#1270; Р5, Ф4-18/19): величина темпа
	// заведения объявляется профилем и незаданная — отказ старта с именем ручки.
	{
		Element: "величина темпа заведения объявлена: предел и окно",
		Stage:   LaneStageConfig,
		Check: func(c Config, _ LaneWiring) error {
			return c.AuthN.Registration.ValidateAdmissionRate()
		},
	},
	{
		Element: "срок кода восстановления доступа объявлен",
		Stage:   LaneStageConfig,
		Check: func(c Config, _ LaneWiring) error {
			return c.AuthN.Login.ValidateRecovery()
		},
	},
	// ПОЧТОВЫЙ УЗЕЛ (kaname#475). Доступ дальше входа получает только человек
	// с подтверждённым адресом (kaname#456), подтвердить адрес и восстановить
	// доступ можно только кодом из письма — без узла установка стартовала бы
	// здоровой, а дальше входа не прошёл бы ни один человек, первый
	// администратор кластера тоже. Согласованность объявленных величин судит
	// InviteMailConfig.Validate; эта строка судит, объявлен ли узел вообще,
	// тем же предикатом, что потребитель (RelayConfigured).
	{
		Element: "почтовый узел объявлен: адрес узла и адрес отправителя",
		Stage:   LaneStageConfig,
		Check: func(c Config, _ LaneWiring) error {
			if c.InviteMail.RelayConfigured() && strings.TrimSpace(c.InviteMail.From) != "" {
				return nil
			}
			return fmt.Errorf(
				"production mode: the mail relay is not declared (invite-mail.relay, env " +
					"KANAME_INVITE_MAIL__RELAY; invite-mail.from, env KANAME_INVITE_MAIL__FROM) — " +
					"access beyond sign-in needs a verified address, and the address verification " +
					"and recovery codes travel only by mail: the process would start and no person, " +
					"the first cluster administrator included, could get past sign-in. Declare both")
		},
	},
	// ПОДТВЕРЖДЕНИЕ АДРЕСА (kaname#456, Р9): пять ручек без умолчания; письмо
	// подтверждения — условие входа дальше экрана подтверждения, и полоса без
	// величин не поднимается.
	{
		Element: "пять величин подтверждения адреса объявлены: срок и предел попыток кода, промежуток, число и окно писем",
		Stage:   LaneStageConfig,
		Check: func(c Config, _ LaneWiring) error {
			return c.AuthN.Login.ValidateVerification()
		},
	},
	// СРОКИ СОБСТВЕННОЙ ЦЕРЕМОНИИ (kaname#318, Р5): срок кода и срок семейства
	// объявляет профиль, не выше потолков фундамента.
	{
		Element: "сроки церемонии объявлены в пределах потолков фундамента: срок кода и срок семейства",
		Stage:   LaneStageConfig,
		Check: func(c Config, _ LaneWiring) error {
			return c.AuthN.Ceremony.Validate()
		},
	},
	// ДВЕ СТРОКИ ВТОРОГО ФАКТОРА (Ф12, kacho#1281; Р2, Р8; Ф12-35, Ф12-36):
	// перечень ключей обёртки секретов и окно свежести правки своих данных
	// объявляет профиль; незаданное — отказ старта с именем ручки.
	{
		Element: "перечень ключей обёртки секретов второго фактора объявлен",
		Stage:   LaneStageConfig,
		Check: func(c Config, _ LaneWiring) error {
			if _, err := c.AuthN.ResolveSecondFactorEncryptionKeys(); err != nil {
				return fmt.Errorf("production mode: %w", err)
			}
			return nil
		},
	},
	{
		Element: "окно свежести правки своих данных объявлено",
		Stage:   LaneStageConfig,
		Check: func(c Config, _ LaneWiring) error {
			return c.AuthN.ValidateSelfServiceFreshness()
		},
	},
	// СТРОКА ПРИВЯЗКИ КЛЮЧЕЙ ДОСТУПА (Ф7, kacho#1273; Р2, Ф7-13): три величины
	// контракта объявляет профиль; незаданная — отказ старта, называющий СВОЮ
	// ручку.
	{
		Element: "привязка ключей доступа объявлена: имя доверяющей стороны, перечень происхождений, перечень алгоритмов",
		Stage:   LaneStageConfig,
		Check: func(c Config, _ LaneWiring) error {
			return c.AuthN.AccessKeys.Validate()
		},
	},
	{
		Element: "подписант своей чеканки провязан",
		Stage:   LaneStageWiring,
		Check: func(c Config, w LaneWiring) error {
			if w.OwnMintSignerWired {
				return nil
			}
			return fmt.Errorf(
				"authn.token-signing.enabled is true, but the signer is not wired in the composition " +
					"root — the setting says we mint and the process has nothing to mint with; this " +
					"refusal is NOT the config-stage one and does not replace it")
		},
	},
	{
		Element: "свои способы входа человека провязаны",
		Stage:   LaneStageWiring,
		Check: func(c Config, w LaneWiring) error {
			if w.HumanCredentialsWired {
				return nil
			}
			return fmt.Errorf(
				"production mode: no store of our own human sign-in methods is wired — the service " +
					"has no identity provider to check a person against, so the stand would come up " +
					"with no way for any human to prove who they are")
		},
	},
	{
		Element: "своя сессия человека провязана",
		Stage:   LaneStageWiring,
		Check: func(c Config, w LaneWiring) error {
			if w.HumanSessionsWired {
				return nil
			}
			return fmt.Errorf(
				"production mode: no store of our own human session is wired — a person could then " +
					"authenticate and carry nothing that says so, and a sign-out would have nothing to end")
		},
	},
	{
		Element: "каждый уровень доверия каталога предъявим",
		Stage:   LaneStageWiring,
		Check: func(c Config, w LaneWiring) error {
			return unreachableFloorsComplaint(w)
		},
	},
	// ЗДЕСЬ СТОЯЛА СТРОКА «дорога к внешнему поставщику не строится» —
	// единственная в таблице, требовавшая ОТСУТСТВИЯ. Снята вместе с дорогой
	// (kaname#363): корень не строит её ни на каком старте, административного
	// клиента поставщика в дереве больше нет, и требовать отсутствия того, что
	// не может быть построено, нечем.
}

// unreachableFloorsComplaint — страж «объявленный пол, который полосе нечем
// предъявить».
//
// Класс не новый: на крае страж такой формы уже работает. Три его свойства
// взяты дословно и здесь.
//
//  1. Счёт идёт ЧЕРЕЗ ОБЩУЮ ФУНКЦИЮ РАНЖИРОВАНИЯ, а не сравнением строк:
//     величина, которой платформа не знает, обязана считаться «требования нет»
//     — ровно так, как её читает точка решения. Иначе страж отказал бы в старте
//     из-за записи, которая ни одного запроса не отвергла бы.
//  2. «Каталог НЕЧИТАЕМ» — отдельный исход, а не ноль: нечитанный и пустой дают
//     одно и то же число.
//  3. Предмет стража — ПРОТИВОРЕЧИЕ, поэтому каталог без полов старт проходит:
//     иначе страж срабатывал бы на отсутствии собственного предмета.
func unreachableFloorsComplaint(w LaneWiring) error {
	if !w.CatalogFloors.Readable {
		return fmt.Errorf(
			"production mode: the permission catalog could not be read, so which assurance levels any " +
				"RPC demands is unknown — an unread catalog is not an empty one (refuse to start)")
	}

	unreachable := 0
	var levels []string
	for level, n := range w.CatalogFloors.ByLevel {
		if acrlevel.Rank(level) <= 0 {
			// Уровень, которого платформа не знает, требованием не является —
			// ровно как в точке решения.
			continue
		}
		if lanePresents(w.PresentableACRs, level) {
			continue
		}
		unreachable += n
		levels = append(levels, level)
	}
	if unreachable == 0 {
		return nil
	}
	sort.Strings(levels)
	return fmt.Errorf(
		"production mode: %d catalog entr(ies) demand assurance level(s) %s that the sign-in lane "+
			"cannot present — the lane offers %s, so those verbs would be unreachable to every human "+
			"while the catalog says they are merely guarded (refuse to start)",
		unreachable, strings.Join(levels, ", "), presentedList(w.PresentableACRs))
}

// lanePresents — умеет ли полоса предъявить названный уровень. Решает
// ЕДИНСТВЕННАЯ функция платформы; своей таблицы рангов полоса не заводит.
func lanePresents(presentable []string, required string) bool {
	for _, p := range presentable {
		if acrlevel.Satisfies(p, required) {
			return true
		}
	}
	return false
}

// presentedList — читаемое перечисление предъявимых уровней для текста отказа.
// Пустой перечень называется словами: «ни одного» отличимо от «не заполнено».
func presentedList(presentable []string) string {
	if len(presentable) == 0 {
		return "none"
	}
	out := append([]string(nil), presentable...)
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// validateLaneRequirements — половина НАСТРОЙКИ: требования, выразимые
// значениями настройки, выполнены.
//
// Прежде ей предшествовала законность посадки (Provider.Validate фундамента),
// и незаконная посадка отвергалась первой и в одиночку. Посадки больше нет —
// ключ снят и отвергается загрузчиком (retired_settings.go), — и строки
// предъявляются всякому боевому старту безусловно.
func (c Config) validateLaneRequirements() error {
	var errs error
	for _, r := range LaneRequirements {
		if r.Stage != LaneStageConfig {
			continue
		}
		errs = multierr.Append(errs, r.Check(c, LaneWiring{}))
	}
	return errs
}

// ValidateLaneWiring — половина ПОЛНОТЫ ПРОВЯЗКИ: объекты, которых настройка не
// видит, собраны.
//
// Зовётся композиционным корнем после сборки и до старта листенеров. Отказ
// здесь — отдельный текст, и он НЕ заменяется проверкой настройки: проба,
// доказавшая одну точку, о второй не утверждает ничего.
//
// В боевом режиме исполняются ВСЕ строки стадии сборки, без раннего возврата:
// прежний возврат «посадка не объявлена — об этом уже отказала настройка»
// после снятия оси остался бы возвратом без предмета, и стадия не исполнялась
// бы вовсе (kaname#363).
//
// В непроизводственном режиме требований нет: in-process фикстура стендом не
// является (та же граница, что у соседних стражей старта).
func ValidateLaneWiring(c Config, w LaneWiring) error {
	if !c.AuthN.Mode.IsProduction() {
		return nil
	}
	var errs error
	for _, r := range LaneRequirements {
		if r.Stage != LaneStageWiring {
			continue
		}
		errs = multierr.Append(errs, r.Check(c, w))
	}
	return errs
}
