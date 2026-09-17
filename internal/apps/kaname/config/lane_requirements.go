// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// lane_requirements.go — ТРЕБОВАНИЯ ПОЛОС посадки личности, объявленные
// таблицей (задача #1125, подфаза Ф4д эпика #896).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ТАБЛИЦА, А НЕ ЦЕПОЧКА `if`
//
// Полосность — это ПРОИЗВЕДЕНИЕ: значение поля × обязательный элемент. Такое
// произведение обязано быть покрыто пробой отказа старта ЦЕЛИКОМ, и держаться
// это должно ПОСТРОЕНИЕМ, а не переписью: проба ходит по ЭТОЙ ЖЕ таблице и
// порождает по случаю на строку, поэтому непокрытой клетки не бывает by
// construction. Чтобы завести требование, его придётся вписать сюда — то есть
// туда, где его увидит проба.
//
// Второй рукописный перечень клеток рядом — находка гейта: два места об одном
// предмете разошлись бы молча, и разошлись бы именно там, где расхождение не
// видно (на клетке, которую забыли дописать во второй перечень).
//
// ─────────────────────────────────────────────────────────────────────────────
// ИНВАРИАНТ, РАДИ КОТОРОГО ВСЁ ОСТАЛЬНОЕ
//
// НЕ СУЩЕСТВУЕТ значения поля, при котором множество обязательных элементов
// пусто. Полоса без требований означала бы посадку, поднимающуюся без всякой
// проверки личности, — то есть ровно то, что запрещает ban #16. Свойство
// проверяется по этой таблице (lane_requirements_gate_test.go).
//
// ─────────────────────────────────────────────────────────────────────────────
// ДВЕ СТАДИИ, И ОНИ НЕ ВЗАИМОЗАМЕНЯЕМЫ
//
//   - LaneStageConfig  — читает ЗНАЧЕНИЯ настройки. Исполняется Config.Validate().
//   - LaneStageWiring  — читает ПРОВЯЗАННЫЕ ОБЪЕКТЫ. Настройка их не видит и
//     выразить их отсутствие не может, поэтому эти строки исполняет
//     композиционный корень через ValidateLaneWiring.
//
// Половины не смягчают друг друга: посадочная проверка НЕ заменяет проверку
// полноты провязки, и наоборот. Включённость своей чеканки обе читают ОДНИМ
// аксессором (TokenSigningConfig.Enabled) — разойтись во мнении о ней они не
// могут.
//
// ─────────────────────────────────────────────────────────────────────────────
// ВЕЛИЧИНА ПОДАЁТСЯ ПАРАМЕТРОМ, А НЕ ЧИТАЕТСЯ СТРАЖЕМ ИЗ ВСТРОЕННОГО ФАЙЛА
//
// Требование «посадка умеет предъявить каждый уровень доверия, которого требует
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

	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/corelib/identityposture"
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
	// ProviderAdminHopBuilt — административная дорога к ВНЕШНЕМУ поставщику
	// собрана этим корнем. Наблюдение, а не намерение профиля: адрес хопа
	// резолвится всегда (при незаданной ручке — деривацией из доменного имени),
	// поэтому «дороги нет» настройкой невыразимо и читается только отсюда.
	ProviderAdminHopBuilt bool
	// ProviderKeySetMirrorPublished — запись зеркала ЧУЖОГО набора проверочных
	// ключей опубликована. Тот же довод, что у дороги выше: путь записи
	// объявлен, издатель резолвится всегда, и пустым это поле настройка сделать
	// не может.
	ProviderKeySetMirrorPublished bool
	// PresentableACRs — уровни доверия, которые полоса УМЕЕТ предъявить
	// человеку. Пустой перечень означает «полоса не предъявляет ни одного»; это
	// законное наблюдаемое состояние, а не «не заполнено».
	PresentableACRs []string
	// CatalogFloors — что требует каталог прав. Подаётся параметром, чтобы
	// сценарий подмены каталога был не описываемым, а вызываемым.
	CatalogFloors CatalogFloors
}

// LaneRequirement — ОДНА клетка произведения «значение поля × обязательный
// элемент».
type LaneRequirement struct {
	// Lanes — полосы, на которых требование действует. Строка, названная
	// обеими полосами, клеткой произведения не является — это общее требование.
	Lanes []IdentityProvider
	// Element — обязательный элемент полосы, человеческим именем. Попадает в
	// перепись гейта и в имя порождённого пробой случая.
	Element string
	// Stage — стадия, на которой требование проверяется.
	Stage LaneStage
	// Check — отказ, называющий элемент. Возвращает nil, когда требование
	// выполнено. Строки стадии «настройка» LaneWiring НЕ читают.
	Check func(Config, LaneWiring) error
}

// AppliesTo сообщает, действует ли требование на названной полосе.
func (r LaneRequirement) AppliesTo(p IdentityProvider) bool {
	for _, l := range r.Lanes {
		if l == p {
			return true
		}
	}
	return false
}

// laneExternal / laneOwn — короткие перечни полос для объявления строк.
// Объявлены переменными, чтобы строка таблицы читалась одной строкой; словарём
// значений это не является (он один — identityProviderNames).
var (
	laneExternal = []IdentityProvider{IdentityProviderExternal}
	laneOwn      = []IdentityProvider{IdentityProviderOwn}
)

// LaneRequirements — ТАБЛИЦА требований полос. Единственное объявление.
//
// Тексты отказов провайдерской полосы сохранены ДОСЛОВНО (они часть контракта
// оператора); полосность добавляет к ним одну строку о том, каким значением
// поля требование снимается.
var LaneRequirements = []LaneRequirement{
	{
		Lanes:   laneExternal,
		Element: "административная дорога к внешнему поставщику",
		Stage:   LaneStageConfig,
		Check: func(c Config, _ LaneWiring) error {
			return laneScoped(c.validateProductionProviderAdminHop())
		},
	},
	{
		Lanes:   laneExternal,
		Element: "набор проверочных ключей внешнего поставщика",
		Stage:   LaneStageConfig,
		Check: func(c Config, _ LaneWiring) error {
			return laneScoped(c.validateProviderPublicHop(providerHopJWKS))
		},
	},
	{
		Lanes:   laneExternal,
		Element: "адрес обмена утверждения у внешнего поставщика",
		Stage:   LaneStageConfig,
		Check: func(c Config, _ LaneWiring) error {
			return laneScoped(c.validateProviderPublicHop(providerHopToken))
		},
	},
	{
		Lanes:   laneOwn,
		Element: "своя чеканка токенов включена",
		Stage:   LaneStageConfig,
		Check: func(c Config, _ LaneWiring) error {
			if c.AuthN.TokenSigning.Enabled {
				return nil
			}
			return fmt.Errorf(
				"production mode: %s=%s but authn.token-signing.enabled is false — this posture "+
					"has no identity provider to fall back to, so with our own minting off the "+
					"process would start and be unable to issue a single token. Enable it, or "+
					"declare %s=%s",
				IdentityProviderSetting, IdentityProviderOwn,
				IdentityProviderSetting, IdentityProviderExternal)
		},
	},
	// ЗДЕСЬ СТОЯЛА СТРОКА «приём предъявленного удостоверения включён», и она
	// ПЕРЕЕХАЛА, а не исчезла: PresentedCredentialConfig.ValidateBinding.
	//
	// Причина переезда — АНТЕЦЕДЕНТ. Здесь требование предъявлялось посадке
	// `own`, которую не выбирает ни один профиль развёртывания, тогда как
	// собственный публичный фронт поднимается на ЛЮБОЙ посадке — его поднимает
	// объявленный адрес, а не выбор посадки. Связывание существовало, его
	// антецедент не наступал никогда, следствие не требовалось ни разу, и всё
	// выглядело настроенным.
	//
	// Второй строкой рядом это не чинится: у требования один предмет, и два
	// стража о нём разошлись бы молча. Поэтому антецедент стал дизъюнкцией
	// («фронт поднят ИЛИ посадка без края»), а требование живёт в ОДНОМ месте —
	// и это место не таблица полос, потому что строка, названная обеими
	// полосами, клеткой произведения не является (см. шапку файла).
	// ШЕСТЬ СТРОК ПОЛОСЫ ВХОДА (Ф3, kacho#1269; шестая — Ф5, kacho#1271):
	// величины, без которых полоса входа паролем и восстановления не
	// собирается, объявляет профиль; незаданная — отказ старта с именем ручки
	// (Ф1 §7 инв. 4; Ф3-28, Ф3-33, Ф3-41, Ф3-42, Ф5-06). Под `external` полосы
	// нет, и её величины не требуются.
	{
		Lanes:   laneOwn,
		Element: "срок сессии и домен печенья объявлены",
		Stage:   LaneStageConfig,
		Check: func(c Config, _ LaneWiring) error {
			return ownScoped(c.AuthN.Login.ValidateSessionAndCookie())
		},
	},
	{
		Lanes:   laneOwn,
		Element: "предел частоты неверных предъявлений объявлен по обеим осям",
		Stage:   LaneStageConfig,
		Check: func(c Config, _ LaneWiring) error {
			return ownScoped(c.AuthN.Login.ValidateRateLimits())
		},
	},
	{
		Lanes:   laneOwn,
		Element: "правило пароля объявлено: длина, состояние и адрес проверки утечек",
		Stage:   LaneStageConfig,
		Check: func(c Config, _ LaneWiring) error {
			return ownScoped(c.AuthN.Login.ValidatePasswordPolicy())
		},
	},
	{
		Lanes:   laneOwn,
		Element: "ручка «что писать» объявлена и в перечне записываемых",
		Stage:   LaneStageConfig,
		Check: func(c Config, _ LaneWiring) error {
			return ownScoped(c.AuthN.Login.ValidateHasher())
		},
	},
	{
		Lanes:   laneOwn,
		Element: "ёмкость проверяющего и резерв памяти объявлены",
		Stage:   LaneStageConfig,
		Check: func(c Config, _ LaneWiring) error {
			return ownScoped(c.AuthN.Login.ValidateCapacity())
		},
	},
	// СТРОКА РЕГИСТРАЦИИ (Ф4, kacho#1270; Р5, Ф4-18/19): величина темпа
	// заведения объявляется профилем и незаданная — отказ старта с именем ручки.
	// Под `external` носитель ключа — идентификатор поставщика, а величину
	// правит администратор облака; требование не предъявляется.
	{
		Lanes:   laneOwn,
		Element: "величина темпа заведения объявлена: предел и окно",
		Stage:   LaneStageConfig,
		Check: func(c Config, _ LaneWiring) error {
			return ownScoped(c.AuthN.Registration.ValidateAdmissionRate())
		},
	},
	{
		Lanes:   laneOwn,
		Element: "срок кода восстановления доступа объявлен",
		Stage:   LaneStageConfig,
		Check: func(c Config, _ LaneWiring) error {
			return ownScoped(c.AuthN.Login.ValidateRecovery())
		},
	},
	// ДВЕ СТРОКИ ВТОРОГО ФАКТОРА (Ф12, kacho#1281; Р2, Р8; Ф12-35, Ф12-36):
	// перечень ключей обёртки секретов и окно свежести правки своих данных
	// объявляет профиль; незаданное — отказ старта с именем ручки. Под
	// `external` второй фактор ведёт поставщик, и величины не требуются.
	{
		Lanes:   laneOwn,
		Element: "перечень ключей обёртки секретов второго фактора объявлен",
		Stage:   LaneStageConfig,
		Check: func(c Config, _ LaneWiring) error {
			if _, err := c.AuthN.ResolveSecondFactorEncryptionKeys(); err != nil {
				return ownScoped(fmt.Errorf("production mode: %w", err))
			}
			return nil
		},
	},
	{
		Lanes:   laneOwn,
		Element: "окно свежести правки своих данных объявлено",
		Stage:   LaneStageConfig,
		Check: func(c Config, _ LaneWiring) error {
			return ownScoped(c.AuthN.ValidateSelfServiceFreshness())
		},
	},
	{
		Lanes:   laneOwn,
		Element: "подписант своей чеканки провязан",
		Stage:   LaneStageWiring,
		Check: func(c Config, w LaneWiring) error {
			if w.OwnMintSignerWired {
				return nil
			}
			return fmt.Errorf(
				"%s=%s and authn.token-signing.enabled is true, but the signer is not wired in "+
					"the composition root — the setting says we mint and the process has nothing "+
					"to mint with; this refusal is NOT the config-stage one and does not replace it",
				IdentityProviderSetting, IdentityProviderOwn)
		},
	},
	{
		Lanes:   laneOwn,
		Element: "свои способы входа человека провязаны",
		Stage:   LaneStageWiring,
		Check: func(c Config, w LaneWiring) error {
			if w.HumanCredentialsWired {
				return nil
			}
			return fmt.Errorf(
				"%s=%s but no store of our own human sign-in methods is wired — on this posture "+
					"there is no identity provider to check a person against, so the stand would "+
					"come up with no way for any human to prove who they are",
				IdentityProviderSetting, IdentityProviderOwn)
		},
	},
	{
		Lanes:   laneOwn,
		Element: "своя сессия человека провязана",
		Stage:   LaneStageWiring,
		Check: func(c Config, w LaneWiring) error {
			if w.HumanSessionsWired {
				return nil
			}
			return fmt.Errorf(
				"%s=%s but no store of our own human session is wired — a person could then "+
					"authenticate and carry nothing that says so, and a sign-out would have "+
					"nothing to end",
				IdentityProviderSetting, IdentityProviderOwn)
		},
	},
	{
		Lanes:   laneOwn,
		Element: "каждый уровень доверия каталога предъявим",
		Stage:   LaneStageWiring,
		Check: func(c Config, w LaneWiring) error {
			return unreachableFloorsComplaint(w)
		},
	},
	// ДВЕ СТРОКИ НИЖЕ ТРЕБУЮТ ОТСУТСТВИЯ, а не наличия, и это единственные
	// такие в таблице (задача #2489). Требование отрицательное потому, что
	// предмет у него — зависимость наружу: на посадке, где внешнего поставщика
	// нет вовсе, дорога к нему и запись зеркала его ключей суть провязка к
	// тому, чего не существует.
	//
	// ПОЧЕМУ СТАДИЯ ПРОВЯЗКИ. Настройкой это невыразимо by construction: оба
	// резолва деривируют значение из доменного имени и пустого не возвращают
	// никогда, поэтому «под own адрес пуст» не выполнимо ни при каком профиле,
	// а требование, которого нельзя выполнить, требованием не является.
	//
	// ЧЕМ ДЕРЖИТСЯ НАБЛЮДЕНИЕ — ВНИМАНИЕМ, и это сказано прямо. Значение полей
	// проставляет композиционный корень тем же способом, что и у двух соседних
	// строк выше: наблюдением, записанным литералом, с названным предикатом
	// смены. Механизма, отличающего честное наблюдение от подставленного, здесь
	// нет — как нет его и у соседей; заводить его этой строке в одиночку значило
	// бы требовать от неё большего, чем от остальной таблицы.
	{
		Lanes:   laneOwn,
		Element: "дорога к внешнему поставщику не строится",
		Stage:   LaneStageWiring,
		Check: func(_ Config, w LaneWiring) error {
			if !w.ProviderAdminHopBuilt {
				return nil
			}
			return fmt.Errorf(
				"%s=%s, but the composition root still builds the admin road to an EXTERNAL "+
					"identity provider — on this posture there is no such provider, and the "+
					"address it dials is not even declared: it is derived from the domain name, "+
					"so the road looks configured on a stand that never configured one",
				IdentityProviderSetting, IdentityProviderOwn)
		},
	},
	{
		Lanes:   laneOwn,
		Element: "запись зеркала чужого набора ключей не публикуется",
		Stage:   LaneStageWiring,
		Check: func(_ Config, w LaneWiring) error {
			if !w.ProviderKeySetMirrorPublished {
				return nil
			}
			return fmt.Errorf(
				"%s=%s, but the publisher still carries the mirror record of an EXTERNAL "+
					"provider key set — a record whose issuer is derived, whose upstream does "+
					"not exist on this posture, and which would answer every caller that asks "+
					"for it with an unavailable upstream instead of an honest refusal",
				IdentityProviderSetting, IdentityProviderOwn)
		},
	},
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
			"%s=%s and the permission catalog could not be read, so which assurance levels any "+
				"RPC demands is unknown — an unread catalog is not an empty one (refuse to start)",
			IdentityProviderSetting, IdentityProviderOwn)
	}

	unreachable := 0
	var levels []string
	for level, n := range w.CatalogFloors.ByLevel {
		if grpcsrv.ACRRank(level) <= 0 {
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
		"%s=%s and %d catalog entr(ies) demand assurance level(s) %s that this posture cannot "+
			"present — the lane offers %s, so those verbs would be unreachable to every human "+
			"while the catalog says they are merely guarded (refuse to start)",
		IdentityProviderSetting, IdentityProviderOwn,
		unreachable, strings.Join(levels, ", "), presentedList(w.PresentableACRs))
}

// lanePresents — умеет ли полоса предъявить названный уровень. Решает
// ЕДИНСТВЕННАЯ функция платформы; своей таблицы рангов полоса не заводит.
func lanePresents(presentable []string, required string) bool {
	for _, p := range presentable {
		if grpcsrv.ACRSatisfies(p, required) {
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

// laneScoped добавляет к отказу полосы ОДНУ строку о том, каким значением поля
// требование снимается. Текст самого отказа не меняется — он часть контракта
// оператора.
// ownScoped — то же для требований, предъявляемых посадке `own`: каждая
// строка отказа называет поле посадки и значение, которым требование снимается.
func ownScoped(err error) error {
	if err == nil {
		return nil
	}
	var out error
	for _, e := range multierr.Errors(err) {
		out = multierr.Append(out, fmt.Errorf(
			"%w [required because %s=%s; declare %s=%s and this requirement is lifted]",
			e, IdentityProviderSetting, IdentityProviderOwn,
			IdentityProviderSetting, IdentityProviderExternal))
	}
	return out
}

func laneScoped(err error) error {
	if err == nil {
		return nil
	}
	var out error
	for _, e := range multierr.Errors(err) {
		out = multierr.Append(out, fmt.Errorf(
			"%w [required because %s=%s; declare %s=%s and this requirement is lifted]",
			e, IdentityProviderSetting, IdentityProviderExternal,
			IdentityProviderSetting, IdentityProviderOwn))
	}
	return out
}

// validateIdentityProviderLane — посадочная половина: поле объявлено, и
// требования ЕГО полосы, выразимые настройкой, выполнены.
//
// Незаданное поле отвергается ПЕРВЫМ и в одиночку: посадка неизвестна, и
// требовать по ней нечего. Предъявлять сверх этого требования какой-нибудь
// полосы значило бы выбрать полосу за оператора.
func (c Config) validateIdentityProviderLane() error {
	p := c.AuthN.IdentityProvider
	if !p.IsSet() {
		// Текст отказа один на оба процесса (identityposture.NotDeclared):
		// расхождение диагностики заставило бы оператора учить два объяснения
		// одного предмета.
		return fmt.Errorf("production mode: %w", identityposture.NotDeclared(IdentityProviderSetting))
	}

	var errs error
	for _, r := range LaneRequirements {
		if r.Stage != LaneStageConfig || !r.AppliesTo(p) {
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
// здесь — отдельный текст, и он НЕ заменяется посадочной проверкой: проба,
// доказавшая одну точку, о второй не утверждает ничего.
//
// В непроизводственном режиме требований полосы нет: in-process фикстура
// поставщика не имеет и стендом не является (та же граница, что у соседних
// провайдерских стражей).
func ValidateLaneWiring(c Config, w LaneWiring) error {
	if !c.AuthN.Mode.IsProduction() {
		return nil
	}
	p := c.AuthN.IdentityProvider
	if !p.IsSet() {
		// Посадка неизвестна — об этом уже отказала проверка настройки; второй
		// отказ о том же предмете сделал бы два места об одном.
		return nil
	}
	var errs error
	for _, r := range LaneRequirements {
		if r.Stage != LaneStageWiring || !r.AppliesTo(p) {
			continue
		}
		errs = multierr.Append(errs, r.Check(c, w))
	}
	return errs
}
