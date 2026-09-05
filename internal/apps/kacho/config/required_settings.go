// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// required_settings.go — ВЕЛИЧИНЫ, БЕЗ КОТОРЫХ СЛУЖБА НЕ ПУСКАЕТСЯ, объявленные
// таблицей: единственный источник перечня, который читает чужой оператор.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ТАБЛИЦА, А НЕ АБЗАЦ В ДОКУМЕНТЕ
//
// Документ установки обязан назвать эти величины: без них оператор ставит
// службу вслепую и узнаёт перечень из текстов отказа, по одному за перезапуск.
// Выписанный от руки перечень разошёлся бы со стражем МОЛЧА — страж меняется
// коммитом в свой файл, документ не меняется вовсе, и расхождение видит только
// тот, кто в этот день ставит службу впервые.
//
// Поэтому перечень в документе ПОРОЖДАЕТСЯ отсюда и сверяется гейтом
// (services/iam/tools/operatordocs), а сама таблица доказывается ПРОГОНОМ
// (required_settings_test.go): снятая величина обязана уронить старт, а поданная
// объявленным путём — отказ снять. Строка, которой страж не требует, и строка,
// чей путь подачи не работает, роняют прогон одинаково.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПУТЬ ПОДАЧИ — ПОЛЕ ТАБЛИЦЫ, А НЕ ОБЩЕЕ ПРАВИЛО. Это главное здесь.
//
// Випер разрешает переменную только для ключа, который УЖЕ знает: у ключа есть
// умолчание в defaults.go либо явная привязка в load.go. Ключ без того и другого
// даёт документированную ручку БЕЗ ЧИТАТЕЛЯ — оператор её задаёт, а исход
// загрузки не меняется.
//
// Цена этого измерена, а не предположена. Так было у трёх ключей сразу, и текст
// отказа при этом называл ИМЕННО ПЕРЕМЕННУЮ: оператор задавал ровно её и получал
// тот же отказ снова, не имея способа отличить свою ошибку от нашей. Ключи
// привязаны задачей #2040, и сегодня НИ ОДНА строка таблицы файлом не
// ограничена — поле `Supply` у всех `SupplyEnv`.
//
// ПОЛЕ ОСТАЁТСЯ, И ЭТО РЕШЕНИЕ, А НЕ ОСТАТОК. Оно объявляет путь подачи ЯВНО,
// поэтому следующая величина без привязки будет названа файловой сразу либо
// уронит прогон — вместо того чтобы разойтись с документом молча. Снять поле
// значило бы вернуть общее правило «всё задаётся переменной», которое однажды
// уже оказалось ложным и было ненаблюдаемым.
//
// Класс держит гейт `TestRefusalNamedEnvVarReachesItsField` (тот же пакет):
// всякая переменная, названная текстом отказа стража, обязана менять исход —
// проверяется ОПЫТОМ на четырёх профилях посадки.
//
// ─────────────────────────────────────────────────────────────────────────────
// ОБЛАСТЬ ТАБЛИЦЫ НАЗВАНА ЧЕСТНО: отказов старта ТРИ СТАДИИ, здесь — ОДНА
//
//	настройка   `Config.Validate()`                — ЭТА таблица;
//	посадка     `pkg/servicecontract`, дескриптор  — шифрование до своей базы,
//	                                                 периметр слушателей, круг
//	                                                 отправителей;
//	сборка      `ValidateLaneWiring`               — провязанность объектов,
//	                                                 которых настройка не видит.
//
// Таблица покрывает первую и о двух остальных не утверждает НИЧЕГО. Обратное
// («здесь весь перечень отказов старта») было бы ложью, которую оператор
// обнаружит отказом на стенде. Две другие стадии названы прозой в документе
// установки — вместе с тем, что перечнем они здесь не представлены.
package config

// SupplyPath — каким путём оператор подаёт величину процессу.
//
// Различие несущее, а не справочное: путь, объявленный неверно, даёт документ,
// который называет способ задать величину, её не задающий.
type SupplyPath int

const (
	// SupplyEnv — переменной окружения. Ключ известен виперу (умолчание в
	// defaults.go либо явная привязка в load.go), поэтому AutomaticEnv его
	// разрешает.
	SupplyEnv SupplyPath = iota
	// SupplyFile — ТОЛЬКО файлом настроек (`KACHO_IAM_CONFIG_PATH`). У ключа нет
	// ни умолчания, ни привязки, поэтому переменная окружения до поля не
	// доезжает — сколько бы раз её ни задали.
	SupplyFile
)

// String — имя пути подачи для порождённой таблицы и текстов прогона.
func (p SupplyPath) String() string {
	switch p {
	case SupplyEnv:
		return "переменная окружения"
	case SupplyFile:
		return "файл настроек"
	default:
		return "неизвестный путь подачи"
	}
}

// RequiredSetting — ОДНА величина, без которой старт не проходит.
type RequiredSetting struct {
	// Key — путь ключа в настройке. Координата, которую называет отказ.
	Key string
	// Env — имя переменной окружения. Для SupplyFile здесь стоит имя, которое
	// оператор попробует ПЕРВЫМ (обычно оно же названо текстом отказа), — оно
	// печатается в документе как НЕРАБОТАЮЩЕЕ, чтобы читатель не искал причину.
	Env string
	// Supply — каким путём величина доезжает до поля.
	Supply SupplyPath
	// Lanes — полосы посадки личности, на которых величина обязательна.
	// Пустой перечень — обязательна на любой.
	Lanes []IdentityProvider
	// Why — почему без неё не пускаемся, словами оператора. Идёт в документ.
	Why string
	// Sample — годное значение. Им величина подаётся в прогоне, и оно же
	// печатается в документе примером.
	Sample string
	// SampleIsLane — годное значение этой величины ЕСТЬ имя полосы (так у
	// самой посадки личности). Тогда Sample служит только примером в документе.
	SampleIsLane bool
	// FileList — в файле настроек величина записывается СПИСКОМ, а не строкой.
	FileList bool
	// Conditional — величина обязательна не всегда, а при выполненном условии
	// (обычно — при заданной соседней величине). Такая строка на ПУСТОМ профиле
	// отказа не производит, и проба полноты её из обратного направления
	// исключает, называя причину.
	Conditional bool
	// Refusal — подстрока текста отказа. Ею строка доказывается прогоном, и она
	// же ведёт оператора от сообщения к строке документа.
	Refusal string
}

// AppliesTo сообщает, обязательна ли величина на названной полосе.
func (s RequiredSetting) AppliesTo(p IdentityProvider) bool {
	if len(s.Lanes) == 0 {
		return true
	}
	for _, l := range s.Lanes {
		if l == p {
			return true
		}
	}
	return false
}

// SampleValue — годное значение для подачи на названной полосе.
func (s RequiredSetting) SampleValue(lane IdentityProvider) string {
	if s.SampleIsLane {
		return lane.String()
	}
	return s.Sample
}

// FileValue — значение в той форме, в какой его читает файл настроек.
func (s RequiredSetting) FileValue(lane IdentityProvider) any {
	v := s.SampleValue(lane)
	if s.FileList {
		return []string{v}
	}
	return v
}

// LaneNames — имена полос, на которых величина обязательна, для порождённой
// таблицы. Пустой перечень полос печатается как «любая».
func (s RequiredSetting) LaneNames() []string {
	if len(s.Lanes) == 0 {
		return nil
	}
	out := make([]string, 0, len(s.Lanes))
	for _, l := range s.Lanes {
		out = append(out, l.String())
	}
	return out
}

// RequiredSettings — ТАБЛИЦА. Единственное объявление; второе разошлось бы с
// первым молча.
//
// Порядок строк — порядок, в котором величины встречает оператор: сперва
// общие для любой посадки, затем полосные.
var RequiredSettings = []RequiredSetting{
	{
		Key:          IdentityProviderSetting,
		Env:          "KACHO_IAM_AUTHN__IDENTITY_PROVIDER",
		Supply:       SupplyEnv,
		SampleIsLane: true,
		// ВЫВЕДЕНО из словаря посадки, а не выписано: второе перечисление
		// канонических имён разошлось бы с типом на первом же новом значении,
		// и разошлось бы молча (гейт pkg/identityposture).
		Sample: IdentityProviderExternal.String(),
		Why: "чем установка проверяет человека: внешним поставщиком удостоверений (external) " +
			"или собственной чеканкой платформы (own). Умолчания нет намеренно — оно в одну сторону " +
			"потребовало бы адресов поставщика у установки, у которой его нет, в другую молча сняло бы " +
			"это требование с установки, которая на него опирается",
		Refusal: "authn.identity-provider is not declared",
	},
	{
		Key:      "authn.trusted-forwarder-sans",
		Env:      "KACHO_IAM_AUTHN__TRUSTED_FORWARDER_SANS",
		Supply:   SupplyEnv,
		FileList: true,
		Sample:   "spiffe://kacho.cloud/ns/kacho/sa/kacho-api-gateway",
		Why: "круг тех, кому позволено ГОВОРИТЬ ЗА пользователя — предъявить чужую личность в " +
			"метаданных запроса. Пустой круг означает не «никому», а «любому пиру, предъявившему " +
			"сертификат внутреннего удостоверяющего центра»: сосед с законным сертификатом читал бы и " +
			"менял данные любого арендатора от его имени",
		Refusal: "authn.trusted-forwarder-sans",
	},
	{
		Key:    "authn.hook-shared-secret",
		Env:    "KACHO_IAM_HOOK_TOKEN",
		Supply: SupplyEnv,
		Sample: "заменить-на-случайную-строку",
		Why: "предъявитель, которым поставщик удостоверений аутентифицируется на хуках выдачи и " +
			"обновления токена. Без него хуки принимали бы вызов без всякой проверки",
		Refusal: "authn.hook-shared-secret is empty",
	},
	{
		Key:    "authn.jwks-encryption-key-hex",
		Env:    "KACHO_IAM_JWKS_ENC_KEY",
		Supply: SupplyEnv,
		Sample: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Why: "ключ ОБЁРТКИ приватной половины подписного ключа: 32 байта в hex (64 знака). " +
			"Принимает перечень через запятую — первый оборачивает, все открывают; так ключ обёртки " +
			"и меняется, без простоя и без переписывания хранилища",
		Refusal: "authn.jwks-encryption-key-hex",
	},
	{
		Key:    "api-server.registry-token.service",
		Env:    "KACHO_IAM_API_SERVER__REGISTRY_TOKEN__SERVICE",
		Supply: SupplyEnv,
		Sample: "kacho-registry",
		Why: "имя службы реестра, которое обе стороны докерной полосы обязаны называть одинаково: " +
			"мы чеканим его в адресата токена, реестр объявляет его докер-клиенту. Умолчания нет " +
			"намеренно — это чужое имя, и совпадение подставленного с настоящим не выбирал бы никто",
		Refusal: "api-server.registry-token.service is not declared",
	},
	{
		Key:    "authn.hydra-admin-url",
		Env:    "KACHO_IAM_HYDRA_ADMIN_URL",
		Supply: SupplyEnv,
		Lanes:  []IdentityProvider{IdentityProviderExternal},
		Sample: "https://hydra-admin.kacho.svc:4445",
		Why: "административная дорога к внешнему поставщику: по ней заводится клиент OAuth и " +
			"сносится сессия входа. Незаданный адрес не пуст — он ВЫВОДИТСЯ из издателя и указывает " +
			"на публичное имя, которого внутри кластера не существует; служба читается настроенной, " +
			"адресуя хост, которого никто не выбирал",
		Refusal: "authn.hydra-admin-url is not declared",
	},
	{
		Key:         "authn.hydra-admin-ca-file",
		Env:         "KACHO_IAM_HYDRA_ADMIN_CA_FILE",
		Supply:      SupplyEnv,
		Lanes:       []IdentityProvider{IdentityProviderExternal},
		Conditional: true,
		Sample:      "/etc/kacho-iam/tls/server/ca.crt",
		Why: "корень доверия для административной дороги. Обязателен, КОГДА адрес выше объявлен по " +
			"https: сертификат поставщика внутри кластера выпущен внутренним удостоверяющим центром, " +
			"а процесс доверяет системным корням — без этой связки каждый вызов падает на неизвестном центре",
		Refusal: "authn.hydra-admin-ca-file is empty",
	},
	{
		Key:    "authn.hydra-jwks-url",
		Env:    "KACHO_IAM_HYDRA_JWKS_URL",
		Supply: SupplyEnv,
		Lanes:  []IdentityProvider{IdentityProviderExternal},
		Sample: "http://hydra-public.kacho.svc:4444/.well-known/jwks.json",
		Why: "набор проверочных ключей поставщика — единственная опора, по которой решается, его ли " +
			"подписью подписан предъявленный токен. Незаданный адрес выводится из издателя ровно так же, " +
			"как административный выше",
		Refusal: "authn.hydra-jwks-url is not declared",
	},
	{
		Key:    "authn.hydra-token-url",
		Env:    "KACHO_IAM_HYDRA_TOKEN_URL",
		Supply: SupplyEnv,
		Lanes:  []IdentityProvider{IdentityProviderExternal},
		Sample: "http://hydra-public.kacho.svc:4444/oauth2/token",
		Why: "адрес обмена подписанного утверждения на токен у внешнего поставщика. Незаданный " +
			"выводится из издателя — с теми же последствиями",
		Refusal: "authn.hydra-token-url is not declared",
	},
	{
		Key:    "authn.token-signing.enabled",
		Env:    "KACHO_IAM_AUTHN__TOKEN_SIGNING__ENABLED",
		Supply: SupplyEnv,
		Lanes:  []IdentityProvider{IdentityProviderOwn},
		Sample: "true",
		Why: "своя чеканка токенов. На посадке own внешнего поставщика нет вовсе, поэтому с " +
			"выключенной чеканкой процесс поднялся бы и не смог выдать ни одного токена",
		Refusal: "authn.token-signing.enabled is false",
	},
	{
		Key:         "authn.token-signing.issuer",
		Env:         "KACHO_IAM_AUTHN__TOKEN_SIGNING__ISSUER",
		Supply:      SupplyEnv,
		Lanes:       []IdentityProvider{IdentityProviderOwn},
		Conditional: true,
		Sample:      "https://iam.example.internal/",
		Why: "издатель, которым подписывается наш токен, и он же — единственная принимаемая " +
			"форма издателя на входе. Незаданный означает не «любой наш», а «не сужаем»: токен " +
			"любого происхождения прошёл бы за наш",
		Refusal: "authn.token-signing.issuer is empty",
	},
	{
		Key:         "authn.token-signing.algorithm",
		Env:         "KACHO_IAM_AUTHN__TOKEN_SIGNING__ALGORITHM",
		Supply:      SupplyEnv,
		Lanes:       []IdentityProvider{IdentityProviderOwn},
		Conditional: true,
		Sample:      "RS256",
		Why:         "чем подписывается выпускаемый токен. Умолчания нет: выбор подписи — решение установки, а не наше",
		Refusal:     "authn.token-signing.algorithm",
	},
	{
		Key:         "authn.token-signing.allowed-algorithms",
		Env:         "KACHO_IAM_AUTHN__TOKEN_SIGNING__ALLOWED_ALGORITHMS",
		Supply:      SupplyEnv,
		Lanes:       []IdentityProvider{IdentityProviderOwn},
		Conditional: true,
		Sample:      "RS256",
		Why: "перечень подписей, принимаемых на входе (через запятую). Пустой означает «любая»: " +
			"на нём сверка заголовка токена с ключом теряет предмет, и подделанный заголовок прошёл бы",
		Refusal: "authn.token-signing.allowed-algorithms has no elements",
	},
}
