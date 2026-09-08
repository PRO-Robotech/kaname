// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// client_token.go — настройка токен-эндпоинта платформы и его страж старта
// (задача #898, приёмка F2 §9.1 п. 1, 9).
//
// # Почему у эндпоинта выдачи страж строже, чем у обычной поверхности
//
// Каждая величина здесь невидима на положительном пути. Незаданный перечень
// адресатов означает «выдаём токен, адресованный чему угодно»; незаданный
// потолок тела — «читаем сколько прислали»; выключенная своя чеканка —
// «выпускать нечем». Ни одно из этих состояний не проявляется отказом: запрос
// проходит, токен выдаётся, клиент доволен, — и ломается у потребителя либо не
// ломается вовсе, оставаясь дырой.
//
// # Асимметрия цены
//
// Слишком строгая настройка даёт отказ В СТАРТЕ — видимый сразу, с именем
// настройки в тексте, читаемый оператором. Слишком слабая даёт выданный не тому
// токен, не видимый никогда. Поэтому на каждой развилке здесь выбрано
// отвергать.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"
	"go.uber.org/multierr"
)

// ClientTokenConfig — токен-эндпоинт платформы: приём вида выдачи «учётные
// данные клиента» с аутентификацией подписанным утверждением.
type ClientTokenConfig struct {
	// Enabled — включён ли эндпоинт. Пока выключен, его настройки не
	// требуются: страж, требующий того, чем не пользуются, — отказ в старте
	// без предмета.
	Enabled bool `mapstructure:"enabled"`
	// AllowedAudiences — объявленный перечень адресатов платформы, через
	// запятую. Считаются ЭЛЕМЕНТЫ, а не длина строки: одинокая запятая непуста
	// по длине и пуста по существу.
	//
	// Это ВНЕШНЯЯ граница выдачи — перечень поверхностей, которым платформа
	// вообще чеканит удостоверения.
	//
	// Прежняя редакция утверждала, что сверка идёт с этим перечнем «и ничем
	// больше, потому что колонки адресатов у клиентов в схеме нет». Колонка
	// есть (задача #1136), и сужение поверх этого перечня действует. Внешней
	// границей перечень при этом быть не перестал: сужение работает внутри
	// него и никогда его не расширяет.
	AllowedAudiences string `mapstructure:"allowed-audiences"`
	// DefaultAudience — адресат, когда запрос его не назвал.
	DefaultAudience string `mapstructure:"default-audience"`
	// TokenTTL — обычный срок выпускаемого токена. Он же верхняя граница:
	// остаток срока клиента укорачивает его, но никогда не удлиняет.
	TokenTTL time.Duration `mapstructure:"token-ttl"`
	// BodyCeiling — потолок тела запроса в байтах. Ноль означал бы «без
	// потолка», поэтому объявляется числом и проверяется стражем.
	BodyCeiling int64 `mapstructure:"body-ceiling"`
}

// AudienceList возвращает перечень адресатов платформы, считая ЭЛЕМЕНТЫ.
//
// Тот же предикат исполняет страж и вызывающий: два места об одном предмете
// разошлись бы ровно на вырожденном значении, и разошлись бы молча.
func (c ClientTokenConfig) AudienceList() []string {
	return ParseCommaList(c.AllowedAudiences)
}

// Validate — страж старта токен-эндпоинта.
//
// Принимает настройку своей чеканки ПАРАМЕТРОМ, а не читает её из корня: две
// величины связаны по существу (эндпоинт выпускает нашим подписантом и
// объявляет нашего издателя ожидаемым адресатом утверждения), и связь обязана
// проверяться там, где она есть, а не там, где о ней помнят.
//
// Каждое сообщение называет НАСТРОЙКУ и правило; ни одно не называет значения
// секрета — текст отказа читает оператор, а не предъявитель.
func (c ClientTokenConfig) Validate(signing TokenSigningConfig, hostListenAddress string) error {
	if !c.Enabled {
		return nil
	}
	var errs error

	// Эндпоинт живёт на УЖЕ ОБЪЯВЛЕННОЙ внешне досягаемой поверхности выдачи, а
	// не заводит свою: вид выдачи задан формой запроса, а не нашим выбором
	// порта, и второй слушатель об одном предмете разошёлся бы с первым в
	// периметре, посадке TLS и профиле развёртывания.
	//
	// Отсюда требование: слушатель, на котором эндпоинт монтируется, обязан
	// быть поднят. Иначе эндпоинт объявлен включённым и не обслуживается —
	// состояние, неотличимое от исправного до первого запроса клиента.
	if strings.TrimSpace(hostListenAddress) == "" {
		errs = multierr.Append(errs, fmt.Errorf(
			"authn.client-token.enabled is set while api-server.registry-token.endpoint declares no "+
				"listener — the endpoint is mounted on that surface, and there would be nowhere to serve it"))
	}

	// Эндпоинт выпускает НАШИМ подписантом и объявляет НАШЕГО издателя
	// единственной принимаемой формой адресата утверждения. Обе величины живут
	// у своей чеканки, поэтому обе требуются здесь.
	if !signing.Enabled {
		errs = multierr.Append(errs, fmt.Errorf(
			"authn.client-token.enabled is set while authn.token-signing.enabled is not — "+
				"the endpoint mints with our own signer, and there would be nothing to mint with"))
	}
	if strings.TrimSpace(signing.Issuer) == "" {
		errs = multierr.Append(errs, fmt.Errorf(
			"authn.token-signing.issuer is empty while authn.client-token.enabled is set — "+
				"the issuer identifier is the only accepted form of the assertion audience, "+
				"and an unset one means «any audience is ours»"))
	}

	audiences := c.AudienceList()
	if len(audiences) == 0 {
		errs = multierr.Append(errs, fmt.Errorf(
			"authn.client-token.allowed-audiences has no elements (got %q) — an empty list means "+
				"«issue a token addressed to anything», and the requested audience is checked "+
				"against this list and nothing else", c.AllowedAudiences))
	}
	def := strings.TrimSpace(c.DefaultAudience)
	if def == "" {
		errs = multierr.Append(errs, fmt.Errorf(
			"authn.client-token.default-audience is empty — a request that names no audience "+
				"would get a token addressed to nothing"))
	} else if len(audiences) > 0 && !containsExactly(audiences, def) {
		// Умолчание вне перечня отвергалось бы собственной проверкой, и глагол
		// не работал бы НИ ПРИ КАКОМ входе — при том что обе половины
		// настройки по отдельности выглядят разумными.
		errs = multierr.Append(errs, fmt.Errorf(
			"authn.client-token.default-audience %q is outside authn.client-token.allowed-audiences %q — "+
				"the default would be refused by our own check", c.DefaultAudience, c.AllowedAudiences))
	}

	switch {
	case c.TokenTTL <= 0:
		errs = multierr.Append(errs, fmt.Errorf(
			"authn.client-token.token-ttl must be declared as a positive number (got %s)", c.TokenTTL))
	case c.TokenTTL > tokenpolicy.MaxTokenTTL:
		// Срок сверх потолка не урезается на выпуске: молчаливое урезание
		// сделало бы величину неизвестной тому, кто её настраивал, и
		// арифметика отсрочки снятия ключа перестала бы сходиться.
		errs = multierr.Append(errs, fmt.Errorf(
			"authn.client-token.token-ttl is %s, above the declared platform ceiling %s",
			c.TokenTTL, tokenpolicy.MaxTokenTTL))
	}

	if c.BodyCeiling <= 0 {
		errs = multierr.Append(errs, fmt.Errorf(
			"authn.client-token.body-ceiling must be declared as a positive number of bytes "+
				"(got %d) — zero means «no ceiling», and the endpoint would read whatever arrives",
			c.BodyCeiling))
	}
	return errs
}

// containsExactly — простое сравнение строк, без нормализации.
//
// Адресат — часть контракта токена, и «почти тот же» адресат есть другой
// адресат: нормализация здесь расширила бы принимаемое множество молча.
func containsExactly(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
