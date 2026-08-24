// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package client_token — выдача токена по учётным данным клиента, чья личность
// доказана подписанным утверждением (задача #898, приёмка F2 §9.1 п. 5, 7).
//
// # Что здесь решается, а что уже решено выше
//
// К моменту входа сюда клиент УЖЕ аутентифицирован: подпись сошлась с ключом из
// реестра, утверждение однократно, время в границах. Здесь решается другое —
// ВЫДАВАТЬ ЛИ ЕМУ, и это отдельный вопрос: аутентифицированный клиент может
// быть истёкшим, а его владелец — снятым.
//
// # Почему срок выданного токена ограничен остатком срока клиента
//
// Отзыв обязан действовать и на предъявлении, иначе он не отзыв, а «больше не
// выдаём». Для истечения КЛИЕНТА читатель на пути каждого запроса стоил бы
// обращения к реестру ради величины, известной в момент выдачи. Ограничение
// срока токена остатком срока клиента даёт то же свойство ценой ОДНОГО
// вычисления при выдаче: токенов, переживших клиента, не существует by
// construction, и читать на предъявлении нечего.
//
// Цена названа и она не нулевая: клиент, которому осталось меньше обычного
// срока токена, получает УКОРОЧЕННЫЙ токен и обязан быть к этому готов. Это
// сказано на странице документации, потому что иначе он узнает об этом
// укороченным токеном, который примет за сбой.
package client_token

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clientassertion"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
	"github.com/PRO-Robotech/kacho/services/iam/internal/tokensigner"
)

// Signer — порт подписанта. Определён здесь, у вызывающего.
type Signer interface {
	Sign(ctx context.Context, req tokensigner.Request) (tokensigner.Token, error)
	Issuer() string
}

// ClaimSource — порт ОДНОГО объявления состава утверждений.
//
// Порт, а не прямая зависимость на службу обогащения: состав обязан быть один
// на оба пути выдачи, и порт делает это требованием к вызывающему, а не
// надеждой на то, что он подставит нужное.
type ClaimSource interface {
	ClaimsForAssertionClient(ctx context.Context, client domain.AssertionClient, hookCtx service.TokenHookContext) (map[string]any, service.ResolvedPrincipal, error)
}

// Config — объявленная настройка выдачи. Каждое поле обязательно.
type Config struct {
	// AllowedAudiences — объявленный конфигурацией перечень адресатов
	// платформы. Пустой означал бы «любой», поэтому он обязателен.
	//
	// Это ВНЕШНЯЯ граница выдачи: перечень поверхностей, которым платформа
	// вообще чеканит удостоверения. Он объявлен посадкой, и расширить его
	// заказчик ключа не может ничем.
	//
	// Прежняя редакция этого комментария говорила, что сверка идёт с ЭТИМ
	// перечнем «и ничем больше, потому что колонки адресатов у клиентов в схеме
	// нет». Колонка теперь есть (задача #1136), и сужение поверх этого перечня
	// действует — см. `resolveAudience`. Внешней границей перечень при этом
	// быть не перестал: сужение работает внутри него.
	AllowedAudiences []string
	// DefaultAudience — адресат, когда запрос его не назвал.
	DefaultAudience string
	// TokenTTL — обычный срок выпускаемого токена.
	TokenTTL time.Duration
	// Clock — источник времени. Вход, а не окружение.
	Clock func() time.Time
}

// Input — вход выдачи.
type Input struct {
	// Client — строка реестра, чью личность доказало утверждение.
	Client domain.AssertionClient
	// RequestedAudience — адресат ИЗ ЗАПРОСА. Никогда из предъявленного
	// утверждения: адресат утверждения — это идентификатор нашего издателя, и
	// перенос его в адресат выданного токена дал бы токен, адресованный нам
	// самим. Положительный путь при этом работает: токен выпускается, подпись
	// верна, клиент доволен, — а ломается у ПОТРЕБИТЕЛЯ, через несколько шагов
	// после места ошибки.
	RequestedAudience []string
	// Scope — запрошенная область.
	Scope string
	// Confirmation — привязка к ключу ВЛАДЕЛЬЦА, взятая из предъявленного при
	// выдаче доказательства владения. Никогда из ключа утверждения: это разные
	// ключи, и совпадение их — частный случай, на котором свойство не
	// измеряется.
	Confirmation *tokensigner.Confirmation
}

// Output — выпущенный токен в форме, которую понимает стандартный клиент.
type Output struct {
	AccessToken string
	TokenType   string
	ExpiresIn   int
	Scope       string
}

// UseCase — выдача по учётным данным клиента.
type UseCase struct {
	cfg    Config
	signer Signer
	claims ClaimSource
}

// New строит выдачу. Неполная настройка — отказ построения.
func New(cfg Config, signer Signer, claims ClaimSource) (*UseCase, error) {
	switch {
	case len(cfg.AllowedAudiences) == 0:
		return nil, fmt.Errorf("client_token: allowed audiences must be declared (empty means 'any')")
	case strings.TrimSpace(cfg.DefaultAudience) == "":
		return nil, fmt.Errorf("client_token: default audience is required")
	case cfg.TokenTTL <= 0:
		return nil, fmt.Errorf("client_token: token lifetime must be declared as a positive number")
	case cfg.TokenTTL > tokenpolicy.MaxTokenTTL:
		return nil, fmt.Errorf("client_token: token lifetime %s exceeds the platform ceiling %s",
			cfg.TokenTTL, tokenpolicy.MaxTokenTTL)
	case cfg.Clock == nil:
		return nil, fmt.Errorf("client_token: clock is required (time source is an input, not the environment)")
	case signer == nil:
		return nil, fmt.Errorf("client_token: signer is required")
	case claims == nil:
		return nil, fmt.Errorf("client_token: claim source is required")
	}
	// Объявленный по умолчанию адресат обязан входить в объявленный перечень:
	// иначе умолчание отвергалось бы собственной проверкой, и глагол не
	// работал бы НИ ПРИ КАКОМ входе — при том что обе половины настройки по
	// отдельности выглядят разумными.
	if !allowed(cfg.AllowedAudiences, cfg.DefaultAudience) {
		return nil, fmt.Errorf("client_token: default audience %q is not in the declared list", cfg.DefaultAudience)
	}
	return &UseCase{cfg: cfg, signer: signer, claims: claims}, nil
}

// Issue выпускает токен.
//
// Исход отказа возвращается ВМЕСТЕ с ошибкой и принадлежит тому же закрытому
// словарю, что исходы аутентификации: перечень исходов есть перечень счётчиков,
// и исход без счётчика делает мёртвый контроль невидимым.
func (u *UseCase) Issue(ctx context.Context, in Input) (Output, clientassertion.Outcome, error) {
	now := u.cfg.Clock().UTC()

	// (1) Владелец. Не-`ACTIVE` — это ДВА значения словаря, и оба ведут сюда.
	if !in.Client.OwnerActive {
		return Output{}, clientassertion.OutcomeOwnerNotActive,
			fmt.Errorf("client_token: owner of client %s is not active", in.Client.ID)
	}

	// (2) Срок клиента. Незаданный означает «бессрочно» — законное состояние
	// схемы, а не «истёк в начале эпохи».
	ttl := u.cfg.TokenTTL
	if in.Client.ExpiresAt != 0 {
		remaining := time.Unix(in.Client.ExpiresAt, 0).UTC().Sub(now)
		if remaining <= 0 {
			return Output{}, clientassertion.OutcomeClientExpired,
				fmt.Errorf("client_token: client %s has expired", in.Client.ID)
		}
		if remaining < ttl {
			// Ровно до остатка, без запаса. Всякий запас здесь — «грация»,
			// округление вверх, «плюс минута» — воскрешает состояние, которое
			// эта строка и объявляет несуществующим: токен, переживший
			// клиента. Проба утверждает НЕРАВЕНСТВО, а не прилагательное,
			// именно поэтому.
			ttl = remaining
		}
	}

	// (3) Адресат — ИЗ ЗАПРОСА, в пределах объявленного ПОСАДКОЙ перечня,
	// сужённого тем, что объявил при выдаче сам КЛЮЧ (задача #1136).
	audience, err := u.resolveAudience(in.Client, in.RequestedAudience)
	if err != nil {
		return Output{}, clientassertion.OutcomeAudienceNotAllowed, err
	}

	// (4) Состав утверждений — из ОДНОГО объявления, тем же кодом, что и на
	// пути обратного вызова.
	claims, principal, err := u.claims.ClaimsForAssertionClient(ctx, in.Client, service.TokenHookContext{
		GrantType:     tokenpolicy.GrantTypeClientCredentials,
		OAuthClientID: in.Client.ID,
		CnfJkt:        confirmationJKT(in.Confirmation),
		CnfX5tS256:    confirmationX5T(in.Confirmation),
	})
	if err != nil {
		return Output{}, clientassertion.OutcomeIssuanceFailed, fmt.Errorf("client_token: claims: %w", err)
	}
	subject := principal.UserID
	if subject == "" {
		subject = in.Client.OwnerID
	}

	tok, err := u.signer.Sign(ctx, tokensigner.Request{
		Subject:      subject,
		Audience:     audience,
		TokenType:    tokenpolicy.TokenTypeAccess,
		TTL:          ttl,
		Confirmation: in.Confirmation,
		Claims:       claims,
	})
	if err != nil {
		return Output{}, clientassertion.OutcomeIssuanceFailed, fmt.Errorf("client_token: sign: %w", err)
	}

	return Output{
		AccessToken: tok.Token,
		TokenType:   "Bearer",
		ExpiresIn:   int(tok.ExpiresAt.Sub(tok.IssuedAt).Seconds()),
		Scope:       in.Scope,
	}, clientassertion.OutcomeAccepted, nil
}

// resolveAudience выбирает адресат выпускаемого токена.
//
// # Границы ДВЕ, и они не равноправны
//
// ВНЕШНЯЯ — перечень, объявленный посадкой: он говорит, каким поверхностям
// платформа вообще чеканит удостоверения, и страж построения требует его
// непустым. ВНУТРЕННЯЯ — перечень, объявленный заказчиком при выдаче ключа: он
// говорит, для чего заведён ЭТОТ ключ.
//
// Сужение действует ВНУТРИ внешней границы и никогда её не расширяет. Иначе
// заказчик ключа сам решал бы, кому платформа выдаёт токен: он назвал бы в поле
// выдачи произвольный адресат, и подписант выпустил бы удостоверение,
// адресованное поверхности, которую посадка не объявляла.
//
// Отказы двух границ РАЗЛИЧАЮТСЯ ТЕКСТОМ — не наружу (там ответ единый), а в
// журнале: «посадка такого адресата не объявляла» и «ключ выдавался не под этот
// адресат» чинятся в разных местах и разными людьми.
func (u *UseCase) resolveAudience(client domain.AssertionClient, requested []string) ([]string, error) {
	effective, fallback, err := u.audienceScope(client)
	if err != nil {
		return nil, err
	}
	if len(requested) == 0 {
		return []string{fallback}, nil
	}
	for _, a := range requested {
		if !allowed(u.cfg.AllowedAudiences, a) {
			return nil, fmt.Errorf("client_token: requested audience %q is not in the declared list", a)
		}
		if !allowed(effective, a) {
			return nil, fmt.Errorf(
				"client_token: requested audience %q is outside the audiences declared for client %s "+
					"at issuance (%v)", a, client.ID, client.DeclaredAudiences)
		}
	}
	return requested, nil
}

// audienceScope — множество, из которого выпуск вправе выбрать, и адресат для
// запроса, не назвавшего ни одного.
//
// # Пустое сужение означает «не объявлено», и это РЕШЕНИЕ, а не умолчание
//
// Ключ, выданный без перечня, ведёт себя ровно как прежде: внешняя граница
// остаётся единственной. Требовать перечень от каждого ключа значило бы сломать
// всякого, кто его не слал, ради величины, которой у него нет, — и сломать на
// пути, где отказ увидит машина, а не человек.
//
// # Умолчание посадки уступает объявленному ключом, а не наоборот
//
// Умолчание — величина для ключа, о своём назначении не заявившего. Пока сужение
// его допускает, оно действует без изменений (наименьший радиус для уже выданных
// ключей); когда не допускает — берётся первый объявленный ключом адресат из
// числа допущенных посадкой. Порядок здесь не произволен: перечень заказчика
// сохраняет порядок по контракту выдачи, поэтому «первый» есть его собственный
// выбор, а не наш.
//
// # Непересекающееся сужение отвергается ЗДЕСЬ, а не на выдаче ключа
//
// Состояние законное: ключ выдан под внешнюю федерацию, а посадка такого
// адресата не объявляла. Отвергать его на выдаче нельзя — перечень посадки
// меняет оператор и после неё, — а молча откатываться на перечень посадки
// нельзя тем более: это ровно то «сужение, переставшее сужать», которое задача
// #1136 и снимает.
func (u *UseCase) audienceScope(client domain.AssertionClient) ([]string, string, error) {
	if len(client.DeclaredAudiences) == 0 {
		return u.cfg.AllowedAudiences, u.cfg.DefaultAudience, nil
	}
	effective := make([]string, 0, len(client.DeclaredAudiences))
	for _, a := range client.DeclaredAudiences {
		if allowed(u.cfg.AllowedAudiences, a) && !allowed(effective, a) {
			effective = append(effective, a)
		}
	}
	if len(effective) == 0 {
		return nil, "", fmt.Errorf(
			"client_token: client %s declared audiences %v at issuance and this deployment declares none of them",
			client.ID, client.DeclaredAudiences)
	}
	if allowed(effective, u.cfg.DefaultAudience) {
		return effective, u.cfg.DefaultAudience, nil
	}
	return effective, effective[0], nil
}

func allowed(list []string, want string) bool {
	for _, a := range list {
		if a == want {
			return true
		}
	}
	return false
}

func confirmationJKT(c *tokensigner.Confirmation) string {
	if c == nil {
		return ""
	}
	return c.JKT
}

func confirmationX5T(c *tokensigner.Confirmation) string {
	if c == nil {
		return ""
	}
	return c.X5TS256
}
