// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ceremony — варианты использования церемонии OAuth 2.1
// `authorization_code` нашими силами (приёмка LINE-A-1; задача
// PRO-Robotech/kaname#423): выдача кода на эндпоинте авторизации и обмен на
// токен-эндпоинте.
//
// # Что решается здесь, а что — на поверхности
//
// Протокол исполняет церемония фундамента (`corelib/oauthceremony`). Здесь —
// то, что она не решает по построению, и порядок, в котором порты спрашиваются:
// доверие цели (клиент и адрес возврата), суждение об уровне входа, граница
// семейства, отказ клиенту без получателя, граница транзакции запроса обмена.
// Каждый вызов справочника клиентов и шва входа идёт под СВОИМ сроком, названным
// сборкой.
//
// Поверхность (`internal/handler/ceremonyhttp`) разбирает запрос, зовёт вариант
// использования и оформляет ответ: перенаправление, текст, JSON, счёт исходов.
// Держит она и то, что принадлежит самому протоколу поверхности: метод,
// однозначность параметров, пол `state`, единый тон отказов.
package ceremony

import (
	"context"
	"time"

	"github.com/PRO-Robotech/corelib/oauthceremony"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// AuthorizationEngine — церемония фундамента в части выдачи кода. Реализует
// `*oauthceremony.Ceremony`.
type AuthorizationEngine interface {
	Authorize(ctx context.Context, req oauthceremony.AuthorizationRequest) (oauthceremony.AuthorizationIntent, error)
	CompleteAuthorization(ctx context.Context, intent oauthceremony.AuthorizationIntent, grant oauthceremony.AuthorizationGrant) (oauthceremony.AuthorizationResult, error)
}

// ExchangeEngine — церемония фундамента в части обмена. Реализует
// `*oauthceremony.Ceremony`.
type ExchangeEngine interface {
	Exchange(ctx context.Context, req oauthceremony.TokenRequest) (oauthceremony.TokenResult, error)
}

var (
	_ AuthorizationEngine = (*oauthceremony.Ceremony)(nil)
	_ ExchangeEngine      = (*oauthceremony.Ceremony)(nil)
)

// Clients — справочник клиентов церемонии: тот же порт, что у движка
// (`oauthceremony.ClientDirectory`), — сверка адреса возврата не заводит второго
// источника регистрации.
type Clients interface {
	LookupClient(ctx context.Context, clientID string) (oauthceremony.ClientRegistration, error)
}

// Login — ответ шва «авторитет входа» (приёмка Р2): кто вошёл, в какой сессии,
// когда и на каком уровне. Церемония знает ЧТО предъявлено, но не ЧЕМ получено.
type Login struct {
	Subject   string
	SessionID string
	AuthTime  time.Time
	Level     string
	// ExpiresAt — срок сессии: граница семейства, выданного в ней.
	ExpiresAt time.Time
}

// LoginAuthority — шов авторитета входа. Производитель — наш вход (Ф1):
// сессия человека по носителю. found=false — «не-аутентифицирован»; ошибка —
// авторитет не ответил.
type LoginAuthority interface {
	Resolve(ctx context.Context, bearer domain.SessionBearer) (login Login, found bool, err error)
}

// RequestUnits — единица запроса обмена: погашение кода, запись выпуска и пара
// — одна транзакция хранилища, открываемая погашением (реализует
// `pg.CeremonyVaults`). settle урегулирует запрос: закрепляет погашение, если
// выдача не состоялась. Зовётся ровно один раз на каждом выходе обмена.
type RequestUnits interface {
	OpenRequest(ctx context.Context) (context.Context, func(context.Context) error)
}
