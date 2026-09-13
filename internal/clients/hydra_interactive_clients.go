// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package clients

// hydra_interactive_clients.go — adapter satisfying the interactive-client
// use-case's provider port, on top of the existing HydraAdminClient.
//
// WHY A THIN NAMED ADAPTER AND NOT THE ADMIN CLIENT DIRECTLY. The use-case must
// not depend on the provider's HTTP shape (Clean Architecture), and the
// translation has one substantive job: it forwards the grant types the use-case
// DECIDED instead of letting the admin client's default apply. That default is
// `client_credentials`, and it is exactly how the three pre-existing
// registration paths all came to mean "machine" — the shape was chosen by an
// adapter default rather than by a caller.

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	interactiveclient "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/interactive_client"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// classifyProviderCall ставит на отказ поставщика признак ПОВТОРИМОСТИ.
//
// # Зачем, если текст и так фиксированный
//
// Утечки здесь нет — текст на проводе опакован общим переводчиком. Неверно
// другое: без признака отказ уходит в ветвь по умолчанию и приходит внутренней
// ошибкой, то есть вызывающий не отличает «поставщик недоступен, повтори» от
// «служба сломана». На крае это 500 вместо 503, а на 500 клиент НЕ повторяет
// Норма контракта: мутация при недоступном соседе отвечает `UNAVAILABLE`
// (fail-closed), а не внутренней ошибкой — первое повторяемо, второе нет.
// Три соседние полосы к тому же поставщику отвечают
// недоступностью явно; четвёртая не отвечала, и это никем не решалось
// (задача #2481).
//
// # Почему это РАЗБОР, а не сплошная пометка
//
// Объявить повторяемым всё подряд — беда той же величины с другой стороны:
// отвергнутый вход повтором не лечится, потому что одинаковый повтор не меняет
// ни одного из входов, и вызывающий повторял бы вечно. Поэтому полос две:
//
//   - неполадка ДОСТАВКИ (не дозвонились, оборвалось, вышел срок) и отказ
//     САМОГО поставщика уровня 5xx — преходящие, признак ставится;
//   - отвергнутый вход (4xx, включая 409, на котором стоит идемпотентность
//     создания) — терминален и остаётся тем, чем был.
//
// Отдельно: «поставщика в этой установке нет вовсе» — тоже НЕ недоступность.
// Это выбор оператора, а не неполадка, и повтор его не изменит.
//
// # Граница названа
//
// Разбор применяется на полосе интерактивного клиента. У выдачи ключа СУ своя
// обёртка того же вызова, и она объявляет недоступностью ЛЮБОЙ отказ
// поставщика — то есть 4xx там тоже повторяем. Сведение двух решений в одно —
// свой предмет: оно меняет наблюдаемый исход чужой полосы.
func classifyProviderCall(err error) error {
	if err == nil {
		return nil
	}
	// Уже названо — не переименовываем: второе имя того же предмета.
	if errors.Is(err, iamerr.ErrUnavailable) {
		return err
	}
	// Дороги нет — выбор оператора, не неполадка.
	if errors.Is(err, ErrNoExternalIdentityProvider) {
		return err
	}
	var apiErr *HydraAPIError
	if errors.As(err, &apiErr) {
		if apiErr.StatusCode >= 500 {
			return fmt.Errorf("%w: %w", iamerr.ErrUnavailable, err)
		}
		// 4xx — вход отвергнут; повтор его не изменит. Цепочка остаётся целой:
		// на `*HydraAPIError` стоит распознавание 409.
		return err
	}
	// Неполадка доставки: запрос не дошёл либо ответ не вернулся. Признак берётся
	// по ТИПУ ошибки транспорта, а не по тексту: текст несёт адрес узла и
	// меняется с каждой библиотекой.
	var urlErr *url.Error
	if errors.As(err, &urlErr) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return fmt.Errorf("%w: %w", iamerr.ErrUnavailable, err)
	}
	return err
}

// InteractiveClientProvider adapts HydraAdminClient to the use-case port.
type InteractiveClientProvider struct {
	admin *HydraAdminClient
}

// NewInteractiveClientProvider — constructor. A nil admin client is refused at
// call time rather than dereferenced: an unwired provider must fail closed, not
// panic the listener.
func NewInteractiveClientProvider(admin *HydraAdminClient) *InteractiveClientProvider {
	return &InteractiveClientProvider{admin: admin}
}

// Register — creates the authorization-code client at the provider.
//
// `response_types` is set to `code` explicitly. Leaving the admin client's
// default (`token`) would register a client the provider refuses to run a code
// ceremony for — the registration would succeed and the ceremony would fail
// later, at the point furthest from the cause.
func (p *InteractiveClientProvider) Register(
	ctx context.Context, in interactiveclient.ProviderClientSpec,
) (interactiveclient.ProviderClient, error) {
	if p == nil || p.admin == nil {
		return interactiveclient.ProviderClient{}, errors.New("identity provider client is not configured")
	}
	out, err := p.admin.CreateOAuthClient(ctx, CreateOAuthClientRequest{
		ClientName:             in.Name,
		GrantTypes:             in.GrantTypes,
		ResponseTypes:          []string{"code"},
		RedirectURIs:           in.RedirectURIs,
		PostLogoutRedirectURIs: in.PostLogoutRedirectURIs,
		Audience:               in.Audiences,
		// A public client with proof of possession: no secret is minted, so
		// there is no secret to return, store, or leak. Inv. 6 of the acceptance
		// is satisfied by construction rather than by remembering to redact.
		TokenEndpointAuthMethod: "none",
	})
	if err != nil {
		return interactiveclient.ProviderClient{}, classifyProviderCall(err)
	}
	return interactiveclient.ProviderClient{
		ClientID:                out.ClientID,
		GrantTypes:              out.GrantTypes,
		TokenEndpointAuthMethod: out.TokenEndpointAuthMethod,
		Audiences:               out.Audience,
	}, nil
}

// Deregister — removes the client at the provider. Used both on Delete and as
// the compensation when the row insert fails after a successful registration.
func (p *InteractiveClientProvider) Deregister(ctx context.Context, providerClientID string) error {
	if p == nil || p.admin == nil {
		return errors.New("identity provider client is not configured")
	}
	return classifyProviderCall(p.admin.DeleteOAuthClient(ctx, providerClientID))
}
