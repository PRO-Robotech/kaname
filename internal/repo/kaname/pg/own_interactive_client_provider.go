// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// own_interactive_client_provider.go — ИСПОЛНИТЕЛЬ заведения и снятия
// интерактивного клиента на посадке БЕЗ внешнего поставщика личности
// (задача PRO-Robotech/kaname#313).
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ ИСПОЛНЯЕТСЯ, А ЧТО ИСПОЛНЯЕТ СХЕМА
//
// Под `external` порт `ProviderClients` зеркалит нашу строку в ЧУЖОЙ реестр:
// тот выдаёт идентификатор клиента, он же хранит его и он же сносит его вместе
// с выданным по нему. Под `own` второго реестра нет: реестр — это
// `kaname.interactive_clients`, и «зеркалить» его некуда.
//
// Поэтому у исполнителя ровно две обязанности, и обе настоящие:
//
//   - ЗАВЕДЕНИЕ чеканит идентификатор клиента и объявляет форму выдачи. Строку
//     кладёт вызывающий (`clientRepo.Insert`) сразу следом — писать её здесь
//     значило бы завести ВТОРОГО писателя одной строки;
//   - СНЯТИЕ снимает проверочное значение секрета. Всё остальное, что было
//     ключено на клиента, сносит СХЕМА: `token_families`, `consent_grants` и,
//     через составной ключ семейства, `authorization_codes` и `refresh_tokens`
//     ссылаются на `interactive_clients(client_id)` с `ON DELETE CASCADE`.
//     Повторять это запросами значило бы завести второе место об одном
//     предмете, которое разойдётся со схемой молча.
//
// ─────────────────────────────────────────────────────────────────────────────
// СЕКРЕТ НЕ ЧЕКАНИТСЯ — И ЭТО РЕШЕНИЕ, А НЕ УМОЛЧАНИЕ
//
// Собственный реестр УМЕЕТ нести проверочное значение секрета клиента
// (`interactive_clients.secret_verifier`, миграция
// `20260920175118_interactive_client_carries_its_secret_verifier.sql`), а
// прежняя дорога секрета интерактивному клиенту не чеканит вовсе: она
// регистрирует его ПУБЛИЧНЫМ, `token_endpoint_auth_method: "none"`, и её
// адаптер объявляет это инвариантом приёмки — «секрет не чеканится, значит его
// нечего вернуть, сохранить или утечь».
//
// Расхождение названо, и решено оно в пользу прежней формы — по БЕЗОПАСНОСТИ,
// не по удобству:
//
//  1. интерактивный клиент предъявляется ИЗ БРАУЗЕРА. Секрет, попавший в
//     загружаемый код, секретом не является ни при какой его длине, а его
//     наличие создаёт ровно одно новое свойство — вид защищённости, которой
//     нет;
//  2. владение здесь доказывается PKCE, и собственная церемония принимает
//     ТОЛЬКО `S256` — `plain` отвергает сама схема. Это доказательство на
//     каждую церемонию, а не одно значение на всю жизнь клиента;
//  3. чеканка секрета под `own` при её отсутствии под `external` развела бы
//     постановки по полю контракта `token_endpoint_auth_method`, которое
//     неизменяемо после заведения. Разошлись бы они молча — в ответе глагола,
//     а сказалось бы это в чужой церемонии.
//
// Поэтому `SetClientSecretVerifier` на ЭТОЙ полосе читателя не получает:
// клиент заводится публичным, колонка остаётся пустой (её умолчание), и
// «секрета нет» у способа `none` держит схема: материал у публичного клиента
// невыразим (`interactive_clients_secret_verifier_method_ck`). Полоса, у
// которой клиент КОНФИДЕНЦИАЛЕН, — свой предмет со своим полем контракта.
//
// Снятие проверочного значения читателя получает: снятие клиента не имеет
// права оставить за собой годный материал, ЧЕМ БЫ он туда ни попал.

import (
	"context"
	stderrors "errors"
	"fmt"

	"github.com/PRO-Robotech/corelib/ids"

	interactiveclient "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/interactive_client"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// ownInteractiveClientIDPrefix — приставка идентификатора клиента, ЧЕКАНЕННОГО
// НАМИ.
//
// Приставка своя, а не общая с идентификатором ресурса (`ic-`): это разные
// имена разных вещей — адрес ресурса в нашем API и имя клиента в церемонии
// OAuth. Одна приставка на оба сделала бы их неразличимыми на глаз, а на
// посадке, переехавшей с чужого поставщика, в одной колонке лежат ОБЕ
// популяции — чеканенная им и чеканенная нами, — и оператор обязан уметь
// сказать, какая перед ним.
//
// В платформенный каталог приставок она не входит и не должна: идентификатор
// клиента ресурсом не адресуется, `validate.ResourceID` его не судит.
const ownInteractiveClientIDPrefix = "oic"

// ownPublicClientAuthMethod — форма удостоверения клиента на токен-эндпоинте.
// Значение то же, что объявляет прежняя дорога: клиент ПУБЛИЧНЫЙ, владение
// доказывается PKCE. Разбор — в шапке файла.
const ownPublicClientAuthMethod = "none"

// ClientSecretStore — то, что исполнителю нужно от собственного реестра.
//
// Порт узкий и объявлен ЗДЕСЬ, у потребителя: исполнителю не нужен ни обмен
// кода, ни ротация, ни согласие, и принимать их значило бы принимать право,
// которым он не пользуется.
//
// Именован наружу, потому что его подаёт композиционный корень.
type ClientSecretStore interface {
	ClearClientSecretVerifier(ctx context.Context, clientID string) error
}

// OwnInteractiveClientProvider — исполнитель порта `ProviderClients` на
// посадке без внешнего поставщика.
type OwnInteractiveClientProvider struct {
	clients ClientSecretStore
}

// NewOwnInteractiveClientProvider — построение над реестром.
func NewOwnInteractiveClientProvider(store ClientSecretStore) *OwnInteractiveClientProvider {
	return &OwnInteractiveClientProvider{clients: store}
}

// Register чеканит идентификатор клиента и объявляет форму его выдачи.
//
// Хранилища здесь не касается НАМЕРЕННО: строку кладёт вызывающий следующим
// оператором, и второй писатель одной строки развёл бы «что записано» и «что
// возвращено». Отсюда же следует, что отказать этот глагол может только на
// негодном входе.
func (p *OwnInteractiveClientProvider) Register(
	_ context.Context, in interactiveclient.ProviderClientSpec,
) (interactiveclient.ProviderClient, error) {
	if in.Name == "" {
		return interactiveclient.ProviderClient{},
			iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument interactive_client.name: required")
	}
	if len(in.RedirectURIs) == 0 {
		return interactiveclient.ProviderClient{},
			iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument interactive_client.redirect_uris: required")
	}
	if len(in.GrantTypes) == 0 {
		return interactiveclient.ProviderClient{},
			iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument interactive_client.grant_types: required")
	}
	return interactiveclient.ProviderClient{
		ClientID: ids.NewHyphenID(ownInteractiveClientIDPrefix),
		// Форму выдачи РЕШИЛ use-case, и она возвращается дословно. Своего
		// умолчания здесь нет: умолчание адаптера — ровно то, из-за чего три
		// соседние полосы регистрации все стали означать машинную выдачу.
		GrantTypes:              append([]string(nil), in.GrantTypes...),
		TokenEndpointAuthMethod: ownPublicClientAuthMethod,
		// Круг получателей тоже решён вызывающим (Р2: он чеканится службой, а
		// не принимается полем запроса).
		Audiences: append([]string(nil), in.Audiences...),
	}, nil
}

// Deregister снимает проверочное значение секрета клиента.
//
// ИДЕМПОТЕНТЕН, и отсутствие клиента — УСПЕХ. Снятие зовётся после удаления
// строки реестра, поэтому «строки нет» — достигнутое состояние, а не неполадка;
// та же идемпотентность, с какой прежняя дорога принимает 404 поставщика.
// Отличить достигнутое состояние от неполадки хранилища позволяет признак
// отказа, а не его текст.
func (p *OwnInteractiveClientProvider) Deregister(ctx context.Context, clientID string) error {
	if p == nil || p.clients == nil {
		return fmt.Errorf("own interactive-client registry is not configured")
	}
	if clientID == "" {
		return iamerr.Wrapf(iamerr.ErrInvalidArg,
			"Illegal argument interactive_client.client_id: required")
	}
	err := p.clients.ClearClientSecretVerifier(ctx, clientID)
	if stderrors.Is(err, iamerr.ErrNotFound) {
		// Строки нет — вместе с ней схема унесла и всё, что было на неё
		// ключено: семейства выданного, коды авторизации, обновляющие токены и
		// согласия субъекта. Снимать нечего и незачем.
		return nil
	}
	return err
}
