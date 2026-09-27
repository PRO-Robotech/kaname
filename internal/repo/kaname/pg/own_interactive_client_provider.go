// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// own_interactive_client_provider.go — ИСПОЛНИТЕЛЬ заведения и снятия
// интерактивного клиента на посадке БЕЗ внешнего поставщика личности
// (задачи PRO-Robotech/kaname#313, #405).
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
//   - ЗАВЕДЕНИЕ чеканит идентификатор клиента, его СЕКРЕТ и проверочное
//     значение секрета и объявляет форму выдачи. Строку — вместе с
//     проверочным значением, одним оператором — кладёт вызывающий
//     (`clientRepo.Insert`) сразу следом: писать её здесь значило бы завести
//     ВТОРОГО писателя одной строки;
//   - СНЯТИЕ снимает проверочное значение секрета. Всё остальное, что было
//     ключено на клиента, сносит СХЕМА: `token_families` ссылается на
//     `interactive_clients(client_id)` с `ON DELETE CASCADE`, а
//     `authorization_codes` и `refresh_tokens` уходят с семейством через его
//     составной ключ.
//     Повторять это запросами значило бы завести второе место об одном
//     предмете, которое разойдётся со схемой молча.
//
// ─────────────────────────────────────────────────────────────────────────────
// КЛИЕНТ КОНФИДЕНЦИАЛЕН — РЕШЕНИЕ ВЛАДЕЛЬЦА, А НЕ УМОЛЧАНИЕ
//
// Одобренная приёмка LINE-A-1 решила (Р3, строка 3 таблицы решений §6), что
// интерактивный клиент нашей церемонии КОНФИДЕНЦИАЛЬНЫЙ и доказывает себя на
// обмене кода; PKCE `S256` обязателен ВДОБАВОК, а не вместо. Приёмка
// confidential-interactive-client-secret-shown-once (#405) дала этому
// удостоверение: способ — `client_secret_basic` (Р1: его RFC 6749 §2.3.1
// обязывает поддерживать всякий сервер авторизации), секрет чеканит служба
// (Р2) и показывает ОДИН раз — в ответе вызова `Create` (Р3).
//
// Прежняя редакция этого файла заводила клиента публичным и разбирала
// конфиденциальность тремя доводами. Их разбор приёмкой #405 (Р1):
//
//  1. «секрет в браузерном коде не секрет» — верно для клиента, чей обмен идёт
//     в браузере; обмен конфиденциального клиента идёт на серверной стороне
//     потребителя, а перевод консоли на нашу церемонию — предмет LINE-A-2;
//  2. «владение доказывает PKCE» — PKCE остаётся, и остаётся обязательным:
//     секрет добавлен к нему, а не вместо него;
//  3. «посадки разойдутся по полю способа» — расходятся НЕ молча: поле
//     `token_endpoint_auth_method` ровно это и называет, под `external` оно
//     `none` и секрет пуст, под `own` — `client_secret_basic` и секрет выдан.
//
// Клиенты, заведённые под `own` ДО этого решения, остаются `none`: способ
// неизменяем после заведения. Их исход — снятие и перезаведение посевом
// стенда, а не миграция.
//
// ─────────────────────────────────────────────────────────────────────────────
// ФОРМА СЕКРЕТА
//
// Секрет — ownClientSecretBytes случайных байт из криптографического источника
// (256 бит; пол приёмки — 128, паритет с базовым удостоверением платформы и с
// полом `state` LINE-A-1), записанных base64url без дополнения. Алфавит — только
// незарезервированные знаки RFC 3986 (`A–Z a–z 0–9 - _`): движок церемонии
// снимает процентное кодирование с обеих половин заголовка Basic, и `+`
// превратился бы в пробел у клиента, не кодирующего пару.
//
// Форма базового удостоверения платформы (`credsecret`, марка `kacho_`) НЕ
// берётся, и это решение, названное вслух: марка ведёт строку в полосу приёма
// базового удостоверения на крае, а секрет клиента предъявляется только нашему
// токен-эндпоинту заголовком Basic и базовым удостоверением не является.
// Следствие тоже названо: предикат сканера утёкших удостоверений
// (`credsecret.Pattern`) секрет клиента НЕ опознаёт — строка без марки ему не
// якорь.
//
// Сорванный источник случайности — ОТКАЗ фиксированным текстом, а не секрет
// предсказуемого вида: угадываемое удостоверение хуже отсутствующего.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРОВЕРОЧНОЕ ЗНАЧЕНИЕ — ТЕМ ЖЕ ХЕШЕРОМ, ЧТО ПАРОЛИ И ПРИМАНКА
//
// Значение пишет хешер ОБЪЯВЛЕННОГО класса записи полосы входа — тот, которым
// корень пишет приманку проверяющего. Порт сверки секрета отвечает клиенту,
// которого нет, вычислением против приманки; отдельный «дешёвый» хешер под
// высокоэнтропийный секрет сделал бы отказ незаведённому клиенту дорогим, а
// заведённому — дешёвым, и время ответа перечисляло бы клиентов. Хешер
// приходит ОТ КОРНЯ; без него исполнитель не строится.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	stderrors "errors"
	"fmt"
	"io"

	"github.com/PRO-Robotech/corelib/ids"

	interactiveclient "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/interactive_client"
	"github.com/PRO-Robotech/kaname/internal/domain"
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

// ownClientSecretBytes — случайных байт в секрете клиента: 256 бит.
const ownClientSecretBytes = 32

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

// ClientSecretHasher — производитель проверочного значения секрета клиента.
// Реализует `*passwordverify.Hasher` объявленного класса записи полосы входа.
type ClientSecretHasher interface {
	Hash(secret string) (domain.LoginVerifier, error)
}

// OwnInteractiveClientProvider — исполнитель порта `ProviderClients` на
// посадке без внешнего поставщика.
type OwnInteractiveClientProvider struct {
	clients ClientSecretStore
	hasher  ClientSecretHasher
	// entropy — источник случайности секрета; nil — криптографический.
	entropy io.Reader
}

// NewOwnInteractiveClientProvider — построение над реестром и хешером.
//
// Без хешера нечем положить проверочное значение, без реестра — нечем его
// снять. Сборка ОТКАЗЫВАЕТ, а не заводит клиента без материала и не
// откатывается к публичному: отказ здесь — отказ старта корня (ban #16).
func NewOwnInteractiveClientProvider(store ClientSecretStore, hasher ClientSecretHasher) (*OwnInteractiveClientProvider, error) {
	switch {
	case store == nil:
		return nil, stderrors.New("own interactive-client executor needs the client registry " +
			"(the secret verification value would have no one to clear it)")
	case hasher == nil:
		return nil, stderrors.New("own interactive-client executor needs the secret hasher " +
			"(a confidential client would get a row without a verification value)")
	}
	return &OwnInteractiveClientProvider{clients: store, hasher: hasher}, nil
}

// Register чеканит идентификатор клиента, его секрет и проверочное значение
// секрета и объявляет форму его выдачи.
//
// Хранилища здесь не касается НАМЕРЕННО: строку вместе с проверочным значением
// кладёт вызывающий следующим оператором, и второй писатель одной строки
// развёл бы «что записано» и «что возвращено». Отказать этот глагол может на
// негодном входе и на сорванной чеканке; второй отказ — фиксированным текстом.
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
	secret, verifier, err := p.mintSecret()
	if err != nil {
		// Причина остаётся в цепочке; наружу — фиксированный текст полосы
		// INTERNAL (`shared.MapRepoErr`), без причины и без секрета.
		return interactiveclient.ProviderClient{},
			iamerr.Wrapf(iamerr.ErrInternal, "interactive client secret was not minted: %v", err)
	}
	return interactiveclient.ProviderClient{
		ClientID: ids.NewHyphenID(ownInteractiveClientIDPrefix),
		// Форму выдачи РЕШИЛ use-case, и она возвращается дословно. Своего
		// умолчания здесь нет: умолчание адаптера — ровно то, из-за чего три
		// соседние полосы регистрации все стали означать машинную выдачу.
		GrantTypes:              append([]string(nil), in.GrantTypes...),
		TokenEndpointAuthMethod: interactiveclient.AuthMethodClientSecretBasic,
		// Круг получателей тоже решён вызывающим (Р2: он чеканится службой, а
		// не принимается полем запроса).
		Audiences:      append([]string(nil), in.Audiences...),
		Secret:         secret,
		SecretVerifier: verifier,
	}, nil
}

// mintSecret — секрет из источника случайности и его проверочное значение.
// Строкой секрет живёт только внутри этой функции: наружу он уходит носителем.
func (p *OwnInteractiveClientProvider) mintSecret() (interactiveclient.ClientSecret, domain.LoginVerifier, error) {
	src := p.entropy
	if src == nil {
		src = rand.Reader
	}
	raw := make([]byte, ownClientSecretBytes)
	if _, err := io.ReadFull(src, raw); err != nil {
		return interactiveclient.ClientSecret{}, domain.LoginVerifier{}, fmt.Errorf("random source: %w", err)
	}
	value := base64.RawURLEncoding.EncodeToString(raw)
	verifier, err := p.hasher.Hash(value)
	if err != nil {
		return interactiveclient.ClientSecret{}, domain.LoginVerifier{}, fmt.Errorf("verification value: %w", err)
	}
	secret, err := interactiveclient.NewClientSecret(value)
	if err != nil {
		return interactiveclient.ClientSecret{}, domain.LoginVerifier{}, err
	}
	return secret, verifier, nil
}

// Deregister снимает проверочное значение секрета клиента.
//
// ИДЕМПОТЕНТЕН, и отсутствие клиента — УСПЕХ. Снятие зовётся после удаления
// строки реестра, поэтому «строки нет» — достигнутое состояние, а не неполадка;
// та же идемпотентность, с какой прежняя дорога принимает 404 поставщика.
// Отличить достигнутое состояние от неполадки хранилища позволяет признак
// отказа, а не его текст.
//
// Материал живёт только колонкой строки, и строку уносит глагол `Delete`, так
// что обычно снимать здесь уже нечего; вызов остаётся, потому что снятие
// клиента не имеет права оставить за собой годный материал, ЧЕМ БЫ он туда ни
// попал.
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
		// ключено: семейства выданного, коды авторизации и обновляющие токены.
		// Снимать нечего и незачем.
		return nil
	}
	return err
}
