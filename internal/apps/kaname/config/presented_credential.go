// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// presented_credential.go — настройка приёма ПРЕДЪЯВЛЕННОГО арендатором
// удостоверения на публичном слушателе и её страж старта (задача продукта
// #2077, приёмка KAN-AUTHN-1).
//
// # Почему каждая величина здесь обязательна, а не «по умолчанию»
//
// Все три невидимы на положительном пути. Незаданный адресат означает «любой»:
// токен, выпущенный для другой поверхности, проходил бы здесь. Незаданный срок
// кеша означает окно отзыва, о котором никто не решал, — а окно И ЕСТЬ этот
// срок. Выключенный приём на посадке, где иного способа назваться нет, означает
// установку, которой арендатор не может позвать ни одного из публичных RPC.
//
// Ни одно из трёх состояний не проявляется отказом: процесс поднимается, запрос
// приходит, отказ выглядит честным — и защиты либо возможности при этом нет.
//
// # Асимметрия цены
//
// Слишком строгая настройка даёт отказ В СТАРТЕ — видимый сразу, с именем
// настройки в тексте, читаемый оператором. Слишком слабая даёт принимаемый
// чужой токен, не видимый никогда. Поэтому на каждой развилке здесь выбрано
// отвергать.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/PRO-Robotech/corelib/tokenpolicy"
	"go.uber.org/multierr"
)

// PresentedCredentialConfig — приём удостоверения, предъявленного самим
// вызывающим.
type PresentedCredentialConfig struct {
	// Enabled — читает ли публичный слушатель предъявленное удостоверение.
	// Пока выключен, его настройки не требуются: страж, требующий того, чем не
	// пользуются, — отказ в старте без предмета.
	Enabled bool `mapstructure:"enabled"`
	// Audience — адресат ЭТОЙ поверхности. Токен, выданный для другой,
	// здесь не годится: адресат и тип суть свойства поверхности предъявления,
	// а не издателя.
	Audience string `mapstructure:"audience"`
	// RevocationCacheTTL — срок кеша ПОЛОЖИТЕЛЬНОГО вердикта об отзыве.
	//
	// Он же ОБЪЯВЛЕННОЕ ОКНО ОТЗЫВА: столько времени субъект с отобранным
	// правом продолжает проходить. Величина оператора, а не платформы, —
	// поэтому объявляется, а не подставляется: величина, которую построение
	// подставляет молча, предметом стража быть не может, он зелен при любом
	// входе.
	RevocationCacheTTL time.Duration `mapstructure:"revocation-cache-ttl"`
}

// revocationWindowCeiling ВЫЧИСЛЯЕТ потолок окна отзыва, а не выбирает его.
//
// Окно, дотягивающее до срока выпускаемого токена, окном быть перестаёт:
// отозванное удостоверение истекло бы раньше, чем кеш о нём забыл, и чтение
// отзыва на предъявлении стало бы неотличимо от его отсутствия. Причём
// неотличимо МОЛЧА: ряд «отвергнуто» не вырос бы, потому что токены истекают
// сами.
//
// Прежняя редакция сравнивала окно с константой, а обоснованием называла срок
// токена — то есть проверяла НЕ ТУ величину, которую объясняла. Оператор,
// объявивший короткий срок токена, проходил страж и получал ровно то состояние,
// которое обоснование описывает как невозможное.
//
// Величина берётся у того, кто её объявляет: срок выпускаемого токена — ручка
// оператора; при выключенном эндпоинте выдачи её нет, и тогда границей служит
// объявленный платформой потолок срока токена.
func revocationWindowCeiling(tokenTTL time.Duration) time.Duration {
	if tokenTTL > 0 {
		return tokenTTL
	}
	return tokenpolicy.MaxTokenTTL
}

// Validate — страж старта приёма предъявленного.
//
// Принимает настройку своей чеканки ПАРАМЕТРОМ, а не читает её из корня: две
// величины связаны по существу — читатель проверяет подпись СОБСТВЕННЫМ
// реестром ключей, и без включённой чеканки реестра не существует вовсе. Связь
// обязана проверяться там, где она есть, а не там, где о ней помнят.
//
// Каждое сообщение называет НАСТРОЙКУ и правило, и ни одно не называет
// значения: текст отказа читает оператор, а не предъявитель.
func (c PresentedCredentialConfig) Validate(signing TokenSigningConfig, tokenTTL time.Duration) error {
	if !c.Enabled {
		return nil
	}
	var errs error

	if !signing.Enabled {
		errs = multierr.Append(errs, fmt.Errorf(
			"authn.presented-credential.enabled is true while authn.token-signing.enabled is false — "+
				"the reader verifies signatures against OUR OWN key registry, and with minting off "+
				"there is no registry at all: every presentation would be refused, and refused for "+
				"a reason the operator cannot see from outside"))
	}

	if strings.TrimSpace(c.Audience) == "" {
		errs = multierr.Append(errs, fmt.Errorf(
			"authn.presented-credential.audience is empty — an unset audience means «we do not "+
				"narrow», and a token minted for any other surface of this installation would be "+
				"accepted on the public listener"))
	}

	switch {
	case c.RevocationCacheTTL <= 0:
		errs = multierr.Append(errs, fmt.Errorf(
			"authn.presented-credential.revocation-cache-ttl is not declared — this value IS the "+
				"revocation window: for that long a subject whose access was taken away keeps "+
				"passing. Refusing to start rather than choosing that window on the operator's behalf"))
	case c.RevocationCacheTTL >= revocationWindowCeiling(tokenTTL):
		errs = multierr.Append(errs, fmt.Errorf(
			"authn.presented-credential.revocation-cache-ttl %s reaches the lifetime of the tokens "+
				"it covers (%s) — a window that wide stops being a window: the revoked credential "+
				"would expire before the cache forgot it, and reading revocation on presentation "+
				"would be indistinguishable from not reading it at all, silently (the refusal "+
				"counter would not grow, because the tokens expire on their own)",
			c.RevocationCacheTTL, revocationWindowCeiling(tokenTTL)))
	}
	return errs
}

// ValidateBinding — СВЯЗЫВАНИЕ: поверхность, на которой предъявляются
// удостоверения, обязана иметь того, кто их читает (задача продукта #2191).
//
// # Почему это отдельный страж, а не строка проверки величин выше
//
// Тот судит СОГЛАСОВАННОСТЬ величин включённого читателя. Этот — ПРОТИВОРЕЧИЕ
// между двумя объявлениями: поверхность поднята, читателя нет. Половина пары
// хуже отсутствия обеих, потому что выглядит настроенной: арендатор дотягивается
// до фронта, предъявляет годное удостоверение и получает тот же отказ, что и
// предъявивший мусор, — назвать его нечем.
//
// # Антецедент — ДИЗЪЮНКЦИЯ, и каждая её половина названа
//
//   - ПОДНЯТЫЙ СОБСТВЕННЫЙ ПУБЛИЧНЫЙ ФРОНТ. Он поднимается на ЛЮБОЙ посадке —
//     его поднимает объявленный адрес, а не выбор посадки, — и всякий, кто до
//     него дотянулся, приходит обычным клиентом: модульного сертификата у
//     арендатора нет и быть не может, а нашего края перед этим фронтом нет by
//     construction. Значит предъявленное удостоверение — единственное, чем он
//     может назваться;
//   - ПОСАДКА БЕЗ ВНЕШНЕГО ПОСТАВЩИКА ЛИЧНОСТИ. Здесь требование то же и по той
//     же причине, и стояло оно прежде отдельной строкой таблицы полос. Строка
//     переехала СЮДА, а не продублирована: два стража об одном предмете
//     разошлись бы молча — и разошлись бы там, где расхождение не видно.
//
// Прежний антецедент («посадка объявлена своей») не наступал НИКОГДА: этого
// значения не выбирает ни один профиль развёртывания. Связывание существовало,
// требование не предъявлялось ни разу, и всё выглядело настроенным.
//
// # Почему отказ называет ОБЕ ручки
//
// Требование снимается любой из них — поднять читателя либо не поднимать фронт,
// — и оператор вправе выбрать сам. Отказ, называющий одну, предписывает выбор,
// которого страж не делал.
//
// # Почему только в БОЕВОЙ посадке, и чего это НЕ означает
//
// Читатель проверяет подпись собственным реестром ключей, поэтому существовать
// он может только вместе с включённой своей чеканкой. Подъём стенда собирает
// боевую посадку НЕ ОДНИМ прогоном: базовый профиль ставит службу в
// дев-посадке, где своей чеканки ещё нет, и лишь наложенный сверху боевой
// профиль включает и её, и читателя. Требование в дев-посадке отвергало бы
// промежуточный шаг подъёма — то есть требовало бы того, чего на нём не бывает
// by construction.
//
// Это НЕ значит «в дев можно фронт без читателя»: ban #16 объявляет, что всякий
// РАЗВЁРНУТЫЙ стенд работает в боевой посадке, и там пара обязательна. Дев
// остаётся только промежуточным шагом установки и внутрипроцессной фикстурой.
func (c PresentedCredentialConfig) ValidateBinding(
	productionMode bool, publicRESTEndpoint string, provider IdentityProvider,
) error {
	if c.Enabled || !productionMode {
		return nil
	}
	frontIsUp := strings.TrimSpace(publicRESTEndpoint) != ""
	postureHasNoEdge := provider == IdentityProviderOwn
	if !frontIsUp && !postureHasNoEdge {
		return nil
	}

	var errs error
	if frontIsUp {
		errs = multierr.Append(errs, fmt.Errorf(
			"api-server.rest-endpoint raises the service's OWN public REST front (%s) while "+
				"authn.presented-credential.enabled is false — whoever reaches that front comes as "+
				"an ordinary client: a tenant has no module certificate and there is no edge of "+
				"ours in front of it, so a PRESENTED credential is the only thing it can name "+
				"itself with. With no reader the front answers a good credential exactly as it "+
				"answers a malformed one, and that looks configured. Enable the reader, or do not "+
				"declare api-server.rest-endpoint",
			strings.TrimSpace(publicRESTEndpoint)))
	}
	if postureHasNoEdge {
		errs = multierr.Append(errs, fmt.Errorf(
			"%s=%s but authn.presented-credential.enabled is false — on this posture there is no "+
				"edge of ours to forward an identity and no module certificate for a person, so a "+
				"tenant has NOTHING to name itself with: every public RPC would answer an honest "+
				"and useless refusal. Enable it, or declare %s=%s",
			IdentityProviderSetting, IdentityProviderOwn,
			IdentityProviderSetting, IdentityProviderExternal))
	}
	return errs
}
