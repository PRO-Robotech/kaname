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

// ValidateBinding — СВЯЗЫВАНИЕ: боевой старт обязан иметь того, кто читает
// удостоверение, предъявленное самим вызывающим (задача продукта #2191).
//
// # Почему это отдельный страж, а не строка проверки величин выше
//
// Тот судит СОГЛАСОВАННОСТЬ величин включённого читателя. Этот — отсутствие
// читателя там, где иного способа назваться у арендатора нет: нашего края,
// чтобы передать личность, в его установке не существует, а модульного
// сертификата у человека не бывает. Без читателя служба поднимается и отвечает
// на годное удостоверение тем же отказом, что на мусор, — и это выглядит
// настроенным.
//
// # Антецедент — боевой режим, и только он
//
// Прежде антецедент был ДИЗЪЮНКЦИЕЙ: «поднят собственный публичный фронт»
// либо «посадка без внешнего поставщика». Внешнего поставщика у службы больше
// нет (kaname#363), вторая половина наступает на всяком боевом старте, и первая
// её больше ничем не расширяет. Совета «не поднимайте фронт», прежде
// снимавшего требование, в тексте больше нет: он послал бы оператора за вторым
// отказом.
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
// Это НЕ значит «в дев можно без читателя»: ban #16 объявляет, что всякий
// РАЗВЁРНУТЫЙ стенд работает в боевой посадке, и там читатель обязателен. Дев
// остаётся только промежуточным шагом установки и внутрипроцессной фикстурой.
func (c PresentedCredentialConfig) ValidateBinding(productionMode bool) error {
	if c.Enabled || !productionMode {
		return nil
	}
	return fmt.Errorf(
		"production mode: authn.presented-credential.enabled is false — there is no edge of ours " +
			"to forward an identity and no module certificate for a person, so a tenant has NOTHING " +
			"to name itself with: every public RPC would answer an honest and useless refusal. Enable it")
}
