// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package registrytokenwire

import (
	"context"
	"errors"
	"strings"
	"testing"

	registrytokenuc "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/registry_token"
	"github.com/PRO-Robotech/kacho-iam/internal/tokensigner"
)

// provider_hop_has_no_subject_test.go — контур докер-токена, переведённый на СВОЮ
// чеканку, не обязан располагать дорогой к прежнему издателю.
//
// ПРЕДМЕТ. Обе точки входа контура (`Execute`, `ExecuteAnonymous`) при
// подключённом подписанте возвращаются ДО обращения к обменнику: утверждение не
// строится, обмен не производится. При этом сборка контура безусловно строила
// клиента к прежнему издателю и ОТКАЗЫВАЛА В СТАРТЕ на негодном якоре — то есть
// требовала пригодной дороги к тому, с кем на этой посадке не разговаривают.
//
// Требование без предмета опаснее лишнего кода: оно неотличимо от действующего.
// Оператор, читающий отказ, чинит адрес, по которому процесс не пойдёт ни разу.
//
// ГРАНИЦА. Требование снимается ТОЛЬКО у переведённого контура. Пока подписанта
// нет (посадка разработчика), прежний издатель — единственный производитель
// токена на этом контуре, и дорога к нему обязана быть пригодной. Это
// утверждается положительным контролем: без него проба зеленела бы на сборке,
// снявшей требование со всех.

// aSigner — непустой подписант. Читается сборкой ТОЛЬКО как признак «контур
// переведён»; ни одного его метода она не зовёт.
func aSigner() *tokensigner.Signer { return &tokensigner.Signer{} }

// unusableAnchor — путь якоря, которого нет. Ровно тот вход, на котором
// построитель клиента к издателю отказывает.
const unusableAnchor = "/nonexistent/provider-hop/ca.crt"

// TestBuild_ConvertedContourNeedsNoRouteToTheFormerIssuer — переведённый контур
// собирается, когда якорь дороги к прежнему издателю негоден.
func TestBuild_ConvertedContourNeedsNoRouteToTheFormerIssuer(t *testing.T) {
	_, err := Build(nil, BuildConfig{
		Realm:            "https://api.kacho.local/iam/token",
		Service:          "registry.kacho.local",
		HydraTokenURL:    "https://provider.invalid/oauth2/token",
		HydraTokenCAFile: unusableAnchor,
		Signer:           aSigner(),
	})
	if err != nil {
		t.Fatalf("Build() = %v, а переведённый контур к прежнему издателю не ходит: "+
			"требование пригодного якоря здесь без предмета", err)
	}
}

// TestBuild_ConvertedContourNeedsNoAddressOfTheFormerIssuer — тот же предмет с
// другой стороны: адреса нет вовсе.
func TestBuild_ConvertedContourNeedsNoAddressOfTheFormerIssuer(t *testing.T) {
	if _, err := Build(nil, BuildConfig{
		Realm:   "https://api.kacho.local/iam/token",
		Service: "registry.kacho.local",
		Signer:  aSigner(),
	}); err != nil {
		t.Fatalf("Build() = %v, а адрес прежнего издателя на переведённом контуре "+
			"не читается ни одним путём", err)
	}
}

// TestBuild_UnconvertedContourStillDemandsAUsableRoute — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ.
//
// Без него проба выше зеленела бы и на сборке, снявшей требование со ВСЕХ
// посадок, — включая ту, где прежний издатель остаётся единственным
// производителем токена.
func TestBuild_UnconvertedContourStillDemandsAUsableRoute(t *testing.T) {
	_, err := Build(nil, BuildConfig{
		Realm:            "https://api.kacho.local/iam/token",
		Service:          "registry.kacho.local",
		HydraTokenURL:    "https://provider.invalid/oauth2/token",
		HydraTokenCAFile: unusableAnchor,
		// Signer намеренно не задан: контур НЕ переведён.
	})
	if err == nil {
		t.Fatal("Build() = nil на негодном якоре у НЕпереведённого контура — " +
			"дорога к прежнему издателю там единственный производитель токена, " +
			"и её пригодность обязана проверяться при старте")
	}
}

// TestRetiredProviderExchange_RefusesAndBlamesTheIssuer — обменник, оставленный
// на месте снятой дороги, обязан ОТКАЗЫВАТЬ, а не молчать.
//
// Достижим он быть не может: обе точки входа возвращаются раньше. Но «не может»
// — свойство сегодняшнего кода, а не типа: следующая правка порядка сделает его
// достижимым молча. Отказ выбран недоступностью ИЗДАТЕЛЯ, а не негодными
// учётными данными: предъявитель к нашей провязке отношения не имеет, и
// обвинять его — значит отправить чинить своё то место, где всё исправно.
func TestRetiredProviderExchange_RefusesAndBlamesTheIssuer(t *testing.T) {
	_, err := retiredProviderExchange{}.Exchange(context.Background(), registrytokenuc.ExchangeInput{})
	if err == nil {
		t.Fatal("Exchange() = nil — снятая дорога обязана отказывать, а не выдавать")
	}
	if !errors.Is(err, registrytokenuc.ErrIssuerUnavailable) {
		t.Fatalf("Exchange() = %v, а отказ обязан читаться как недоступность издателя", err)
	}
	if !strings.Contains(err.Error(), "чеканк") {
		t.Fatalf("Exchange() = %q — отказ обязан называть состояние контура", err.Error())
	}
}

// TestProviderExchangeFor_ConvertedContourGetsTheRetiredLane — переведённый
// контур получает ОТСТАВЛЕННУЮ полосу, а не полосу к прежнему издателю.
//
// Утверждение о ВЫБОРЕ, а не о том, что сборка не упала: сборка, продолжающая
// строить дорогу к издателю и лишь глотающая ошибку якоря, прошла бы пробы выше
// и оставила бы непроверенный хоп — то есть ровно тот исход, ради недопущения
// которого отказ и заведён.
func TestProviderExchangeFor_ConvertedContourGetsTheRetiredLane(t *testing.T) {
	ex, err := providerExchangeFor(BuildConfig{
		HydraTokenURL:    "https://provider.invalid/oauth2/token",
		HydraTokenCAFile: unusableAnchor,
		Signer:           aSigner(),
	})
	if err != nil {
		t.Fatalf("providerExchangeFor() = %v, ожидался выбор без ошибки", err)
	}
	if _, ok := ex.(retiredProviderExchange); !ok {
		t.Fatalf("providerExchangeFor() дал %T — переведённый контур обязан получить "+
			"отставленную полосу, иначе дорога к издателю всё ещё строится", ex)
	}
}

// TestProviderExchangeFor_UnconvertedContourGetsTheIssuerLane — ПОЛОЖИТЕЛЬНЫЙ
// КОНТРОЛЬ выбора: без подписанта полоса обязана вести к прежнему издателю.
//
// Без этой пробы утверждение выше зеленело бы на реализации, отдающей
// отставленную полосу ВСЕГДА, — то есть на молчаливом снятии выдачи там, где
// прежний издатель единственный производитель токена.
func TestProviderExchangeFor_UnconvertedContourGetsTheIssuerLane(t *testing.T) {
	ex, err := providerExchangeFor(BuildConfig{
		HydraTokenURL: "https://provider.invalid/oauth2/token",
		// Якорь не пинится: тогда построитель клиента законно проходит, и
		// проба говорит о ВЫБОРЕ полосы, а не о чтении файла.
	})
	if err != nil {
		t.Fatalf("providerExchangeFor() = %v, ожидалась полоса к прежнему издателю", err)
	}
	if _, ok := ex.(retiredProviderExchange); ok {
		t.Fatal("providerExchangeFor() дал отставленную полосу НЕпереведённому контуру — " +
			"выдача токена на нём перестала бы работать молча")
	}
}
