// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package moduleroster — ОДИН набор форм идентификатора и ОДИН перечень
// личностей для табличной пробы единства признания (kaname#984, DoD п. 4).
//
// Набор живёт здесь, а не в каждой пробе, потому что проба утверждает
// РАВЕНСТВО решений разных путей на ОДНОМ входе: путь, судимый на своём наборе,
// о равенстве не свидетельствует ничего. Пути живут в разных пакетах
// (`authzguard`, обработчик решений), поэтому набор вынесен в общий пакет проб.
package moduleroster

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/corelib/grpcsrv"

	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
	"github.com/PRO-Robotech/kaname/internal/servicesan"
)

// DomainName — домен доверия набора.
const DomainName = "kacho.cloud"

// NameFormRaw — форма имени службы набора (kaname#308): учётки его записей и
// идентификаторов названы ею.
const NameFormRaw = "kacho-{service}"

// NameForm — форма имени службы набора величиной.
func NameForm() servicesan.Form { return servicesan.NewForm(NameFormRaw) }

// Domain — домен доверия набора величиной.
func Domain() grpcsrv.TrustDomain { return grpcsrv.NewTrustDomain(DomainName) }

// Entries — перечень личностей набора, как его объявила бы установка.
func Entries() []string {
	return []string{
		"kacho/kacho-api-gateway=edge",
		"kacho/kacho-vpc=module-writer",
		"kacho/kacho-compute=module-writer",
		"kacho/kacho-nlb=module-writer",
		"kacho/kacho-storage=module-writer",
		"kacho/kacho-registry=module-writer",
		"registry/kacho-registry-dp=data-plane",
	}
}

// Roster — перечень набора. Ошибка разбора — дефект набора, а не входа пробы.
func Roster(t testing.TB) moduleidentity.Roster {
	t.Helper()
	r, err := moduleidentity.Parse(NameForm(), Entries())
	if err != nil {
		t.Fatalf("набор личностей проб не разобрался: %v", err)
	}
	return r
}

// Form — одна форма предъявленного идентификатора и ожидаемое признание.
type Form struct {
	// Name — имя формы для отчёта.
	Name string
	// SAN — идентификатор листа.
	SAN string
	// Verified — лист проверен слушателем.
	Verified bool
	// Module — признаётся ли форма объявленным модулем `vpc`.
	Module bool
}

// DeclaredVPC — идентификатор объявленного модуля-владельца `vpc`.
const DeclaredVPC = "spiffe://" + DomainName + "/ns/kacho/sa/kacho-vpc"

// Forms — набор форм. Ровно одна форма признаётся: объявленная пара с
// проверенным листом. Каждая прочая меняет против неё РОВНО один факт.
func Forms() []Form {
	return []Form{
		{Name: "объявленная пара", SAN: DeclaredVPC, Verified: true, Module: true},
		{Name: "та же учётка в необъявленном пространстве", SAN: "spiffe://" + DomainName + "/ns/intruder/sa/kacho-vpc", Verified: true},
		{Name: "необъявленная учётка в объявленном пространстве", SAN: "spiffe://" + DomainName + "/ns/kacho/sa/kacho-dns", Verified: true},
		{Name: "чужой домен доверия", SAN: "spiffe://other.cloud/ns/kacho/sa/kacho-vpc", Verified: true},
		{Name: "лишний сегмент пространства", SAN: "spiffe://" + DomainName + "/ns/x/kacho/sa/kacho-vpc", Verified: true},
		{Name: "лишний сегмент учётки", SAN: DeclaredVPC + "/extra", Verified: true},
		{Name: "лист не проверен", SAN: DeclaredVPC, Verified: false},
	}
}

// Context — контекст вызова, несущий форму так, как её кладёт извлекатель
// личности сертификата.
func (f Form) Context(ctx context.Context) context.Context {
	return grpcsrv.WithCertIdentityIn(ctx, Domain(), f.SAN, f.Verified)
}

// IdentityContext — контекст вызова с проверенным листом идентификатора san.
func IdentityContext(san string) context.Context {
	return grpcsrv.WithCertIdentityIn(context.Background(), Domain(), san, true)
}
