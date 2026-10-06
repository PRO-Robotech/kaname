// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package seed_test

// current_authz_revision_contract_test.go — производитель токена версии прав:
// метод `InternalIAMService/CurrentAuthzRevision{}` → `{authz_rev}` (приёмка
// NTF-3, kacho#2918, Р30 «Производитель токена», редакция 38; сценарий
// NTF3-179 (г) в части контракта и каталога прав; §3 шаг (14); полоса K1).
//
// Утверждается контракт и каталог, а не поведение: поведение — круг
// вызывающих и полнота снимка — держит проба корня
// `cmd/kaname/current_authz_revision_integration_test.go`.
//
// Круг вызывающих — «тот же, что `RegisterResource`» (Р30), поэтому запись
// каталога сравнивается с записью `RegisterResource` целиком, а не с
// выписанными пробой значениями: выписанное разошлось бы с кругом молча.

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
)

const (
	carService    = "kaname.cloud.iam.v1.InternalIAMService"
	carMethod     = "CurrentAuthzRevision"
	carFQN        = carService + "/" + carMethod
	carControlFQN = carService + "/RegisterResource"
)

// TestNTF3179_CurrentAuthzRevisionIsAnInternalContractMethod — метод объявлен
// на внутренней службе доступа, без HTTP-привязки (`ban06`), запрос без полей,
// ответ несёт строковое `authz_rev` — текстовую форму полного снимка.
func TestNTF3179_CurrentAuthzRevisionIsAnInternalContractMethod(t *testing.T) {
	sd, ok := rdServiceDescriptor(t, carService)
	if !ok {
		t.Fatalf("контроль: служба %s не найдена в реестре дескрипторов — реестр не загружен", carService)
	}
	if ctl := sd.Methods().ByName("RegisterResource"); ctl == nil || rdHasHTTP(ctl) {
		t.Fatalf("контроль: %s без HTTP-привязки не найден — различение сломано", carControlFQN)
	}

	m := sd.Methods().ByName(carMethod)
	if m == nil {
		t.Fatalf("метод %s не объявлен контрактом (Р30 «Производитель токена»: токен R_E производит служба "+
			"доступа методом %s{} → {authz_rev}); методов у службы %d", carFQN, carMethod, sd.Methods().Len())
	}
	if rdHasHTTP(m) {
		t.Fatalf("метод %s несёт HTTP-привязку — он только на внутреннем слушателе (ban06)", carFQN)
	}
	if n := m.Input().Fields().Len(); n != 0 {
		t.Fatalf("запрос %s несёт %d полей, а объявлен пустым: %s{}", carFQN, n, carMethod)
	}
	f := m.Output().Fields().ByName("authz_rev")
	if f == nil {
		t.Fatalf("ответ %s (%s) не несёт поля authz_rev", carFQN, m.Output().FullName())
	}
	if f.Kind() != protoreflect.StringKind || f.Cardinality() == protoreflect.Repeated {
		t.Fatalf("поле authz_rev ответа %s — %s %s, ожидалась одиночная строка (текстовая форма снимка)",
			carFQN, f.Cardinality(), f.Kind())
	}
}

// TestNTF3179_CurrentAuthzRevisionIsInTheCatalogInTheRegistrationCircle — запись
// каталога прав метода есть и совпадает с записью `RegisterResource` во всём,
// кроме имени: круг вызывающих — модули-владельцы видов (Р30).
func TestNTF3179_CurrentAuthzRevisionIsInTheCatalogInTheRegistrationCircle(t *testing.T) {
	reg, err := seed.LoadPermissionRegistry(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("фикстура: каталог прав не загружен: %v", err)
	}
	ctl, ok := reg.LookupFQN(carControlFQN)
	if !ok {
		t.Fatalf("контроль: %s нет в каталоге — поиск по каталогу сломан (записей %d)", carControlFQN, len(reg.All()))
	}
	got, ok := reg.LookupFQN(carFQN)
	if !ok {
		t.Fatalf("метода %s нет в каталоге прав (Р30: каталог прав метода — круг RegisterResource); записей %d",
			carFQN, len(reg.All()))
	}
	ctl.FQN, got.FQN = "", ""
	if got != ctl {
		t.Fatalf("запись каталога %s расходится с кругом RegisterResource:\n  метод:   %+v\n  контроль: %+v",
			carFQN, got, ctl)
	}
}
