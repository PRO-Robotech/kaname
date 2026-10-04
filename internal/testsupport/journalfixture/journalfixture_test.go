// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package journalfixture

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/corelib/auth"
	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
)

// TestFixtureInitiatorIsTheComponentInitiator — ролевая настройка посева и
// контекст посева продуктовым писателем дают ОДНОГО инициатора, и строит его
// фундамент: литерал ролевой настройки не расходится с парой компонента.
func TestFixtureInitiatorIsTheComponentInitiator(t *testing.T) {
	got, err := auth.InitiatorOf(auth.SystemPrincipalFor(fixtureService, fixtureRole))
	if err != nil {
		t.Fatalf("пара компонента посева не переводится в инициатора: %v", err)
	}
	if got.String() != FixtureInitiator {
		t.Fatalf("инициатор пары компонента %q ≠ ролевой настройке %q", got, FixtureInitiator)
	}
	ctx := Ctx(t, context.Background())
	p, ok := operations.PrincipalFromContextOK(ctx)
	if !ok {
		t.Fatal("контекст посева без принципала")
	}
	if i, err := auth.InitiatorOf(p); err != nil || i.String() != FixtureInitiator {
		t.Fatalf("контекст посева даёт инициатора %q (%v), ожидался %q", i, err, FixtureInitiator)
	}
}

// TestFixtureServiceIsTheServiceOfTheComponents — служба в паре личности
// посева проб та же, что у компонентов продукта: литерал здесь выписан
// потому, что импорт пакета вариантов использования из пакета обвязки
// замкнул бы круг в пробах репозитория.
func TestFixtureServiceIsTheServiceOfTheComponents(t *testing.T) {
	if fixtureService != shared.JournalComponentService {
		t.Fatalf("служба посева проб %q ≠ службе компонентов %q", fixtureService, shared.JournalComponentService)
	}
}
