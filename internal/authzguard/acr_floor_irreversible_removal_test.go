// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// acr_floor_irreversible_removal_test.go — снятие личности и сервисного
// аккаунта требует того же уровня сессии, что обратимые операции над тем же
// субъектом (задача kaname#720; приёмка
// `docs/engineering/acceptance/own-account-and-identity-are-removed-in-order.md`
// ред. 4, Р12, KN664-44, KN664-45, KN664-49 и их близнецы уровня «2»).
//
// # ЧТО УТВЕРЖДАЕТСЯ
//
// Две вещи, и обе — над НАСТОЯЩИМ встроенным каталогом прав службы, тем же,
// который край порождает из контракта:
//
//	(1) ОТНОШЕНИЕ (Р12): необратимое снятие не дешевле обратимых операций над
//	    тем же субъектом. Пол `UserService.Delete` не ниже полов `Block`,
//	    `Unblock`, `ResetSecondFactor`; пол `ServiceAccountService.Delete` — не
//	    ниже `Disable` и `Enable`. Отношение, а не литерал: литерал повторял бы
//	    то, что читает, и согласился бы с любой редакцией контракта.
//	(2) ИСХОД ПРАВИЛА ПОВЫШЕНИЯ (`grpcsrv.EvaluateStepUp`, одно на оба замка):
//	    субъект-человек с уровнем «1» получает отказ по уровню, с уровнем «2» —
//	    проход. Администратор облака — тот же субъект-человек: у правила нет оси
//	    «кто вызывает», освобождён только машинный принципал, поэтому KN664-45
//	    утверждается тем же входом, что KN664-44, и это сказано, а не умолчано.
//
// # ЧЕГО ЗДЕСЬ НЕТ
//
// Ответ края на недостаток уровня (`401`, `code` 16, вызов с `acr_values`) —
// дом платформы: его производит край до пересылки службе. Проба судит вход
// этого ответа — пол каталога и вердикт общего правила над ним.
//
// # СПОСОБНОСТЬ ПАДАТЬ
//
// Предикат отношения вынесен функцией; инъекция ниже зовёт ТОТ ЖЕ предикат с
// законным близнецом и с каждым видом дефекта.
package authzguard

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"testing"

	"github.com/PRO-Robotech/corelib/acrlevel"
	"github.com/PRO-Robotech/corelib/grpcsrv"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
)

// irreversibleRemoval — необратимое снятие субъекта и его обратимые соседи.
type irreversibleRemoval struct {
	removal    string
	reversible []string
}

var irreversibleRemovals = []irreversibleRemoval{
	{
		removal: "kaname.cloud.iam.v1.UserService/Delete",
		reversible: []string{
			"kaname.cloud.iam.v1.UserService/Block",
			"kaname.cloud.iam.v1.UserService/Unblock",
			"kaname.cloud.iam.v1.UserService/ResetSecondFactor",
		},
	},
	{
		removal: "kaname.cloud.iam.v1.ServiceAccountService/Delete",
		reversible: []string{
			"kaname.cloud.iam.v1.ServiceAccountService/Disable",
			"kaname.cloud.iam.v1.ServiceAccountService/Enable",
		},
	},
}

// irreversibleRemovalFindings — предикат отношения (1) по ОДНОМУ каталогу.
func irreversibleRemovalFindings(lookup ACRRequirementLookup) []string {
	var out []string
	for _, r := range irreversibleRemovals {
		floor := lookup.RequiredACRMin(r.removal)
		if acrlevel.Rank(floor) == 0 {
			out = append(out, fmt.Sprintf("%s: пола нет (%q)", r.removal, floor))
		}
		for _, n := range r.reversible {
			nf := lookup.RequiredACRMin(n)
			if acrlevel.Rank(nf) == 0 {
				out = append(out, fmt.Sprintf("%s: у обратимого соседа пола нет (%q) — "+
					"отношение сказано ни о чём", n, nf))
				continue
			}
			if acrlevel.Rank(floor) < acrlevel.Rank(nf) {
				out = append(out, fmt.Sprintf("необратимое %s требует %q, обратимое %s — %q: "+
					"необратимое снятие дешевле обратимой операции над тем же субъектом",
					r.removal, floor, n, nf))
			}
		}
	}
	sort.Strings(out)
	return out
}

func loadRealACRCatalog(t *testing.T) *seed.PermissionRegistry {
	t.Helper()
	reg, err := seed.LoadPermissionRegistry(context.Background(),
		slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: каталог прав не прочитан: %v", err)
	}
	return reg
}

// TestACRFloorIrreversibleRemovalIsNotCheaperThanReversible — Р12, отношение (1).
func TestACRFloorIrreversibleRemovalIsNotCheaperThanReversible(t *testing.T) {
	reg := loadRealACRCatalog(t)
	for _, r := range irreversibleRemovals {
		t.Logf("перепись: %s → required_acr_min=%q", r.removal, reg.RequiredACRMin(r.removal))
		for _, n := range r.reversible {
			t.Logf("перепись:   сосед %s → required_acr_min=%q", n, reg.RequiredACRMin(n))
		}
	}
	if f := irreversibleRemovalFindings(reg); len(f) > 0 {
		t.Fatalf("необратимое снятие стоит дешевле обратимых соседей — %d находк(и):\n  %v\n\n"+
			"Пол объявляет контракт (`required_acr_min` у `rpc Delete` в "+
			"proto/kaname/cloud/iam/v1/user_service.proto и service_account_service.proto); "+
			"копия каталога службы порождается из него (kaname#720, Р12).", len(f), f)
	}
}

// TestACRFloorIrreversibleRemovalStepUpVerdict — KN664-44, 45, 49 и близнецы
// уровня «2»: исход общего правила повышения над полом каталога.
func TestACRFloorIrreversibleRemovalStepUpVerdict(t *testing.T) {
	reg := loadRealACRCatalog(t)
	cases := []struct {
		id, fqn, who string
	}{
		{"KN664-44", "kaname.cloud.iam.v1.UserService/Delete", "сам человек"},
		{"KN664-45", "kaname.cloud.iam.v1.UserService/Delete", "администратор облака"},
		{"KN664-49", "kaname.cloud.iam.v1.ServiceAccountService/Delete", "администратор аккаунта"},
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			required := reg.RequiredACRMin(c.fqn)
			verdict := func(acr string) grpcsrv.StepUpVerdict {
				// Субъект-человек: у правила нет оси «кто вызывает», и
				// администратор облака входит им же (исключение — только машина).
				return grpcsrv.EvaluateStepUp(grpcsrv.StepUpInput{
					PrincipalType: "user", PresentedACR: acr, RequiredACR: required,
				})
			}
			if got := verdict("1"); got != grpcsrv.StepUpDenyACR {
				t.Errorf("%s (%s): %s сессией уровня «1» при поле каталога %q — вердикт %d, "+
					"ожидался отказ по уровню (StepUpDenyACR)", c.id, c.who, c.fqn, required, got)
			}
			if got := verdict("2"); got != grpcsrv.StepUpAllow {
				t.Errorf("%s близнец (%s): %s сессией уровня «2» при поле каталога %q — вердикт %d, "+
					"ожидался проход", c.id, c.who, c.fqn, required, got)
			}
		})
	}
}

// TestACRFloorIrreversibleRemovalPredicateCanFail — инъекция с законным близнецом.
func TestACRFloorIrreversibleRemovalPredicateCanFail(t *testing.T) {
	legal := fakeACRCatalog{}
	for _, r := range irreversibleRemovals {
		legal[r.removal] = "2"
		for _, n := range r.reversible {
			legal[n] = "2"
		}
	}
	if f := irreversibleRemovalFindings(legal); len(f) != 0 {
		t.Fatalf("законное решение объявлено находкой: %v", f)
	}
	clone := func() fakeACRCatalog {
		c := fakeACRCatalog{}
		for k, v := range legal {
			c[k] = v
		}
		return c
	}

	t.Run("снятие личности дешевле блокировки", func(t *testing.T) {
		bad := clone()
		bad[irreversibleRemovals[0].removal] = "1"
		f := irreversibleRemovalFindings(bad)
		if len(f) != len(irreversibleRemovals[0].reversible) {
			t.Fatalf("ожидалось %d находки (по одной на соседа), получено %d: %v",
				len(irreversibleRemovals[0].reversible), len(f), f)
		}
	})
	t.Run("снятие сервисного аккаунта без пола", func(t *testing.T) {
		bad := clone()
		bad[irreversibleRemovals[1].removal] = ""
		f := irreversibleRemovalFindings(bad)
		// пол снят: одна находка «пола нет» и по одной на каждого соседа
		if want := 1 + len(irreversibleRemovals[1].reversible); len(f) != want {
			t.Fatalf("ожидалось %d находки, получено %d: %v", want, len(f), f)
		}
	})
	t.Run("сосед без пола — отношение ни о чём", func(t *testing.T) {
		bad := clone()
		bad[irreversibleRemovals[1].reversible[0]] = ""
		if f := irreversibleRemovalFindings(bad); len(f) != 1 {
			t.Fatalf("ожидалась одна находка, получено %d: %v", len(f), f)
		}
	})
}
