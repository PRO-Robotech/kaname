// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// public_level_two_second_lock_test.go — пол «2» у трёх глаголов ключа доступа
// держит САМА служба, независимо от края (задача kaname#747; приёмка
// `docs/engineering/acceptance/level-two-is-enrolled-at-level-two.md`, Р3).
//
// # ЧТО УТВЕРЖДАЕТСЯ
//
// Глаголы `AccessKeyService/BeginRegistration`, `FinishRegistration`, `Revoke`
// живут на ПУБЛИЧНОМ слушателе, и до него доходят два пути:
//
//	(а) через край: проверенный лист края, личность и уровень — переданными
//	    метаданными доверенного отправителя;
//	(б) мимо края: удостоверение, предъявленное самим вызывающим и проверенное
//	    службой целиком.
//
// На обоих путях человек с уровнем «1» получает указание повысить уровень до
// «2», не доходя до обработчика, а с уровнем «2» проходит. Пол читается у
// встроенного каталога службы, а не у копии края: каталог края может отставать
// (так было в kacho@1266 — там у трёх глаголов «1»), и проход по пути (а)
// тогда держался бы только на крае.
//
// # ЗАКОННЫЕ БЛИЗНЕЦЫ
//
//   - уровень «2» на тех же глаголах — проход (меняется один факт: уровень);
//   - `AccessKeyService/List` с полом «1» и уровнем «1» через край — проход
//     (меняется один факт: глагол);
//   - машинный принципал через край — проход: освобождение решает общее
//     правило платформы, а не эта проба.
//
// # СПОСОБНОСТЬ ПАДАТЬ
//
// До правки ветвь края в политике вызывающего отвечала `nil` на любой глагол —
// случай «через край, уровень «1»» красный по каждому из трёх глаголов.
package authzguard

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/acrlevel"
	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/callerorigin"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// kn747PublicVerbs — полные имена трёх глаголов на проводе.
var kn747PublicVerbs = []string{
	"/" + kn747BeginRegistration,
	"/" + kn747FinishRegistration,
	"/" + kn747Revoke,
}

const kn747ListVerb = "/kaname.cloud.iam.v1.AccessKeyService/List"

func kn747PublicPolicy(t *testing.T, prod bool) *PublicCallerPolicy {
	t.Helper()
	return NewPublicCallerPolicy(prod, PublicPeerCallableRPCs(), loadRealACRCatalog(t), callerorigin.IsPresentedCredential).WithModuleRoster(testModuleRoster())
}

// presentedCredentialCtx — запрос, чью личность назвало удостоверение,
// предъявленное самим вызывающим (путь мимо края).
func presentedCredentialCtx(principalType, acr string) context.Context {
	ctx := callerorigin.With(context.Background(), callerorigin.PresentedCredential)
	ctx = callerorigin.WithAssurance(ctx, acr)
	return operations.WithPrincipal(ctx, operations.Principal{Type: principalType, ID: "sub-kn747"})
}

// requireStepUpToTwo — отказ — указание повысить уровень до «2» с уровня «1»,
// с вызовом.
func requireStepUpToTwo(t *testing.T, err error, what string) {
	t.Helper()
	requireStepUpToTwoFrom(t, err, what, "1")
}

// requireStepUpToTwoFrom — отказ — указание повысить уровень до «2», и вызов
// называет засчитанный службой уровень presented: по нему видно, какой уровень
// служба ПРИНЯЛА, а не только то, что она отказала.
func requireStepUpToTwoFrom(t *testing.T, err error, what, presented string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: служба пропустила вызов на полу «2» — пол держит только край", what)
	}
	st := status.Convert(err)
	if st.Code() != codes.Unauthenticated || st.Message() != iamerr.TextStepUpRequired {
		t.Fatalf("%s: отказ не той формы — код %s, текст %q", what, st.Code(), st.Message())
	}
	var su *stepUpRequired
	if !errors.As(err, &su) {
		t.Fatalf("%s: отказ не несёт вызова повышения: %v", what, err)
	}
	if want := iamerr.StepUpChallenge("2", presented); su.challenge != want {
		t.Fatalf("%s: вызов %q, ожидался %q", what, su.challenge, want)
	}
}

func TestKN747_ServiceHoldsLevelTwoOnKeyVerbsThroughTheEdge(t *testing.T) {
	p := kn747PublicPolicy(t, true)
	reg := loadRealACRCatalog(t)
	for _, verb := range kn747PublicVerbs {
		// Фикстура раньше предмета: пол каталога обязан быть «2».
		if got := reg.RequiredACRMin(verb[1:]); got != "2" {
			t.Fatalf("НЕ ВЫПОЛНИЛОСЬ: у %s в каталоге пол %q, а не «2»", verb, got)
		}
		t.Run(verb, func(t *testing.T) {
			requireStepUpToTwo(t, p.allow(gatewayCallerCtx("user", "1"), verb), "через край, уровень «1»")
			if err := p.allow(gatewayCallerCtx("user", "2"), verb); err != nil {
				t.Fatalf("через край, уровень «2»: отказ %v", err)
			}
			if err := p.allow(gatewayCallerCtx("service_account", ""), verb); err != nil {
				t.Fatalf("через край, машинный принципал: отказ %v — освобождение решает общее правило", err)
			}
		})
	}
	// Близнец по глаголу: пол «1» — уровень «1» проходит.
	if err := p.allow(gatewayCallerCtx("user", "1"), kn747ListVerb); err != nil {
		t.Fatalf("через край, %s уровнем «1»: отказ %v", kn747ListVerb, err)
	}
}

func TestKN747_ForwardedLevelCountsOnlyFromATrustedForwarder(t *testing.T) {
	p := kn747PublicPolicy(t, true)
	for _, verb := range kn747PublicVerbs {
		ctx := grpcsrv.WithCertIdentityIn(context.Background(), grpcsrv.NewTrustDomain("kacho.cloud"), gatewaySAN, true)
		ctx = grpcsrv.WithTrustedPrincipal(ctx, operations.Principal{Type: "user", ID: "sub-kn747"}, false)
		ctx = grpcsrv.WithTrustedACR(ctx, "2", false)
		// Уровень от недоверенного отправителя не засчитан вовсе: указание
		// называет засчитанным «0», а не «2» и не «1».
		requireStepUpToTwoFrom(t, p.allow(ctx, verb), verb+": недоверенный отправитель", "0")
	}
}

func TestKN747_ServiceHoldsLevelTwoOnKeyVerbsWithoutTheEdge(t *testing.T) {
	p := kn747PublicPolicy(t, true)
	for _, verb := range kn747PublicVerbs {
		t.Run(verb, func(t *testing.T) {
			requireStepUpToTwo(t, p.allow(presentedCredentialCtx("user", "1"), verb), "мимо края, уровень «1»")
			if err := p.allow(presentedCredentialCtx("user", "2"), verb); err != nil {
				t.Fatalf("мимо края, уровень «2»: отказ %v", err)
			}
		})
	}
}

// ─── kaname#767: второй замок у КАЖДОГО публичного глагола с полом ──────────
//
// # ЧТО УТВЕРЖДАЕТСЯ
//
// Перепись берётся у НАСТОЯЩЕГО встроенного каталога службы: всякая запись
// домена `kaname.cloud.iam.v1.`, чья служба смонтирована на публичном слушателе
// (имя без префикса `Internal` — ban #6: внутренние на :9091), с полом выше «0».
// По каждой записи переписи одно из двух, третьего нет:
//
//   - второй замок держит пол: через край уровнем на ступень ниже пола —
//     указание повысить уровень с вызовом, называющим пол и засчитанный уровень;
//     уровнем, равным полу, — проход; машинный принципал — проход (освобождение
//     решает общее правило платформы);
//   - глагол назван в изъятии [PublicGatewayFloorExemptRPCs] с основанием, и
//     край на нём проходит без суждения о поле.
//
// # ЗАКОННЫЕ БЛИЗНЕЦЫ
//
// Уровень, равный полу, — меняется один факт (уровень) против отказа. Глагол
// без пола (`AccessKeyService/BeginAssertion`) уровнем «0» — проход: меняется
// один факт (пол).
//
// # СПОСОБНОСТЬ ПАДАТЬ
//
// До правки ветвь края судила пол лишь у трёх глаголов ключа: уровень ниже пола
// проходил на каждом из прочих — красное по каждой записи переписи, кроме трёх.

// kn767PublicFloored — перепись: публичные глаголы службы с полом выше «0»,
// полным именем на проводе, с полом каталога.
func kn767PublicFloored(t *testing.T) (rows int, floored map[string]string) {
	t.Helper()
	reg := loadRealACRCatalog(t)
	floored = map[string]string{}
	all := reg.All()
	for _, e := range all {
		svc, ok := strings.CutPrefix(e.FQN, "kaname.cloud.iam.v1.")
		if !ok || strings.HasPrefix(svc, "Internal") {
			continue
		}
		if acrlevel.Rank(e.RequiredACRMin) > 0 {
			floored["/"+e.FQN] = e.RequiredACRMin
		}
	}
	return len(all), floored
}

// kn767Below — уровень на ступень ниже пола, строкой каталога.
func kn767Below(floor string) string { return strconv.Itoa(acrlevel.Rank(floor) - 1) }

func TestKN767_EveryFlooredPublicVerbIsHeldByTheServiceThroughTheEdge(t *testing.T) {
	rows, floored := kn767PublicFloored(t)
	// Предпосылка обхода раньше предмета: пустая перепись — «не выполнилось», а
	// не «нарушений нет»; три глагола ключа обязаны в неё попасть.
	if len(floored) == 0 {
		t.Fatalf("НЕ ВЫПОЛНИЛОСЬ: перепись пуста — записей каталога %d, публичных с полом 0", rows)
	}
	for _, verb := range kn747PublicVerbs {
		if _, ok := floored[verb]; !ok {
			t.Fatalf("НЕ ВЫПОЛНИЛОСЬ: %s нет в переписи — обход не тот", verb)
		}
	}
	exempt := PublicGatewayFloorExemptRPCs()
	p := kn747PublicPolicy(t, true)
	verbs := make([]string, 0, len(floored))
	for v := range floored {
		verbs = append(verbs, v)
	}
	sort.Strings(verbs)
	locked := 0
	for _, verb := range verbs {
		floor := floored[verb]
		if why, ok := exempt[verb]; ok {
			if strings.TrimSpace(why) == "" {
				t.Errorf("%s: изъятие без основания", verb)
			}
			// Изъятие исполнено: край проходит без суждения о поле даже без
			// переданного уровня и вида принципала.
			if err := p.allow(gatewayCallerCtx("", ""), verb); err != nil {
				t.Errorf("%s: изъят, но служба отказала краю: %v", verb, err)
			}
			continue
		}
		locked++
		t.Run(verb, func(t *testing.T) {
			below := kn767Below(floor)
			err := p.allow(gatewayCallerCtx("user", below), verb)
			if err == nil {
				t.Fatalf("через край уровнем %q при поле %q: служба пропустила — пол держит только край", below, floor)
			}
			st := status.Convert(err)
			if st.Code() != codes.Unauthenticated || st.Message() != iamerr.TextStepUpRequired {
				t.Fatalf("отказ не той формы — код %s, текст %q", st.Code(), st.Message())
			}
			var su *stepUpRequired
			if !errors.As(err, &su) {
				t.Fatalf("отказ не несёт вызова повышения: %v", err)
			}
			if want := iamerr.StepUpChallenge(floor, below); su.challenge != want {
				t.Fatalf("вызов %q, ожидался %q", su.challenge, want)
			}
			if err := p.allow(gatewayCallerCtx("user", floor), verb); err != nil {
				t.Fatalf("через край уровнем, равным полу %q: отказ %v", floor, err)
			}
			if err := p.allow(gatewayCallerCtx("service_account", ""), verb); err != nil {
				t.Fatalf("через край, машинный принципал: отказ %v", err)
			}
		})
	}
	t.Logf("перепись: записей каталога %d · публичных глаголов с полом %d · под вторым замком %d · изъято %d",
		rows, len(floored), locked, len(floored)-locked)
	// Близнец по полу: глагол без пола уровнем «0» через край — проход.
	if err := p.allow(gatewayCallerCtx("user", "0"), "/kaname.cloud.iam.v1.AccessKeyService/BeginAssertion"); err != nil {
		t.Fatalf("глагол без пола уровнем «0»: отказ %v", err)
	}
}

// TestKN767_ExemptionExpiresWithItsSubject — изъятие истекает само: запись,
// чьего глагола нет в переписи (снят, ушёл с публичного слушателя, потерял
// пол), — находка, а не молчаливое послабление про запас.
func TestKN767_ExemptionExpiresWithItsSubject(t *testing.T) {
	_, floored := kn767PublicFloored(t)
	exempt := PublicGatewayFloorExemptRPCs()
	if len(exempt) == 0 {
		t.Logf("перепись изъятий: записей 0")
	}
	for verb := range exempt {
		if _, ok := floored[verb]; !ok {
			t.Errorf("изъятие %s без предмета: глагола нет среди публичных с полом выше «0»", verb)
		}
	}
}
