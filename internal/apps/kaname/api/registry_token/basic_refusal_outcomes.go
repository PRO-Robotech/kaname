// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package registry_token

import (
	"errors"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// ─────────────────────────────────────────────────────────────────────────────
// ОТКАЗ БАЗОВОГО СЕКРЕТА НА ПОЛОСЕ РЕЕСТРА — ПО ПРИЧИНЕ (задача kaname#390)
//
// Полоса реестра — второй потребитель авторитета базового секрета (первый —
// глаголы внутреннего слушателя). Наружу она отвечает тем же единым отказом,
// что на всякий неверный вход, — различимый отказ был бы оракулом. Внутри
// отказ обязан различаться так же, как у первого потребителя: тем же закрытым
// словарём причин домена ([domain.BasicCredentialRefusalReasons]), а не своим.
// Иначе отсечка отзыва-всех, сработавшая на этой полосе тысячу раз, неотличима
// от перебора секрета и от полосы, не обслужившей ни одного входа.
//
// Клетки переписи ВЫВОДЯТСЯ из словаря домена, а не выписываются: причина,
// заведённая в домене, получает клетку здесь тем же изменением.

const (
	// outcomeBasicRefusedPrefix — общая приставка клеток отказа по причине.
	outcomeBasicRefusedPrefix = "basic_refused_"

	// OutcomeBasicRefusedReasonUnnamed — авторитет отказал, не назвав причины:
	// нарушение его контракта. Своя клетка, а не подставленная причина:
	// подставленная выглядела бы фактом.
	OutcomeBasicRefusedReasonUnnamed = outcomeBasicRefusedPrefix + "reason_unnamed"

	// OutcomeBasicPrincipalKindRefused — секрет действителен, но принадлежит
	// принципалу вида, который эта поверхность не обслуживает (удостоверение
	// реестра выдаётся машинному принципалу). Не причина словаря авторитета —
	// решение самой полосы.
	OutcomeBasicPrincipalKindRefused = "basic_principal_kind_refused"
)

// ErrBasicPrincipalKindNotAccepted — секрет принадлежит принципалу вида, не
// обслуживаемого полосой. Наружу — тот же [ErrUnauthenticated].
var ErrBasicPrincipalKindNotAccepted = errors.New("registry-token: basic credential principal kind is not served by this lane")

// BasicRefusedOutcome — клетка отказа по причине словаря домена. Имя клетки —
// имя причины в форме меток счётчика (подчёркивание вместо дефиса).
func BasicRefusedOutcome(r domain.BasicCredentialRefusalReason) string {
	return outcomeBasicRefusedPrefix + strings.ReplaceAll(string(r), "-", "_")
}

// basicRefusalOutcome — клетка отказа авторитета. Причина вне словаря либо не
// названная вовсе — [OutcomeBasicRefusedReasonUnnamed].
func basicRefusalOutcome(err error) string {
	reason, named := domain.BasicCredentialRefusalReasonOf(err)
	if !named {
		return OutcomeBasicRefusedReasonUnnamed
	}
	for _, known := range domain.BasicCredentialRefusalReasons() {
		if reason == known {
			return BasicRefusedOutcome(reason)
		}
	}
	return OutcomeBasicRefusedReasonUnnamed
}

// CredentialKindOutcomes — ЗАКРЫТЫЙ набор исходов полосы предъявленного
// удостоверения целиком, в объявленном порядке. Набор клеток счётчика
// выводится отсюда, а не выписывается у адаптера метрик.
func CredentialKindOutcomes() []string {
	reasons := domain.BasicCredentialRefusalReasons()
	out := make([]string, 0, len(reasons)+5)
	out = append(out, OutcomeBasicAccepted, OutcomeKeyMaterialAcceptedInWindow, OutcomeKeyMaterialRefused)
	for _, r := range reasons {
		out = append(out, BasicRefusedOutcome(r))
	}
	return append(out, OutcomeBasicRefusedReasonUnnamed, OutcomeBasicPrincipalKindRefused)
}
