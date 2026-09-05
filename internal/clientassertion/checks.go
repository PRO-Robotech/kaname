// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package clientassertion

import "github.com/PRO-Robotech/kacho/pkg/tokenpolicy"

// DeclaredChecks возвращает состав проверок ЭТОГО проверяющего.
//
// Объявление существует затем, чтобы его можно было СВЕРИТЬ с единым перечнем
// (`tokenpolicy.MandatoryChecks`), а не читать четыре реализации глазами. Этот
// проверяющий — четвёртый ответ на тот же вопрос «годен ли предъявленный
// подписанный материал», и он появился ровно так, как предсказывала задача,
// заводившая единый перечень: вместе с новой поверхностью приёма.
//
// Запись, которой проверяющий не исполняет, отсюда нельзя: тогда объявление
// станет вторым местом об одном предмете и разойдётся молча.
func (v *Verifier) DeclaredChecks() []tokenpolicy.Check {
	return []tokenpolicy.Check{
		tokenpolicy.CheckAlgorithmAllowed,
		tokenpolicy.CheckKeyID,
		tokenpolicy.CheckSignature,
		tokenpolicy.CheckKeyBoundAlgorithm,
		tokenpolicy.CheckIssuer,
		tokenpolicy.CheckAudience,
		tokenpolicy.CheckTokenType,
		tokenpolicy.CheckExpiry,
		tokenpolicy.CheckNotBefore,
		tokenpolicy.CheckCriticalHeaders,
	}
}

// DeclaredDeviations — обязательные проверки, которых этот проверяющий НЕ
// исполняет, вместе с причиной.
//
// Причина про РАЗНИЦУ ПРЕДМЕТА, а не про очередь работ: утверждение клиента —
// не токен доступа. Оно предъявляется РОВНО ОДИН раз, на обмен, и его
// однократность держит страж повтора (`ReplayGuard`) — механизм строже отзыва:
// отзыв запрещает предъявлять снова начиная с момента, страж — вообще.
// Спрашивать авторитет отзыва о материале, который живёт минуты и принимается
// единожды, нечего.
func (v *Verifier) DeclaredDeviations() []tokenpolicy.Deviation {
	return []tokenpolicy.Deviation{
		{
			Check: tokenpolicy.CheckRevocation,
			Reason: "утверждение клиента принимается ровно один раз, и однократность " +
				"держит страж повтора — он строже отзыва: запрещает повторное " +
				"предъявление вообще, а не начиная с момента",
		},
	}
}
