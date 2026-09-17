// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession

// sf_present.go — СВЕРКА КОДА второго фактора, общая для входа с полем
// `secondFactor` и глаголов внутри сессии (церемония, снятие, перечеканка).
//
// # Две половины, и вторая пишет только при ПОЛНОМ успехе (Р5, Р6; Б3 круга 1)
//
//	prepare — дорогая половина ДО транзакции: чтение строк без замка, HMAC по
//	          окну либо медленный хеш кандидата под ёмкостью проверяющего;
//	settle  — ПОД транзакцией вызывающего: у кода по времени — условная запись
//	          принятого шага (она же арбитр гонки); у запасного кода — замок
//	          строки набора, сравнение с каждым элементом и снятие совпавшего.
//
// Сверка выполняется и там, где пароль не сошёлся (Ф12-13 «б», «ж», Ф12-33):
// prepare идёт тем же путём, а settle зовётся с write=false — замок и
// сравнение те же, записи нет. И там, где секрета нет (личность без фактора,
// строка `pending`), — холостая сверка над неизменным холостым материалом:
// проверяющие делают это сами (Р5, Р6).
//
// Что считается попыткой (Р7): «не сошёлся» и «повторён». Не считается:
// состояние строки (не заведён), недоступность материала, исчерпание ёмкости.

import (
	"context"
	"errors"

	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
	"github.com/PRO-Robotech/kaname/internal/totpverify"
)

func isNotFound(err error) bool { return errors.Is(err, iamerr.ErrNotFound) }

// presentVerdict — исход сверки после обеих половин.
type presentVerdict int

const (
	// verdictMatched — код сошёлся и (при write) записан: полный успех.
	verdictMatched presentVerdict = iota
	// verdictMismatched — не сошёлся либо повторён: попытка.
	verdictMismatched
	// verdictNotEnrolled — строки `active` нет: состояние, не попытка.
	verdictNotEnrolled
	// verdictUnavailable — материал не открывается: недоступность.
	verdictUnavailable
	// verdictCapacity — ёмкость проверяющего исчерпана: преходящий исход.
	verdictCapacity
)

// preparedPresentation — исход первой половины.
type preparedPresentation struct {
	method   assurance.Method
	userID   domain.UserID
	verdict  presentVerdict
	outcome  PresentationOutcome
	observed bool
	// totp
	step int64
	// lookup_secret
	candidate passwordverify.SetCandidate
	remaining int
}

// settledPresentation — исход второй половины.
type settledPresentation struct {
	verdict presentVerdict
	outcome PresentationOutcome
	// remaining — остаток набора ПОСЛЕ потребления (только у запасного кода).
	remaining int
	consumed  bool
}

// presenter — сверка кода портами глагола.
type presenter struct {
	deps SecondFactorDeps
}

// prepare — см. шапку. Состояние судится РАНЬШЕ кода: при «нет» и `pending`
// сверка холостая, исход — «не заведён».
func (p presenter) prepare(ctx context.Context, userID domain.UserID, in SecondFactorPresentation) (preparedPresentation, error) {
	out := preparedPresentation{method: in.Method, userID: userID}
	now := p.deps.Now().UTC()
	totp, found, err := factorState(ctx, p.deps.Methods, userID)
	if err != nil {
		return out, err
	}
	enrolled := found && totp.Enrolled()
	switch in.Method {
	case assurance.MethodTOTP:
		stored := domain.LoginVerifier{}
		last := totpverify.NoAcceptedStep()
		if enrolled {
			stored = totp.Verifier
			if totp.StepAccepted {
				last = totpverify.AcceptedStep(totp.AcceptedStep)
			}
		}
		res := p.deps.TOTP.Verify(stored, last, in.Code, now)
		if !enrolled {
			out.verdict = verdictNotEnrolled
			return out, nil
		}
		switch res.Outcome {
		case totpverify.OutcomeMatched:
			out.verdict, out.outcome, out.step = verdictMatched, PresentationMatched, res.Step
		case totpverify.OutcomeReplayed:
			out.verdict, out.outcome = verdictMismatched, PresentationReplayed
		case totpverify.OutcomeMaterialUnreadable:
			out.verdict, out.outcome = verdictUnavailable, PresentationMaterialUnreadable
		default:
			out.verdict, out.outcome = verdictMismatched, PresentationMismatched
		}
	case assurance.MethodLookupSecret:
		stored := domain.LoginVerifier{}
		if enrolled {
			set, serr := p.deps.Methods.Get(ctx, userID, domain.LoginMethodLookupSecret)
			switch {
			case serr == nil:
				stored = set.Verifier
			case isNotFound(serr):
				// `active` без набора — наш дефект хранения; сверка холостая,
				// исход — «материал не открывается».
			default:
				return out, serr
			}
		}
		cand := p.deps.Sets.SetCandidate(stored, in.Code)
		if !enrolled {
			out.verdict = verdictNotEnrolled
			return out, nil
		}
		if !cand.Ready() {
			switch cand.Refusal() {
			case passwordverify.OutcomeCapacityExhausted:
				out.verdict, out.outcome = verdictCapacity, PresentationCapacityExhausted
			default:
				out.verdict, out.outcome = verdictUnavailable, PresentationMaterialUnreadable
			}
			return out, nil
		}
		out.candidate = cand
		out.verdict = verdictMatched // сравнение — под замком, в settle
	default:
		return out, &FieldError{Field: "method", Rule: "must be one of totp|lookup_secret"}
	}
	return out, nil
}

// settle — вторая половина под транзакцией вызывающего. write=false — путь тот
// же, записи нет (неполный успех: пароль не сошёлся).
func (p presenter) settle(ctx context.Context, w Writer, pr preparedPresentation, write bool) (settledPresentation, error) {
	out := settledPresentation{verdict: pr.verdict, outcome: pr.outcome}
	if pr.verdict != verdictMatched {
		return out, nil
	}
	switch pr.method {
	case assurance.MethodTOTP:
		if !write {
			return out, nil
		}
		recorded, err := w.RecordAcceptedStep(ctx, pr.userID, pr.step)
		if err != nil {
			return out, err
		}
		if !recorded {
			// Второй из двух одновременных: шаг уже принят строкой — повтор.
			out.verdict, out.outcome = verdictMismatched, PresentationReplayed
		}
	case assurance.MethodLookupSecret:
		set, found, err := w.LockLookupSet(ctx, pr.userID)
		if err != nil {
			return out, err
		}
		if !found {
			out.verdict, out.outcome = verdictUnavailable, PresentationMaterialUnreadable
			return out, nil
		}
		match := p.deps.Sets.MatchSet(set.Verifier, pr.candidate)
		switch match.Outcome {
		case passwordverify.OutcomeMatched:
			out.remaining = match.Remaining
			if !write {
				return out, nil
			}
			consumed, err := w.ConsumeLookupElement(ctx, pr.userID, pr.candidate.Element())
			if err != nil {
				return out, err
			}
			if !consumed {
				// Замок сериализует, поэтому сюда не приходят: элемент был в
				// наборе под замком. Отказ — наш дефект, не «не подошёл».
				return out, iamerr.Wrapf(iamerr.ErrInternal, "backup code matched but was not consumed")
			}
			out.consumed = true
			out.remaining = match.Remaining - 1
		case passwordverify.OutcomeMismatched:
			out.verdict, out.outcome = verdictMismatched, PresentationMismatched
		default:
			out.verdict, out.outcome = verdictUnavailable, PresentationMaterialUnreadable
		}
	}
	return out, nil
}

// observe — клетка предъявления по способу × исходу; отказы по состоянию —
// своей клеткой.
func (p presenter) observe(pr preparedPresentation, st settledPresentation) {
	switch st.verdict {
	case verdictNotEnrolled:
		p.deps.Observer.SecondFactorRefusalObserved(RefusalNotEnrolled)
	case verdictUnavailable:
		p.deps.Observer.SecondFactorPresentationObserved(pr.method, PresentationMaterialUnreadable)
		p.deps.Observer.SecondFactorRefusalObserved(RefusalUnavailable)
	default:
		p.deps.Observer.SecondFactorPresentationObserved(pr.method, st.outcome)
	}
	if st.consumed {
		p.deps.Observer.SecondFactorEventObserved(SecondFactorBackupCodeConsumed)
	}
}

// refusalOf — отказ наружу по вердикту неуспеха.
func refusalOf(v presentVerdict) error {
	switch v {
	case verdictNotEnrolled:
		return ErrSecondFactorNotEnrolled
	case verdictUnavailable:
		return ErrSecondFactorUnavailable
	default:
		return ErrAuthenticationFailed
	}
}

// countsAsAttempt — вердикт увеличивает счёт неверных предъявлений (Р7).
func countsAsAttempt(v presentVerdict) bool { return v == verdictMismatched }
