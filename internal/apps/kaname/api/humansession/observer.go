// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession

// observer.go — порт наблюдаемости полосы (Р14, Ф3-48). Клетки заводятся нулём
// до первого события (форма Ф-е) — перечни исходов закрыты и отдаются
// приёмнику словарями ниже; приёмник ими и засевает клетки.

// LoginOutcome — исход входа по причине. Перечень закрыт: исходы проверяющего
// — из его словаря (`passwordverify.OutcomeNames`), плюс исходы полосы.
type LoginOutcome string

const (
	LoginOutcomeIssued        LoginOutcome = "issued"
	LoginOutcomeNoRow         LoginOutcome = "no-row"         // адреса нет
	LoginOutcomeBlocked       LoginOutcome = "blocked"        // личность заблокирована
	LoginOutcomeRateLimited   LoginOutcome = "rate-limited"   // отказ по частоте
	LoginOutcomeStoreFailed   LoginOutcome = "store-failed"   // хранилище не ответило
	LoginOutcomeVerifierIssue LoginOutcome = "verifier-issue" // наш отказ проверяющего: формат, тело, потолок
	LoginOutcomeMismatched    LoginOutcome = "mismatched"
	LoginOutcomeMaterialNone  LoginOutcome = "material-missing"
	LoginOutcomeCapacity      LoginOutcome = "capacity-exhausted"
)

// LoginOutcomes — закрытый перечень исходов входа.
func LoginOutcomes() []LoginOutcome {
	return []LoginOutcome{
		LoginOutcomeIssued, LoginOutcomeNoRow, LoginOutcomeBlocked, LoginOutcomeRateLimited,
		LoginOutcomeStoreFailed, LoginOutcomeVerifierIssue, LoginOutcomeMismatched,
		LoginOutcomeMaterialNone, LoginOutcomeCapacity,
	}
}

// RewriteOutcome — исход переписывания материала при успешной проверке
// (Ф3-43; ID-PW-1 PWV-08…11, 19): переписано · не требовалось · отказ записи ·
// не переписывается по причине (72 байта · нулевой байт).
type RewriteOutcome string

const (
	RewriteDone               RewriteOutcome = "rewritten"
	RewriteNotNeeded          RewriteOutcome = "not-needed"
	RewriteWriteFailed        RewriteOutcome = "write-failed"
	RewriteSkippedLong72      RewriteOutcome = "skipped-72-bytes"
	RewriteSkippedNulByte     RewriteOutcome = "skipped-nul-byte"
	RewriteSkippedUnjudgeable RewriteOutcome = "skipped-unjudgeable"
)

// RewriteOutcomes — закрытый перечень.
func RewriteOutcomes() []RewriteOutcome {
	return []RewriteOutcome{RewriteDone, RewriteNotNeeded, RewriteWriteFailed,
		RewriteSkippedLong72, RewriteSkippedNulByte, RewriteSkippedUnjudgeable}
}

// BreachCheckOutcome — исход проверки по базе утечек (Р11, Ф3-34).
type BreachCheckOutcome string

const (
	BreachCheckClean         BreachCheckOutcome = "clean"
	BreachCheckFound         BreachCheckOutcome = "found"
	BreachCheckUnavailable   BreachCheckOutcome = "unavailable"   // проход громко
	BreachCheckMisconfigured BreachCheckOutcome = "misconfigured" // отказ
	BreachCheckDisabled      BreachCheckOutcome = "disabled"
)

// BreachCheckOutcomes — закрытый перечень.
func BreachCheckOutcomes() []BreachCheckOutcome {
	return []BreachCheckOutcome{BreachCheckClean, BreachCheckFound, BreachCheckUnavailable, BreachCheckMisconfigured, BreachCheckDisabled}
}

// FormRefusal — отказы формы (Ф3-36): признака нет · признак не подошёл.
type FormRefusal string

const (
	FormRefusalMissing  FormRefusal = "missing"
	FormRefusalRejected FormRefusal = "rejected"
)

// FormRefusals — закрытый перечень.
func FormRefusals() []FormRefusal { return []FormRefusal{FormRefusalMissing, FormRefusalRejected} }

// Observer — приёмник событий полосы. Все методы обязаны быть дёшевы и не
// возвращать ничего: наблюдение не меняет исхода.
type Observer interface {
	LoginObserved(outcome LoginOutcome)
	NoSessionObserved(reason NoSessionReason)
	FormRefusalObserved(refusal FormRefusal)
	RateLimitObserved(scope FailureScope)
	BreachCheckObserved(outcome BreachCheckOutcome)
	LogoutStoreFailureObserved()
	RewriteObserved(outcome RewriteOutcome)
}

// NopObserver — приёмник, ничего не считающий; для проб, не о наблюдаемости.
type NopObserver struct{}

func (NopObserver) LoginObserved(LoginOutcome)             {}
func (NopObserver) NoSessionObserved(NoSessionReason)      {}
func (NopObserver) FormRefusalObserved(FormRefusal)        {}
func (NopObserver) RateLimitObserved(FailureScope)         {}
func (NopObserver) BreachCheckObserved(BreachCheckOutcome) {}
func (NopObserver) LogoutStoreFailureObserved()            {}
func (NopObserver) RewriteObserved(RewriteOutcome)         {}
