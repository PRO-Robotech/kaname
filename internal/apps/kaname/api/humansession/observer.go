// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession

// observer.go — порт наблюдаемости полосы (Р14, Ф3-48). Клетки заводятся нулём
// до первого события (форма Ф-е) — перечни исходов закрыты и отдаются
// приёмнику словарями ниже; приёмник ими и засевает клетки.

import "github.com/PRO-Robotech/kaname/internal/assurance"

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
	// LoginOutcomeSecondFactorRefused — пароль сошёлся, вход отказан по полю
	// `secondFactor` (Ф12): какой именно исход — в клетках предъявления.
	LoginOutcomeSecondFactorRefused LoginOutcome = "second-factor-refused"
	// LoginOutcomeSecondFactorNotEnrolled — пароль сошёлся, код предъявлен, а
	// фактора у личности нет (строки нет либо `pending`). Наружу — тот же один
	// отказ входа и та же попытка, что «код не тот» (Ф12-13 «е», Р7 редакции 8,
	// kaname#257): иначе код ответа называл бы совпавший пароль всякому, кто
	// приложил код. Различимость — только этой клеткой и журналом; клетка
	// отказов второго фактора `not-enrolled` считает отказы ПОД СЕССИЕЙ и на
	// входе не растёт.
	LoginOutcomeSecondFactorNotEnrolled LoginOutcome = "second-factor-not-enrolled"
	// LoginOutcomeBeforeCutoff — пароль сошёлся, а момент входа не позже
	// стоящей отсечки личности (принудительный выход, завершение
	// восстановления, сброс второго фактора распорядителем): вход накрыт ею, и
	// сессии не выдаёт (kaname#385, Р1, Р3). Наружу — тот же один отказ, что на
	// неверный пароль, попыткой не считается: удостоверение предъявлено верно,
	// и принудительный выход иначе приближал бы человека к отказу по частоте.
	LoginOutcomeBeforeCutoff LoginOutcome = "before-cutoff"
)

// LoginOutcomes — закрытый перечень исходов входа.
func LoginOutcomes() []LoginOutcome {
	return []LoginOutcome{
		LoginOutcomeIssued, LoginOutcomeNoRow, LoginOutcomeBlocked, LoginOutcomeRateLimited,
		LoginOutcomeStoreFailed, LoginOutcomeVerifierIssue, LoginOutcomeMismatched,
		LoginOutcomeMaterialNone, LoginOutcomeCapacity, LoginOutcomeSecondFactorRefused,
		LoginOutcomeSecondFactorNotEnrolled, LoginOutcomeBeforeCutoff,
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

// RecoveryRequestOutcome — исход запроса кода восстановления (Ф5-01, Ф5-02).
// Вызывающий видит ОДИН ответ; причина — только здесь.
type RecoveryRequestOutcome string

const (
	RecoveryRequestQueued      RecoveryRequestOutcome = "queued"       // код выдан, письмо в очереди
	RecoveryRequestNoRow       RecoveryRequestOutcome = "no-row"       // адреса нет ни у кого
	RecoveryRequestUnverified  RecoveryRequestOutcome = "unverified"   // адрес не подтверждён (Ф1-25)
	RecoveryRequestStoreFailed RecoveryRequestOutcome = "store-failed" // хранилище не ответило
)

// RecoveryRequestOutcomes — закрытый перечень.
func RecoveryRequestOutcomes() []RecoveryRequestOutcome {
	return []RecoveryRequestOutcome{RecoveryRequestQueued, RecoveryRequestNoRow, RecoveryRequestUnverified, RecoveryRequestStoreFailed}
}

// RecoveryCompletionOutcome — исход предъявления кода (Ф5-03…08, Ф5-17).
type RecoveryCompletionOutcome string

const (
	RecoveryCompletionIssued           RecoveryCompletionOutcome = "issued"            // сессия выдана
	RecoveryCompletionNoRow            RecoveryCompletionOutcome = "no-row"            // адреса нет ни у кого
	RecoveryCompletionCodeRejected     RecoveryCompletionOutcome = "code-rejected"     // код неверен, истёк либо применён
	RecoveryCompletionBlocked          RecoveryCompletionOutcome = "blocked"           // личность заблокирована (Ф1-59)
	RecoveryCompletionRateLimited      RecoveryCompletionOutcome = "rate-limited"      // отказ по частоте
	RecoveryCompletionPasswordRejected RecoveryCompletionOutcome = "password-rejected" // новый пароль негоден по правилу
	RecoveryCompletionStoreFailed      RecoveryCompletionOutcome = "store-failed"      // хранилище не ответило
)

// RecoveryCompletionOutcomes — закрытый перечень.
func RecoveryCompletionOutcomes() []RecoveryCompletionOutcome {
	return []RecoveryCompletionOutcome{
		RecoveryCompletionIssued, RecoveryCompletionNoRow, RecoveryCompletionCodeRejected, RecoveryCompletionBlocked,
		RecoveryCompletionRateLimited, RecoveryCompletionPasswordRejected, RecoveryCompletionStoreFailed,
	}
}

// Observer — приёмник событий полосы. Все методы обязаны быть дёшевы и не
// возвращать ничего: наблюдение не меняет исхода.
type Observer interface {
	LoginObserved(outcome LoginOutcome)
	NoSessionObserved(reason NoSessionReason)
	FormRefusalObserved(refusal FormRefusal)
	RateLimitObserved(scope FailureScope)
	// SourceUnknownObserved — вопрос о частоте задан БЕЗ адреса источника: ось
	// источника не спрашивалась. На живом проводе источник ставит край всегда
	// (Р10); ненулевой счёт означает, что до полосы дошёл запрос без него.
	SourceUnknownObserved()
	BreachCheckObserved(outcome BreachCheckOutcome)
	LogoutStoreFailureObserved()
	RewriteObserved(outcome RewriteOutcome)
	RecoveryRequestObserved(outcome RecoveryRequestOutcome)
	RecoveryCompletionObserved(outcome RecoveryCompletionOutcome)
	// Второй фактор (Ф12, Ф12-43): предъявления по способу × исходу, отказы
	// по состоянию/свежести/недоступности, события.
	SecondFactorPresentationObserved(method assurance.Method, outcome PresentationOutcome)
	SecondFactorRefusalObserved(refusal SecondFactorRefusal)
	SecondFactorEventObserved(event SecondFactorEvent)
}

// NopObserver — приёмник, ничего не считающий; для проб, не о наблюдаемости.
type NopObserver struct{}

func (NopObserver) LoginObserved(LoginOutcome)                                             {}
func (NopObserver) NoSessionObserved(NoSessionReason)                                      {}
func (NopObserver) FormRefusalObserved(FormRefusal)                                        {}
func (NopObserver) RateLimitObserved(FailureScope)                                         {}
func (NopObserver) SourceUnknownObserved()                                                 {}
func (NopObserver) BreachCheckObserved(BreachCheckOutcome)                                 {}
func (NopObserver) LogoutStoreFailureObserved()                                            {}
func (NopObserver) RewriteObserved(RewriteOutcome)                                         {}
func (NopObserver) RecoveryRequestObserved(RecoveryRequestOutcome)                         {}
func (NopObserver) RecoveryCompletionObserved(RecoveryCompletionOutcome)                   {}
func (NopObserver) SecondFactorPresentationObserved(assurance.Method, PresentationOutcome) {}
func (NopObserver) SecondFactorRefusalObserved(SecondFactorRefusal)                        {}
func (NopObserver) SecondFactorEventObserved(SecondFactorEvent)                            {}
