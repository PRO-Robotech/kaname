// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

// login_lane_recorder.go — счётчики полосы входа паролем и нашей сессии (фаза
// Ф3, задача PRO-Robotech/kacho#1269; Р14, Ф3-48). Клетки заводятся НУЛЁМ до
// первого события по закрытым словарям исходов их производителей: «ноль за всю
// жизнь» обязано быть отличимо от «клетки нет».

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registration"
	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

const (
	LoginOutcomesMetric                = Namespace + "_login_outcomes_total"
	PasswordVerificationOutcomesMetric = Namespace + "_password_verification_outcomes_total"
	HumanSessionNoSessionMetric        = Namespace + "_human_session_no_session_total"
	LoginFormRefusalsMetric            = Namespace + "_login_form_refusals_total"
	LoginRateLimitRefusalsMetric       = Namespace + "_login_rate_limit_refusals_total"
	PasswordBreachCheckMetric          = Namespace + "_password_breach_check_total"
	LogoutStoreFailuresMetric          = Namespace + "_logout_store_failures_total"
	LoginSourceUnknownMetric           = Namespace + "_login_source_unknown_total"
	PasswordMaterialRewriteMetric      = Namespace + "_password_material_rewrite_total"
	RegistrationOutcomesMetric         = Namespace + "_registration_outcomes_total"
	// Восстановление доступа (Ф5, kacho#1271): вызывающий видит один ответ на
	// запрос кода и один отказ на предъявление; причина — только здесь.
	RecoveryRequestOutcomesMetric    = Namespace + "_recovery_request_outcomes_total"
	RecoveryCompletionOutcomesMetric = Namespace + "_recovery_completion_outcomes_total"
	// Огибающая по потолку (Ф3-31, решение kaname#188): потолок, стоимость
	// каждого калиброванного класса, калибровки по поводу.
	LoginTimingEnvelopeFloorMetric = Namespace + "_login_timing_envelope_seconds"
	LoginTimingClassCostMetric     = Namespace + "_login_timing_class_cost_seconds"
	LoginTimingCalibrationsMetric  = Namespace + "_login_timing_calibrations_total"
	// Второй фактор (Ф12, kacho#1281; Ф12-43): предъявления по способу × исходу,
	// отказы по состоянию/свежести/недоступности, события.
	SecondFactorPresentationsMetric = Namespace + "_second_factor_presentations_total"
	SecondFactorRefusalsMetric      = Namespace + "_second_factor_refusals_total"
	SecondFactorEventsMetric        = Namespace + "_second_factor_events_total"
)

// LoginLaneRecorder — приёмник событий полосы (`humansession.Observer`) и
// исходов проверяющего (`passwordverify.Observer`).
type LoginLaneRecorder struct {
	login     *prometheus.CounterVec
	verify    *prometheus.CounterVec
	noSession *prometheus.CounterVec
	form      *prometheus.CounterVec
	rate      *prometheus.CounterVec
	breach    *prometheus.CounterVec
	logout    prometheus.Counter
	rewrite   *prometheus.CounterVec
	noSource  prometheus.Counter
	register  *prometheus.CounterVec
	recReq    *prometheus.CounterVec
	recDone   *prometheus.CounterVec
	// Огибающая по потолку.
	envFloor     prometheus.Gauge
	envClassCost *prometheus.GaugeVec
	envCalibs    *prometheus.CounterVec
	sfPresent    *prometheus.CounterVec
	sfRefuse     *prometheus.CounterVec
	sfEvent      *prometheus.CounterVec
}

// LoginLaneRecorder — единственный экземпляр на реестр.
func (r *Registry) LoginLaneRecorder() *LoginLaneRecorder {
	r.loginLaneOnce.Do(func() {
		rec := &LoginLaneRecorder{
			login: prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: LoginOutcomesMetric,
				Help: "Outcomes of the password sign-in lane by cause. The caller always sees ONE refusal " +
					"(authentication failed); the cause is visible only here and in the journal.",
			}, []string{"outcome"}),
			verify: prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: PasswordVerificationOutcomesMetric,
				Help: "Outcomes of the password verifier by kind: matched, mismatched, our-side data " +
					"issues (format not in registry, body not parsable, params above ceiling), material " +
					"missing, capacity exhausted.",
			}, []string{"outcome"}),
			noSession: prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: HumanSessionNoSessionMetric,
				Help: "Resolve answers of «no session» by reason (unknown bearer, ended, expired, blocked). " +
					"The edge and the presenter get one answer; the reason lives only here.",
			}, []string{"reason"}),
			form: prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: LoginFormRefusalsMetric,
				Help: "Form-token refusals on the sign-in lane: token missing, token rejected.",
			}, []string{"refusal"}),
			rate: prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: LoginRateLimitRefusalsMetric,
				Help: "Refusals by attempt rate, by axis (address, source).",
			}, []string{"scope"}),
			breach: prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: PasswordBreachCheckMetric,
				Help: "Password breach-corpus checks by outcome: clean, found, unavailable (passed loudly), " +
					"misconfigured (operation refused), disabled.",
			}, []string{"outcome"}),
			logout: prometheus.NewCounter(prometheus.CounterOpts{
				Name: LogoutStoreFailuresMetric,
				Help: "Sign-outs not performed because the store did not answer; the bearer stays with the client.",
			}),
			noSource: prometheus.NewCounter(prometheus.CounterOpts{
				Name: LoginSourceUnknownMetric,
				Help: "Attempt-rate questions asked WITHOUT a source address: the source axis was not judged. " +
					"The edge always sets the address on the live wire, so a non-zero count means a request " +
					"reached the lane past the edge.",
			}),
			rewrite: prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: PasswordMaterialRewriteMetric,
				Help: "Rewrites of stored password material after a successful check, by outcome: rewritten, " +
					"not needed, write failed, skipped (72-byte password, NUL byte, unjudgeable).",
			}, []string{"outcome"}),
			register: prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: RegistrationOutcomesMetric,
				Help: "Outcomes of registration by lane and cause. The caller always sees ONE refusal " +
					"(registration refused) for an occupied address and for the admission-rate ceiling; " +
					"the cause is visible only here and in the journal (Ф4 Р3).",
			}, []string{"lane", "outcome"}),
			recReq: prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: RecoveryRequestOutcomesMetric,
				Help: "Outcomes of recovery-code requests by cause: queued (code minted, letter queued), no row " +
					"(address belongs to nobody), unverified (address not confirmed), store failed. The caller " +
					"always gets the same answer; the cause is visible only here.",
			}, []string{"outcome"}),
			recDone: prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: RecoveryCompletionOutcomesMetric,
				Help: "Outcomes of recovery-code presentations by cause: issued, no row, code rejected (wrong, " +
					"expired or already used), blocked person, rate limited, new password rejected by the rule, " +
					"store failed. The caller always sees ONE refusal; the cause is visible only here.",
			}, []string{"outcome"}),
			envFloor: prometheus.NewGauge(prometheus.GaugeOpts{
				Name: LoginTimingEnvelopeFloorMetric,
				Help: "Timing envelope floor of the password sign-in lane, seconds: no outcome after the rate gate " +
					"leaves earlier. Calibrated at start as the cost of the dearest stored cost class (or the " +
					"class the product writes) plus headroom; zero means no class has been calibrated.",
			}),
			envClassCost: prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Name: LoginTimingClassCostMetric,
				Help: "Calibrated verification cost per stored cost class, seconds, by format and parameters. " +
					"The maximum across classes is what the envelope floor is derived from; a class present here " +
					"is a class present in the store or written by the product.",
			}, []string{"format", "params"}),
			envCalibs: prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: LoginTimingCalibrationsMetric,
				Help: "Cost-class calibrations of the timing envelope by trigger: startup (store census and the " +
					"writing knob), read (the sign-in lane met a class the envelope did not know — a value was " +
					"stored past this process).",
			}, []string{"trigger"}),
			sfPresent: prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: SecondFactorPresentationsMetric,
				Help: "Second-factor code presentations by method (totp, lookup_secret) and outcome: matched, " +
					"mismatched, replayed (totp only), material-unreadable (our stored material does not open — " +
					"a finding about the key ring, not the caller), capacity-exhausted (lookup_secret only). " +
					"Presentations judged after a wrong password are not counted here: the password never opened them.",
			}, []string{"method", "outcome"}),
			sfRefuse: prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: SecondFactorRefusalsMetric,
				Help: "Second-factor refusals that are NOT attempts: not enrolled, already enrolled, no pending " +
					"enrollment, session not fresh, material unavailable.",
			}, []string{"reason"}),
			sfEvent: prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: SecondFactorEventsMetric,
				Help: "Second-factor lifecycle events: enrollment started/confirmed, factor removed, backup codes " +
					"regenerated, a backup code consumed.",
			}, []string{"event"}),
		}
		r.reg.MustRegister(rec.login, rec.verify, rec.noSession, rec.form, rec.rate, rec.breach, rec.logout, rec.rewrite, rec.noSource,
			rec.register, rec.recReq, rec.recDone, rec.envFloor, rec.envClassCost, rec.envCalibs, rec.sfPresent, rec.sfRefuse, rec.sfEvent)
		for _, o := range humansession.LoginOutcomes() {
			rec.login.WithLabelValues(string(o)).Add(0)
		}
		for _, o := range passwordverify.OutcomeNames() {
			rec.verify.WithLabelValues(o).Add(0)
		}
		for _, o := range humansession.NoSessionReasons() {
			rec.noSession.WithLabelValues(string(o)).Add(0)
		}
		for _, o := range humansession.FormRefusals() {
			rec.form.WithLabelValues(string(o)).Add(0)
		}
		for _, s := range []humansession.FailureScope{humansession.FailureByAddress, humansession.FailureBySource} {
			rec.rate.WithLabelValues(string(s)).Add(0)
		}
		for _, o := range humansession.BreachCheckOutcomes() {
			rec.breach.WithLabelValues(string(o)).Add(0)
		}
		for _, o := range humansession.RewriteOutcomes() {
			rec.rewrite.WithLabelValues(string(o)).Add(0)
		}
		// Полосы — из единственного объявления, исходы — от производителя:
		// клетка каждой пары существует с нулём (Ф4 Р3, форма Ф-е).
		for _, lane := range registration.Lanes {
			for _, o := range registration.Outcomes() {
				rec.register.WithLabelValues(lane.Name, string(o)).Add(0)
			}
		}
		for _, o := range humansession.RecoveryRequestOutcomes() {
			rec.recReq.WithLabelValues(string(o)).Add(0)
		}
		for _, o := range humansession.RecoveryCompletionOutcomes() {
			rec.recDone.WithLabelValues(string(o)).Add(0)
		}
		for _, tr := range passwordverify.EnvelopeTriggers() {
			rec.envCalibs.WithLabelValues(string(tr)).Add(0)
		}
		rec.envFloor.Set(0)
		for _, c := range humansession.PresentationCells() {
			rec.sfPresent.WithLabelValues(c.Method.String(), string(c.Outcome)).Add(0)
		}
		for _, o := range humansession.SecondFactorRefusals() {
			rec.sfRefuse.WithLabelValues(string(o)).Add(0)
		}
		for _, o := range humansession.SecondFactorEvents() {
			rec.sfEvent.WithLabelValues(string(o)).Add(0)
		}
		r.loginLane = rec
	})
	return r.loginLane
}

func (l *LoginLaneRecorder) LoginObserved(o humansession.LoginOutcome) {
	l.login.WithLabelValues(string(o)).Inc()
}

func (l *LoginLaneRecorder) VerificationObserved(o passwordverify.Outcome) {
	l.verify.WithLabelValues(string(o)).Inc()
}

func (l *LoginLaneRecorder) NoSessionObserved(r humansession.NoSessionReason) {
	l.noSession.WithLabelValues(string(r)).Inc()
}

func (l *LoginLaneRecorder) FormRefusalObserved(f humansession.FormRefusal) {
	l.form.WithLabelValues(string(f)).Inc()
}

func (l *LoginLaneRecorder) RateLimitObserved(s humansession.FailureScope) {
	l.rate.WithLabelValues(string(s)).Inc()
}

func (l *LoginLaneRecorder) BreachCheckObserved(o humansession.BreachCheckOutcome) {
	l.breach.WithLabelValues(string(o)).Inc()
}

func (l *LoginLaneRecorder) LogoutStoreFailureObserved() { l.logout.Inc() }

func (l *LoginLaneRecorder) SourceUnknownObserved() { l.noSource.Inc() }

func (l *LoginLaneRecorder) RewriteObserved(o humansession.RewriteOutcome) {
	l.rewrite.WithLabelValues(string(o)).Inc()
}

// RegistrationObserved — исход регистрации по полосе и причине (Ф4 Р3).
func (l *LoginLaneRecorder) RegistrationObserved(lane string, o registration.Outcome) {
	l.register.WithLabelValues(lane, string(o)).Inc()
}

func (l *LoginLaneRecorder) RecoveryRequestObserved(o humansession.RecoveryRequestOutcome) {
	l.recReq.WithLabelValues(string(o)).Inc()
}

func (l *LoginLaneRecorder) RecoveryCompletionObserved(o humansession.RecoveryCompletionOutcome) {
	l.recDone.WithLabelValues(string(o)).Inc()
}

// ClassCalibrated — класс калиброван: его стоимость и повод (Ф3-31, kaname#188).
func (l *LoginLaneRecorder) ClassCalibrated(class domain.PasswordCostClass, cost time.Duration, trigger passwordverify.EnvelopeTrigger) {
	l.envClassCost.WithLabelValues(string(class.Format), class.ParamsLabel()).Set(cost.Seconds())
	l.envCalibs.WithLabelValues(string(trigger)).Inc()
}

// EnvelopeFloorObserved — потолок огибающей сменился.
func (l *LoginLaneRecorder) EnvelopeFloorObserved(floor time.Duration, _ domain.PasswordCostClass) {
	l.envFloor.Set(floor.Seconds())
}

func (l *LoginLaneRecorder) SecondFactorPresentationObserved(m assurance.Method, o humansession.PresentationOutcome) {
	l.sfPresent.WithLabelValues(m.String(), string(o)).Inc()
}

func (l *LoginLaneRecorder) SecondFactorRefusalObserved(o humansession.SecondFactorRefusal) {
	l.sfRefuse.WithLabelValues(string(o)).Inc()
}

func (l *LoginLaneRecorder) SecondFactorEventObserved(o humansession.SecondFactorEvent) {
	l.sfEvent.WithLabelValues(string(o)).Inc()
}

var (
	_ humansession.Observer           = (*LoginLaneRecorder)(nil)
	_ passwordverify.Observer         = (*LoginLaneRecorder)(nil)
	_ passwordverify.EnvelopeObserver = (*LoginLaneRecorder)(nil)
	_ registration.Observer           = (*LoginLaneRecorder)(nil)
)
