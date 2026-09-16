// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

// login_lane_recorder.go — счётчики полосы входа паролем и нашей сессии (фаза
// Ф3, задача PRO-Robotech/kacho#1269; Р14, Ф3-48). Клетки заводятся НУЛЁМ до
// первого события по закрытым словарям исходов их производителей: «ноль за всю
// жизнь» обязано быть отличимо от «клетки нет».

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
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
	PasswordMaterialRewriteMetric      = Namespace + "_password_material_rewrite_total"
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
			rewrite: prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: PasswordMaterialRewriteMetric,
				Help: "Rewrites of stored password material after a successful check, by outcome: rewritten, " +
					"not needed, write failed, skipped (72-byte password, NUL byte, unjudgeable).",
			}, []string{"outcome"}),
		}
		r.reg.MustRegister(rec.login, rec.verify, rec.noSession, rec.form, rec.rate, rec.breach, rec.logout, rec.rewrite)
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

func (l *LoginLaneRecorder) RewriteObserved(o humansession.RewriteOutcome) {
	l.rewrite.WithLabelValues(string(o)).Inc()
}

var (
	_ humansession.Observer   = (*LoginLaneRecorder)(nil)
	_ passwordverify.Observer = (*LoginLaneRecorder)(nil)
)
