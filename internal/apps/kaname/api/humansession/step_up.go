// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession

// step_up.go — ЦЕРЕМОНИЯ ПОВЫШЕНИЯ внутри живой сессии (Ф11 §6 «серверная
// операция и её ответ»; адрес и форму заводит Ф12 Р4 — `POST /iam/v1/auth/step-up`;
// Ф11-08, Ф11-09, Ф11-11, Ф11-29, Ф11-30; Ф12-10, Ф12-15…22).
//
// Глагол ОДИН на три ветви, способ называет клиент: `password` (ветвь Ф11 —
// сверка текущего пароля тем же проверяющим, что вход), `totp`, `lookup_secret`
// (ветви Ф12 — `sf_present.go`). Второго адреса церемонии — на способ — не
// заводится: консоль звала бы два адреса об одном предмете.
//
// Всякое успешное предъявление — предъявление в смысле Ф11: способ кладётся в
// множество, уровень пересчитывается правилом (монотонно: понижения нет),
// носитель перевыпускается, момент последнего предъявления сдвигается; момент
// аутентификации не двигает ничто. Неудачное предъявление сессию не гасит и не
// понижает (Ф11-30). Ответ называет достигнутый уровень и чего не хватает.
//
// # Журнал повышения — на каждом СУЖДЁННОМ предъявлении (Ф11-14)
//
// Принятое и отклонённое предъявление оставляют по записи журнала одного вида;
// исход — её поле (`accepted` / `refused`). Отказ суждённый ровно там, где он
// считается попыткой (Р7), поэтому запись об отказе и след попытки пишутся
// одним условием и одной транзакцией. У пароля это всякий окончательный
// несовпавший исход проверяющего — наружу он неотличим от неверного пароля;
// у кода — «не сошёлся» и «повторён». Попыткой не считаются и записи не
// оставляют: исчерпание ёмкости проверяющего (преходящий исход), фактор не
// заведён (сверка холостая), материал кода не открывается (сверять нечем).

import (
	"context"
	"fmt"
	"time"

	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

// StepUpInput — предъявление одного способа внутри сессии.
type StepUpInput struct {
	Bearer domain.SessionBearer
	Method assurance.Method
	// Password — у способа `password`; Code — у `totp` и `lookup_secret`.
	Password string
	Code     string
	Source   string
}

// StepUpOutput — сессия после предъявления, новый носитель, вид `assurance`.
type StepUpOutput struct {
	View      SessionView
	Bearer    domain.SessionBearer
	Assurance AssuranceView
	// BackupCodesRemaining — только в ответе, потребившем запасной код (Р4).
	BackupCodesRemaining *int
}

// StepUpUseCase — церемония.
type StepUpUseCase struct {
	deps SecondFactorDeps
	gate attemptGate
}

// NewStepUpUseCase — построение с проверкой зависимостей.
func NewStepUpUseCase(d SecondFactorDeps) (*StepUpUseCase, error) {
	d, err := d.validate("step-up")
	if err != nil {
		return nil, err
	}
	return &StepUpUseCase{deps: d, gate: d.gate()}, nil
}

// Execute — порядок: форма → сессия → частота → (у кода) состояние → сверка →
// предъявление одним исходом с журналом повышения; суждённый отказ — след
// попытки одним исходом с журналом повышения.
func (uc *StepUpUseCase) Execute(ctx context.Context, in StepUpInput) (StepUpOutput, error) {
	if err := JudgeStepUpForm(in); err != nil {
		return StepUpOutput{}, err
	}
	now := uc.deps.Now().UTC()
	resolved, err := resolveLiveSession(ctx, uc.deps, in.Bearer, now)
	if err != nil {
		return StepUpOutput{}, err
	}
	user := resolved.User
	addressKey := AddressKey(string(user.Email))
	if hit, err := uc.gate.check(ctx, addressKey, in.Source); err != nil {
		return StepUpOutput{}, ErrStoreUnavailable
	} else if hit != nil {
		uc.deps.Observer.RateLimitObserved(hit.Scope)
		return StepUpOutput{}, hit
	}

	var (
		p          = presenter{deps: uc.deps}
		pr         preparedPresentation
		passwordOK bool
		judged     = judgedPresentation{user: user, session: resolved.Session, method: in.Method,
			addressKey: addressKey, source: in.Source, at: now}
	)
	if in.Method == assurance.MethodPassword {
		outcome, err := uc.verifyPassword(ctx, user.ID, in.Password)
		if err != nil {
			return StepUpOutput{}, ErrStoreUnavailable
		}
		switch outcome {
		case passwordverify.OutcomeMatched:
			passwordOK = true
		case passwordverify.OutcomeCapacityExhausted:
			// Преходящий исход: попыткой не считается (PWV-15.3) и предъявлением
			// не судился — ни следа попытки, ни записи журнала; наружу — тот же отказ.
			return StepUpOutput{}, ErrAuthenticationFailed
		default:
			uc.recordRefusal(ctx, judged)
			return StepUpOutput{}, ErrAuthenticationFailed
		}
	} else {
		pr, err = p.prepare(ctx, user.ID, SecondFactorPresentation{Method: in.Method, Code: in.Code})
		if err != nil {
			return StepUpOutput{}, ErrStoreUnavailable
		}
		if pr.verdict != verdictMatched {
			st, _ := p.settle(ctx, nil, pr, false)
			p.observe(pr, st)
			return StepUpOutput{}, uc.refuse(ctx, pr.verdict, judged)
		}
	}

	bearer, err := domain.NewSessionBearer()
	if err != nil {
		return StepUpOutput{}, ErrStoreUnavailable
	}
	methods := withMethod(resolved.Session.PresentedMethods, in.Method)
	level, err := levelOf(methods)
	if err != nil {
		uc.deps.Logger.Error("step-up: level not derived", "err", err.Error())
		return StepUpOutput{}, ErrStoreUnavailable
	}

	// Заведённое читается ДО открытия транзакции: оба адаптера делят один пул,
	// и чтение изнутри открытой транзакции дало бы вложенный захват соединения.
	enrolled, enrolledKnown := enrollmentBeforeWrite(ctx, uc.deps.Methods, uc.deps.Logger, user.ID)
	// Строка личности — ПЕРВОЙ, до строки фактора и записи сессии (kaname#382):
	// порядок «личность → дети» у всех писателей сессии одной личности один, и
	// держит его открытие, а не то, что следом за сверкой не пишется ничего,
	// требующего личности.
	w, err := uc.deps.Store.PersonWriter(ctx, user.ID)
	if err != nil {
		return StepUpOutput{}, ErrStoreUnavailable
	}
	defer func() { _ = w.Rollback(ctx) }()
	var st settledPresentation
	if !passwordOK {
		st, err = p.settle(ctx, w, pr, true)
		if err != nil {
			return StepUpOutput{}, ErrStoreUnavailable
		}
		if st.verdict != verdictMatched {
			// Транзакция предъявления откатывается целиком; запись об отказе
			// ложится своей транзакцией в refuse, а не в эту.
			_ = w.Rollback(ctx)
			p.observe(pr, st)
			return StepUpOutput{}, uc.refuse(ctx, st.verdict, judged)
		}
	}
	if err := w.PresentInSession(ctx, resolved.Session.ID, methods, level, bearer.Digest(), now); err != nil {
		return StepUpOutput{}, ErrStoreUnavailable
	}
	// Счёт по адресу обнуляет вход, ЗАВЕРШЁННЫЙ до уровня всех заведённых у
	// личности факторов (Ф12 Р7 ред. 11, Ф3 Р10 ред. 11). У церемонии сюда
	// ведут ОБЕ ветви: код доводит сессию до «2» и счёт обнуляет, а ветвь
	// `password` у личности с заведённым фактором оставляет «1» — успех, но не
	// завершённый вход, и счёт остаётся (kaname#287).
	if err := resetFailuresOnCompletedLogin(ctx, w, completedLogin{
		Enrolled: enrolled, EnrolledKnown: enrolledKnown,
		AddressKey: addressKey, Presented: methods,
	}); err != nil {
		return StepUpOutput{}, ErrStoreUnavailable
	}
	if err := emitStepUpJournal(ctx, w, user, resolved.Session, in.Method, level); err != nil {
		return StepUpOutput{}, ErrStoreUnavailable
	}
	if err := w.Commit(ctx); err != nil {
		return StepUpOutput{}, ErrStoreUnavailable
	}
	if !passwordOK {
		p.observe(pr, st)
	}

	s := resolved.Session
	s.PresentedMethods, s.AssuranceLevel, s.LastPresentedAt = methods, level, now
	out := StepUpOutput{
		View:      SessionView{User: user, Session: s, EmailVerified: resolved.EmailVerified},
		Bearer:    bearer,
		Assurance: assuranceAfter(ctx, uc.deps, user.ID, methods),
	}
	if st.consumed {
		remaining := st.remaining
		out.BackupCodesRemaining = &remaining
	}
	return out, nil
}

// verifyPassword — ветвь пароля (Ф11-09): тем же проверяющим, что вход; исход
// проверяющего наружу не выходит.
func (uc *StepUpUseCase) verifyPassword(ctx context.Context, userID domain.UserID, password string) (passwordverify.Outcome, error) {
	var stored domain.LoginVerifier
	m, err := uc.deps.Methods.Get(ctx, userID, domain.LoginMethodPassword)
	switch {
	case err == nil:
		stored = m.Verifier
	case isNotFound(err):
	default:
		return "", err
	}
	res := uc.deps.Verifier.Verify(stored, password)
	if res.Outcome.IsOurError() {
		uc.deps.Logger.Error("step-up: stored password material could not be checked — our data, not the caller's input",
			"outcome", string(res.Outcome))
	}
	return res.Outcome, nil
}

// judgedPresentation — кто, в какой сессии, каким способом и откуда предъявил:
// предмет следа попытки и записи журнала об отказе.
type judgedPresentation struct {
	user       domain.User
	session    domain.HumanSession
	method     assurance.Method
	addressKey string
	source     string
	at         time.Time
}

// refuse — отказ по вердикту сверки кода. Суждённый отказ (он же попытка, Р7)
// оставляет след и запись журнала; отказ по состоянию, недоступности или
// ёмкости не оставляет ни того ни другого.
func (uc *StepUpUseCase) refuse(ctx context.Context, v presentVerdict, j judgedPresentation) error {
	if countsAsAttempt(v) {
		uc.recordRefusal(ctx, j)
	}
	return refusalOf(v)
}

// refusalWriteBudget — срок записей об отказе, отвязанных от отмены запроса.
// Вердикт вынесен, и уход клиента после него не вправе стереть ни след
// попытки, ни запись журнала. Отвязка снимает отмену, но не время: повисшая
// база иначе держала бы горутину без предела. Величина — та же, что у других
// отвязанных записей службы (`providerReleaseTimeout`), и её получает КАЖДАЯ из
// двух записей отдельно, а не пополам: транзакция из трёх вставок и, при её
// сбое, транзакция из двух — каждой свой полный срок (С2).
const refusalWriteBudget = 5 * time.Second

// recordRefusal — суждённое предъявление отклонено: след попытки и запись
// журнала повышения с исходом `refused` — ОДНОЙ транзакцией (Р7, Ф11-14),
// отвязанной от отмены запроса. Отказ наружу уходит в любом исходе записи. Не
// сложилась транзакция — след попытки пишется СВОЕЙ, со СВОИМ сроком: счёт
// неверных предъявлений есть контроль частоты, и сбой записи журнала не вправе
// его выключить; потеря записи журнала звучит ошибкой в журнале процесса.
//
// Срок каждой записи — свой, не общий (С2). Общий срок на насыщенном пуле
// доставался бы запасной уже истёкшим: основная транзакция ждёт соединения и
// выбирает его целиком, а `pgxpool.Acquire` запасной падает сразу на истёкшем
// контексте — след попытки не лёг бы, неверное предъявление осталось бы
// несосчитанным.
func (uc *StepUpUseCase) recordRefusal(ctx context.Context, j judgedPresentation) {
	base := context.WithoutCancel(ctx)
	if err := uc.writeRefusal(base, j); err != nil {
		uc.deps.Logger.ErrorContext(ctx, "step-up: refused presentation not journaled", j.logAttrs(err)...)
		if werr := uc.recordRefusalAttempt(base, j); werr != nil {
			uc.deps.Logger.ErrorContext(ctx, "step-up: failed attempt not recorded", j.logAttrs(werr)...)
		}
	}
}

// writeRefusal — след попытки и запись журнала `refused` одной транзакцией,
// под собственным сроком, отсчитанным от base.
func (uc *StepUpUseCase) writeRefusal(base context.Context, j judgedPresentation) error {
	ctx, cancel := context.WithTimeout(base, refusalWriteBudget)
	defer cancel()
	w, err := uc.deps.Store.Writer(ctx)
	if err != nil {
		return fmt.Errorf("step-up refusal: open writer: %w", err)
	}
	defer func() { _ = w.Rollback(ctx) }()
	if err := recordFailure(ctx, w, j.addressKey, j.source, j.at); err != nil {
		return fmt.Errorf("step-up refusal: record attempt: %w", err)
	}
	if err := emitStepUpRefusal(ctx, w, j.user, j.session, j.method); err != nil {
		return fmt.Errorf("step-up refusal: journal record: %w", err)
	}
	if err := w.Commit(ctx); err != nil {
		return fmt.Errorf("step-up refusal: commit: %w", err)
	}
	return nil
}

// recordRefusalAttempt — только след попытки, под СВОИМ сроком от base:
// запасная запись, когда общая транзакция не сложилась.
func (uc *StepUpUseCase) recordRefusalAttempt(base context.Context, j judgedPresentation) error {
	ctx, cancel := context.WithTimeout(base, refusalWriteBudget)
	defer cancel()
	return recordFailureTx(ctx, uc.deps.Store, j.addressKey, j.source, j.at)
}

// logAttrs — чья запись не легла: идентификаторы личности и сессии и способ.
// Ни адреса почты, ни секрета предъявления, ни носителя.
func (j judgedPresentation) logAttrs(err error) []any {
	return []any{"user_id", string(j.user.ID), "session_id", string(j.session.ID),
		"method", j.method.String(), "err", err.Error()}
}
