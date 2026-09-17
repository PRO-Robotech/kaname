// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package passwordverify

// envelope.go — ОГИБАЮЩАЯ ПО ПОТОЛКУ фактической популяции (решение
// kaname#188 по Ф3-31; ID-PW-1 Р4, PWV-03, PWV-06; критерий Ф1-48).
//
// # Что это и почему именно так
//
// Отказ на неверном пароле, стоящий столько, сколько стоит проверка хранимого
// значения, сообщает постороннему КЛАСС этого значения — формат и параметры
// (Р4 называет это оракулом). Стоимости классов различаются в 25–900 раз
// (замер Ф3-31), и никакое выравнивание «по классу ручки» их не покрывает:
// класс на потолке своего же формата выдаёт себя (PWV-03).
//
// Огибающая ставит ПОТОЛОК: всякий исход входа уходит не раньше калиброванной
// стоимости самого дорогого класса среди
//
//	{классы, лежащие в хранилище} ∪ {класс ручки «что писать»}.
//
// Потолок берётся из ФАКТИЧЕСКОЙ популяции, а не из теоретического перечня
// (bcrypt ≤ 14, argon2id ≤ 128 МиБ·10·8): статический потолок остаётся
// границей ПРИЁМА — что вообще читается, — а задержка входа платится по тому,
// что реально лежит. Популяция переноса — bcrypt стоимости 12 (≈0,2 с на
// машине разработки), а не потолок формата (≈0,85 с), которого в хранилище нет.
//
// # Калибровка — прогон проверяющего, а не таблица
//
// Стоимость класса на ЭТОМ железе узнаётся единственным честным способом —
// прогоном той же функции с теми же параметрами: синтетическое значение класса
// строится от случайного пароля, и `calibrationSamples` раз против него
// считается неверный пароль. Стоимость класса — максимум из прогонов; потолок —
// стоимость с запасом в `1/headroomDivisor`: прогон под нагрузкой длиннее
// калибровочного, а исход, вышедший за потолок, снова отличим по времени.
// Величины названы с причиной у констант; держит их измерительная проба Ф3-31:
// медиана самой дорогой полосы выше потолка — числа выбраны неверно.
//
// # Ёмкость и приёмник
//
// Калибровка идёт В ёмкости проверяющего: страж старта сверил с пределом памяти
// ровно `ёмкость × память проверки`, и прогон мимо ёмкости вышел бы за бюджет.
// Ждёт она места, а не отказывает, — срок ожидания даёт контекст вызывающего.
// Исход калибровки НЕ уходит приёмнику исходов проверяющего: сосчитанный, он
// читался бы как поток неверных паролей при каждом старте.
//
// # Что класс ДОПУСКАЕТ в огибающую, и когда
//
//   - при старте — композиционный корень: каждый класс переписи хранилища и
//     класс ручки (повод `startup`);
//   - на чтении — полоса входа, встретив вычисленный исход по классу, которого
//     огибающая не знает (повод `read`): значение, положенное мимо нашего
//     процесса (иным процессом), приносит класс, которого перепись старта не
//     видела; первый вход по нему поднимает потолок, и окно оракула равно
//     одному обращению, а не времени до перезапуска. Известный класс — поиск
//     по ключу, без прогона. Это ЕДИНСТВЕННЫЙ путь чужого класса в огибающую;
//   - при записи — повода НЕТ И НЕ БУДЕТ: у него нет производителя. Все
//     четыре писателя материала (регистрация, смена пароля, восстановление,
//     переписывание при входе) пишут классом ручки, допущенным при старте by
//     construction, — класс дороже потолка записать своим процессом некому.
//     Единственный писатель чужих классов тем же процессом, перенос, снят
//     решением `PRO-Robotech/kacho#1268` (популяции нет, данные не
//     переносятся), и заказ повода `write` (`kaname#222`) закрыт с ним:
//     клетка счётчика, которую нечем поднять, лгала бы о провязке. Словарь
//     поводов закрыт ДВУМЯ (TestEnvelopeTriggers_DictionaryIsClosed), и
//     третьего в нём не заводится.
//
// Класс, который проверяющий не читает (выше потолка записи, за областью
// допустимости), не калибруется: ось годности от времени освобождена (Р4) —
// отказ на таком значении приходит без вычисления, и вычислять его ради
// выравнивания значило бы платить ту цену, от которой потолок защищает.
//
// # Что огибающая НЕ делает
//
// Не опускает потолок: класс, ушедший из хранилища (переписан входом, снят),
// остаётся в ней до перезапуска — лишняя задержка есть цена, а не оракул.
// Не держит ёмкость на ожидании: ждёт полоса входа, а не проверяющий.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

const (
	// calibrationSamples — прогонов на класс. Пять: замер Ф3-31 даёт размах до
	// 13 % медианы у класса на потолке объявленного формата (шум машины;
	// проверка argon2id параллельна и потому к нему чувствительнее), и
	// максимум из пяти при таком разбросе лежит выше медианы устойчиво.
	calibrationSamples = 5
	// headroomDivisor — запас потолка над стоимостью: четверть, вдвое больше
	// наблюдённого размаха. Ниже — исход самого дорогого класса под нагрузкой
	// выходил бы за потолок и снова был бы отличим; выше — каждый вход платил
	// бы задержкой за запас, которого шум не требует.
	headroomDivisor = 4
	// calibrationSecretLen — байт случайного пароля синтетического значения и
	// неверного пароля прогона: ни тот ни другой никому не известен.
	calibrationSecretLen = 32
)

// EnvelopeTrigger — повод калибровки класса.
type EnvelopeTrigger string

const (
	// EnvelopeTriggerStartup — старт процесса: перепись хранилища и ручка.
	EnvelopeTriggerStartup EnvelopeTrigger = "startup"
	// EnvelopeTriggerRead — полоса входа встретила класс, которого огибающая
	// не знала.
	EnvelopeTriggerRead EnvelopeTrigger = "read"
)

var envelopeTriggers = []EnvelopeTrigger{EnvelopeTriggerStartup, EnvelopeTriggerRead}

// EnvelopeTriggers — словарь поводов копией: клетки счётчика заводятся из
// него, и вызывающий его не расширяет.
func EnvelopeTriggers() []EnvelopeTrigger {
	out := make([]EnvelopeTrigger, len(envelopeTriggers))
	copy(out, envelopeTriggers)
	return out
}

// EnvelopeObserver — приёмник событий огибающей: калибровка класса (с его
// стоимостью и поводом) и смена потолка.
type EnvelopeObserver interface {
	ClassCalibrated(class domain.PasswordCostClass, cost time.Duration, trigger EnvelopeTrigger)
	EnvelopeFloorObserved(floor time.Duration, ceiling domain.PasswordCostClass)
}

// NopEnvelopeObserver — приёмник, ничего не считающий; для проб не о
// наблюдаемости.
type NopEnvelopeObserver struct{}

func (NopEnvelopeObserver) ClassCalibrated(domain.PasswordCostClass, time.Duration, EnvelopeTrigger) {
}
func (NopEnvelopeObserver) EnvelopeFloorObserved(time.Duration, domain.PasswordCostClass) {}

// CalibratedClass — класс и его калиброванная стоимость.
type CalibratedClass struct {
	Class domain.PasswordCostClass
	Cost  time.Duration
}

// Admission — исход допуска класса: его стоимость, потолок после допуска и
// то, калибровался ли класс этим допуском (известный — нет).
type Admission struct {
	Cost       time.Duration
	Floor      time.Duration
	Calibrated bool
}

// ClassNotReadableError — класс проверяющий не читает: исход разбора назван.
type ClassNotReadableError struct {
	Class   domain.PasswordCostClass
	Outcome Outcome
}

func (e *ClassNotReadableError) Error() string {
	return fmt.Sprintf("password_envelope: класс %s проверяющий не читает (%s) — калибровать нечего", e.Class.Key(), e.Outcome)
}

// flight — калибровка класса, идущая сейчас: второй допуск того же класса
// ждёт её, а не считает второй раз.
type flight struct {
	done chan struct{}
	adm  Admission
	err  error
}

// Envelope — огибающая по потолку.
type Envelope struct {
	verifier *Verifier
	observer EnvelopeObserver

	// floor — потолок; читается полосой входа без замка.
	floor atomic.Int64

	mu       sync.RWMutex
	classes  map[string]CalibratedClass
	inflight map[string]*flight
	ceiling  CalibratedClass
	hasCeil  bool
}

// NewEnvelope — огибающая над проверяющим. Оба довода обязательны: без
// проверяющего калибровать нечем, без приёмника потолок невидим.
func NewEnvelope(verifier *Verifier, observer EnvelopeObserver) (*Envelope, error) {
	if verifier == nil {
		return nil, fmt.Errorf("password_envelope.verifier: required — калибровать нечем")
	}
	if observer == nil {
		return nil, fmt.Errorf("password_envelope.observer: required — потолок без приёмника невидим оператору")
	}
	return &Envelope{
		verifier: verifier, observer: observer,
		classes: map[string]CalibratedClass{}, inflight: map[string]*flight{},
	}, nil
}

// Floor — потолок: раньше него ни один исход входа не уходит. Ноль — ни один
// класс ещё не допущен.
func (e *Envelope) Floor() time.Duration { return time.Duration(e.floor.Load()) }

// Ceiling — класс-потолок и его стоимость; false — классов нет.
func (e *Envelope) Ceiling() (CalibratedClass, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.ceiling, e.hasCeil
}

// Classes — все калиброванные классы, по ключу.
func (e *Envelope) Classes() []CalibratedClass {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]CalibratedClass, 0, len(e.classes))
	for _, c := range e.classes {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Class.Key() < out[j].Class.Key() })
	return out
}

// Admit — класс входит в огибающую: известный — поиск по ключу; новый —
// калибровка, и потолок поднимается, если класс дороже текущего. Одновременные
// допуски одного нового класса дают ОДНУ калибровку.
func (e *Envelope) Admit(ctx context.Context, class domain.PasswordCostClass, trigger EnvelopeTrigger) (Admission, error) {
	if err := class.Validate(); err != nil {
		return Admission{}, fmt.Errorf("password_envelope: %w", err)
	}
	key := class.Key()

	e.mu.RLock()
	known, ok := e.classes[key]
	e.mu.RUnlock()
	if ok {
		return Admission{Cost: known.Cost, Floor: e.Floor()}, nil
	}

	e.mu.Lock()
	if known, ok := e.classes[key]; ok {
		e.mu.Unlock()
		return Admission{Cost: known.Cost, Floor: e.Floor()}, nil
	}
	if fl, ok := e.inflight[key]; ok {
		e.mu.Unlock()
		select {
		case <-fl.done:
			if fl.err != nil {
				return Admission{}, fl.err
			}
			return Admission{Cost: fl.adm.Cost, Floor: e.Floor()}, nil
		case <-ctx.Done():
			return Admission{}, fmt.Errorf("password_envelope: ожидание калибровки класса %s: %w", key, ctx.Err())
		}
	}
	fl := &flight{done: make(chan struct{})}
	e.inflight[key] = fl
	e.mu.Unlock()

	cost, err := e.calibrate(ctx, class)

	e.mu.Lock()
	delete(e.inflight, key)
	if err != nil {
		fl.err = err
		close(fl.done)
		e.mu.Unlock()
		return Admission{}, err
	}
	calibrated := CalibratedClass{Class: class, Cost: cost}
	e.classes[key] = calibrated
	floorChanged := false
	if !e.hasCeil || cost > e.ceiling.Cost {
		e.ceiling, e.hasCeil = calibrated, true
		e.floor.Store(int64(cost + cost/headroomDivisor))
		floorChanged = true
	}
	fl.adm = Admission{Cost: cost, Floor: e.Floor(), Calibrated: true}
	close(fl.done)
	e.mu.Unlock()

	e.observer.ClassCalibrated(class, cost, trigger)
	if floorChanged {
		e.observer.EnvelopeFloorObserved(fl.adm.Floor, class)
	}
	return fl.adm, nil
}

// calibrate — стоимость класса на этом железе: максимум из
// `calibrationSamples` прогонов неверного пароля против синтетического
// значения класса, каждый — в ёмкости проверяющего.
func (e *Envelope) calibrate(ctx context.Context, class domain.PasswordCostClass) (time.Duration, error) {
	// Читаемость судится ДО построения значения — разбором синтаксической
	// формы без вычисления: построить значение класса выше потолка значило бы
	// заплатить его цену ради того, чтобы узнать, что платить не следовало.
	probe, err := syntheticClassText(class)
	if err != nil {
		return 0, err
	}
	if res := inspectAndCompare(probe, "", false); res.Outcome != OutcomeMismatched {
		return 0, &ClassNotReadableError{Class: class, Outcome: res.Outcome}
	}

	secret, err := calibrationSecret()
	if err != nil {
		return 0, err
	}
	wrong, err := calibrationSecret()
	if err != nil {
		return 0, err
	}
	value, err := syntheticClassValue(class, secret)
	if err != nil {
		return 0, err
	}

	var cost time.Duration
	for i := 0; i < calibrationSamples; i++ {
		release, err := e.verifier.capacity.acquireWait(ctx)
		if err != nil {
			return 0, fmt.Errorf("password_envelope: ёмкость для калибровки класса %s не получена: %w", class.Key(), err)
		}
		start := time.Now()
		res := e.verifier.compute(value, wrong)
		elapsed := time.Since(start)
		release()
		if res.Outcome != OutcomeMismatched {
			// Синтетическое значение проверяющий обязан читать: иное — наш
			// дефект построения, а не свойство класса.
			return 0, fmt.Errorf("password_envelope: синтетическое значение класса %s дало исход %s вместо «не совпал»", class.Key(), res.Outcome)
		}
		if elapsed > cost {
			cost = elapsed
		}
	}
	return cost, nil
}

func calibrationSecret() (string, error) {
	raw := make([]byte, calibrationSecretLen)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("password_envelope: random source: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// syntheticClassText — значение класса СИНТАКСИЧЕСКИ: случайные соль и тело
// нужной длины, без вычисления. Годится только для разбора без сравнения.
func syntheticClassText(class domain.PasswordCostClass) (string, error) {
	switch class.Format {
	case domain.PasswordHashFormatBcrypt:
		body := make([]byte, bcryptValueLen-len(bcryptMarkerPrefix)-bcryptCostDigits-1)
		if _, err := rand.Read(body); err != nil {
			return "", fmt.Errorf("password_envelope: random source: %w", err)
		}
		for i := range body {
			body[i] = bcryptAlphabet[int(body[i])%len(bcryptAlphabet)]
		}
		return fmt.Sprintf("%s%02d$%s", bcryptMarkerPrefix, class.Params[domain.CostParamBcryptCost], body), nil
	case domain.PasswordHashFormatArgon2id:
		salt := make([]byte, argon2idSaltLen)
		body := make([]byte, argon2idKeyLen)
		if _, err := rand.Read(salt); err != nil {
			return "", fmt.Errorf("password_envelope: random source: %w", err)
		}
		if _, err := rand.Read(body); err != nil {
			return "", fmt.Errorf("password_envelope: random source: %w", err)
		}
		return argon2idMaterial(class.Params[domain.CostParamArgon2Memory], class.Params[domain.CostParamArgon2Iterations],
			class.Params[domain.CostParamArgon2Parallelism], salt, body), nil
	default:
		return "", fmt.Errorf("password_envelope: формат %q строить нечем", class.Format)
	}
}

// bcryptAlphabet — алфавит тела bcrypt, тот же, что судит
// `bcryptBodyIsWellFormed`.
const bcryptAlphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// syntheticClassValue — значение класса ПО СУЩЕСТВУ: посчитано той же функцией
// от случайного пароля, как считал бы прежний поставщик либо наш хешер.
// Стоимость проверки против него равна стоимости против всякого значения того
// же класса. Наследуемый формат строит сторонняя библиотека: продукт его не
// пишет, и синтетическое значение — не запись, а мера.
func syntheticClassValue(class domain.PasswordCostClass, password string) (domain.LoginVerifier, error) {
	switch class.Format {
	case domain.PasswordHashFormatBcrypt:
		raw, err := bcrypt.GenerateFromPassword([]byte(password), int(class.Params[domain.CostParamBcryptCost]))
		if err != nil {
			return domain.LoginVerifier{}, fmt.Errorf("password_envelope: синтетическое значение %s: %w", class.Key(), err)
		}
		return domain.NewLoginVerifier(string(raw))
	case domain.PasswordHashFormatArgon2id:
		memory := class.Params[domain.CostParamArgon2Memory]
		iterations := class.Params[domain.CostParamArgon2Iterations]
		parallelism := class.Params[domain.CostParamArgon2Parallelism]
		if parallelism > 255 {
			return domain.LoginVerifier{}, fmt.Errorf("password_envelope: синтетическое значение %s: параллельность вне типа читателя", class.Key())
		}
		salt := make([]byte, argon2idSaltLen)
		if _, err := rand.Read(salt); err != nil {
			return domain.LoginVerifier{}, fmt.Errorf("password_envelope: random source: %w", err)
		}
		body := argon2.IDKey([]byte(password), salt, iterations, memory, uint8(parallelism), argon2idKeyLen)
		return domain.NewLoginVerifier(argon2idMaterial(memory, iterations, parallelism, salt, body))
	default:
		return domain.LoginVerifier{}, fmt.Errorf("password_envelope: формат %q строить нечем", class.Format)
	}
}
