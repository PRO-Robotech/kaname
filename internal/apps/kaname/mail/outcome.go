// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package mail

// Outcome — исход Enqueue (З1): закрытый перечень. Нулевое значение
// OutcomeUnset — «исхода нет»: его отдаёт Enqueue рядом с ошибкой.
type Outcome uint8

// Исходы Enqueue.
const (
	OutcomeUnset Outcome = iota
	// OutcomeQueued — строка ленты записана в транзакции события.
	OutcomeQueued
	// OutcomeResentSame — повтор письма с тем же живым кодом (З12).
	OutcomeResentSame
	// OutcomeFloor — письмо, пропущенное полом окна адресата (Р6).
	OutcomeFloor
	// OutcomeTrustedDevice — письмо восстановления из запаса доверенного
	// устройства (Р12).
	OutcomeTrustedDevice
	// OutcomeCapped — письма нет: исчерпан потолок окна адресата либо лимит
	// шаблона ленты (З19).
	OutcomeCapped
	// OutcomeCooldown — письма нет: пауза от прошлого письма прогрессии.
	OutcomeCooldown
	// OutcomeDisabled — письма нет: флаг почты выключен; не записано ничего
	// (З2, NTF-1 Р9).
	OutcomeDisabled
	// OutcomeNoRecipient — письма нет: у события нет адресата (З16).
	OutcomeNoRecipient
)

var outcomeNames = [...]string{
	OutcomeUnset:         "unset",
	OutcomeQueued:        "queued",
	OutcomeResentSame:    "resent_same",
	OutcomeFloor:         "floor",
	OutcomeTrustedDevice: "trusted_device",
	OutcomeCapped:        "capped",
	OutcomeCooldown:      "cooldown",
	OutcomeDisabled:      "disabled",
	OutcomeNoRecipient:   "no_recipient",
}

// String — слово исхода.
func (o Outcome) String() string {
	if int(o) < len(outcomeNames) {
		return outcomeNames[o]
	}
	return "unset"
}

// Outcomes — закрытый перечень исходов Enqueue, без OutcomeUnset.
func Outcomes() []Outcome {
	return []Outcome{
		OutcomeQueued, OutcomeResentSame, OutcomeFloor, OutcomeTrustedDevice,
		OutcomeCapped, OutcomeCooldown, OutcomeDisabled, OutcomeNoRecipient,
	}
}

// Verb — глагол работы окна адресата: метка verb метрики
// kaname_mail_intents_total (З11).
type Verb string

// Глаголы работ окна (З11: LockAnchor зовут recovery, register, verify-email).
const (
	VerbRecovery    Verb = "recovery"
	VerbRegister    Verb = "register"
	VerbVerifyEmail Verb = "verify-email"
)

// Verbs — закрытый перечень глаголов метрики.
func Verbs() []Verb { return []Verb{VerbRecovery, VerbRegister, VerbVerifyEmail} }

// IntentOutcome — исход работы окна: метка outcome метрики
// kaname_mail_intents_total. Набор закрыт приёмкой NTF-2 (Р6):
// queued|resent_same|cooldown|capped|floor|trusted_device|dropped_overload.
type IntentOutcome string

// Исходы метрики.
const (
	IntentQueued          IntentOutcome = "queued"
	IntentResentSame      IntentOutcome = "resent_same"
	IntentCooldown        IntentOutcome = "cooldown"
	IntentCapped          IntentOutcome = "capped"
	IntentFloor           IntentOutcome = "floor"
	IntentTrustedDevice   IntentOutcome = "trusted_device"
	IntentDroppedOverload IntentOutcome = "dropped_overload"
)

// IntentOutcomes — закрытый перечень исходов метрики в порядке приёмки.
func IntentOutcomes() []IntentOutcome {
	return []IntentOutcome{
		IntentQueued, IntentResentSame, IntentCooldown, IntentCapped,
		IntentFloor, IntentTrustedDevice, IntentDroppedOverload,
	}
}

// Intent — исход метрики, которым является исход Enqueue. Disabled и
// NoRecipient исходом окна не являются (окно не спрашивалось); dropped_overload
// — исход диспетчера, а не Enqueue.
func (o Outcome) Intent() (IntentOutcome, bool) {
	switch o {
	case OutcomeQueued:
		return IntentQueued, true
	case OutcomeResentSame:
		return IntentResentSame, true
	case OutcomeFloor:
		return IntentFloor, true
	case OutcomeTrustedDevice:
		return IntentTrustedDevice, true
	case OutcomeCapped:
		return IntentCapped, true
	case OutcomeCooldown:
		return IntentCooldown, true
	case OutcomeUnset, OutcomeDisabled, OutcomeNoRecipient:
		return "", false
	}
	return "", false
}
