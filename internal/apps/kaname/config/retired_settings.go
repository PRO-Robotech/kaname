// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// retired_settings.go — СНЯТЫЙ КЛЮЧ НАСТРОЙКИ ОТВЕРГАЕТСЯ ВСЛУХ (kaname#363).
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗАЧЕМ ОТКАЗ, А НЕ ПРОСТО СНЯТАЯ ПРИВЯЗКА
//
// Загрузчик незнакомых ключей не отвергает: у разбора задан только перевод
// значений, запрета на лишнее нет. Ключ, снятый одной лишь правкой структуры,
// оставался бы в профиле оператора и читался бы как настроенный — «принято и
// проигнорировано», — хотя прежде он был ОБЯЗАТЕЛЕН и менял старт. Поэтому ключ,
// снятый вместе с тем, что он выбирал, отвергается при ЛЮБОМ значении и на
// КАЖДОМ пути подачи процессу: файлом настройки и переменной окружения. Путь
// значений чарта отвергает свой страж (`kaname-svc.requireNoRetiredKnobs`).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ В ПЕРЕЧНЕ ОДНА СТРОКА, ХОТЯ СНЯТО БОЛЬШЕ
//
// Тем же изменением ушли ключи хуков внешнего поставщика и его
// административной дороги. Их значение не меняло старта единственной законной
// посадки и прежде: под `own` хуки не собирались, дорога не строилась, и эти
// ключи были инертны уже тогда. Снятие их читателя ничего молча не
// переворачивает, а отказ на них заставил бы каждую установку менять профиль
// ради того, что поведения не меняло. Ключ посадки — иной: он был ОБЯЗАТЕЛЕН,
// его значение выбирало требования старта, и оставленный в профиле он
// выглядел бы решением, которого больше никто не принимает.
//
// Строка сюда добавляется тем изменением, которое снимает ключ, чьё значение
// меняло поведение; перечень — единственное место об этом предмете.
package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
	"go.uber.org/multierr"
)

// retiredSetting — снятый ключ настройки так, как его знал оператор.
type retiredSetting struct {
	// Key — путь ключа в файле настройки.
	Key string
	// Env — переменная окружения, которой ключ подавался процессу.
	Env string
	// Why — почему ключ снят и чем прежний его предмет задаётся теперь.
	// Входит в отказ дословно.
	Why string
}

// retiredSettings — перечень снятых ключей. Единственное объявление.
var retiredSettings = []retiredSetting{
	{
		Key: "authn.identity-provider",
		Env: "KANAME_AUTHN__IDENTITY_PROVIDER",
		Why: "the service has a single identity posture — its own sign-in and its own minting — and " +
			"reads no key that chooses one; the requirements this key used to select are judged on " +
			"every production start",
	},
}

// refuseRetiredSettingsInEnv — отказ на каждой снятой переменной, заданной в
// окружении процесса. Заданная пустой — тоже заданная: под объявляет её явно,
// и молча принятая пустая переменная — тот же класс.
func refuseRetiredSettingsInEnv(lookupEnv func(string) (string, bool)) error {
	var errs error
	for _, r := range retiredSettings {
		if _, set := lookupEnv(r.Env); !set {
			continue
		}
		errs = multierr.Append(errs, fmt.Errorf(
			"%s is a retired setting and is refused, not ignored: %s. The environment carries %s — "+
				"remove the variable from the process environment",
			r.Key, r.Why, r.Env))
	}
	return errs
}

// refuseRetiredSettingsInFile — отказ на каждом снятом ключе, объявленном
// файлом настройки, при любом значении — в том числе пустом и `null`.
func refuseRetiredSettingsInFile(v *viper.Viper, path string) error {
	var errs error
	for _, r := range retiredSettings {
		if !declaredInFile(v, r.Key) {
			continue
		}
		errs = multierr.Append(errs, fmt.Errorf(
			"%s is a retired setting and is refused, not ignored: %s. The settings file %q declares "+
				"it — remove the line",
			r.Key, r.Why, path))
	}
	return errs
}

// declaredInFile — объявлен ли ключ прочитанным файлом настройки.
//
// `InConfig` отвечает по ЗНАЧЕНИЮ и на `null` говорит «нет»: строка
// `identity-provider:` без значения прошла бы мимо. Поэтому присутствие
// проверяется ещё и по ключу в родительской карте файла.
func declaredInFile(v *viper.Viper, key string) bool {
	if v.InConfig(key) {
		return true
	}
	i := strings.LastIndex(key, ".")
	if i < 0 {
		return false
	}
	parent, ok := v.Get(key[:i]).(map[string]any)
	if !ok {
		return false
	}
	_, has := parent[key[i+1:]]
	return has
}
