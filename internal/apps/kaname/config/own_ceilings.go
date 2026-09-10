// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"fmt"

	"go.uber.org/multierr"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// own_ceilings.go — ТРИ СОБСТВЕННЫХ ПОТОЛКА СЛУЖБЫ ДОСТУПА, объявленные
// ПОСАДКОЙ (приёмка `KAN-QUOTA-1`, `П25`, §2.0/§2.1; задача продукта #2117).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЭТО ПОСАДКА, А НЕ НАСТРОЙКА С УМОЛЧАНИЕМ
//
// Служба доступа перестаёт быть авторитетом величин, но три её собственных
// потолка остаются действующими: сколько аккаунтов заводит одна личность и
// сколько путей входа держит человек и машина. Спросить величину не у кого —
// в самостоятельной установке внешнего авторитета нет by construction.
//
// Величина, которую подставляет построение, предметом стража быть НЕ МОЖЕТ: он
// зелен при любом входе, потому что незаданной она не бывает. Поэтому умолчания
// нет ни здесь, ни в `defaults.go`, а ключи привязаны к окружению явно в
// `load.go` — `AutomaticEnv` разрешает переменную только для ключа, который
// viper УЖЕ знает.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ УКАЗАТЕЛЬ, А НЕ ЧИСЛО
//
// Ноль — ЗАКОННАЯ И ОСМЫСЛЕННАЯ величина: «ресурсов этого вида не заводить».
// На простом `int64` он неотличим от «величина не объявлена», и оператор,
// желающий запретить вид, не смог бы этого выразить ни при каком вводе.
// Отсутствие обязано быть представимо ОТДЕЛЬНО от значения.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЭТИ ТРИ РУЧКИ НЕ ОТМЕНЯЮТ
//
// Ручку внешнего авторитета величин: для ЧУЖИХ видов служба остаётся обычным
// потребителем и спрашивает величину у объявленного авторитета ровно как
// остальные пять. Роль выбирается по владельцу вида, а не глобальным режимом.

// ownCeilingKnob — ОДНА величина посадки: ключ, переменная, вид и доступ к полю.
//
// Таблица — единственное место, где ключ настройки связан со ВИДОМ. Второе
// разошлось бы с первым молча: ключ правят коммитом в этот файл, вид — в
// каталог, и расхождение видно только тому, кто в этот день ставит службу.
type ownCeilingKnob struct {
	// Key — путь ключа в файле настроек. Координата, которую называет отказ.
	Key string
	// Env — имя переменной окружения. ВЫВОДИТСЯ из ключа тем же правилом, каким
	// его выводит viper (см. envNameOf), поэтому второго написания не бывает.
	Env string
	// Kind — вид каталога, чей потолок объявляет эта величина.
	Kind domain.LimitKind
	// Why — чем этот потолок защищает установку, словами оператора.
	Why string
	// Value — доступ к полю. Функция, а не смещение: поле остаётся обычным и
	// читается прямо, а таблица не заводит второго способа его назвать.
	Value func(OwnCeilingsConfig) *int64
}

// ownCeilingKeyPrefix — секция настроек. Отдельная от `authn` намеренно: предмет
// здесь не проверка предъявленного, а потолок числа ресурсов.
const ownCeilingKeyPrefix = "own-ceilings."

// OwnCeilingKnobs — ТАБЛИЦА. Порядок — порядок, в котором величины встречает
// оператор: сперва аккаунты (первое, что делает человек), затем удостоверения.
var OwnCeilingKnobs = []ownCeilingKnob{
	{
		Key:  ownCeilingKeyPrefix + "accounts-per-identity",
		Env:  "KANAME_OWN_CEILINGS__ACCOUNTS_PER_IDENTITY",
		Kind: "iam.account",
		Why: "сколько аккаунтов заводит ОДНА личность. Приём аккаунта — самообслуживание, " +
			"поэтому без этого потолка второй аккаунт покупает второй полный набор всех " +
			"прочих потолков тем же жестом, каким получен первый",
		Value: func(c OwnCeilingsConfig) *int64 { return c.AccountsPerIdentity },
	},
	{
		Key:  ownCeilingKeyPrefix + "credentials-per-user",
		Env:  "KANAME_OWN_CEILINGS__CREDENTIALS_PER_USER",
		Kind: "iam.user.credential",
		Why: "сколько путей входа держит ОДИН человек одновременно. Слот освобождает ОТЗЫВ, " +
			"а не истечение срока: иначе накопление удостоверений ничем не ограничено",
		Value: func(c OwnCeilingsConfig) *int64 { return c.CredentialsPerUser },
	},
	{
		Key:   ownCeilingKeyPrefix + "credentials-per-service-account",
		Env:   "KANAME_OWN_CEILINGS__CREDENTIALS_PER_SERVICE_ACCOUNT",
		Kind:  "iam.serviceAccount.credential",
		Why:   "то же для машины: сколько ключей держит одна служебная учётка одновременно",
		Value: func(c OwnCeilingsConfig) *int64 { return c.CredentialsPerServiceAccount },
	},
}

// OwnCeilingsConfig — три величины посадки.
type OwnCeilingsConfig struct {
	// AccountsPerIdentity — потолок вида `iam.account`.
	AccountsPerIdentity *int64 `mapstructure:"accounts-per-identity"`
	// CredentialsPerUser — потолок вида `iam.user.credential`.
	CredentialsPerUser *int64 `mapstructure:"credentials-per-user"`
	// CredentialsPerServiceAccount — потолок вида `iam.serviceAccount.credential`.
	CredentialsPerServiceAccount *int64 `mapstructure:"credentials-per-service-account"`
}

// Validate — страж посадки: каждая из трёх величин объявлена и неотрицательна.
//
// Отказ по КАЖДОЙ величине сразу (multierr), а не по первой: оператор, узнающий
// перечень по одному имени за перезапуск, платит перекатом за каждую строку.
func (c OwnCeilingsConfig) Validate() error {
	var errs error
	for _, k := range OwnCeilingKnobs {
		v := k.Value(c)
		if v == nil {
			errs = multierr.Append(errs, fmt.Errorf(
				"%s не задан (%s): потолок вида %s объявляет ПОСАДКА службы доступа — "+
					"внешнего авторитета в самостоятельной установке нет, и спросить "+
					"величину не у кого. Задайте неотрицательное целое; 0 означает "+
					"«ресурсов этого вида не заводить». Зачем: %s",
				k.Key, k.Env, k.Kind, k.Why))
			continue
		}
		if *v < 0 {
			errs = multierr.Append(errs, fmt.Errorf(
				"%s = %d (%s): потолок вида %s обязан быть неотрицательным. "+
					"Отрицательное значение НЕ означает «без ограничения» — такое "+
					"прочтение сняло бы потолок величиной, похожей на опечатку; "+
					"«не заводить вовсе» выражается нулём",
				k.Key, *v, k.Env, k.Kind))
		}
	}
	return errs
}

// Stated — объявленные величины по видам. Пустая карта означает, что посадка не
// объявлена; страж выше до этого не допускает.
//
// Единственный путь, которым величины уезжают из настройки в схему: композиционный
// корень зовёт его и проецирует результат в таблицу, откуда их читает списание.
func (c OwnCeilingsConfig) Stated() map[domain.LimitKind]int64 {
	out := make(map[domain.LimitKind]int64, len(OwnCeilingKnobs))
	for _, k := range OwnCeilingKnobs {
		if v := k.Value(c); v != nil {
			out[k.Kind] = *v
		}
	}
	return out
}
