// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// front_admission.go — допуск предъявителя собственного внутреннего REST-фронта
// и сужения довода, которые обработчики делают по личности вызывающего
// (SEC-1017-1, kaname#987 вместе с kaname#984).
//
// # Предмет: хоп фронта не переносит личность, а сужение довода её требует
//
// Предел хопа по МЕТОДАМ ([hopMethodSet]) — пересечение перечней профилей: то,
// что позволено любой личности. Этого мало там, где обработчик сужает не метод,
// а ДОВОД вызова по личности вызывающего: внутренний Check плоскости данных
// отвечает только об объектах её модуля (kaname#987). Личность обработчик берёт у
// пира gRPC, а на хопе пир — сам фронт; личности за ним не видно, и сужение не
// применяется. Фронт же пускает держателя ЛЮБОГО листа внутреннего центра:
// плоскость данных спросила бы через HTTP о чужом модуле, а лист вне перечня —
// о чём угодно, хотя gRPC-полоса ему отказывает полом.
//
// # Решение: судит тот, кто видит предъявителя, — фронт
//
// Личность предъявителя HTTP видит только фронт: состояние его рукопожатия.
// Поэтому допуск решается там, ТЕМ ЖЕ признанием, что на слушателях
// ([moduleidentity.Roster.FromTLSState]), и по ТОМУ ЖЕ перечню:
//
//   - лист вне перечня — отказ: на gRPC ему отказывает пол;
//   - личность профиля, у которого какой-либо метод хопа сужается по личности, —
//     отказ: сузить довод на хопе нечем, и пропустить её значило бы отвечать ей
//     шире, чем на gRPC. Полоса HTTP у такой личности УЖЕ gRPC-полосы, и это
//     допустимое направление;
//   - прочие признанные личности — допуск: их gRPC-полоса по методам хопа не
//     сужена, и полоса HTTP ей равна.
//
// Переноса личности внутрь здесь нет и не заводится: фронт не переносит ни
// одного заголовка, а слушатель не читает переданных личностей.
package authzguard

import (
	"crypto/tls"

	"github.com/PRO-Robotech/corelib/grpcsrv"

	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
)

// callerNarrowedArguments — методы внутреннего слушателя, чей обработчик сужает
// ДОВОД вызова по личности вызывающего, и профили, к которым сужение применяется.
// Объявлено один раз: обработчик спрашивает отсюда, к кому применять сужение, а
// допуск фронта — кого не пускать.
var callerNarrowedArguments = map[string][]moduleidentity.Profile{
	// Плоскость данных спрашивает только об объектах своего модуля (kaname#987).
	internalCheckMethod: {moduleidentity.ProfileDataPlane},
}

// NarrowsCallerArgument — сужает ли обработчик метода fullMethod довод вызова
// для личности профиля p.
func NarrowsCallerArgument(fullMethod string, p moduleidentity.Profile) bool {
	for _, q := range callerNarrowedArguments[fullMethod] {
		if q == p {
			return true
		}
	}
	return false
}

// HopAdmits — пускает ли собственный внутренний REST-фронт предъявителя с
// состоянием рукопожатия st (см. шапку файла).
//
// Непроверенный лист, лист вне перечня и лист чужого центра у личности с
// привязкой — не личность, отказ.
func HopAdmits(modules moduleidentity.Roster, d grpcsrv.TrustDomain, st *tls.ConnectionState) bool {
	id, ok := modules.FromTLSState(d, st)
	if !ok {
		return false
	}
	for m := range hopMethodSet(profileMethodSets()) {
		if NarrowsCallerArgument(m, id.Profile) {
			return false
		}
	}
	return true
}

// InternalFrontAdmission — допуск предъявителя внутреннего фронта посадки.
//
// Боевой режим — [HopAdmits] по перечню установки. Вне боевого режима политика
// вызывающего слушателя вырождается целиком (пол, перечни профилей и круг края
// пропускают всех), и допуск фронта вырождается с ней: суд строже слушателя на
// этой посадке был бы вторым местом об одном предмете.
func InternalFrontAdmission(prodMode bool, modules moduleidentity.Roster, d grpcsrv.TrustDomain) func(*tls.ConnectionState) bool {
	if !prodMode {
		return func(*tls.ConnectionState) bool { return true }
	}
	return func(st *tls.ConnectionState) bool { return HopAdmits(modules, d, st) }
}
