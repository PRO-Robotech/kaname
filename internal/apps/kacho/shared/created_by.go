// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package shared

// created_by.go — ЕДИНЫЙ источник правила про `created_by_user_id` на полосах
// выдачи удостоверений (персональный токен человека, ключ служебной учётки).
//
// Правило одно, и записано оно здесь ОДИН раз:
//
//	присланный ответственный обязан совпасть с тем, которого сервис запишет;
//	там, где край записываемого значения не знает, поле обязано быть пустым.
//
// Почему общий источник, а не проверка «полосы согласны между собой». Полос
// две, реализаций правила было тоже две, и они разошлись молча: анти-подлог
// сидел в ветке вызывающего-ЧЕЛОВЕКА, а на полосе машины у персонального токена
// поле не читал никто — значение принималось и выбрасывалось (запрещённый третий
// исход, api-conventions.md «Принято-и-проигнорировано»). Сверка двух копий
// поймала бы расхождение, но не сделала бы его невозможным; один источник —
// делает.
//
// ОДНО ОТЛИЧИЕ ПОЛОС НАЗВАНО ЗДЕСЬ, А НЕ ОСТАВЛЕНО МОЛЧАЛИВЫМ. У персонального
// токена записываемый ответственный назван САМИМ запросом (`user_id`), поэтому
// присланное совпадающее значение край сверить может — и применяет. У ключа
// служебной учётки ответственный резолвится внутри use-case из владельца
// аккаунта целевой учётки; на крае его нет ни в каком виде, сверять нечем, и
// любое непустое значение отвергается. Различие не во вкусе, а в том, доступно
// ли краю записываемое значение, — и оно выражено ОТДЕЛЬНЫМ полем, а не
// вынесено в комментарий.

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// CreatedByLane описывает, что полоса выдачи запишет в `created_by_user_id`.
//
// Знание значения и само значение — РАЗНЫЕ поля намеренно: пустая строка в
// MachineLaneRecords означала бы одновременно «записывается пустое» и «край не
// знает», а это два разных состояния, и правило на них отвечает по-разному.
type CreatedByLane struct {
	// Principal — идентификатор аутентифицированного вызывающего.
	Principal string
	// CallerIsServiceAccount — вызывающий есть машина (служебная учётка). Её
	// идентификатор строкой users(id) не является, поэтому ответственным она
	// быть не может ни на одной полосе.
	CallerIsServiceAccount bool
	// MachineLaneKnowsRecord — знает ли КРАЙ, какого ответственного полоса
	// запишет вызывающему-машине. false → присланное сверить нечем.
	MachineLaneKnowsRecord bool
	// MachineLaneRecords — то самое значение. Читается только при
	// MachineLaneKnowsRecord.
	MachineLaneRecords string
	// MachineLaneRecordSource — как ответственный называется в отказе, который
	// читает вызывающий. Часть контракта сообщений.
	MachineLaneRecordSource string
}

// CreatedByLaneForUserToken — полоса персонального токена: вызывающей машине
// ответственным записывается ЦЕЛЕВОЙ пользователь, и он же назван запросом.
func CreatedByLaneForUserToken(principal string, callerIsServiceAccount bool, targetUserID string) CreatedByLane {
	return CreatedByLane{
		Principal:               principal,
		CallerIsServiceAccount:  callerIsServiceAccount,
		MachineLaneKnowsRecord:  true,
		MachineLaneRecords:      targetUserID,
		MachineLaneRecordSource: "the token's user_id",
	}
}

// CreatedByLaneForSAKey — полоса ключа служебной учётки: вызывающей машине
// ответственным записывается владелец аккаунта ЦЕЛЕВОЙ учётки, и край его не
// знает — резолв идёт в use-case, из репозитория.
func CreatedByLaneForSAKey(principal string, callerIsServiceAccount bool) CreatedByLane {
	return CreatedByLane{
		Principal:               principal,
		CallerIsServiceAccount:  callerIsServiceAccount,
		MachineLaneKnowsRecord:  false,
		MachineLaneRecordSource: "the service account's account owner",
	}
}

// ValidateRequested судит присланного ответственного. nil — вход законен;
// InvalidArgument с именем поля — сервис его не запишет.
//
// Тексты отказов — часть контракта и здесь дословно те, что полосы произносили
// до сведения: сведение правила не есть повод переписать сообщения.
func (l CreatedByLane) ValidateRequested(requested string) error {
	if requested == "" {
		// Не назван — законный вход: ответственного подставит полоса. Обязательным
		// это поле не делается ни на одной из них, и контракт больше не утверждает
		// обратного.
		return nil
	}
	if !l.CallerIsServiceAccount {
		if requested == l.Principal {
			return nil
		}
		return status.Error(codes.InvalidArgument,
			"Illegal argument created_by_user_id: must match authenticated principal or be empty")
	}
	if !l.MachineLaneKnowsRecord {
		// Записываемое значение краю недоступно — сверить присланное нечем.
		// Принять и выбросить было бы запрещённым третьим исходом.
		return status.Error(codes.InvalidArgument,
			"Illegal argument created_by_user_id: must be empty for a service-account caller "+
				"(created_by is resolved from "+l.MachineLaneRecordSource+")")
	}
	if requested == l.MachineLaneRecords {
		// Совпало с тем, что полоса и запишет: параметр ПРИМЕНЁН, а не выброшен.
		return nil
	}
	return status.Error(codes.InvalidArgument,
		"Illegal argument created_by_user_id: must match "+l.MachineLaneRecordSource+
			" or be empty for a service-account caller")
}
