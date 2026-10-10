// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package errors

// step_up.go — указание повысить уровень аутентификации (решение Р11 приёмки
// «уровень уверенности объявляет наша сессия», редакция 9;
// PRO-Robotech/kaname#511).
//
// # Предмет
//
// На недостаток уровня три поверхности отвечали по-разному: край — вызовом
// RFC 9470, публичный слушатель службы — отказом прав, церемония —
// перенаправлением. Обработчик повышения, написанный под одну поверхность, на
// другой не срабатывал, а по `403` дежурный искал выдачи прав вместо повышения.
// Р11 приводит слушатель службы к форме края (KA1-15): `UNAUTHENTICATED` /
// `401`, текст, называющий шаг, и вызов с параметрами уровня.
//
// # Почему здесь, а не у производителя
//
// Указание собирают ДВА звена одного процесса: политика публичного слушателя
// (вердикт и параметры) и публичный REST-фронт (вызов на проводе). Свой текст и
// своя сборка вызова у каждого — ровно тот раскол, который и найден; пакет
// общих отказов зависимостей не несёт и доступен обоим.

// TextStepUpRequired — текст указания, дословно один на все поверхности
// (Р11; тот же, что у края — сторона края kaname#511). Называет ШАГ и ничего не
// говорит об объекте: КАКОЙ уровень нужен, несёт вызов (`acr_values`).
const TextStepUpRequired = "authentication level is insufficient: step up with a second factor, or present a credential of another kind"

// StepUpChallengeTrailer — ключ хвостовых метаданных ответа gRPC, которым
// публичный слушатель передаёт СВОЕМУ REST-фронту готовый вызов указания.
//
// Хвост, а не заголовки: отказ перехватчика уходит ответом без тела, и
// заголовки, не отправленные до статуса, клиент gRPC не получает вовсе —
// хвост доезжает всегда. Значение — тот же вызов, что ставится в
// `WWW-Authenticate`: держатель удостоверения читает его и на нативном gRPC.
const StepUpChallengeTrailer = "kaname-step-up-challenge"

// StepUpChallenge — значение `WWW-Authenticate` указания (RFC 9470 §3,
// RFC 6750 §3) в форме края (KA1-15):
//
//	Bearer error="insufficient_user_authentication",
//	  error_description="Required ACR <N> for this resource; presented ACR <M>",
//	  acr_values="<N>"
//
// required и presented — ступени лестницы уровней, уже приведённые вызывающим
// к числу (незнакомое и пустое — «0»): в значение заголовка не попадает ничего,
// кроме цифр, и кавычку внутрь параметра подставить нечем.
func StepUpChallenge(required, presented string) string {
	return `Bearer error="insufficient_user_authentication", error_description="Required ACR ` +
		required + ` for this resource; presented ACR ` + presented + `", acr_values="` + required + `"`
}
