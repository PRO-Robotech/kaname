// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package admission — ОДИН предикат допуска субъекта и ОДНО значение отказа
// положения подтверждения (задача PRO-Robotech/kaname#456; приёмка
// `docs/engineering/acceptance/access-beyond-login-needs-a-verified-address.md`,
// решения Р1, Р3, Р4, Р5, Р5а, Р5б; §8 инв. 1, 2, 4).
//
// # Предмет
//
// Человек, чей текущий адрес почты не подтверждён, не допущен ни к одному
// решению о праве, ни к выдаче удостоверения, ни к предъявлению выданного.
// Положение не хранится и не кэшируется: его читает каждый, кто решает, из
// отметки в строке человека — на каждом вопросе (Р1).
//
// # Почему здесь, а не в каждом читателе
//
// Читателей у предиката четыре рода: формы вопроса двери решения (Р4а), рубеж
// по принципалу на обоих слушателях (Р4б, Р4в), правило выдачи удостоверений
// человеку на всех полосах выдачи (Р5, Р5б) и правило предъявления наших
// токенов (Р5а). Своего чтения отметки ни у одного читателя нет (инв. 4): копия
// предиката в каждом разошлась бы с остальными молча, и неверной была бы их
// разница, а не каждый по отдельности.
//
// # Что такое «человек» — строка людей, а не утверждение
//
// Вид принципала НЕ берётся на веру ни из утверждения токена, ни из переданного
// заголовка (условие аудита поверхности): идентификатор судится по строкам
// людей. Идентификатор, которому строка человека есть, — человек, и его отметка
// судится; идентификатора без строки человека предикат не судит — это модуль,
// служебная учётная запись, группа или системный принципал, и их вопросы о
// праве человека судит дверь решения. Идентификаторы платформы глобально
// уникальны, поэтому вид в записи субъекта на исход не влияет.
//
// # Исходов три
//
// Допущен · не допущен · СПРОСИТЬ НЕ СМОГЛИ. Третий — ошибка, и он никогда не
// сливается с первым: «не смогли прочесть отметку» есть отказ либо
// «не решено», а не «подтверждён».
package admission

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/refusaldomain"
)

// Значение отказа положения (Р3) — ОДНО на полосе формы и на обоих
// слушателях; второе написание — находка (инв. 2).
const (
	// TextNotVerified — текст отказа положения.
	TextNotVerified = "email address is not verified"
	// ReasonNotVerified — машинный признак отказа положения (`ErrorInfo.reason`).
	ReasonNotVerified = "EMAIL_NOT_VERIFIED"
	// DenyReason — причина отказа в ответе двери решения (`deny_reasons`, Р4а).
	DenyReason = "email_not_verified"
)

// Marks — хранилище отметок.
//
// Отвечает, какие из названных идентификаторов — строки людей и подтверждён ли
// их ТЕКУЩИЙ адрес. Идентификатор, которому строки человека нет, в ответе
// отсутствует. Ошибка — третий исход, «спросить не смогли».
type Marks interface {
	PersonMarks(ctx context.Context, ids []string) (map[string]bool, error)
}

// ErrNoMarks — читатель отметок не провязан. Отказ, а не допуск.
var ErrNoMarks = errors.New("admission: the address mark reader is not wired")

// ID — допущен ли принципал с этим идентификатором: false — строка человека с
// неподтверждённым текущим адресом. Пустой идентификатор никого не называет и
// допущен по построению: судить нечего, решает вызывающий.
func ID(ctx context.Context, m Marks, id string) (bool, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return true, nil
	}
	if m == nil {
		return false, ErrNoMarks
	}
	marks, err := m.PersonMarks(ctx, []string{id})
	if err != nil {
		return false, fmt.Errorf("admission: address mark of %s: %w", id, err)
	}
	verified, person := marks[id]
	return !person || verified, nil
}

// SubjectID — идентификатор, который субъект модели прав называет: вторая
// половина записи «тип:идентификатор». Набор («тип:идентификатор#отношение»),
// подстановочный знак и запись без двоеточия идентификатора не называют —
// ok=false: такой субъект не человек, и предикат его не судит.
func SubjectID(subject string) (string, bool) {
	i := strings.IndexByte(subject, ':')
	if i <= 0 || i == len(subject)-1 {
		return "", false
	}
	id := subject[i+1:]
	if strings.ContainsAny(id, "#*") {
		return "", false
	}
	return id, true
}

// Subject — допущен ли субъект модели прав (Р4а).
func Subject(ctx context.Context, m Marks, subject string) (bool, error) {
	id, ok := SubjectID(subject)
	if !ok {
		return true, nil
	}
	return ID(ctx, m, id)
}

// Subjects — допущенность каждого субъекта ОДНИМ вопросом к хранилищу: ответ
// той же длины и в порядке заданных субъектов (перечень держателей, Р4а).
func Subjects(ctx context.Context, m Marks, subjects []string) ([]bool, error) {
	out := make([]bool, len(subjects))
	ids := make([]string, 0, len(subjects))
	for i, s := range subjects {
		out[i] = true
		if id, ok := SubjectID(s); ok {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return out, nil
	}
	if m == nil {
		return nil, ErrNoMarks
	}
	marks, err := m.PersonMarks(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("admission: address marks of %d subjects: %w", len(ids), err)
	}
	for i, s := range subjects {
		if id, ok := SubjectID(s); ok {
			if verified, person := marks[id]; person && !verified {
				out[i] = false
			}
		}
	}
	return out, nil
}

// RefusalStatus — значение отказа положения на слушателях gRPC (Р3):
// PERMISSION_DENIED, текст [TextNotVerified], `ErrorInfo` с признаком
// [ReasonNotVerified] и доменом отказов службы — у объявления
// (`refusaldomain`), а не по месту. Звено, приписывающее отказам по правам свою
// причину, отказ с `ErrorInfo` не трогает: второго признака у отказа положения
// нет.
func RefusalStatus() error {
	st := status.New(codes.PermissionDenied, TextNotVerified)
	withDetails, err := st.WithDetails(&errdetails.ErrorInfo{Reason: ReasonNotVerified, Domain: refusaldomain.For(refusaldomain.ServiceIAM)})
	if err != nil {
		// Сборка деталей не удалась — отказ остаётся отказом тем же кодом и
		// текстом: пропуск на неудаче сборки был бы мягким проходом.
		return st.Err()
	}
	return withDetails.Err()
}

// IsRefusal — несёт ли ошибка значение отказа положения.
func IsRefusal(err error) bool {
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.PermissionDenied || st.Message() != TextNotVerified {
		return false
	}
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok && info.GetReason() == ReasonNotVerified {
			return true
		}
	}
	return false
}
