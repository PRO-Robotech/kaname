// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/domain"
	abrepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
)

// emitSubjectChangeForEverySubject эмитит строку журнала смены субъекта НА
// КАЖДОГО субъекта привязки.
//
// # Почему развёртка, а не легаси-одиночка
//
// Выдача разворачивается по всем субъектам привязки (`create.go` эмитит строку
// на каждого), а снятие брало `binding.SubjectID` — легаси-проекцию, которая по
// объявлению домена равна `Subjects[0]`. Субъекты со второго по N-й не получали
// строки НИКОГДА.
//
// Пока строку читал только сплошной сброс кэша, цена была «кэш второго субъекта
// не сброшен» — ограниченная сроком жизни записи. С поимённым закрытием потоков
// (kacho#1022) цена другая: поток второго субъекта живёт до своего бюджета, то
// есть снятое право продолжает действовать на открытом соединении.
//
// # Почему с откатом на одиночку, а не только по дочерней таблице
//
// Привязки, записанные до многосубъектной модели, дочерних строк не имеют.
// Развёртка по пустому набору не эмитила бы НИЧЕГО — то есть починка одного
// класса завела бы второй, тише первого. Откат на легаси-одиночку сохраняет
// поведение ровно там, где набора нет.
// Порты УЗКИЕ — две функции, а не два интерфейса репозитория целиком. Так
// развёртка проверяется вызовом, без подделки полусотни методов, которых у неё
// нет предмета; а подделка, которую иначе пришлось бы писать, была бы
// снисходительнее продукта ровно в том месте, где предмет пробы.
type subjectLister func(context.Context, domain.AccessBindingID) ([]domain.Subject, error)

type subjectChangeEmitter func(context.Context, abrepo.SubjectChangeEvent) error

func emitSubjectChangeForEverySubject(
	ctx context.Context,
	listSubjects subjectLister,
	emit subjectChangeEmitter,
	binding domain.AccessBinding,
	eventType, op string,
) error {
	subjects, err := listSubjects(ctx, binding.ID)
	if err != nil {
		return err
	}
	if len(subjects) == 0 {
		subjects = []domain.Subject{{Type: binding.SubjectType, ID: binding.SubjectID}}
	}
	for _, s := range subjects {
		if err := emit(ctx, abrepo.SubjectChangeEvent{
			SubjectID:   string(s.ID),
			SubjectType: string(s.Type),
			EventType:   eventType,
			Op:          op,
		}); err != nil {
			return err
		}
	}
	return nil
}
