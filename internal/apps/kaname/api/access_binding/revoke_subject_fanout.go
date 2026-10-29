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
	subjects, err := bindingSubjectsOf(ctx, listSubjects, binding)
	if err != nil {
		return err
	}
	return emitSubjectChangeFor(ctx, emit, subjects, eventType, op)
}

// bindingSubjectsOf — весь перечень субъектов выдачи; пустой перечень (выдача,
// записанная до многосубъектной модели) — её одиночная пара.
//
// Снятие, удаляющее строку выдачи, зовёт его ДО удаления: дочерние строки
// субъектов уходят каскадом в той же транзакции, и прочитанный после удаления
// перечень пуст — откат на одиночку отдал бы ровно первого субъекта
// (kaname#880).
func bindingSubjectsOf(ctx context.Context, listSubjects subjectLister, binding domain.AccessBinding) ([]domain.Subject, error) {
	subjects, err := listSubjects(ctx, binding.ID)
	if err != nil {
		return nil, err
	}
	if len(subjects) == 0 {
		subjects = []domain.Subject{{Type: binding.SubjectType, ID: binding.SubjectID}}
	}
	return subjects, nil
}

// emitSubjectChangeFor — строка журнала смены субъекта на каждого из `subjects`.
func emitSubjectChangeFor(ctx context.Context, emit subjectChangeEmitter, subjects []domain.Subject, eventType, op string) error {
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

// revokedAuditFor — строка аудита «отозвано» на каждого из `subjects`, симметрично
// строке «выдано», которую создание пишет на каждого (`create.go`). Строка на
// одного первого оставляла бы в следе выдачу субъектам со второго по N-й
// неснятой (kaname#880).
//
// Ссылку на делегирование строка несёт по ВЫДАЧЕ, а не по тому, кто отзывает:
// отзыв делегатом и отзыв обычным держателем права пишут её одинаково, и аккаунт
// строки у такой выдачи — аккаунт делегирования при любой области (kaname#986,
// Р5). Ссылка читается из строки выдачи под замком снятия (условие CE-16); у
// выдачи без ссылки ключа нет.
func revokedAuditFor(ctx context.Context, w Writer,
	subjects []domain.Subject, actor string, binding domain.AccessBinding) error {
	tenant, extra, err := delegationAuditScope(ctx, w, binding)
	if err != nil {
		return err
	}
	for _, s := range subjects {
		if err := w.AccessBindingsW().EmitAuditEvent(ctx, abrepo.AuditEvent{
			EventType:       abrepo.AuditEventTypeRevoked,
			Actor:           actor,
			SubjectType:     string(s.Type),
			SubjectID:       string(s.ID),
			ResourceType:    string(binding.ResourceType),
			ResourceID:      binding.ResourceID,
			RoleID:          string(binding.RoleID),
			BindingID:       string(binding.ID),
			TenantAccountID: tenant,
			ExtraPayload:    extra,
		}); err != nil {
			return err
		}
	}
	return nil
}

// delegationAuditScope — аккаунт строки аудита и полезная нагрузка сверх
// канонической у выдачи, несущей ссылку на делегирование (Р5): аккаунт
// делегирования и `delegation_id`. У прочей выдачи — прежний писатель
// (`auditTenantAccountID`) и пустая добавка.
func delegationAuditScope(ctx context.Context, w Writer, binding domain.AccessBinding) (string, map[string]any, error) {
	if binding.DelegationID == "" {
		return auditTenantAccountID(binding), nil, nil
	}
	account, err := w.AccessBindingsW().GrantDelegationsW().AccountOf(ctx, binding.DelegationID)
	if err != nil {
		return "", nil, err
	}
	return string(account), map[string]any{"delegation_id": string(binding.DelegationID)}, nil
}
