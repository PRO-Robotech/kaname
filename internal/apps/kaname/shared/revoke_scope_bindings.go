// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package shared

// revoke_scope_bindings.go — снятие ВЫДАЧ, сделанных на область, которую сносят.
//
// # Почему это живёт здесь, а не копией в каждом ресурсном пакете
//
// `access_bindings` не несут внешнего ключа ни на `accounts`, ни на `projects`
// (ссылка мягкая, межресурсная), поэтому удаление носителя области НЕ доводится
// базой: строка выдачи остаётся ACTIVE, её кортежи остаются в движке, а
// периодический реконсайлер продолжает их материализовать. Значит снимает либо
// код удаления, либо никто.
//
// Тело этого снятия параметрично ровно по паре (вид области, id) — всё
// остальное дословно совпадает у аккаунта и у проекта. Второй экземпляр того же
// перечня разошёлся бы с первым при заведении следующего носителя области, и
// разошёлся бы МОЛЧА: обе копии по отдельности выглядят исправными.
//
// # Дренаж, а не выборка
//
// Читаем СТРАНИЦАМИ, пока область не опустеет. Чтение одной страницы с
// отброшенным продолжением означало бы: всё сверх страницы сохраняет и строку, и
// кортежи, а операция рапортует полный успех — ни ошибки, ни счётчика, ни строки.
// Запрос фильтрует только по области, поэтому страницу занимают и давно
// отозванные, и истёкшие выдачи, старейшие первыми, — а размер страницы и так
// платформенный максимум, поднимать его некуда.
//
// Первая страница перечитывается каждым проходом вместо следования за курсором
// намеренно: дренаж идёт ВНУТРИ writer-транзакции, поэтому удалённые предыдущим
// проходом строки следующему чтению уже не видны, а курсор пришлось бы нести
// через удаление тех самых строк, на которые он указывает.
//
// # Отказ, а не частичная работа
//
// Потолок проходов превращает патологическую область в ГРОМКИЙ ОТКАЗ, называющий
// ситуацию, и никогда — в тихое частичное удаление. Весь чинимый этим кодом
// дефект есть усечение, которого никто не мог увидеть.
//
// # Симметрия снятия — из ВЕДОМОСТИ
//
// Снимается ровно тот набор, который постановка записала в
// `access_binding_emitted_tuples`, а не выведенный заново из текущей роли: роль
// могла с тех пор измениться, и повторный вывод снял бы не то, что клал. Снятие
// кортежей в движке идемпотентно (дренаж отображает cannot_delete в успех),
// поэтому повторный проход at-least-once безопасен.
//
// Чтения идут ДО удаления строки выдачи, пока строки ведомости ещё на месте —
// они уходят каскадом по внешнему ключу вместе с выдачей.

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	abrepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
)

// ScopeBindingRevokePageSize / ScopeBindingRevokeMaxPasses — границы дренажа.
// Размер страницы — платформенный максимум списка; потолок проходов обращает
// патологическую область в отказ, а не в тихую частичную работу.
const (
	ScopeBindingRevokePageSize  = 1000
	ScopeBindingRevokeMaxPasses = 50
)

// RevokeBindingsInScope сносит КАЖДУЮ выдачу, сделанную на область
// (resourceType, resourceID), внутри транзакции вызывающего: читает её
// персистентную ведомость выпущенных кортежей, удаляет строку выдачи (её
// ведомость уходит каскадом) и ВОЗВРАЩАЕТ собранный набор кортежей на снятие.
//
// Эмитит собранное САМ ВЫЗЫВАЮЩИЙ — вместе со своими собственными кортежами
// жизненного цикла (указатель аккаунта на кластер, структурные указатели
// проекта), которые в ведомости выдач по построению не значатся.
//
// displayNoun — существительное ресурса в тоне контракта («Account», «Project»);
// попадает в текст отказа, который читает оператор.
func RevokeBindingsInScope(
	ctx context.Context,
	w kanamerepo.Writer,
	resourceType domain.ResourceType,
	resourceID string,
	displayNoun string,
) ([]outboxtypes.RelationTuple, int, error) {
	var fgaDeletes []outboxtypes.RelationTuple
	var revoked int
	for pass := 0; ; pass++ {
		if pass >= ScopeBindingRevokeMaxPasses {
			// Отказываем громко, а не рапортуем успех о частичной работе.
			return nil, 0, status.Errorf(codes.FailedPrecondition,
				"%s %s carries more than %d access bindings; delete them before deleting the %s",
				displayNoun, resourceID,
				ScopeBindingRevokeMaxPasses*ScopeBindingRevokePageSize,
				lowerASCII(displayNoun))
		}
		bindings, _, err := w.AccessBindings().ListByScope(
			ctx, resourceType, resourceID,
			abrepo.PageFilter{PageSize: ScopeBindingRevokePageSize},
		)
		if err != nil {
			return nil, 0, MapRepoErr(err)
		}
		if len(bindings) == 0 {
			break
		}
		for _, b := range bindings {
			stored, serr := w.AccessBindings().SelectEmittedTuples(ctx, b.ID)
			if serr != nil {
				return nil, 0, MapRepoErr(serr)
			}
			for _, tp := range stored {
				fgaDeletes = append(fgaDeletes, outboxtypes.RelationTuple{
					User: tp.User, Relation: tp.Relation, Object: tp.Object,
				})
			}
			if derr := w.AccessBindingsW().Delete(ctx, b.ID); derr != nil {
				return nil, 0, MapRepoErr(derr)
			}
			revoked++
		}
	}
	return fgaDeletes, revoked, nil
}

// lowerASCII опускает первую букву существительного для хвоста сообщения
// («…before deleting the account»). Тон сообщения — часть контракта, поэтому
// хвост выводится из того же слова, а не пишется вторым литералом: два места об
// одном предмете разошлись бы молча.
func lowerASCII(s string) string {
	if s == "" {
		return s
	}
	b := []byte(s)
	if b[0] >= 'A' && b[0] <= 'Z' {
		b[0] += 'a' - 'A'
	}
	return string(b)
}
