// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

// emitted_completion.go — неизменный член выдачи нескольким субъектам доводится
// до полного набора кортежей (kaname#880).
//
// # Почему сверки по ключу члена здесь мало
//
// Сверка прохода судит члена по ключу (правило, объект) и статусу: совпали —
// член «не изменился», и его кортежи не пишутся. Для выдачи ОДНОМУ субъекту это
// точно: набор кортежей члена — функция ключа. Для выдачи нескольким субъектам —
// нет: кортежи — объединение по субъектам, а субъектов в ключе нет.
//
// Код до kaname#880 разворачивал выдачу одному первому субъекту. Член такой
// выдачи записан с тем же ключом, что даёт ему нынешний вывод, но с кортежами
// одного субъекта; сверка по ключу сочла бы его неизменным навсегда, и кортежи
// субъектов со второго по N-й не были бы записаны ни одним проходом — ни обходом
// по таймеру, ни проходом при старте. Свидетель полноты один — реестр
// выпущенного: недостающее в нём дописывается тем же порядком, что запись
// нового члена (журнал кортежей и реестр в одной транзакции).
//
// # Цена
//
// Реестр читается лишь у выдачи с двумя и более субъектами, лениво — когда в
// проходе нашёлся неизменный действующий член, и не более раза за проход:
// полный проход — одно обращение по префиксу первичного ключа реестра
// (binding_id), строк столько, сколько выдача выпустила; проход по объекту —
// одно обращение по объекту. У сошедшейся выдачи недостающего нет, и проход
// ничего не пишет (проба TestReconcileMultiSubject_ConvergedBindingIsNotRewritten).
//
// # Контракт: дописывание только добавляет
//
// Дописывание по ключу члена даёт НАДМНОЖЕСТВО выпущенного и само ничего не
// снимает: кортеж субъекта, которого в наборе больше нет, оно оставило бы на
// месте. Это верно, пока набор субъектов выдачи после создания неизменен —
// `subjects` стоит в перечне неизменяемых полей обновления
// (`abImmutableFields`, update.go), а снятие выдачи целиком идёт по реестру
// выпущенного: отзыв (`RevokeAccessBindingUseCase.doRevoke`) и удаление
// (`DeleteAccessBindingUseCase.deleteOnce`) читают его через
// `SelectEmittedTuples`. Метод сужения набора (`DeleteSubject` репозитория
// выдачи) в рабочем коде не вызывается; появится такой вызов — дописывание
// обязано снимать кортежи вычтенных членов, и это отдельный предмет, а не
// правка этого файла мимоходом.

import (
	"context"
	"fmt"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// emittedView — реестр выпущенного выдачей в границах прохода, прочитанный
// лениво и не более одного раза. nil — проход недостающего не ищет.
type emittedView struct {
	load func(ctx context.Context) ([]domain.MembershipTuple, error)
	set  map[domain.MembershipTuple]struct{}
}

// bindingEmitted — реестр всей выдачи (полный проход).
func bindingEmitted(s ReconcileStore, bindingID domain.AccessBindingID) *emittedView {
	return &emittedView{load: func(ctx context.Context) ([]domain.MembershipTuple, error) {
		return s.LedgerTuples(ctx, bindingID)
	}}
}

// objectEmitted — реестр выдачи на одном объекте (проход по объекту). Тип без
// живой строки каталога кортежей не имеет — искать недостающее не в чем.
func (r *Reconciler) objectEmitted(s ReconcileStore, bindingID domain.AccessBindingID, objectType, objectID string) *emittedView {
	fgaType, ok := r.cat.Facts().FGAObjectType(objectType)
	if !ok {
		return nil
	}
	object := fgaType + ":" + objectID
	return &emittedView{load: func(ctx context.Context) ([]domain.MembershipTuple, error) {
		return s.LedgerTuplesForObject(ctx, bindingID, object)
	}}
}

func (v *emittedView) tuples(ctx context.Context) (map[domain.MembershipTuple]struct{}, error) {
	if v.set != nil {
		return v.set, nil
	}
	rows, err := v.load(ctx)
	if err != nil {
		return nil, err
	}
	v.set = make(map[domain.MembershipTuple]struct{}, len(rows))
	for _, t := range rows {
		v.set[t] = struct{}{}
	}
	return v.set, nil
}

// completeMemberTuples дописывает неизменному действующему члену `d` кортежи,
// которых нет в реестре выпущенного выдачей: журнал кортежей и реестр — в той
// же транзакции прохода, тем же порядком, что запись нового члена (applyDiff).
// Выдача одному субъекту не читается вовсе — у неё ключ члена точен.
func (r *Reconciler) completeMemberTuples(ctx context.Context, s ReconcileStore, bs BindingScope,
	d DesiredMember, emitted *emittedView, col *syncFGACollector) error {
	if emitted == nil || len(bs.Subjects) < 2 || len(d.Tuples) == 0 {
		return nil
	}
	have, err := emitted.tuples(ctx)
	if err != nil {
		return fmt.Errorf("emitted ledger of %s: %w", bs.BindingID, err)
	}
	var missing []domain.MembershipTuple
	for _, t := range d.Tuples {
		if _, ok := have[t]; !ok {
			missing = append(missing, t)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	if fresh := col.collectNew(missing); len(fresh) > 0 {
		if err := s.EmitTupleWrite(ctx, fresh); err != nil {
			return fmt.Errorf("emit missing tuple write %s:%s: %w", d.ObjectType, d.ObjectID, err)
		}
	}
	if err := s.RecordEmittedTuples(ctx, bs.BindingID, missing); err != nil {
		return fmt.Errorf("record missing emitted tuple %s:%s: %w", d.ObjectType, d.ObjectID, err)
	}
	for _, t := range missing {
		have[t] = struct{}{}
	}
	return nil
}
