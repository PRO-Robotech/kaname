// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

// emitted_completion.go — неизменный действующий член выдачи сводится к своему
// желаемому набору кортежей: недостающее дописывается (kaname#880), лишнее
// снимается (kaname#1006).
//
// # Почему сверки по ключу члена здесь мало
//
// Сверка прохода судит члена по ключу (правило, объект) и статусу: совпали —
// член «не изменился», и его кортежи не пишутся. Это было бы точно, будь набор
// кортежей члена функцией ключа. Он ею не является, и случаев два:
//
//   - выдача нескольким субъектам (kaname#880): кортежи — объединение по
//     субъектам, а субъектов в ключе нет. Код до kaname#880 разворачивал выдачу
//     одному первому субъекту; член такой выдачи записан с тем же ключом, что
//     даёт ему нынешний вывод, но с кортежами одного субъекта, и сверка по ключу
//     сочла бы его неизменным навсегда;
//   - набор глаголов правила зависит не только от отпечатка правила, но и от
//     каталога и политики роли (kaname#1006): роль модуля перестала получать
//     удаление к правке, а ключ её члена остался прежним. Выдача,
//     материализованная прежним вычислением, несла бы лишний `v_delete`
//     навсегда — ни обход по таймеру, ни проход при старте его не сняли бы.
//
// Свидетель выпущенного один — реестр: недостающее в нём дописывается тем же
// порядком, что запись нового члена (журнал кортежей и реестр в одной
// транзакции); лишнее снимается тем же порядком, что снятие выпавшего члена
// (`revokeMemberTuples`): своя строка реестра — раньше строки снятия (kaname#919),
// кортеж, на который претендует другой выживший член выдачи, в движке остаётся.
//
// # Где сводится и цена
//
// ПОЛНЫЙ проход (обход по таймеру, проход при старте, правка роли) сводит
// каждого неизменного действующего члена при любом числе субъектов: реестр
// выдачи читается лениво — когда нашёлся неизменный действующий член — и не
// более раза за проход, одним обращением по префиксу первичного ключа реестра
// (binding_id); строк столько, сколько выдача выпустила, — того же порядка, что
// чтение её членов, которое полный проход делает всегда. Проход ПО ОБЪЕКТУ —
// горячий путь регистрации — реестр читает, как прежде, лишь у выдачи с двумя и
// более субъектами, одним обращением по объекту; выдачу одному субъекту по
// объекту сводит следующий полный проход. У сошедшейся выдачи ни недостающего,
// ни лишнего нет, и проход ничего не пишет (пробы
// TestReconcileMultiSubject_ConvergedBindingIsNotRewritten,
// TestReconcile_ConvergedModuleRoleBindingIsNotRewritten).
//
// # Что лишним НЕ считается
//
// Лишняя — строка реестра ПОД КООРДИНАТОЙ сводимого члена, на которую не
// претендует ни один желаемый действующий член этой координаты. Строки других
// координат и строки уровня выдачи (нулевая координата) не трогаются: у них свой
// владелец и свой путь снятия.

import (
	"cmp"
	"context"
	"fmt"
	"slices"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// emittedView — реестр выпущенного выдачей в границах прохода, прочитанный
// лениво и не более одного раза. nil — проход неизменных членов не сводит. Строка
// реестра судится парой (координата члена, кортеж): кортеж, записанный ДРУГОЙ
// координатой, за свой этому члену не засчитывается — уход той координаты снял бы
// его (kaname#933).
type emittedView struct {
	load func(ctx context.Context) ([]LedgerRow, error)
	// whole — реестр всей выдачи (полный проход): неизменный член сводится при
	// любом числе субъектов.
	whole bool
	set   map[LedgerRow]struct{}
	// byCoord — те же строки по координате члена: сведение одного члена не
	// обходит реестр всей выдачи.
	byCoord map[MemberCoord]map[domain.MembershipTuple]struct{}
}

// bindingEmitted — реестр всей выдачи (полный проход).
func bindingEmitted(s ReconcileStore, bindingID domain.AccessBindingID) *emittedView {
	return &emittedView{whole: true, load: func(ctx context.Context) ([]LedgerRow, error) {
		return s.LedgerTuples(ctx, bindingID)
	}}
}

// objectEmitted — реестр выдачи, выпущенный членом на одном объекте (проход по
// объекту): координата прохода — та же, что у его членов, и каталог для её сборки не
// нужен.
func objectEmitted(s ReconcileStore, bindingID domain.AccessBindingID, objectType, objectID string) *emittedView {
	coord := MemberCoord{ObjectType: objectType, ObjectID: objectID}
	return &emittedView{load: func(ctx context.Context) ([]LedgerRow, error) {
		tuples, err := s.LedgerTuplesForMember(ctx, bindingID, coord)
		if err != nil {
			return nil, err
		}
		rows := make([]LedgerRow, 0, len(tuples))
		for _, t := range tuples {
			rows = append(rows, LedgerRow{Member: coord, Tuple: t})
		}
		return rows, nil
	}}
}

// converges — сводит ли проход неизменного члена выдачи `bs`.
func (v *emittedView) converges(bs BindingScope) bool {
	return v != nil && (v.whole || len(bs.Subjects) >= 2)
}

func (v *emittedView) ensure(ctx context.Context) error {
	if v.set != nil {
		return nil
	}
	rows, err := v.load(ctx)
	if err != nil {
		return err
	}
	v.set = make(map[LedgerRow]struct{}, len(rows))
	v.byCoord = make(map[MemberCoord]map[domain.MembershipTuple]struct{})
	for _, row := range rows {
		v.add(row)
	}
	return nil
}

func (v *emittedView) add(row LedgerRow) {
	v.set[row] = struct{}{}
	at := v.byCoord[row.Member]
	if at == nil {
		at = make(map[domain.MembershipTuple]struct{})
		v.byCoord[row.Member] = at
	}
	at[row.Tuple] = struct{}{}
}

func (v *emittedView) forget(row LedgerRow) {
	delete(v.set, row)
	delete(v.byCoord[row.Member], row.Tuple)
}

// convergeMemberTuples сводит неизменного действующего члена `d` к его желаемому
// набору: дописывает кортежи, которых нет в реестре под ЕГО координатой, и снимает
// строки этой координаты, на которые не претендует ни один желаемый действующий
// член (`claims`). Порядок записи — тот же, что у нового члена (applyDiff), порядок
// снятия — тот же, что у выпавшего (revokeMemberTuples).
func (r *Reconciler) convergeMemberTuples(ctx context.Context, s ReconcileStore, bs BindingScope,
	d DesiredMember, emitted *emittedView, claims *memberClaims, col *syncFGACollector) error {
	if !emitted.converges(bs) || len(d.Tuples) == 0 {
		return nil
	}
	if err := emitted.ensure(ctx); err != nil {
		return fmt.Errorf("emitted ledger of %s: %w", bs.BindingID, err)
	}
	coord := desiredCoord(d)

	var missing []domain.MembershipTuple
	for _, t := range d.Tuples {
		if _, ok := emitted.set[LedgerRow{Member: coord, Tuple: t}]; !ok {
			missing = append(missing, t)
		}
	}
	if len(missing) > 0 {
		if fresh := col.collectNew(missing); len(fresh) > 0 {
			if err := s.EmitTupleWrite(ctx, fresh); err != nil {
				return fmt.Errorf("emit missing tuple write %s:%s: %w", d.ObjectType, d.ObjectID, err)
			}
		}
		if err := s.RecordEmittedTuples(ctx, bs.BindingID, coord, missing); err != nil {
			return fmt.Errorf("record missing emitted tuple %s:%s: %w", d.ObjectType, d.ObjectID, err)
		}
		for _, t := range missing {
			emitted.add(LedgerRow{Member: coord, Tuple: t})
		}
	}

	var forget []LedgerRow
	var revoke []domain.MembershipTuple
	for t := range emitted.byCoord[coord] {
		if claims.claimedAt(coord, t) {
			continue
		}
		forget = append(forget, LedgerRow{Member: coord, Tuple: t})
		if !claims.claimed(t) {
			revoke = append(revoke, t)
		}
	}
	if len(forget) == 0 {
		return nil
	}
	// Порядок — детерминированный: строка снятия журнала и вызовы порта не должны
	// зависеть от обхода карты.
	slices.SortFunc(forget, func(a, b LedgerRow) int { return compareTuples(a.Tuple, b.Tuple) })
	slices.SortFunc(revoke, compareTuples)
	// Своя строка реестра — раньше строки снятия (kaname#919).
	if err := s.ForgetEmittedTuples(ctx, bs.BindingID, forget); err != nil {
		return fmt.Errorf("forget surplus emitted tuple %s:%s: %w", d.ObjectType, d.ObjectID, err)
	}
	for _, row := range forget {
		emitted.forget(row)
	}
	// Строка снятия — в конец прохода (вычитание записанного тем же проходом).
	col.deferDelete(bs.BindingID, revoke)
	return nil
}

// compareTuples — порядок кортежей: субъект, отношение, объект.
func compareTuples(a, b domain.MembershipTuple) int {
	return cmp.Or(cmp.Compare(a.User, b.User), cmp.Compare(a.Relation, b.Relation), cmp.Compare(a.Object, b.Object))
}
