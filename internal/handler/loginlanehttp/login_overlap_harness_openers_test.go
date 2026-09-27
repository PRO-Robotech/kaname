// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// login_overlap_harness_openers_test.go — ПРЕДПОСЫЛКА стенда проб границы входа
// (`login_overlap_harness_integration_test.go`, kaname#385): обёртка хранилища
// входа перехватывает КАЖДУЮ дверь порта, открывающую транзакцию записи, а не
// одну из них (kaname#382).
//
// Точки З1…З4 стоят на обёртке транзакции записи (`overlapWriter`), и она
// появляется у глагола только тогда, когда транзакцию открыла ОБЁРТКА
// хранилища. Обёртка встраивает порт `humansession.Store` — поэтому дверь,
// которую обёртка не переопределила, проходит к настоящему адаптеру МОЛЧА:
// стенд собирается, сцена не строится, и пробы падают через 20 с словами
// «НЕ ВЫПОЛНИЛОСЬ: вход не дошёл до точки З1», ни разу не назвав причину. Так и
// было: выдача входа перешла с `Writer` на `PersonWriter` (a941fa831), обёртка
// перехватывала только `Writer`, и 15 проб KN-OVL из 16 не выполнились.
//
// Перечень дверей берётся ИЗ ПОРТА отражением, а не выписывается: дверь —
// метод порта, чьи результаты ровно `(humansession.Writer, error)`. Дверь,
// которую порт заведёт завтра, попадёт в перечень сама. Каждая дверь
// вызывается на обёртке поверх дублёра с взведённой точкой З1: перехваченная
// дверь до этой точки доходит и отдаёт `overlapWriter` поверх транзакции
// дублёра; неперехваченная возвращается раньше, чем точка наступила, — и проба
// называет дверь по имени. Сна нет: исход различают каналы.
//
// Способность падать доказана внесённой обёрткой, забывшей `PersonWriter` —
// ровно форма дефекта; законный близнец той же формы — `Writer` той же
// обёртки, перехваченный, — молчит.
package loginlanehttp_test

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// openerStubWriter — транзакция дублёра: опознаётся по тождеству.
type openerStubWriter struct{ humansession.Writer }

// openerStubStore — дублёр хранилища, отвечающий на каждую дверь порта своей
// транзакцией. Дверь, которой дублёр не знает, уходит во встроенный пустой
// порт и падает — проба ловит это и называет дверь.
type openerStubStore struct {
	humansession.Store
	w *openerStubWriter
}

func (s openerStubStore) Writer(context.Context) (humansession.Writer, error) { return s.w, nil }

func (s openerStubStore) SessionSetWriter(context.Context, domain.UserID) (humansession.Writer, error) {
	return s.w, nil
}

func (s openerStubStore) PersonWriter(context.Context, domain.UserID) (humansession.Writer, error) {
	return s.w, nil
}

// forgetfulOverlapStore — ВНЕСЁННЫЙ дефект: обёртка, у которой `PersonWriter`
// идёт к настоящему хранилищу мимо обёртки, как было до kaname#382.
type forgetfulOverlapStore struct{ *overlapStore }

func (s forgetfulOverlapStore) PersonWriter(ctx context.Context, userID domain.UserID) (humansession.Writer, error) {
	return s.overlapStore.Store.PersonWriter(ctx, userID)
}

// writerOpenersOfTheLoginStore — двери порта `humansession.Store`: методы,
// чьи результаты ровно `(humansession.Writer, error)`.
func writerOpenersOfTheLoginStore() []reflect.Method {
	port := reflect.TypeFor[humansession.Store]()
	writer := reflect.TypeFor[humansession.Writer]()
	errType := reflect.TypeFor[error]()
	var out []reflect.Method
	for i := range port.NumMethod() {
		m := port.Method(i)
		if m.Type.NumOut() == 2 && m.Type.Out(0) == writer && m.Type.Out(1) == errType {
			out = append(out, m)
		}
	}
	return out
}

// openerArgs — аргументы двери: контекст, непустой идентификатор, прочее — нуль.
func openerArgs(m reflect.Method) []reflect.Value {
	ctxType := reflect.TypeFor[context.Context]()
	args := make([]reflect.Value, m.Type.NumIn())
	for i := range args {
		in := m.Type.In(i)
		switch {
		case in == ctxType:
			args[i] = reflect.ValueOf(context.Background())
		case in.Kind() == reflect.String:
			args[i] = reflect.ValueOf("usr0000000opener0probe").Convert(in)
		default:
			args[i] = reflect.Zero(in)
		}
	}
	return args
}

// openerOutcome — что дверь сделала на обёртке.
type openerOutcome struct {
	writer   humansession.Writer
	err      error
	panicked any
}

// bypassesOfTheWrapper — двери, которые обёртка store НЕ перехватывает, с
// причиной; пустой ответ — перехвачены все. Точка З1 взводится на gates.
func bypassesOfTheWrapper(t *testing.T, store humansession.Store, gates *overlapGates, stub *openerStubWriter) map[string]string {
	t.Helper()
	bypass := map[string]string{}
	for _, m := range writerOpenersOfTheLoginStore() {
		g := gates.arm(t, pointOpen)
		done := make(chan openerOutcome, 1)
		call := reflect.ValueOf(store).MethodByName(m.Name)
		go func() {
			var o openerOutcome
			defer func() {
				if r := recover(); r != nil {
					o.panicked = r
				}
				done <- o
			}()
			res := call.Call(openerArgs(m))
			o.writer, _ = res[0].Interface().(humansession.Writer)
			o.err, _ = res[1].Interface().(error)
		}()
		var o openerOutcome
		reached := false
		select {
		case <-g.reached:
			reached = true
			g.lift()
			o = <-done
		case o = <-done:
			// Дверь вернулась, не дойдя до З1: взведённую точку забирает проба,
			// иначе следующая дверь нашла бы её занятой.
			gates.take(pointOpen)
		}
		switch {
		case o.panicked != nil:
			bypass[m.Name] = fmt.Sprintf("дублёр хранилища этой двери не знает — вызов упал: %v", o.panicked)
		case !reached:
			bypass[m.Name] = "дверь вернулась, не дойдя до точки З1: обёртка её не перехватывает"
		case o.err != nil:
			bypass[m.Name] = "дверь отказала: " + o.err.Error()
		default:
			ow, ok := o.writer.(*overlapWriter)
			switch {
			case !ok:
				bypass[m.Name] = fmt.Sprintf("дверь отдала %T, а не обёртку транзакции — точки З2…З4 на ней не наступят", o.writer)
			case ow.Writer != humansession.Writer(stub):
				bypass[m.Name] = fmt.Sprintf("обёртка транзакции стоит не над транзакцией хранилища: %T", ow.Writer)
			}
		}
	}
	return bypass
}

func newOpenerProbeStore(t *testing.T) (*overlapStore, *overlapGates, *openerStubWriter) {
	t.Helper()
	gates := newOverlapGates(t)
	stub := &openerStubWriter{}
	return &overlapStore{
		Store: openerStubStore{w: stub},
		gates: gates,
		clock: &overlapClock{},
		seq:   new(atomic.Int64),
	}, gates, stub
}

func openerNames(ms []reflect.Method) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.Name)
	}
	return out
}

func bypassNames(b map[string]string) []string {
	out := make([]string, 0, len(b))
	for k := range b {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestLoginOverlapHarnessInterceptsEveryWriterOpenerOfTheLoginStore — каждая
// дверь порта, открывающая транзакцию записи, проходит через точку З1 обёртки
// и отдаёт обёртку транзакции: сцены KN-OVL строятся, каким бы открытием ни
// пользовалась выдача входа.
func TestLoginOverlapHarnessInterceptsEveryWriterOpenerOfTheLoginStore(t *testing.T) {
	openers := writerOpenersOfTheLoginStore()
	t.Logf("перепись: дверей записи у порта humansession.Store — %d (%v)", len(openers), openerNames(openers))
	require.NotEmpty(t, openers,
		"НЕ ВЫПОЛНИЛОСЬ: у порта humansession.Store не найдено ни одной двери записи — перепись ничего не прочла")

	store, gates, stub := newOpenerProbeStore(t)
	bypass := bypassesOfTheWrapper(t, store, gates, stub)
	for _, name := range bypassNames(bypass) {
		t.Errorf("обёртка хранилища входа не перехватывает дверь %s: %s", name, bypass[name])
	}
	require.Equal(t, len(openers), store.opens(),
		"каждая перехваченная дверь отмечает открытие транзакции записи входа")
}

// TestLoginOverlapHarnessOpenerProbeFindsAForgottenOpener — способность падать:
// обёртка, забывшая `PersonWriter`, названа по этой двери; её `Writer`,
// перехваченный, — законный близнец — не назван.
func TestLoginOverlapHarnessOpenerProbeFindsAForgottenOpener(t *testing.T) {
	store, gates, stub := newOpenerProbeStore(t)
	bypass := bypassesOfTheWrapper(t, forgetfulOverlapStore{overlapStore: store}, gates, stub)
	require.Contains(t, bypass, "PersonWriter", "внесённый дефект: забытая дверь названа — %v", bypass)
	require.Contains(t, bypass["PersonWriter"], "не дойдя до точки З1", "находка называет причину, а не симптом")
	require.NotContains(t, bypass, "Writer", "законный близнец: перехваченная дверь той же обёртки молчит")
}
