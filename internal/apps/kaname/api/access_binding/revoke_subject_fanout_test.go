// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// revoke_subject_fanout_test.go — снятие называет КАЖДОГО субъекта привязки
// (kacho#1022, B3).

import (
	"context"
	"errors"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	abrepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
)

func recordingEmitter(out *[]abrepo.SubjectChangeEvent) subjectChangeEmitter {
	return func(_ context.Context, e abrepo.SubjectChangeEvent) error {
		*out = append(*out, e)
		return nil
	}
}

// TestRevokeNamesEverySubject — несущее утверждение.
//
// Выдача разворачивается по всем субъектам привязки, снятие брало легаси-
// одиночку (`Subjects[0]` по объявлению домена). Субъекты со второго по N-й не
// получали строки журнала НИКОГДА: их кэш не сбрасывался, а с поимённым
// закрытием потоков их поток жил бы до своего бюджета — то есть снятое право
// продолжало действовать на открытом соединении.
func TestRevokeNamesEverySubject(t *testing.T) {
	binding := domain.AccessBinding{
		ID: "abn-1", SubjectType: "user", SubjectID: "usr_first",
		ResourceType: "project", ResourceID: "prj-a",
	}
	list := func(context.Context, domain.AccessBindingID) ([]domain.Subject, error) {
		return []domain.Subject{
			{Type: "user", ID: "usr_first"},
			{Type: "user", ID: "usr_second"},
			{Type: "service_account", ID: "sva_third"},
		}, nil
	}

	var got []abrepo.SubjectChangeEvent
	if err := emitSubjectChangeForEverySubject(context.Background(), list,
		recordingEmitter(&got), binding, "binding_revoke", "binding_delete"); err != nil {
		t.Fatalf("развёртка: %v", err)
	}

	if len(got) != 3 {
		t.Fatalf("строк журнала %d, ожидалось 3 — субъекты со второго не названы, "+
			"их потоки пережили бы отзыв", len(got))
	}
	want := []struct{ typ, id string }{
		{"user", "usr_first"}, {"user", "usr_second"}, {"service_account", "sva_third"},
	}
	for i, w := range want {
		if got[i].SubjectID != w.id || got[i].SubjectType != w.typ {
			t.Errorf("строка %d названа %s:%s, ожидалось %s:%s",
				i, got[i].SubjectType, got[i].SubjectID, w.typ, w.id)
		}
		if got[i].EventType != "binding_revoke" || got[i].Op != "binding_delete" {
			t.Errorf("строка %d несёт вид %q/%q", i, got[i].EventType, got[i].Op)
		}
		// Здесь утверждалось, что строка несёт предмет привязки
		// (`ResourceID == "prj-a"`). Утверждение снято ВМЕСТЕ СО СВОИМ ПРЕДМЕТОМ,
		// а не ослаблено: величины предмета журнала не читал никто — ни проекция
		// чтения, ни контракт PollSubjectChanges, ни потребитель на крае, — и они
		// сняты (миграция 20260829124512, kacho#1462). Предмет ЭТОЙ пробы другой
		// и цел: снятие обязано назвать КАЖДОГО субъекта привязки.
	}
}

// TestRevokeFallsBackToTheLegacySingleSubject — привязки, записанные до
// многосубъектной модели, дочерних строк не имеют.
//
// Без отката развёртка по пустому набору не эмитила бы НИЧЕГО — то есть починка
// одного класса завела бы второй, тише первого: отзыв старой привязки перестал
// бы доезжать вообще.
func TestRevokeFallsBackToTheLegacySingleSubject(t *testing.T) {
	binding := domain.AccessBinding{
		ID: "abn-legacy", SubjectType: "service_account", SubjectID: "sva_only",
		ResourceType: "project", ResourceID: "prj-b",
	}
	empty := func(context.Context, domain.AccessBindingID) ([]domain.Subject, error) {
		return nil, nil
	}

	var got []abrepo.SubjectChangeEvent
	if err := emitSubjectChangeForEverySubject(context.Background(), empty,
		recordingEmitter(&got), binding, "binding_revoke", "binding_delete"); err != nil {
		t.Fatalf("развёртка: %v", err)
	}
	if len(got) != 1 || got[0].SubjectID != "sva_only" || got[0].SubjectType != "service_account" {
		t.Fatalf("на пустом наборе субъектов эмитировано %d строк (%+v) — "+
			"отзыв старой привязки перестал бы доезжать вовсе", len(got), got)
	}
}

// TestUnreadableSubjectSetIsNotSilentlyNarrowed — отказ чтения набора НЕ
// вырождается в «одного назвали, и ладно».
//
// Молчаливый откат на одиночку при ОШИБКЕ чтения назвал бы первого и потерял
// остальных, а вызывающий увидел бы успех. Отказ уходит наверх, и снятие не
// коммитится: строки журнала пишутся в той же транзакции.
func TestUnreadableSubjectSetIsNotSilentlyNarrowed(t *testing.T) {
	boom := errors.New("набор субъектов не прочитан")
	failing := func(context.Context, domain.AccessBindingID) ([]domain.Subject, error) {
		return nil, boom
	}
	var got []abrepo.SubjectChangeEvent
	err := emitSubjectChangeForEverySubject(context.Background(), failing,
		recordingEmitter(&got), domain.AccessBinding{ID: "abn-2", SubjectID: "usr_x", SubjectType: "user"},
		"binding_revoke", "binding_delete")
	if !errors.Is(err, boom) {
		t.Fatalf("отказ чтения набора не доехал наверх: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("на непрочитанном наборе эмитировано %d строк — вызывающий увидел бы успех "+
			"при потерянных субъектах", len(got))
	}
}
