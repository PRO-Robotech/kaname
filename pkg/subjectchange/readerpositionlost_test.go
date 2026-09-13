// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

// readerpositionlost_test.go — отказ «позиция утрачена» ПЕРЕЖИВАЕТ ПРОВОД.
//
// # Почему настоящий gRPC, а не подставной источник
//
// Признак полосы едет НЕ кодом и НЕ текстом, а деталью ответа
// (`google.rpc.ErrorInfo`). Деталь пакуется в `Any`, проходит сериализацию и
// распаковывается на другой стороне — то есть ровно то звено, которым эта полоса
// и держится, лежит в транспорте. Проба на подставном источнике вернула бы ту же
// структуру в памяти и осталась бы зелёной при отказе, деталь ТЕРЯЮЩЕМ.
//
// Рядом стоит положительный контроль: обычный отказ владельца сквозь тот же
// провод полосой НЕ признаётся. Без него утверждение зеленело бы на адаптере,
// объявляющем утраченной всякую позицию.
package subjectchange_test

import (
	"context"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/PRO-Robotech/kaname/pkg/subjectchange"
)

// refusingJournalStub — владелец журнала, отвечающий заготовленным отказом.
type refusingJournalStub struct {
	iamv1.UnimplementedInternalIAMServiceServer
	mu  sync.Mutex
	err error
}

func (s *refusingJournalStub) PollSubjectChanges(
	context.Context, *iamv1.PollSubjectChangesRequest,
) (*iamv1.PollSubjectChangesResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return nil, s.err
}

// TestPositionLostReachesTheReaderThroughTheWire — деталь доезжает и разбирается.
func TestPositionLostReachesTheReaderThroughTheWire(t *testing.T) {
	stub := &refusingJournalStub{err: subjectchange.PositionLost(599)}
	conn := dial(t, func(s *grpc.Server) {
		iamv1.RegisterInternalIAMServiceServer(s, stub)
	})

	_, _, err := subjectchange.NewReader(conn).PollSubjectChanges(context.Background(), 42, 256)
	if err == nil {
		t.Fatal("владелец отказал, адаптер отказа не вернул")
	}

	lost, ok := subjectchange.AsPositionLost(err)
	if !ok {
		t.Fatalf("отказ «позиция утрачена» не пережил провод: %v (код %v). "+
			"Признак полосы едет деталью ответа, и потеря детали делает полосу неотличимой "+
			"от общего отказа — то есть читатель повторял бы с утраченной позиции вечно", err, status.Code(err))
	}
	if lost.EarliestResumable != 599 {
		t.Errorf("возобновимая позиция %d, ожидалось 599 — читателю некуда садиться", lost.EarliestResumable)
	}
}

// TestOrdinaryOwnerRefusalIsNotReadAsPositionLost — положительный контроль.
func TestOrdinaryOwnerRefusalIsNotReadAsPositionLost(t *testing.T) {
	stub := &refusingJournalStub{
		err: status.Error(codes.Unavailable, "subject change position not settled"),
	}
	conn := dial(t, func(s *grpc.Server) {
		iamv1.RegisterInternalIAMServiceServer(s, stub)
	})

	_, _, err := subjectchange.NewReader(conn).PollSubjectChanges(context.Background(), 42, 256)
	if err == nil {
		t.Fatal("владелец отказал, адаптер отказа не вернул")
	}
	if _, ok := subjectchange.AsPositionLost(err); ok {
		t.Fatal("холодный старт владельца прочитан как утраченная позиция — " +
			"читатель погасил бы кэш и сдвинул курсор там, где верный шаг переспросить")
	}
}
