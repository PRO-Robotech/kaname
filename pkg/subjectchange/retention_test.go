// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

// retention_test.go — УДЕРЖАНИЕ ЖУРНАЛА СВЯЗЫВАЕТ ЧИТАТЕЛЯ (задача #1758).
//
// # Что здесь утверждается
//
// Величина [JournalRetention] объявлена как «наибольшее отставание читателя,
// которое владелец обязан обслужить точно». Объявление, которое ничего не
// связывает, есть число, за которым никто не следит: посадка вправе объявить
// срок молчания шире удержания, и тогда читатель, здоровый по собственному
// объявлению, получает отказ «позиция утрачена» в ШТАТНОЙ работе — сплошное
// гашение кэша решений и закрытие всех открытых потоков.
//
// Поэтому сборка читателя отвергает такую посадку. Проба утверждает ОБЕ стороны:
// негодная отвергается ПО ИМЕНИ величины, годная (в том числе ровно на границе)
// собирается. Односторонняя проба зеленела бы на сборке, отвергающей всё.
package subjectchange

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// retentionCloserStub — реестр открытых потоков, ничего не держащий.
type retentionCloserStub struct{}

func (retentionCloserStub) CloseSubject(string) int { return 0 }
func (retentionCloserStub) CloseAll() int           { return 0 }

// retentionPollerStub — источник изменений, ничего не отдающий. Предмет пробы —
// СБОРКА, а не чтение.
type retentionPollerStub struct{}

func (retentionPollerStub) PollSubjectChanges(context.Context, int64, int32) ([]SubjectChange, int64, error) {
	return nil, 0, nil
}

func retentionConfig(interval, staleAfter time.Duration) Config {
	return Config{
		Poller:     retentionPollerStub{},
		Flush:      func() {},
		Interval:   interval,
		Closer:     retentionCloserStub{},
		StaleAfter: staleAfter,
		Logger:     slog.New(slog.DiscardHandler),
	}
}

// TestReaderMayNotOutlastTheJournalItReads — срок молчания шире удержания
// отвергается сборкой.
func TestReaderMayNotOutlastTheJournalItReads(t *testing.T) {
	_, err := New(retentionConfig(time.Second, JournalRetention+time.Second))
	if err == nil {
		t.Fatal("читатель, объявивший рабочим молчание длиннее удержания журнала, собран. " +
			"На первом же удачном перепросе он получал бы отказ «позиция утрачена» в штатной " +
			"работе: сплошное гашение кэша решений и закрытие ВСЕХ открытых потоков — и решать " +
			"это никто не решал")
	}
	// Отказ обязан НАЗЫВАТЬ обе величины: оператор чинит посадку, а не гадает,
	// какая из двух ручек ему велика.
	for _, want := range []string{"StaleAfter", "удержание журнала"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("текст отказа не называет %q: %v", want, err)
		}
	}
}

// TestReaderOnTheRetentionBoundaryIsAccepted — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ.
//
// Без него отрицание выше зеленело бы на сборке, отвергающей всякий срок:
// «отвергнуто» неотличимо от «отвергается всё». Граница ВКЛЮЧАЮЩАЯ — читатель,
// молчащий ровно столько, сколько владелец хранит, ещё возобновляется точно.
func TestReaderOnTheRetentionBoundaryIsAccepted(t *testing.T) {
	if _, err := New(retentionConfig(time.Second, JournalRetention)); err != nil {
		t.Fatalf("срок РОВНО в удержание журнала отвергнут: %v — граница обязана быть включающей, "+
			"иначе она объявляет негодной посадку, при которой ничего не теряется", err)
	}
	// Сегодняшняя посадка края: `StaleAfter = max(5 × 2s, 10s)`.
	if _, err := New(retentionConfig(2*time.Second, 10*time.Second)); err != nil {
		t.Fatalf("сегодняшняя посадка края отвергнута: %v", err)
	}
}

// TestJournalRetentionDominatesTheDeclaredEdgePosture — величина СЕГОДНЯ не
// несущая, и это сказано числом, а не умолчано.
//
// Проба утверждает ПРАВИЛО, а не сегодняшний запас: отказ «позиция утрачена» не
// вправе производиться посадкой, которую край объявляет по умолчанию. Опустят
// удержание к сроку молчания края — проба покраснеет и позовёт решать, а не
// узнается по разорванным соединениям клиентов.
func TestJournalRetentionDominatesTheDeclaredEdgePosture(t *testing.T) {
	// `revocationStaleAfter` края: пять периодов, пол десять секунд.
	const edgePollInterval = 2 * time.Second
	edgeStaleAfter := edgePollInterval * 5
	if edgeStaleAfter < 10*time.Second {
		edgeStaleAfter = 10 * time.Second
	}
	if JournalRetention <= edgeStaleAfter {
		t.Fatalf("удержание журнала %v не превосходит срок молчания края %v — отказ «позиция "+
			"утрачена» становится штатным исходом, а он стоит сплошного гашения кэша и закрытия "+
			"всех потоков", JournalRetention, edgeStaleAfter)
	}
	t.Logf("перепись: удержание журнала %v, срок молчания края %v, запас ×%d",
		JournalRetention, edgeStaleAfter, int64(JournalRetention/edgeStaleAfter))
}
