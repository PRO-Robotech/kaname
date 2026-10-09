// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/service"
)

// publicationCall — один вызов порта публикации, как его увидел дублёр. `kind` —
// какой путь позван: "apply" (намерение владельца), "withdraw" (публикация уходит
// со снятием объекта), "drop-stale" (новое воплощение не наследует прежнюю).
type publicationCall struct {
	kind             string
	objectType       string
	objectID         string
	headType         string
	published        bool
	version          time.Time
	objectGeneration int64
}

// recordingPublisher — дублёр порта публикации для проб, чей предмет — МАРШРУТ:
// какой путь позван, для какого объекта, в какую сторону, С КАКОЙ ВЕРСИЕЙ и каким
// воплощением.
//
// Порядок и воплощение он НЕ судит и на каждое намерение отвечает «применилось».
// Сравнение версий и суд воплощения по голове — свойство хранилища (одним
// оператором под блокировкой строки), и держат его пробы с настоящей базой:
// internal/repo/kaname/pg/public_read_order_integration_test.go и
// set_public_read_publication_integration_test.go. Строить через этот дублёр
// утверждение «запоздавшая доставка не открыла» нельзя — он открыл бы, и проба
// доказала бы только собственную фикстуру.
type recordingPublisher struct {
	mu    sync.Mutex
	calls []publicationCall
	err   error
}

func (p *recordingPublisher) record(c publicationCall) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return p.err
	}
	p.calls = append(p.calls, c)
	return nil
}

func (p *recordingPublisher) ApplyTx(_ context.Context, _ service.Tx, in service.PublicReadIntent) (bool, error) {
	if err := p.record(publicationCall{
		kind: "apply", objectType: in.ObjectType, objectID: in.ObjectID, headType: in.HeadType,
		published: in.Published, version: in.Version, objectGeneration: in.ObjectGeneration,
	}); err != nil {
		return false, err
	}
	return true, nil
}

func (p *recordingPublisher) WithdrawTx(_ context.Context, _ service.Tx, objectType, objectID string) error {
	return p.record(publicationCall{kind: "withdraw", objectType: objectType, objectID: objectID})
}

func (p *recordingPublisher) DropStaleIncarnationTx(_ context.Context, _ service.Tx, objectType, objectID, headType string) error {
	return p.record(publicationCall{kind: "drop-stale", objectType: objectType, objectID: objectID, headType: headType})
}

func (p *recordingPublisher) seen() []publicationCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]publicationCall(nil), p.calls...)
}

// standingResidual — дублёр читателя снимаемого: на объекте стоят заданные кортежи
// (те, что положила бы его регистрация). Для проб, чей предмет — что снятие делает с
// очередью и проходом, а не какие строки оно читает.
type standingResidual struct{ tuples []service.RelationTuple }

func (r standingResidual) ObjectTuplesTx(_ context.Context, _ service.Tx, object string) ([]service.RelationTuple, error) {
	var out []service.RelationTuple
	for _, t := range r.tuples {
		if t.Object == object {
			out = append(out, t)
		}
	}
	return out, nil
}

// noResidual — дублёр читателя снимаемого: на объекте не стоит ничего. Для проб,
// чей предмет не снятие кортежей.
type noResidual struct{}

func (noResidual) ObjectTuplesTx(context.Context, service.Tx, string) ([]service.RelationTuple, error) {
	return nil, nil
}

// assertPublications сверяет вызовы порта поэлементно. Версия сравнивается как
// МГНОВЕНИЕ (`time.Time.Equal`), а не как структура: зона и показание монотонных
// часов у времени, прошедшего через контракт, другие, а момент — тот же.
func assertPublications(t *testing.T, want, got []publicationCall, msg string) {
	t.Helper()
	if len(want) != len(got) {
		t.Fatalf("%s: вызовов порта публикации %d, ожидалось %d: %+v", msg, len(got), len(want), got)
	}
	for i := range want {
		w, g := want[i], got[i]
		if w.kind != g.kind || w.objectType != g.objectType || w.objectID != g.objectID || w.headType != g.headType ||
			w.published != g.published || !w.version.Equal(g.version) || w.objectGeneration != g.objectGeneration {
			t.Fatalf("%s: вызов %d = %+v, ожидался %+v", msg, i, g, w)
		}
	}
}
