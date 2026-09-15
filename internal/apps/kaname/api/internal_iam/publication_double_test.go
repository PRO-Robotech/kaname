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

// publicationCall — один вызов порта публикации, как его увидел дублёр.
type publicationCall struct {
	objectType string
	objectID   string
	published  bool
	version    time.Time
}

// recordingPublisher — дублёр порта публикации для проб, чей предмет — МАРШРУТ:
// какой путь позван, для какого объекта, в какую сторону и С КАКОЙ ВЕРСИЕЙ.
//
// Порядок он НЕ судит и на каждый вызов отвечает «применилось». Сравнение версий —
// свойство хранилища (одним оператором под блокировкой строки), и держит его проба с
// настоящей базой: internal/repo/kaname/pg/public_read_order_integration_test.go.
// Строить через этот дублёр утверждение «запоздавшая доставка не открыла» нельзя —
// он открыл бы, и проба доказала бы только собственную фикстуру.
type recordingPublisher struct {
	mu    sync.Mutex
	calls []publicationCall
	err   error
}

func (p *recordingPublisher) ApplyTx(_ context.Context, _ service.Tx, objectType, objectID string, published bool, version time.Time) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return false, p.err
	}
	p.calls = append(p.calls, publicationCall{objectType: objectType, objectID: objectID, published: published, version: version})
	return true, nil
}

func (p *recordingPublisher) seen() []publicationCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]publicationCall(nil), p.calls...)
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
		if w.objectType != g.objectType || w.objectID != g.objectID || w.published != g.published || !w.version.Equal(g.version) {
			t.Fatalf("%s: вызов %d = %+v, ожидался %+v", msg, i, g, w)
		}
	}
}
