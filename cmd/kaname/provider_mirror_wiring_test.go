// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"testing"

	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

type fakeProviderMirrorReader struct {
	rows kanamepg.ProviderMirrorRows
	err  error
}

func (f *fakeProviderMirrorReader) Count(context.Context) (kanamepg.ProviderMirrorRows, error) {
	return f.rows, f.err
}

// Отказ замера не обнуляет величину: ноль здесь открывает снятие компонента, и
// недоступность базы не вправе его объявить.
func TestProviderMirrorSampler_FailureKeepsTheLastReadingAndCountsItself(t *testing.T) {
	t.Parallel()
	src := &fakeProviderMirrorReader{rows: kanamepg.ProviderMirrorRows{ServiceAccountKeys: 3, UserTokens: 2}}
	s := newProviderMirrorSampler(src)

	if err := s.sampleOnce(context.Background()); err != nil {
		t.Fatalf("первый замер: %v", err)
	}
	got := s.Counts()
	if got.ServiceAccountKeys != 3 || got.UserTokens != 2 || got.SamplesOK != 1 || got.SamplesFailed != 0 {
		t.Fatalf("после удачного замера: %+v", got)
	}

	src.err = errors.New("db down")
	src.rows = kanamepg.ProviderMirrorRows{}
	if err := s.sampleOnce(context.Background()); err == nil {
		t.Fatal("отказ источника обязан вернуться ошибкой")
	}
	got = s.Counts()
	if got.ServiceAccountKeys != 3 || got.UserTokens != 2 {
		t.Fatalf("отказ замера обнулил окно: %+v — ноль открывает снятие, подставлять его нельзя", got)
	}
	if got.SamplesOK != 1 || got.SamplesFailed != 1 {
		t.Fatalf("исходы замера считаются раздельно: %+v", got)
	}

	// Закрытие окна — законное падение до нуля, и оно доезжает.
	src.err = nil
	if err := s.sampleOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := s.Counts(); got.ServiceAccountKeys != 0 || got.UserTokens != 0 || got.SamplesOK != 2 {
		t.Fatalf("закрытое окно обязано читаться нулём: %+v", got)
	}
}
