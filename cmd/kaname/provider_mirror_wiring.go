// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// provider_mirror_wiring.go — фоновый замер ОКНА ПРЕЖНЕГО ИЗДАТЕЛЯ: строк
// удостоверений, чьё зеркало у внешнего OAuth-сервера ещё предъявимо
// (эпик kacho#2564, линия B).
//
// # Что производит продукт и чего он не производит
//
// Продукт производит СОБЫТИЯ: ключ выдан, ключ снят. «Строк с зеркалом у
// прежнего издателя осталось N» — это СОСТОЯНИЕ, и его не производит никто,
// кроме периодического чтения обеих таблиц. Без него окно, закрытие которого
// открывает необратимое снятие компонента, считалось бы запросом по памяти.
//
// # Что этот замер НЕ делает
//
// Не мутирует таблицы, не участвует в пути запроса и не может уронить под: отказ
// чтения считается своей клеткой, величина при отказе НЕ обнуляется — ноль здесь
// открывает снятие, и подставлять его вместо непрочитанного нельзя.
package main

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// providerMirrorInterval — период замера. Тот же, что у соседних фоновых
// замеров: порог тревоги, написанный по одному ряду, читается одинаково.
const providerMirrorInterval = 15 * time.Second

// providerMirrorReader — источник величины. Порт, а не тип репозитория.
type providerMirrorReader interface {
	Count(ctx context.Context) (kanamepg.ProviderMirrorRows, error)
}

// providerMirrorSampler — держатель последнего замера и счётчиков его исходов.
type providerMirrorSampler struct {
	read providerMirrorReader

	mu         sync.Mutex
	rows       kanamepg.ProviderMirrorRows
	samplesOK  uint64
	samplesBad uint64
}

func newProviderMirrorSampler(read providerMirrorReader) *providerMirrorSampler {
	return &providerMirrorSampler{read: read}
}

// Counts — то, что читает витрина.
func (s *providerMirrorSampler) Counts() metrics.ProviderMirrorCounts {
	s.mu.Lock()
	defer s.mu.Unlock()
	return metrics.ProviderMirrorCounts{
		ServiceAccountKeys: s.rows.ServiceAccountKeys,
		UserTokens:         s.rows.UserTokens,
		SamplesOK:          s.samplesOK,
		SamplesFailed:      s.samplesBad,
	}
}

// sampleOnce — один замер. Отказ не трогает величину: ноль по этому ряду читают
// как закрытое окно, и одна недоступность базы не вправе его объявить.
func (s *providerMirrorSampler) sampleOnce(ctx context.Context) error {
	rows, err := s.read.Count(ctx)

	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.samplesBad++
		return err
	}
	s.rows = rows
	s.samplesOK++
	return nil
}

// Run — цикл замера до отмены контекста. На-реплику, как у соседей: замер —
// чистое чтение, разойтись репликам нечем, а ряд обязан быть у каждой.
func (s *providerMirrorSampler) Run(ctx context.Context, logger *slog.Logger) {
	ticker := time.NewTicker(providerMirrorInterval)
	defer ticker.Stop()

	for {
		if err := s.sampleOnce(ctx); err != nil && ctx.Err() == nil {
			logger.Warn("provider mirror window sample failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
