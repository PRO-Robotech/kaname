// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// identity_growth_wiring.go — фоновый замер НАКОПИТЕЛЬНОГО журнала личностей.
//
// # Что производит продукт и чего он не производит
//
// Продукт производит СОБЫТИЯ: личность появилась, приглашение активировано.
// «Личностей за всё время N, из них M за последний час» — это СОСТОЯНИЕ, и его
// не производит никто, кроме периодического чтения журнала. Без него медленное
// накопление неотличимо от его отсутствия: обе картины молчат одинаково.
//
// # Что этот замер НЕ делает
//
// Не мутирует таблицу, не участвует в пути запроса и не может уронить под:
// отказ чтения считается своей клеткой и цикл продолжается. Наблюдаемость — не
// гейт.
package main

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
)

// identityGrowthInterval — период замера.
//
// Совпадает с периодом сканов очередей: одна и та же величина у всех фоновых
// замеров, чтобы порог тревоги, написанный по одному ряду, читался одинаково на
// любом другом.
const identityGrowthInterval = 15 * time.Second

// identityGrowthReader — источник величины. Порт, а не тип репозитория:
// композиционный корень не обязан знать, чем именно журнал прочитан.
type identityGrowthReader interface {
	IdentitiesEverSeen(ctx context.Context) (int64, error)
}

// identityGrowthSampler — держатель последнего замера и счётчиков его исходов.
type identityGrowthSampler struct {
	read identityGrowthReader

	mu         sync.Mutex
	identities int64
	samplesOK  uint64
	samplesBad uint64
}

// newIdentityGrowthSampler — constructor.
func newIdentityGrowthSampler(read identityGrowthReader) *identityGrowthSampler {
	return &identityGrowthSampler{read: read}
}

// Counts — то, что читает витрина.
func (s *identityGrowthSampler) Counts() metrics.IdentityGrowthCounts {
	s.mu.Lock()
	defer s.mu.Unlock()
	return metrics.IdentityGrowthCounts{
		IdentitiesEverSeen: s.identities,
		SamplesOK:          s.samplesOK,
		SamplesFailed:      s.samplesBad,
	}
}

// sampleOnce — один замер.
//
// Отказ НЕ трогает величину, и это несущее свойство, а не аккуратность. Ряд
// объявлен счётчиком, и витрина считает его монотонным: падение читается ею как
// ПЕРЕЗАПУСК счётчика, после которого `increase()` прибавляет всё накопленное
// заново. Одна недоступность базы на период замера превращалась бы во всплеск
// роста, которого не было, — то есть в ложную тревогу ровно на том пороге, ради
// которого ряд и заведён.
//
// Отказ виден ОТДЕЛЬНОЙ клеткой: «замер не прошёл» и «личностей стало меньше» —
// разные утверждения, и второе к тому же невозможно.
func (s *identityGrowthSampler) sampleOnce(ctx context.Context) error {
	total, err := s.read.IdentitiesEverSeen(ctx)

	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.samplesBad++
		return err
	}
	s.identities = total
	s.samplesOK++
	return nil
}

// Run — цикл замера до отмены контекста.
//
// РЕПЛИКИ: на-реплику — петля наполняет витрину СВОЕГО процесса: величину отдаёт
// коллектор этого же реестра, и ряд у каждой реплики свой. Дубль безвреден не по
// намерению автора, а по оператору: замер — чистое чтение накопительного журнала,
// он ничего не пишет и разойтись с другой репликой ему нечем. Одиночкой делать
// нельзя: тогда ряд был бы только у выбранной реплики, а на остальных «ноль» и
// «не замеряем» снова стали бы неотличимы.
func (s *identityGrowthSampler) Run(ctx context.Context, logger *slog.Logger) {
	ticker := time.NewTicker(identityGrowthInterval)
	defer ticker.Stop()

	for {
		if err := s.sampleOnce(ctx); err != nil && ctx.Err() == nil {
			logger.Warn("identity ledger sample failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
