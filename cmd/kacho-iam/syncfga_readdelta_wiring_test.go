// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzcascade"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
)

// strongTupleReader — ДОСЛОВНО та возможность, которую композиционный корень обязан
// донести до синхронного писателя прав.
//
// `kachopg.NewSyncFGAWriter` не требует её типом параметра: он ПРОБУЕТ привести
// переданное значение к этому набору методов и, если не выходит, молча остаётся без
// него. Поэтому потеря возможности не видна ни компилятору, ни обзору диффа — только
// такой проверке. Набор объявлен здесь копией намеренно: он приватен в пакете
// назначения, а предмет проверки — именно совпадение НАБОРОВ МЕТОДОВ, а не общий тип.
type strongTupleReader interface {
	ReadTuplesStrong(ctx context.Context, subjectFilter, relationFilter, objectFilter string,
		pageSize int, pageToken string) ([]clients.ConditionalTuple, string, error)
}

// TestSyncFGAWriter_ReadDeltaCapability_SurvivesTheCompositionRoot.
//
// ЧТО ЗДЕСЬ ЗАЩИЩАЕТСЯ. Когда попытка записать набор прав объекта натыкается на уже
// существующий кортеж, писатель обязан перейти на идемпотентный путь: прочитать, что
// уже есть, и дописать только недостающее. Этот путь включается ТОЛЬКО если
// переданное значение умеет сильное чтение. Иначе весь набор объекта уезжает в
// очередь и материализуется с задержкой в десятки секунд, а под нагрузкой очередь
// растёт быстрее, чем разбирается.
//
// ПОЧЕМУ ПРОВЕРКА СТОИТ ЗДЕСЬ, А НЕ РЯДОМ С САМИМ ПИСАТЕЛЕМ. Модульные тесты писателя
// подают ему заглушку, которая сильное чтение УМЕЕТ, поэтому идемпотентный путь у них
// исполняется и они зелены. Композиционный корень подаёт другое значение — обёртку.
// Значение решает всё, и проверять надо именно то, что подаётся в бою.
//
// Предпосылка проверяется первой: если бы сам транспорт разучился сильному чтению,
// утверждение про обёртку стало бы бессмысленным, и об этом надо узнать отдельной
// строкой, а не через путаное падение второго утверждения.
func TestSyncFGAWriter_ReadDeltaCapability_SurvivesTheCompositionRoot(t *testing.T) {
	transport := &clients.OpenFGAHTTPClient{Endpoint: "127.0.0.1:1", StoreID: "s"}

	require.Implements(t, (*strongTupleReader)(nil), transport,
		"предпосылка: транспорт обязан уметь сильное чтение — иначе проверка ниже "+
			"ничего не утверждает об обёртке")

	// ИМЕННО ЭТО значение композиционный корень отдаёт писателю (wiring.go:
	// relationStore := authzcascade.Wrap(fgaTransport, structuralFacts), затем
	// WithSyncFGA(kachopg.NewSyncFGAWriter(relationStore, logger))).
	wrapped := authzcascade.Wrap(transport, nil)

	require.Implements(t, (*strongTupleReader)(nil), wrapped,
		"обёртка вокруг транспорта ТЕРЯЕТ сильное чтение: писатель прав не сможет "+
			"дописать недостающее и отдаст ВЕСЬ набор объекта в очередь на каждом "+
			"уже существующем кортеже")
}
