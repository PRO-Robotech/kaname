// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzfilter

// held_on_test.go — HeldOn: одно отношение о наборе объектов РАЗНЫХ типов,
// партиями по типу. Цена — число запросов, а не число объектов.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// typedBatchChecker — партийная дверь, отказывающая на партии двух типов так же,
// как настоящая (`authzcascade.Client.BatchCheckWithContext`), и считающая
// запросы и объекты.
type typedBatchChecker struct {
	mu       sync.Mutex
	held     map[string]bool // «отношение|тип:id»
	err      error
	short    bool
	requests int
	tuples   int
	asked    map[string]int
}

func newTypedBatchChecker(held ...string) *typedBatchChecker {
	h := make(map[string]bool, len(held))
	for _, k := range held {
		h[k] = true
	}
	return &typedBatchChecker{held: h, asked: map[string]int{}}
}

func (c *typedBatchChecker) BatchCheckWithContext(_ context.Context, _, relation string, objects []string,
	_ map[string]any) ([]bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requests++
	c.tuples += len(objects)
	if len(objects) > MaxBatchChecksPerRequest {
		return nil, fmt.Errorf("партия %d шире %d", len(objects), MaxBatchChecksPerRequest)
	}
	typ := ""
	for _, o := range objects {
		c.asked[o]++
		t, _, _ := strings.Cut(o, ":")
		if typ == "" {
			typ = t
		} else if t != typ {
			return nil, fmt.Errorf("партия несёт два типа объектов (%q и %q)", typ, t)
		}
	}
	if c.err != nil {
		return nil, c.err
	}
	if c.short {
		return make([]bool, len(objects)-1), nil
	}
	out := make([]bool, len(objects))
	for i, o := range objects {
		out[i] = c.held[relation+"|"+o]
	}
	return out, nil
}

// Смешанный набор: 120 проектов, 3 аккаунта, кластер. Запросов — по
// ceil(n/MaxBatchChecksPerRequest) на тип; каждый объект спрошен однажды.
func TestHeldOn_MixedTypesCostOneBatchPerTypePartition(t *testing.T) {
	require.Equal(t, 50, MaxBatchChecksPerRequest, "предпосылка: число запросов ниже посчитано от размера партии")
	var objects, held []string
	for i := 0; i < 120; i++ {
		o := fmt.Sprintf("project:prj-%03d", i)
		objects = append(objects, o)
		if i%2 == 0 {
			held = append(held, "admin|"+o)
		}
	}
	for i := 0; i < 3; i++ {
		objects = append(objects, fmt.Sprintf("account:acc-%d", i))
	}
	objects = append(objects, "cluster:cluster_root", "project:prj-000") // повтор — спрашивается однажды
	held = append(held, "admin|account:acc-1", "admin|cluster:cluster_root")

	chk := newTypedBatchChecker(held...)
	got, err := HeldOn(context.Background(), chk, "user:u", "admin", objects)

	require.NoError(t, err)
	assert.Equal(t, 3+1+1, chk.requests, "проекты 120/50 → 3, аккаунты → 1, кластер → 1")
	assert.Equal(t, 124, chk.tuples, "каждый различный объект — однажды")
	for o, n := range chk.asked {
		assert.Equalf(t, 1, n, "объект %s спрошен %d раз", o, n)
	}
	assert.Len(t, got, 60+1+1)
	assert.True(t, got["project:prj-000"])
	assert.False(t, got["project:prj-001"])
	assert.True(t, got["account:acc-1"])
	assert.False(t, got["account:acc-0"])
	assert.True(t, got["cluster:cluster_root"])
}

// Отказ двери проваливает весь ответ: частичного набора нет.
func TestHeldOn_ErrorFailsTheWholeAnswer(t *testing.T) {
	chk := newTypedBatchChecker("admin|project:p1")
	chk.err = errors.New("инъекция: хранилище не ответило")
	got, err := HeldOn(context.Background(), chk, "user:u", "admin", []string{"project:p1", "account:a1"})
	require.Error(t, err)
	assert.Nil(t, got, "частичный набор не возвращается")
}

// Ответ не той длины — ошибка, а не набор отказов.
func TestHeldOn_ShortAnswerIsAnError(t *testing.T) {
	chk := newTypedBatchChecker()
	chk.short = true
	_, err := HeldOn(context.Background(), chk, "user:u", "admin", []string{"project:p1", "project:p2"})
	require.Error(t, err)
}

// Вырожденный вход — пустой набор без единого вопроса (закрыто по умолчанию).
func TestHeldOn_DegradedInputsHoldNothingAndAskNothing(t *testing.T) {
	chk := newTypedBatchChecker("admin|project:p1")
	for name, tc := range map[string]struct {
		chk      BatchObjectChecker
		subject  string
		relation string
		objects  []string
	}{
		"нет двери":       {nil, "user:u", "admin", []string{"project:p1"}},
		"нет субъекта":    {chk, "", "admin", []string{"project:p1"}},
		"нет отношения":   {chk, "user:u", "", []string{"project:p1"}},
		"нет объектов":    {chk, "user:u", "admin", nil},
		"объект без типа": {chk, "user:u", "admin", []string{":p1", "p1", "project:"}},
	} {
		got, err := HeldOn(context.Background(), tc.chk, tc.subject, tc.relation, tc.objects)
		require.NoErrorf(t, err, "%s", name)
		assert.NotNilf(t, got, "%s: набор не nil", name)
		assert.Emptyf(t, got, "%s", name)
	}
	assert.Zero(t, chk.requests, "вырожденный вход не спрашивает хранилище")
}
