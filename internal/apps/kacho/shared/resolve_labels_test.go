// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package shared

// resolve_labels_test.go — таблица решений ResolveLabelsUpdate.
//
// proto3-map не несет presence: пустой `labels:{}` и отсутствующий labels в теле
// приходят в use-case как nil domain.Labels — неотличимо. Поэтому единственный
// надежный сигнал «очистить labels» — присутствие "labels" в update_mask. Тест
// фиксирует дисциплину update_mask для labels (включая очистку пустым телом).

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

func TestResolveLabelsUpdate(t *testing.T) {
	cases := []struct {
		name      string
		mask      []string
		body      domain.Labels
		wantApply bool
		wantNew   domain.Labels
	}{
		{
			name:      "mask содержит labels, тело пустое (nil) → очистка",
			mask:      []string{"labels"},
			body:      nil,
			wantApply: true,
			wantNew:   domain.Labels{},
		},
		{
			name:      "mask содержит labels, тело пустой не-nil map → очистка",
			mask:      []string{"labels"},
			body:      domain.Labels{},
			wantApply: true,
			wantNew:   domain.Labels{},
		},
		{
			name:      "mask содержит labels, тело с метками → применить тело",
			mask:      []string{"labels"},
			body:      domain.Labels{"team": "sec"},
			wantApply: true,
			wantNew:   domain.Labels{"team": "sec"},
		},
		{
			name:      "mask содержит labels среди прочих полей, тело пустое → очистка",
			mask:      []string{"name", "labels"},
			body:      nil,
			wantApply: true,
			wantNew:   domain.Labels{},
		},
		{
			name:      "mask без labels, тело с метками → не трогать",
			mask:      []string{"name"},
			body:      domain.Labels{"team": "sec"},
			wantApply: false,
			wantNew:   nil,
		},
		{
			name:      "mask без labels, тело пустое → не трогать",
			mask:      []string{"name"},
			body:      nil,
			wantApply: false,
			wantNew:   nil,
		},
		{
			name:      "пустой mask (full-PATCH), тело с метками → применить",
			mask:      nil,
			body:      domain.Labels{"team": "sec"},
			wantApply: true,
			wantNew:   domain.Labels{"team": "sec"},
		},
		{
			name:      "пустой mask (full-PATCH), тело пустое → не трогать (presence неотличима)",
			mask:      []string{},
			body:      nil,
			wantApply: false,
			wantNew:   nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotNew, gotApply := ResolveLabelsUpdate(tc.mask, tc.body)
			assert.Equal(t, tc.wantApply, gotApply, "apply")
			assert.Equal(t, tc.wantNew, gotNew, "newLabels")
			if gotApply {
				assert.NotNil(t, gotNew, "при apply=true newLabels всегда non-nil (пустой набор = очистка)")
			}
		})
	}
}
