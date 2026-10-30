// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestR7InterpretationWriterHistogram(t *testing.T) {
	for _, tc := range []struct {
		name      string
		members   int
		saturated bool
		count     int
	}{
		{"at_model_threshold", 5000, false, 0},
		{"above_model_threshold", 5001, true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := renderWDReport([]wdResult{{band: "fixture", point: wdPoint{Objects: tc.members, Rules: 1}, saturated: tc.saturated}}, time.Second, true)
			for _, want := range []string{
				"модельный порог 5000",
				"реальная гистограмма не снималась",
				fmt.Sprintf("точек сверх модельного порога: %d из 1", tc.count),
			} {
				if !strings.Contains(report, want) {
					t.Errorf("интерпретация не содержит %q", want)
				}
			}
			if strings.Contains(report, "штатной наблюдаемости на этом режиме НЕТ") {
				t.Error("модельный threshold выдан за доказанное отсутствие наблюдаемости")
			}
		})
	}
}
