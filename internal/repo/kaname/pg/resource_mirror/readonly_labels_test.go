// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package resource_mirror

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// Повторное декодирование является контрактом владения, а не замером времени.
func TestReadOnlyLabelDecoderExactBytesAndBufferOwnership(t *testing.T) {
	decode := NewReadOnlyLabelDecoder()
	raw := []byte(`{"env":"prod"}`)
	first, err := decode(raw)
	require.NoError(t, err)
	same, err := decode(raw)
	require.NoError(t, err)
	require.Equal(t, fmt.Sprintf("%p", first), fmt.Sprintf("%p", same))
	copy(raw, []byte(`{"env":"test"}`))
	changed, err := decode(raw)
	require.NoError(t, err)
	require.Equal(t, "test", changed["env"])
	again, err := decode([]byte(`{"env":"prod"}`))
	require.NoError(t, err)
	require.Equal(t, "prod", again["env"])
	require.Equal(t, fmt.Sprintf("%p", first), fmt.Sprintf("%p", again))
	whitespace, err := decode([]byte(`{ "env": "prod" }`))
	require.NoError(t, err)
	require.Equal(t, first, whitespace)
	require.NotEqual(t, fmt.Sprintf("%p", first), fmt.Sprintf("%p", whitespace))
	null, err := decode([]byte(`null`))
	require.NoError(t, err)
	require.Nil(t, null)
	empty, err := decode([]byte(`{}`))
	require.NoError(t, err)
	require.NotNil(t, empty)
	require.Empty(t, empty)
	for _, raw := range []string{`{"env":1}`, `{"env":`, `[]`} {
		_, want := decodeLabels([]byte(raw))
		require.Error(t, want)
		for i := 0; i < 2; i++ {
			_, got := decode([]byte(raw))
			require.Error(t, got)
			require.IsType(t, want, got)
			require.Equal(t, want.Error(), got.Error())
		}
	}
}

func TestReadOnlyLabelDecoderCapacityFallsBackWithoutChangingResults(t *testing.T) {
	for _, limit := range []string{"entries", "raw_bytes", "label_entries"} {
		t.Run(limit, func(t *testing.T) {
			cache := &readOnlyLabelCache{values: make(map[string]map[string]string)}
			saved, err := cache.decode([]byte(`{"saved":"v"}`))
			require.NoError(t, err)
			switch limit {
			case "entries":
				for i := 1; i < readOnlyLabelsMaxEntries; i++ {
					_, err = cache.decode([]byte(fmt.Sprintf(`{"k%d":"v"}`, i)))
					require.NoError(t, err)
				}
			case "raw_bytes":
				payload := []byte(`{"large":"` + strings.Repeat("x", readOnlyLabelsMaxRawBytes-cache.rawBytes-len(`{"large":""}`)) + `"}`)
				_, err = cache.decode(payload)
				require.NoError(t, err)
				require.Equal(t, readOnlyLabelsMaxRawBytes, cache.rawBytes)
			case "label_entries":
				labels := make(map[string]string)
				for i := 0; i < readOnlyLabelsMaxLabelEntries-1; i++ {
					labels[fmt.Sprint(i)] = "v"
				}
				payload, err := json.Marshal(labels)
				require.NoError(t, err)
				_, err = cache.decode(payload)
				require.NoError(t, err)
				require.Equal(t, readOnlyLabelsMaxLabelEntries, cache.labelEntries)
			}
			entries, bytes, labels := len(cache.values), cache.rawBytes, cache.labelEntries
			a, err := cache.decode([]byte(`{"overflow":"ok"}`))
			require.NoError(t, err)
			b, err := cache.decode([]byte(`{"overflow":"ok"}`))
			require.NoError(t, err)
			require.Equal(t, a, b)
			require.NotEqual(t, fmt.Sprintf("%p", a), fmt.Sprintf("%p", b))
			require.Equal(t, entries, len(cache.values))
			require.Equal(t, bytes, cache.rawBytes)
			require.Equal(t, labels, cache.labelEntries)
			hit, err := cache.decode([]byte(`{"saved":"v"}`))
			require.NoError(t, err)
			require.Equal(t, fmt.Sprintf("%p", saved), fmt.Sprintf("%p", hit))
		})
	}
}

type labelReaderRows struct {
	pgx.Rows
	raw          []byte
	accessLabels []byte
	done         bool
	scanErr      error
	rowsErr      error
}

func (r *labelReaderRows) Next() bool {
	if r.done {
		return false
	}
	r.done = true
	return true
}
func (r *labelReaderRows) Close()     {}
func (r *labelReaderRows) Err() error { return r.rowsErr }
func (r *labelReaderRows) Scan(dest ...any) error {
	if r.scanErr != nil {
		return r.scanErr
	}
	for i, value := range []string{"compute.instance", "same-id", "project", "account"} {
		*dest[i].(*string) = value
	}
	*dest[4].(*[]byte) = r.raw
	*dest[5].(*[]byte) = r.accessLabels
	return nil
}

type labelReaderQuery struct {
	querier
	raw      []byte
	sql      []string
	args     [][]any
	err      error
	rowCount int
	rowsErr  error
}

type repeatingLabelReaderRows struct {
	*labelReaderRows
	remaining int
}

func (r *repeatingLabelReaderRows) Next() bool {
	if r.remaining == 0 {
		return false
	}
	r.remaining--
	return true
}

func (q *labelReaderQuery) Query(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
	q.sql = append(q.sql, sql)
	q.args = append(q.args, args)
	if q.err != nil {
		return nil, q.err
	}
	rows := &labelReaderRows{raw: q.raw, rowsErr: q.rowsErr}
	if q.rowCount > 0 {
		return &repeatingLabelReaderRows{labelReaderRows: rows, remaining: q.rowCount}, nil
	}
	return rows, nil
}

func TestLabelSelectorUnionKeepsParametersAndDiscardsPartialResults(t *testing.T) {
	ctx := context.Background()
	filters := []LabelSelector{
		{ObjectTypes: []string{"compute.instance"}, Labels: map[string]string{"env": "prod"}},
		{ObjectTypes: []string{"compute.instance", "vpc.network"}, Labels: map[string]string{"team": ""}},
	}
	decode := NewReadOnlyLabelDecoder()
	q := &labelReaderQuery{raw: []byte(`{"env":"prod","team":""}`)}
	rows, complete, err := MatchLabelSelectorUnionReadOnly(ctx, q, filters, decode)
	require.NoError(t, err)
	require.True(t, complete)
	require.Len(t, rows, 1)
	require.Equal(t, "account", rows[0].ParentAccountID)
	require.Contains(t, q.sql[0], "(m.object_type = ANY($1) AND m.labels @> $2::jsonb) OR (m.object_type = ANY($3) AND m.labels @> $4::jsonb)")
	require.Contains(t, q.sql[0], "ORDER BY m.object_type ASC, m.object_id ASC")
	require.Contains(t, q.sql[0], fmt.Sprintf("LIMIT %d", labelSelectorUnionMaxRows+1))
	require.Equal(t, []any{filters[0].ObjectTypes, []byte(`{"env":"prod"}`), filters[1].ObjectTypes, []byte(`{"team":""}`)}, q.args[0])

	q.rowCount = labelSelectorUnionMaxRows
	rows, complete, err = MatchLabelSelectorUnionReadOnly(ctx, q, filters, decode)
	require.NoError(t, err)
	require.True(t, complete)
	require.Len(t, rows, labelSelectorUnionMaxRows)

	q.rowCount++
	rows, complete, err = MatchLabelSelectorUnionReadOnly(ctx, q, filters, decode)
	require.NoError(t, err)
	require.False(t, complete)
	require.Nil(t, rows)

	q.rowsErr = errors.New("ошибка потока строк")
	_, _, err = MatchLabelSelectorUnionReadOnly(ctx, q, filters, decode)
	require.ErrorIs(t, err, q.rowsErr)

	q.rowsErr = nil
	q.rowCount = labelSelectorUnionMaxRows
	q.raw = make([]byte, labelSelectorUnionMaxLabelBytes/labelSelectorUnionMaxRows+1)
	rows, complete, err = MatchLabelSelectorUnionReadOnly(ctx, q, filters, func([]byte) (map[string]string, error) { return nil, nil })
	require.NoError(t, err)
	require.False(t, complete)
	require.Nil(t, rows)
}

func TestLabelReaderPublicIndependenceAndPrivateFreshRows(t *testing.T) {
	q := &labelReaderQuery{raw: []byte(`{"env":"prod"}`)}
	ctx := context.Background()
	types := []string{"compute.instance"}
	match := map[string]string{"env": "prod"}
	first, err := MatchByLabels(ctx, q, types, match)
	require.NoError(t, err)
	first[0].Labels["env"] = "caller-mutation"
	second, err := MatchByLabels(ctx, q, types, match)
	require.NoError(t, err)
	require.Equal(t, "prod", second[0].Labels["env"])
	decode := NewReadOnlyLabelDecoder()
	a, err := MatchByLabelsReadOnly(ctx, q, types, match, decode)
	require.NoError(t, err)
	b, err := MatchByLabelsReadOnly(ctx, q, types, match, decode)
	require.NoError(t, err)
	require.Equal(t, second, a)
	require.Equal(t, a, b)
	require.Equal(t, fmt.Sprintf("%p", a[0].Labels), fmt.Sprintf("%p", b[0].Labels))
	q.raw = []byte(`{"env":"changed"}`)
	changed, err := MatchByLabelsReadOnly(ctx, q, types, match, decode)
	require.NoError(t, err)
	require.Equal(t, a[0].ObjectID, changed[0].ObjectID)
	require.Equal(t, "changed", changed[0].Labels["env"])
	for i := range q.sql {
		require.Equal(t, q.sql[0], q.sql[i])
		require.Equal(t, q.args[0], q.args[i])
	}
	failure := errors.New("query failure")
	q.err = failure
	_, oldErr := MatchByLabels(ctx, q, types, match)
	_, newErr := MatchByLabelsReadOnly(ctx, q, types, match, decode)
	require.ErrorIs(t, oldErr, failure)
	require.ErrorIs(t, newErr, failure)
	require.Equal(t, oldErr.Error(), newErr.Error())
}

func TestLabelReaderDecoderPreservesScanJSONAndRowsErrors(t *testing.T) {
	for _, kind := range []string{"scan", "json_type", "json_syntax", "rows"} {
		t.Run(kind, func(t *testing.T) {
			failure := errors.New("reader failure")
			makeRows := func() *labelReaderRows {
				r := &labelReaderRows{raw: []byte(`{"k":"v"}`)}
				switch kind {
				case "scan":
					r.scanErr = failure
				case "json_type":
					r.raw = []byte(`{"k":2}`)
				case "json_syntax":
					r.raw = []byte(`{`)
				case "rows":
					r.rowsErr = failure
				}
				return r
			}
			_, oldErr := scanRows(makeRows())
			_, newErr := scanRowsWithDecoder(makeRows(), NewReadOnlyLabelDecoder())
			require.Error(t, oldErr)
			require.Error(t, newErr)
			require.Equal(t, oldErr.Error(), newErr.Error())
			if kind == "scan" || kind == "rows" {
				require.ErrorIs(t, newErr, failure)
			}
		})
	}
}

func TestMirrorReaderKeepsAccessLabelsSeparate(t *testing.T) {
	r := &labelReaderRows{raw: []byte(`{"team":"ordinary"}`), accessLabels: []byte(`{"team":"restricted"}`)}
	rows, err := scanRows(r)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, map[string]string{"team": "ordinary"}, rows[0].Labels)
	require.Equal(t, map[string]string{"team": "restricted"}, rows[0].AccessLabels)
}
