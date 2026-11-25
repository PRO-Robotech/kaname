// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

type accessLabelsReadRow func(...any) error

func (r accessLabelsReadRow) Scan(dest ...any) error { return r(dest...) }

// Exercise the real aggregate scanners: protected labels must survive reads
// independently of ordinary labels, including legacy NULL and empty values.
func TestAggregateScannersReadAccessLabels(t *testing.T) {
	cases := []struct {
		name       string
		columns    int
		labelsSlot int
		jsonSlots  map[int]string
		scan       func(scanner) (domain.Labels, domain.Labels, error)
	}{
		{"account", 7, 3, nil, func(r scanner) (domain.Labels, domain.Labels, error) {
			v, err := scanAccount(r)
			return v.Labels, v.AccessLabels, err
		}},
		{"project", 7, 4, nil, func(r scanner) (domain.Labels, domain.Labels, error) {
			v, err := scanProject(r)
			return v.Labels, v.AccessLabels, err
		}},
		{"group", 7, 4, nil, func(r scanner) (domain.Labels, domain.Labels, error) {
			v, err := scanGroup(r)
			return v.Labels, v.AccessLabels, err
		}},
		{"service_account", 8, 4, nil, func(r scanner) (domain.Labels, domain.Labels, error) {
			v, err := scanSA(r)
			return v.Labels, v.AccessLabels, err
		}},
		{"user", 11, 8, nil, func(r scanner) (domain.Labels, domain.Labels, error) {
			v, err := scanUser(r)
			return v.Labels, v.AccessLabels, err
		}},
		{"role", 14, 12, map[int]string{6: `[]`, 7: `[]`}, func(r scanner) (domain.Labels, domain.Labels, error) {
			v, err := scanRole(r)
			return v.Labels, v.AccessLabels, err
		}},
		{"access_binding", 21, 14, map[int]string{15: `{}`}, func(r scanner) (domain.Labels, domain.Labels, error) {
			v, err := scanAB(r)
			return v.Labels, v.AccessLabels, err
		}},
		{"user_state_write", 12, 9, nil, func(r scanner) (domain.Labels, domain.Labels, error) {
			v, updated, exists, err := scanUserStateWrite(accessLabelsReadRow(func(dest ...any) error {
				if err := r.Scan(dest...); err != nil {
					return err
				}
				*dest[0].(*bool) = true
				*dest[1].(*sql.NullString) = sql.NullString{String: "user", Valid: true}
				return nil
			}))
			if err == nil {
				require.True(t, updated)
				require.True(t, exists)
			}
			return v.Labels, v.AccessLabels, err
		}},
	}
	values := []struct {
		name string
		raw  []byte
		want domain.Labels
	}{
		{"sql_null", nil, domain.Labels{}},
		{"json_null", []byte(`null`), domain.Labels{}},
		{"empty", []byte(`{}`), domain.Labels{}},
		{"present", []byte(`{"classification":"restricted"}`), domain.Labels{"classification": "restricted"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			row := func(raw []byte) scanner {
				return accessLabelsReadRow(func(dest ...any) error {
					require.Len(t, dest, tc.columns)
					for slot, value := range tc.jsonSlots {
						*dest[slot].(*[]byte) = []byte(value)
					}
					*dest[tc.labelsSlot].(*[]byte) = []byte(`{"display":"ordinary"}`)
					*dest[tc.columns-1].(*[]byte) = raw
					return nil
				})
			}
			for _, value := range values {
				t.Run(value.name, func(t *testing.T) {
					labels, protected, err := tc.scan(row(value.raw))
					require.NoError(t, err)
					require.Equal(t, domain.Labels{"display": "ordinary"}, labels)
					require.Equal(t, value.want, protected)
				})
			}
			t.Run("malformed", func(t *testing.T) {
				_, _, err := tc.scan(row([]byte(`{"classification":1}`)))
				require.Error(t, err)
			})
		})
	}
}
