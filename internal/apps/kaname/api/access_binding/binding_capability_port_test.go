// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	ab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Внешний writer намеренно имеет marker, но возвращает независимо выбранный
// порт. Это воспроизводит продвижение метода через embedding: проверять только
// writer недостаточно, иначе raw Insert выдавал бы себя за semantic.
type capabilityPortBoundaryWriter struct {
	Writer
	port ab.WriterIface
}

func (w *capabilityPortBoundaryWriter) AccessBindingsW() ab.WriterIface { return w.port }
func (w *capabilityPortBoundaryWriter) BindingCapabilityVersion() int   { return 1 }

type capabilityPortInsertProbe struct {
	ab.WriterIface
	calls int
}

func (w *capabilityPortInsertProbe) Insert(context.Context, domain.AccessBinding) (domain.AccessBinding, error) {
	w.calls++
	return domain.AccessBinding{}, status.Error(codes.Aborted, "вставка достигнута")
}

type capabilityPortVersionProbe struct {
	ab.WriterIface
	version int
}

func (w *capabilityPortVersionProbe) BindingCapabilityVersion() int { return w.version }

func TestBindingCapabilityActualPortAndLegacySelection(t *testing.T) {
	for _, tc := range []struct {
		name       string
		capability bool
		marked     bool
		version    int
		wantInsert bool
	}{
		{name: "legacy raw", wantInsert: true},
		{name: "semantic version1", capability: true, marked: true, version: 1, wantInsert: true},
		{name: "outer marker with raw port", capability: true},
		{name: "semantic version0", capability: true, marked: true},
		{name: "semantic unknown version", capability: true, marked: true, version: 2},
		{name: "legacy with semantic port", marked: true, version: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := newABFakeRepo("usr_owner", "acc_scope", "", "rol00000000000000001", "viewer", nil)
			probe := &capabilityPortInsertProbe{}
			var port ab.WriterIface = probe
			if tc.marked {
				port = &capabilityPortVersionProbe{WriterIface: port, version: tc.version}
			}
			writer := &capabilityPortBoundaryWriter{
				Writer: &abFakeWriter{abFakeReader: abFakeReader{repo: repo}},
				port:   port,
			}
			_, _, err := (&CreateAccessBindingUseCase{}).writeCreatedBinding(context.Background(), writer,
				domain.AccessBinding{ID: "acb00000000000000001", RoleID: "rol00000000000000001"}, "usr_owner", tc.capability)
			require.Error(t, err)
			if tc.wantInsert {
				require.Equal(t, 1, probe.calls)
				require.Contains(t, err.Error(), "вставка достигнута")
			} else {
				require.Zero(t, probe.calls, "несовместимый порт отвергается до DML")
				require.Equal(t, codes.Unavailable, status.Code(err))
			}
		})
	}
}
