// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package installruntime

import (
	"fmt"
	"net"
)

// NativePorts перемещает только слушатели. Издатель, аудитории, CA, SAN доверенного шлюза
// и все политики идентичности/допуска остаются одинаковыми между процессами.
type NativePorts struct {
	PublicGRPC, InternalGRPC, Metrics, Token, JWKS, PublicREST, InternalREST, Login int
}

func DefaultNativePorts() NativePorts {
	return NativePorts{9090, 9091, 9095, 9096, 9097, 9098, 9099, 9100}
}
func SecondNativePorts() NativePorts {
	return NativePorts{9190, 9191, 9195, 9196, 9197, 9198, 9199, 9200}
}
func (p NativePorts) All() []int {
	return []int{p.PublicGRPC, p.InternalGRPC, p.Metrics, p.Token, p.JWKS, p.PublicREST, p.InternalREST, p.Login}
}
func (p NativePorts) Validate() error {
	seen := map[int]bool{}
	for _, port := range p.All() {
		if port < 1024 || port > 65535 || seen[port] {
			return fmt.Errorf("invalid or duplicate native fixture port %d", port)
		}
		seen[port] = true
	}
	return nil
}
func (p NativePorts) EnvironmentOverrides() (map[string]string, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	names := []string{"ENDPOINT", "INTERNAL_ENDPOINT", "METRICS_ENDPOINT", "REGISTRY_TOKEN__ENDPOINT", "JWKS_PROXY__ENDPOINT", "REST_ENDPOINT", "INTERNAL_REST_ENDPOINT", "LOGIN_LANE_ENDPOINT"}
	result := map[string]string{}
	for i, port := range p.All() {
		result["KANAME_API_SERVER__"+names[i]] = "tcp://" + net.JoinHostPort("127.0.0.1", fmt.Sprint(port))
	}
	return result, nil
}
func NewWireAtPorts(pki string, p NativePorts) (*Wire, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	w, err := NewWire(pki, fmt.Sprintf("https://localhost:%d", p.PublicREST), fmt.Sprintf("https://localhost:%d", p.Token), fmt.Sprintf("https://localhost:%d", p.JWKS))
	if err != nil {
		return nil, err
	}
	w.ports = p
	return w, nil
}
func (w *Wire) InternalGatewayAddress() string {
	return net.JoinHostPort("localhost", fmt.Sprint(w.ports.InternalGRPC))
}
