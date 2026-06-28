// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// fakeStopper — управляемый grpcStopper: GracefulStop блокируется до release,
// Stop() освобождает его. Позволяет проверить bounded-семантику без реального
// gRPC-сервера и сетевого слушателя (которые текут goroutine'ами под -race).
type fakeStopper struct {
	mu          sync.Mutex
	stopCalled  bool
	gracefulRet bool
	release     chan struct{}
}

func (f *fakeStopper) GracefulStop() {
	<-f.release
	f.mu.Lock()
	f.gracefulRet = true
	f.mu.Unlock()
}

func (f *fakeStopper) Stop() {
	f.mu.Lock()
	f.stopCalled = true
	f.mu.Unlock()
	close(f.release) // форсированный Stop разблокирует висящий GracefulStop
}

// TestStopGRPCBounded_ForcesStopWhenGracefulBlocks — если GracefulStop не
// завершается за timeout (зависший handler), bounded-stop форсирует Stop() и
// возвращается за ~timeout, а не виснет навсегда.
func TestStopGRPCBounded_ForcesStopWhenGracefulBlocks(t *testing.T) {
	f := &fakeStopper{release: make(chan struct{})}

	start := time.Now()
	stopGRPCBounded(f, 100*time.Millisecond)
	elapsed := time.Since(start)

	require.GreaterOrEqual(t, elapsed, 90*time.Millisecond, "ждет ~timeout перед форсом")
	require.Less(t, elapsed, 2*time.Second, "форсирует Stop, не виснет на GracefulStop")
	f.mu.Lock()
	defer f.mu.Unlock()
	require.True(t, f.stopCalled, "при зависшем GracefulStop вызывается Stop()")
}

// TestStopGRPCBounded_FastGracefulNoForce — штатный быстрый GracefulStop не
// должен приводить к форсированному Stop().
func TestStopGRPCBounded_FastGracefulNoForce(t *testing.T) {
	f := &fakeStopper{release: make(chan struct{})}
	close(f.release) // GracefulStop возвращается немедленно

	stopGRPCBounded(f, 2*time.Second)

	f.mu.Lock()
	defer f.mu.Unlock()
	require.True(t, f.gracefulRet, "GracefulStop отработал")
	require.False(t, f.stopCalled, "быстрый graceful → форсированный Stop не нужен")
}
