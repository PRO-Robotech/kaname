// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package kaname

import "context"

// InstallationOpenFailure carries only closed classifications. The observer
// receives neither a driver error nor SQL, query arguments or connection data.
type InstallationOpenFailure struct {
	Stage string
	Class string
}

type installationOpenObserverKey struct{}

func WithInstallationOpenObserver(ctx context.Context, observe func(InstallationOpenFailure)) context.Context {
	return context.WithValue(ctx, installationOpenObserverKey{}, observe)
}

func ObserveInstallationOpenFailure(ctx context.Context, classify func() InstallationOpenFailure) {
	if observe, ok := ctx.Value(installationOpenObserverKey{}).(func(InstallationOpenFailure)); ok && observe != nil {
		observe(classify())
	}
}
