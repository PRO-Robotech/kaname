// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package moduleseed_test

// recipient_directory_test.go — применитель строки `recipientDirectory`
// (приёмка NTF-3, kacho#2918: Р28, NTF3-50, близнец «применён, заведён ровно
// `service:notify reader notification_recipient_directory:root`»).
//
// Положительный контроль — тот же манифест notify без строки: кортежа
// справочника нет. Без него «кортеж есть» зеленело бы на применителе, пишущем
// кортеж всякому манифесту notify.

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleseed"
	"github.com/PRO-Robotech/kaname/internal/manifest"
)

const (
	rdNotifyWithLine = `
apiVersion: iam/v1
module: notify
resources: []
recipientDirectory: {readers: [notify]}
`
	rdNotifyWithoutLine = `
apiVersion: iam/v1
module: notify
resources: []
`
	rdDirectoryTuple = "tuple service:notify reader notification_recipient_directory:root"
)

func rdDirectoryTuples(calls []string) []string {
	var out []string
	for _, c := range tupleCalls(calls) {
		if strings.Contains(c, "notification_recipient_directory") {
			out = append(out, c)
		}
	}
	return out
}

func TestNTF350_ApplierWritesTheRecipientDirectoryReaderTuple(t *testing.T) {
	// Контроль: без строки кортежа справочника нет.
	without, err := manifest.Load([]byte(rdNotifyWithoutLine))
	require.NoError(t, err, "фикстура: манифест notify без строки не принят разбором — вопрос пробы сломан")
	w0 := &recordingWriter{changed: true}
	_, err = moduleseed.NewApplier(&recordingTx{w: w0}).Apply(context.Background(), nil, []*manifest.Manifest{without})
	require.NoError(t, err, "фикстура: посев манифеста notify без строки отказал")
	require.Empty(t, rdDirectoryTuples(w0.calls), "кортеж справочника заведён манифесту БЕЗ строки")

	// Предмет: строка Р28 заводит ровно один кортеж.
	with, err := manifest.Load([]byte(rdNotifyWithLine))
	require.NoError(t, err, "строка `recipientDirectory: {readers: [notify]}` манифеста notify не принята разбором (Р28)")
	w := &recordingWriter{changed: true}
	census, err := moduleseed.NewApplier(&recordingTx{w: w}).Apply(context.Background(), nil, []*manifest.Manifest{with})
	require.NoError(t, err)
	t.Logf("перепись: %s\nвызовы: %s", census, strings.Join(w.calls, " · "))
	require.Equal(t, []string{rdDirectoryTuple}, rdDirectoryTuples(w.calls),
		"строка манифеста notify обязана завести ровно `service:notify reader notification_recipient_directory:root`")
	require.Equal(t, 1, census.Seeding, "манифест со строкой recipientDirectory — предмет посева")
}
