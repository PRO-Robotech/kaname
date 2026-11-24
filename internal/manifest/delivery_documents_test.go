// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDeliveredDocumentsKeepCheckedBytesAcrossProjectedVolumeUpdate(t *testing.T) {
	root := t.TempDir()
	original := []byte("# исходные комментарии и CRLF сохраняются\r\napiVersion: iam/v1\r\nmodule: iam\r\n")
	replacement := []byte("apiVersion: iam/v1\nmodule: vpc\nrevision: 2\n")
	for directory, data := range map[string][]byte{"..first": original, "..second": replacement} {
		require.NoError(t, os.Mkdir(filepath.Join(root, directory), 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(root, directory, "module.yaml"), data, 0o600))
	}
	require.NoError(t, os.Symlink("..first", filepath.Join(root, "..data")))
	require.NoError(t, os.Symlink("..data/module.yaml", filepath.Join(root, "module.yaml")))
	calls := 0
	// LoadOption вызывается после чтения, перед разбором: подмена тома здесь
	// детерминированно обнаруживает повторное чтение пути ради исходных байтов.
	documents, err := LoadDeliveredDocuments(root, func(*loadOptions) {
		calls++
		require.NoError(t, os.Symlink("..second", filepath.Join(root, "..next")))
		require.NoError(t, os.Rename(filepath.Join(root, "..next"), filepath.Join(root, "..data")))
	})
	require.NoError(t, err)
	require.Equal(t, 1, calls)
	require.Len(t, documents, 1)
	require.Equal(t, "module.yaml", documents[0].Path)
	require.Equal(t, original, documents[0].Bytes)
	require.Equal(t, "iam", documents[0].Manifest.Module)
	_, declared := documents[0].Manifest.Revision()
	require.False(t, declared, "загрузчик не дописывает revision старой доставке")
	now, err := os.ReadFile(filepath.Join(root, "module.yaml"))
	require.NoError(t, err)
	require.Equal(t, replacement, now, "путь уже содержит другую редакцию")
}

func TestDeliveredDocumentsShareRefusalsAndDoNotReturnPartialInput(t *testing.T) {
	for _, test := range []struct {
		name  string
		files map[string]string
	}{
		{"пусто", nil},
		{"неверный сосед", map[string]string{"a.yaml": "apiVersion: iam/v1\nmodule: iam\n", "b.yaml": "not: a-manifest\n"}},
		{"повтор модуля", map[string]string{"a.yaml": "apiVersion: iam/v1\nmodule: iam\n", "b.yaml": "apiVersion: iam/v1\nmodule: iam\n"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			for name, data := range test.files {
				require.NoError(t, os.WriteFile(filepath.Join(root, name), []byte(data), 0o600))
			}
			_, legacyErr := LoadDelivered(root)
			require.Error(t, legacyErr)
			documents, err := LoadDeliveredDocuments(root)
			require.EqualError(t, err, legacyErr.Error())
			require.Nil(t, documents)
		})
	}
}

func TestDeliveredDocumentsDoNotExposeRawInputInCheckReport(t *testing.T) {
	root := t.TempDir()
	const marker = "raw-comment-visible-only-to-document-loader"
	data := []byte("# " + marker + "\napiVersion: iam/v1\nmodule: iam\nrevision: 3\n")
	require.NoError(t, os.WriteFile(filepath.Join(root, "iam.yaml"), data, 0o600))
	documents, err := LoadDeliveredDocuments(root)
	require.NoError(t, err)
	require.Len(t, documents, 1)
	require.Equal(t, data, documents[0].Bytes)
	revision, declared := documents[0].Manifest.Revision()
	require.True(t, declared)
	require.EqualValues(t, 3, revision)
	report, err := LoadDelivered(root)
	require.NoError(t, err)
	raw, err := json.Marshal(report)
	require.NoError(t, err)
	require.NotContains(t, string(raw), marker)
	require.NotContains(t, string(raw), "\"Bytes\"")
	require.NotContains(t, report.Summary(), marker)
}
