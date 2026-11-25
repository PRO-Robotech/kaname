// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"

// Экспорт существующего writer только для сквозной проверки до подключения readiness.
func UserMetadataWriterForTest(f *MetadataMutationWriters) kaname.UserAccessLabelsWriter {
	return &userAccessLabelsWriter{factory: f}
}
