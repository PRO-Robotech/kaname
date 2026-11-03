// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package installruntime

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"
)

// EvidenceDirectory never interpolates a raw Go subtest identity into a shell
// path. Hashing the COMPLETE identity also keeps a/b distinct from a-b, unlike
// replacing separators or dropping punctuation. The caller records the original
// identity separately as JSON data, not as executable shell syntax.
func EvidenceDirectory(root, identity string) (string, error) {
	if err := validateStandPath(root); err != nil {
		return "", err
	}
	if identity == "" {
		return "", fmt.Errorf("evidence requires a nonempty test identity")
	}
	digest := sha256.Sum256([]byte(identity))
	return filepath.Join(root, fmt.Sprintf("case-%x", digest)), nil
}

// The existing stand environment builder evaluates its fixed variable names.
// Its supplied PKI/run/delivery paths must therefore use this restricted ASCII
// alphabet before ANY preparation subprocess or filesystem mutation. This is a
// test orchestration constraint, not an alteration of production configuration.
func validateStandPath(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("native stand path must be absolute and canonical")
	}
	for _, c := range path {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '/' || c == '.' || c == '_' || c == '-' {
			continue
		}
		return fmt.Errorf("native stand path contains characters outside its safe path alphabet")
	}
	return nil
}
