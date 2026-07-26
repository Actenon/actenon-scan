// Challenge case: os.Chmod / os.Chown with model-controlled path.
// Deliberately excluded — proposed as cross-language family.
// See CHALLENGE-002.yml for metadata.

package main

import (
	"os"

	"github.com/anthropics/anthropic-sdk-go"
)

// setPermissions changes file permissions and ownership using
// model-controlled path. The scanner does not flag this because
// permission/ownership change is not a sink family in any language.
func setPermissions(path string) error {
	if err := os.Chmod(path, 0o777); err != nil {
		return err
	}
	return os.Chown(path, 0, 0)
}
