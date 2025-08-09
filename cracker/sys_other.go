//go:build !windows

package cracker

import "os/exec"

func hideWindow(cmd *exec.Cmd) {
	// No-op on non-Windows systems
}