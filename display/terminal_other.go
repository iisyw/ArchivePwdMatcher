//go:build !windows

package display

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// 获取终端宽度（非Windows平台实现）
func getTerminalWidth() int {
	cmd := exec.Command("stty", "size")
	cmd.Stdin = os.Stdin
	output, err := cmd.Output()
	if err != nil {
		return 80 // 默认宽度
	}

	parts := strings.Split(strings.TrimSpace(string(output)), " ")
	if len(parts) != 2 {
		return 80 // 默认宽度
	}

	width, err := strconv.Atoi(parts[1])
	if err != nil {
		return 80 // 默认宽度
	}

	return width
}