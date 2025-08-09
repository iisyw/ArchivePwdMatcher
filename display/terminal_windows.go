//go:build windows

package display

import (
	"syscall"
	"unsafe"
)

// 获取终端宽度（Windows平台实现）
func getTerminalWidth() int {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getConsoleScreenBufferInfo := kernel32.NewProc("GetConsoleScreenBufferInfo")
	handle, err := syscall.GetStdHandle(syscall.STD_OUTPUT_HANDLE)
	if err != nil {
		return 80 // 默认宽度
	}

	var csbi struct {
		size struct {
			x, y uint16
		}
		cursorPosition struct {
			x, y uint16
		}
		attributes uint16
		window     struct {
			left, top, right, bottom uint16
		}
		maximumWindowSize struct {
			x, y uint16
		}
	}

	ret, _, _ := getConsoleScreenBufferInfo.Call(uintptr(handle), uintptr(unsafe.Pointer(&csbi)))
	if ret == 0 {
		return 80 // 默认宽度
	}

	return int(csbi.window.right - csbi.window.left + 1)
}