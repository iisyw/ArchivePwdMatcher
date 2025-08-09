package cracker

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"ArchivePwdMatcher/config"
)

// Mode 定义了破解模式
type Mode int

const (
	// QuickMode 快速模式，超时即成功
	QuickMode Mode = iota
	// AccurateMode 精确模式，等待进程返回结果
	AccurateMode
)

// Cracker 定义了破解器的接口
type Cracker interface {
	TryPassword(ctx context.Context, password string) (bool, error)
}

// NewCracker 是一个工厂函数，根据文件类型返回合适的破解器
func NewCracker(filePath string, mode Mode, timeout time.Duration) (Cracker, error) {
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".rar", ".7z", ".zip":
		return newCommandCracker(filePath, mode, timeout)
	default:
		return nil, fmt.Errorf("不支持的文件类型: %s", ext)
	}
}

// --- 命令行破解器 (用于 rar, 7z, zip) ---

type commandCracker struct {
	filePath string
	mode     Mode
	timeout  time.Duration
	command  string
	baseArgs []string
}

func newCommandCracker(filePath string, mode Mode, timeout time.Duration) (Cracker, error) {
	ext := strings.ToLower(filepath.Ext(filePath))
	var cmdPath string
	var args []string

	switch ext {
	case ".rar":
		cmdPath = config.Cfg.UnrarPath
		// unrar t -p<password> <archive>
		// 注意参数顺序，密码在前
		args = []string{"t"}
	case ".7z", ".zip":
		cmdPath = config.Cfg.SevenZipPath
		// 7z t -p<password> <archive>
		args = []string{"t"}
	default:
		return nil, errors.New("内部错误: 不支持的命令行破解类型")
	}

	return &commandCracker{
		filePath: filePath,
		mode:     mode,
		timeout:  timeout,
		command:  cmdPath,
		baseArgs: args,
	}, nil
}

func (c *commandCracker) TryPassword(parentCtx context.Context, password string) (bool, error) {
	// 将密码和文件路径参数附加到 baseArgs
	// 这样可以正确处理带空格的文件路径
	fullArgs := append(c.baseArgs, fmt.Sprintf("-p%s", password), c.filePath)

	ctx, cancel := context.WithTimeout(parentCtx, c.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, c.command, fullArgs...)

	// 在 Windows 上隐藏命令行窗口
	hideWindow(cmd)

	// 对于快速模式，我们不关心输出，只关心是否超时
	if c.mode == QuickMode {
		err := cmd.Run()
		if ctx.Err() == context.DeadlineExceeded {
			// 超时被我们视为成功
			return true, nil
		}
		// 如果没有超时就正常结束了，检查是否是密码错误
		if _, ok := err.(*exec.ExitError); ok {
			// 对于 unrar 和 7z，密码错误的退出码通常不是 0
			// 我们假设任何非零退出码都意味着密码错误
			return false, nil // 密码错误，但不是程序错误
		}
		// 如果 err 是 nil，说明密码正确
		return err == nil, err
	}

	// 对于精确模式，我们等待结果
	err := cmd.Run()
	if err == nil {
		return true, nil // 成功
	}

	if _, ok := err.(*exec.ExitError); ok {
		// 密码错误，返回 false，但 error 为 nil
		return false, nil
	}

	// 其他类型的错误（如命令找不到），作为真实错误返回
	return false, err
}
