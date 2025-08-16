package cracker

import (
	"ArchivePwdMatcher/config"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
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
	Extract(ctx context.Context, password, destPath string) error
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
		args = []string{"t"}
	case ".7z", ".zip":
		cmdPath = config.Cfg.SevenZipPath
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
	fileName := filepath.Base(c.filePath)
	workDir := filepath.Dir(c.filePath)
	fullArgs := append(c.baseArgs, fmt.Sprintf("-p%s", password), fileName)

	ctx, cancel := context.WithTimeout(parentCtx, c.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, c.command, fullArgs...)
	cmd.Dir = workDir // 设置工作目录
	hideWindow(cmd)

	if c.mode == QuickMode {
		err := cmd.Run()
		if ctx.Err() == context.DeadlineExceeded {
			return true, nil
		}
		if _, ok := err.(*exec.ExitError); ok {
			return false, nil
		}
		return err == nil, err
	}

	err := cmd.Run()
	if err == nil {
		return true, nil
	}
	if _, ok := err.(*exec.ExitError); ok {
		return false, nil
	}
	return false, err
}

func (c *commandCracker) Extract(ctx context.Context, password, destPath string) error {
	// 统一使用 7z 进行解压，因为它兼容 rar 且行为更可预测
	command := config.Cfg.SevenZipPath
	fileName := filepath.Base(c.filePath)
	workDir := filepath.Dir(c.filePath)

	// 确保目标路径是绝对路径
	absDestPath, err := filepath.Abs(destPath)
	if err != nil {
		return fmt.Errorf("无法获取绝对目标路径: %w", err)
	}

	// 7z x <fileName> -p<password> -o<absDestPath> -y
	args := []string{
		"x",
		fileName,
		fmt.Sprintf("-p%s", password),
		fmt.Sprintf("-o%s", absDestPath),
		"-y", // Assume Yes on all queries
	}

	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Dir = workDir // 设置工作目录
	hideWindow(cmd)

	// 使用 CombinedOutput 来捕获所有输出，以便在出错时提供更详细的信息
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("解压失败: %w\n--- 7z 输出 ---\n%s", err, string(output))
	}

	return nil
}
