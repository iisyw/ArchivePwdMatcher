package config

import (
	"os"
	"path/filepath"
	"runtime"
)

// AppConfig 保存应用程序的全局配置
type AppConfig struct {
	SevenZipPath string
}

// Cfg 是全局唯一的配置实例
var Cfg *AppConfig

func init() {
	Cfg = &AppConfig{
		SevenZipPath: findExecutable("7z", "7za"),
	}
}

// findExecutable 优先在程序工作目录查找，然后才依赖系统 PATH
func findExecutable(baseName, fallbackName string) string {
	// 1. 获取当前可执行文件所在的目录
	exePath, err := os.Executable()
	if err != nil {
		// 如果获取失败，回退到只使用 baseName，依赖系统 PATH
		return addExeSuffix(baseName)
	}
	workDir := filepath.Dir(exePath)

	// 2. 尝试在工作目录查找主名称 (e.g., 7z.exe)
	searchPath := filepath.Join(workDir, addExeSuffix(baseName))
	if _, err := os.Stat(searchPath); err == nil {
		return searchPath // 直接返回绝对路径
	}

	// 3. 尝试在工作目录查找备用名称 (e.g., 7za.exe)
	if fallbackName != "" {
		fallbackPath := filepath.Join(workDir, addExeSuffix(fallbackName))
		if _, err := os.Stat(fallbackPath); err == nil {
			return fallbackPath // 直接返回绝对路径
		}
	}

	// 4. 如果在工作目录都找不到，则回退，依赖系统 PATH
	return addExeSuffix(baseName)
}

// addExeSuffix 在 Windows 系统上为可执行文件添加 ".exe" 后缀
func addExeSuffix(name string) string {
	if runtime.GOOS == "windows" && filepath.Ext(name) == "" {
		return name + ".exe"
	}
	return name
}
