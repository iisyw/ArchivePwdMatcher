package utils

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ScanOptions 定义了扫描文件的选项
type ScanOptions struct {
	Recursive     bool
	ExcludePacked bool
}

var supportedExtensions = map[string]bool{
	".zip": true,
	".rar": true,
	".7z":  true,
}

// LoadPasswords 从指定文件中加载密码列表，并去除重复项。
func LoadPasswords(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("密码文件 '%s' 不存在", filePath)
		}
		return nil, fmt.Errorf("无法打开密码文件 '%s': %w", filePath, err)
	}
	defer file.Close()

	passwords := []string{}
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		password := strings.TrimSpace(scanner.Text())
		if password != "" && !seen[password] {
			seen[password] = true
			passwords = append(passwords, password)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取密码文件时出错: %w", err)
	}

	return passwords, nil
}

// ScanArchives 扫描指定路径下的所有支持的压缩文件。
func ScanArchives(rootPath string, opts ScanOptions) ([]string, error) {
	archives := []string{}
	info, err := os.Stat(rootPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("路径 '%s' 不存在", rootPath)
		}
		return nil, fmt.Errorf("无法访问路径 '%s': %w", rootPath, err)
	}

	if !info.IsDir() {
		// 如果是单个文件
		if supportedExtensions[filepath.Ext(rootPath)] {
			archives = append(archives, rootPath)
		}
		return archives, nil
	}

	// 根据是否递归选择不同的扫描方式
	if opts.Recursive {
		err = filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				fmt.Printf("\n[警告] 无法访问路径: %s, 错误: %v\n", path, err)
				return nil
			}
			if !d.IsDir() {
				processFile(path, &archives, opts)
			}
			return nil
		})
	} else {
		entries, err := os.ReadDir(rootPath)
		if err != nil {
			return nil, fmt.Errorf("无法读取目录 '%s': %w", rootPath, err)
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				path := filepath.Join(rootPath, entry.Name())
				processFile(path, &archives, opts)
			}
		}
	}

	if err != nil {
		return nil, fmt.Errorf("扫描目录时出错: %w", err)
	}

	return archives, nil
}

// processFile 是一个辅助函数，用于处理单个文件，检查是否符合条件
func processFile(path string, archives *[]string, opts ScanOptions) {
	// 1. 检查扩展名
	if !supportedExtensions[filepath.Ext(path)] {
		return
	}

	// 2. 如果需要，检查是否已解压
	if opts.ExcludePacked {
		ext := filepath.Ext(path)
		dirPath := strings.TrimSuffix(path, ext)
		if info, err := os.Stat(dirPath); err == nil && info.IsDir() {
			return // 存在同名文件夹，跳过
		}
	}

	// 3. 将符合条件的文件添加到列表
	*archives = append(*archives, path)
}