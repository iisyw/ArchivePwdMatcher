package utils

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

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
func ScanArchives(rootPath string) ([]string, error) {
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

	// 如果是目录，则遍历
	err = filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && supportedExtensions[filepath.Ext(d.Name())] {
			archives = append(archives, path)
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("扫描目录时出错: %w", err)
	}

	return archives, nil
}