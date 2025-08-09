package main

import (
	"ArchivePwdMatcher/cracker"
	"ArchivePwdMatcher/display"
	"ArchivePwdMatcher/utils"
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	passwordsFile   = "passwords.txt"
	resultDir       = "result"
	processTimeout  = 500 * time.Millisecond // 快速模式下的超时时间
)

// Result 用于保存破解结果
type Result struct {
	FilePath string
	Password string
}

func main() {
	// 1. 打印标题
	display.PrintDivider()
	display.PrintCenteredTitle("Archive Password Matcher - Go Version")
	display.PrintDivider()
	display.PrintEmptyLine()

	// 2. 获取用户输入
	targetPath := getUserInput()

	// 3. 加载密码和扫描文件
	passwords, archives, err := prepareTask(targetPath)
	if err != nil {
		display.PrintError(fmt.Sprintf("任务准备失败: %v", err))
		return
	}

	// 4. 显示摘要并获取用户选择的模式
	mode := showSummaryAndGetMode(targetPath, passwords, archives)

	// 5. 创建结果文件
	resultFile, err := setupResultFile()
	if err != nil {
		display.PrintError(fmt.Sprintf("无法创建结果文件: %v", err))
		return
	}
	defer resultFile.Close()

	// 6. 开始处理
	display.PrintSection("开始匹配")
	ctx := context.Background()
	var foundResult bool

	for i, archivePath := range archives {
		fileName := filepath.Base(archivePath)
		
		// 初始进度显示
		progressPrefix := fmt.Sprintf("[%03d/%03d]", i+1, len(archives))
		truncatedName := truncateString(fileName, 40)
		
		// 循环尝试密码
		found, password := processFile(ctx, archivePath, passwords, mode, progressPrefix, truncatedName)

		if found {
			foundResult = true
			result := Result{FilePath: archivePath, Password: password}
			
			// 清理行并打印成功信息
			clearLine()
			display.PrintSuccess(fmt.Sprintf("%s %s -> 密码: %s", progressPrefix, truncatedName, password))
			writeResult(resultFile, result)
		} else {
			// 失败了，也清理行并打印失败信息
			clearLine()
			display.PrintWarning(fmt.Sprintf("%s %s -> 未找到密码", progressPrefix, truncatedName))
		}
	}
	
	display.PrintSectionEnd()
	display.PrintEmptyLine()

	if !foundResult {
		display.PrintWarning("所有任务已完成，但未找到任何密码。")
	} else {
		display.PrintSuccess("所有任务已完成。")
	}
}

func processFile(ctx context.Context, filePath string, passwords []string, mode cracker.Mode, prefix, name string) (bool, string) {
	c, err := cracker.NewCracker(filePath, mode, processTimeout)
	if err != nil {
		clearLine()
		display.PrintError(fmt.Sprintf("创建破解器失败 (%s): %v", name, err))
		return false, ""
	}

	for _, password := range passwords {
		// 动态更新当前行
		fmt.Printf("\r%s %s 正在尝试: %s", prefix, name, password)

		ok, err := c.TryPassword(ctx, password)
		if err != nil {
			clearLine()
			display.PrintError(fmt.Sprintf("尝试密码时出错 (%s): %v", name, err))
			return false, "" 
		}
		if ok {
			return true, password
		}
	}
	return false, ""
}

// --- 辅助函数 ---

func getUserInput() string {
	display.PrintInputPrompt("请输入压缩包或文件夹的路径 (留空使用当前目录): ")
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	
	if input == "" {
		wd, _ := os.Getwd()
		display.PrintInfo(fmt.Sprintf("使用当前目录: %s", wd))
		return wd
	}
	return strings.Trim(input, "\"")
}

func prepareTask(path string) ([]string, []string, error) {
	display.PrintInfo("正在加载密码文件...")
	passwords, err := utils.LoadPasswords(passwordsFile)
	if err != nil {
		return nil, nil, err
	}
	if len(passwords) == 0 {
		return nil, nil, fmt.Errorf("密码文件 '%s' 为空", passwordsFile)
	}
	display.PrintSuccess(fmt.Sprintf("加载了 %d 个唯一密码", len(passwords)))

	display.PrintInfo("正在扫描压缩文件...")
	archives, err := utils.ScanArchives(path)
	if err != nil {
		return nil, nil, err
	}
	if len(archives) == 0 {
		return nil, nil, fmt.Errorf("在 '%s' 下未找到支持的压缩文件", path)
	}
	display.PrintSuccess(fmt.Sprintf("扫描到 %d 个待匹配文件", len(archives)))

	return passwords, archives, nil
}

func showSummaryAndGetMode(path string, passwords, archives []string) cracker.Mode {
	display.PrintSection("任务摘要")
	display.PrintFieldValue("目标路径", path)
	display.PrintFieldValue("密码数量", fmt.Sprintf("%d 个", len(passwords)))
	display.PrintFieldValue("待匹配文件", fmt.Sprintf("%d 个", len(archives)))
	display.PrintSectionEnd()
	display.PrintEmptyLine()

	display.PrintInputPrompt("请选择匹配模式 (1.快速, 2.精确) [默认为1]: ")
	reader := bufio.NewReader(os.Stdin)
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	if choice == "2" {
		display.PrintInfo("已选择: 精确模式")
		return cracker.AccurateMode
	}
	display.PrintInfo("已选择: 快速模式 (默认)")
	return cracker.QuickMode
}

func setupResultFile() (*os.File, error) {
	if err := os.MkdirAll(resultDir, 0755); err != nil {
		return nil, err
	}
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	fileName := filepath.Join(resultDir, fmt.Sprintf("results_%s.txt", timestamp))
	display.PrintInfo(fmt.Sprintf("本次任务的结果将记录在: %s", fileName))
	return os.Create(fileName)
}

func writeResult(file *os.File, result Result) {
	if file == nil {
		return
	}
	content := fmt.Sprintf("文件: %s\n密码: %s\n%s\n",
		result.FilePath,
		result.Password,
		strings.Repeat("-", 20))

	if _, err := file.WriteString(content); err != nil {
		log.Printf("写入结果文件失败: %v", err)
	}
}

func truncateString(s string, num int) string {
	if len(s) <= num {
		return s
	}
	// 考虑中文字符
	runes := []rune(s)
	if len(runes) <= num {
		return s
	}
	return string(runes[:num]) + "..."
}

func clearLine() {
	fmt.Printf("\r%s\r", strings.Repeat(" ", display.GetTerminalWidth()))
}