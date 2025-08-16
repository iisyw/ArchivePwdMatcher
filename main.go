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
	passwordsFile  = "passwords.txt"
	resultDir      = "result"
	processTimeout = 500 * time.Millisecond // 快速模式下的超时时间
)

// Result 用于保存破解结果
type Result struct {
	FilePath string
	Password string
}

func main() {
	// 1. 打印通用标题
	display.PrintDivider()
	display.PrintCenteredTitle("Archive Tools - Go Version")
	display.PrintDivider()
	display.PrintEmptyLine()

	// 2. 首先获取用户需要处理的路径
	targetPath := getUserInput("请输入要处理的压缩包或文件夹路径 (留空使用当前目录): ")

	// 3. 获取扫描选项
	scanOptions := showScanOptionsMenu()

	// 4. 显示主菜单并获取选择
	choice := showMainMenu()

	// 5. 根据选择执行不同的功能
	switch choice {
	case "1":
		runPasswordMatcher(targetPath, scanOptions)
	case "2":
		runExtractor(targetPath, scanOptions)
	default:
		display.PrintWarning("无效的选择，程序退出。")
	}

	display.PrintEmptyLine()
	display.PrintInfo("感谢使用，程序已退出。")
}

// showMainMenu 显示主菜单并返回用户的选择
func showMainMenu() string {
	display.PrintSection("主菜单")
	display.PrintInfo("1. 密码匹配器 (批量扫描并使用密码本匹配压缩包密码)")
	display.PrintInfo("2. 批量解压器 (批量扫描并使用密码本解压压缩包)")
	display.PrintSectionEnd()
	display.PrintEmptyLine()

	display.PrintInputPrompt("请输入功能选项 [1-2]: ")
	reader := bufio.NewReader(os.Stdin)
	choice, _ := reader.ReadString('\n')
	return strings.TrimSpace(choice)
}

// showScanOptionsMenu 显示扫描选项菜单并返回用户的选择
func showScanOptionsMenu() utils.ScanOptions {
	display.PrintSection("扫描选项")

	// 询问是否递归
	display.PrintInputPrompt("是否递归扫描子文件夹? (y/N): ")
	reader := bufio.NewReader(os.Stdin)
	recursiveChoice, _ := reader.ReadString('\n')
	recursive := strings.TrimSpace(strings.ToLower(recursiveChoice)) == "y"

	// 询问是否排除已解压
	display.PrintInputPrompt("是否排除已解压的压缩包? (Y/n): ")
	excludeChoice, _ := reader.ReadString('\n')
	exclude := strings.TrimSpace(strings.ToLower(excludeChoice)) != "n"

	display.PrintSectionEnd()
	return utils.ScanOptions{
		Recursive:     recursive,
		ExcludePacked: exclude,
	}
}

// runPasswordMatcher 运行密码匹配功能的完整流程
func runPasswordMatcher(targetPath string, scanOpts utils.ScanOptions) {
	display.PrintHeader("--- 密码匹配器 ---")

	// 1. 加载密码和扫描文件
	passwords, archives, err := prepareTask(targetPath, scanOpts)
	if err != nil {
		display.PrintError(fmt.Sprintf("任务准备失败: %v", err))
		return
	}

	// 2. 显示摘要并获取用户选择的模式
	mode := showSummaryAndGetMode(targetPath, passwords, archives)

	// 3. 创建结果文件
	resultFile, err := setupResultFile()
	if err != nil {
		display.PrintError(fmt.Sprintf("无法创建结果文件: %v", err))
		return
	}
	defer resultFile.Close()

	// 4. 开始处理
	display.PrintSection("开始匹配")
	ctx := context.Background()
	var foundResult bool

	for i, archivePath := range archives {
		fileName := filepath.Base(archivePath)
		progressPrefix := fmt.Sprintf("[%03d/%03d]", i+1, len(archives))
		truncatedName := truncateString(fileName, 40)

		found, password := processFile(ctx, archivePath, passwords, mode, progressPrefix, truncatedName)

		if found {
			foundResult = true
			result := Result{FilePath: archivePath, Password: password}
			clearLine()
			display.PrintSuccess(fmt.Sprintf("%s %s -> 密码: %s", progressPrefix, truncatedName, password))
			writeResult(resultFile, result)
		} else {
			clearLine()
			display.PrintWarning(fmt.Sprintf("%s %s -> 未找到密码或无需密码", progressPrefix, truncatedName))
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

// runExtractor 运行批量解压功能的流程
func runExtractor(targetPath string, scanOpts utils.ScanOptions) {
	display.PrintHeader("--- 批量解压器 ---")

	// 1. 显示解压选项菜单
	extractMode := showExtractorMenu()
	if extractMode == 0 {
		display.PrintWarning("未选择解压模式，操作取消。")
		return
	}

	// 2. 加载密码和扫描文件
	passwords, archives, err := prepareTask(targetPath, scanOpts)
	if err != nil {
		display.PrintError(fmt.Sprintf("任务准备失败: %v", err))
		return
	}

	display.PrintSection("开始解压")
	ctx := context.Background()
	var extractedCount int

	for i, archivePath := range archives {
		fileName := filepath.Base(archivePath)
		progressPrefix := fmt.Sprintf("[%03d/%03d]", i+1, len(archives))
		truncatedName := truncateString(fileName, 40)

		// 尝试用密码本解压
		success, password, err := extractFile(ctx, archivePath, passwords, extractMode, progressPrefix, truncatedName)

		if success {
			extractedCount++
			clearLine()
			display.PrintSuccess(fmt.Sprintf("%s %s -> 解压成功, 密码: %s", progressPrefix, truncatedName, password))
		} else {
			clearLine()
			display.PrintWarning(fmt.Sprintf("%s %s -> 解压失败", progressPrefix, truncatedName))
			if err != nil {
				display.PrintError(fmt.Sprintf("  └─> 错误详情: %v", err))
			}
		}
	}

	display.PrintSectionEnd()
	display.PrintEmptyLine()
	display.PrintSuccess(fmt.Sprintf("所有任务已完成，成功解压 %d 个文件。", extractedCount))
}

// extractFile 尝试用密码列表解压单个文件
func extractFile(ctx context.Context, filePath string, passwords []string, extractMode int, prefix, name string) (bool, string, error) {
	c, err := cracker.NewCracker(filePath, cracker.AccurateMode, time.Hour)
	if err != nil {
		return false, "", fmt.Errorf("创建解压器失败: %w", err)
	}

	var lastErr error
	for _, password := range passwords {
		fmt.Printf("\r%s %s 正在尝试密码: %s", prefix, name, password)

		finalExtractMode := extractMode
		// 如果是智能模式，需要先检查文件列表来决定最终模式
		if extractMode == 1 { // 1 是智能模式
			rootItems, listErr := c.ListRootItems(ctx, password)
			if listErr != nil {
				// 如果列表失败（可能是密码错误），则继续尝试下一个密码
				lastErr = listErr
				continue
			}

			// 智能判断逻辑
			archiveNameNoExt := strings.TrimSuffix(filepath.Base(filePath), filepath.Ext(filePath))
			// 检查根目录下是否只有一个项目，并且该项目的名称与压缩包名称（不含扩展名）相同
			if len(rootItems) == 1 && rootItems[0] == archiveNameNoExt {
				finalExtractMode = 2 // 判定为：应该解压到当前目录
			} else {
				finalExtractMode = 3 // 其他所有情况，都解压到同名文件夹
			}
		}

		// 确定输出目录
		var destPath string
		if finalExtractMode == 2 { // 解压到当前目录
			destPath = filepath.Dir(filePath)
		} else { // 解压到同名文件夹 (模式3 和 智能模式的默认情况)
			ext := filepath.Ext(filePath)
			destPath = filepath.Join(filepath.Dir(filePath), strings.TrimSuffix(filepath.Base(filePath), ext))
		}

		err := c.Extract(ctx, password, destPath)
		if err == nil {
			return true, password, nil
		}
		lastErr = err
	}

	return false, "", lastErr
}

// showExtractorMenu 显示解压器子菜单并返回用户的选择
func showExtractorMenu() int {
	display.PrintSection("解压选项")
	display.PrintInfo("1. 智能解压 (推荐)")
	display.PrintInfo("2. 解压到当前目录")
	display.PrintInfo("3. 解压到同名文件夹")
	display.PrintSectionEnd()
	display.PrintEmptyLine()

	display.PrintInputPrompt("请选择解压模式 [默认为1]: ")
	reader := bufio.NewReader(os.Stdin)
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	switch choice {
	case "2":
		return 2
	case "3":
		return 3
	case "1", "": // 默认选项
		return 1
	default:
		return 0
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

func getUserInput(prompt string) string {
	display.PrintInputPrompt(prompt)
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

func prepareTask(path string, scanOpts utils.ScanOptions) ([]string, []string, error) {
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
	archives, err := utils.ScanArchives(path, scanOpts)
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
	runes := []rune(s)
	if len(runes) <= num {
		return s
	}
	return string(runes[:num]) + "..."
}

func clearLine() {
	fmt.Printf("\r%s\r", strings.Repeat(" ", display.GetTerminalWidth()))
}