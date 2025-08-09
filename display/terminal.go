package display

import (
	"fmt"
	"os"
	"strings"
)

// 终端颜色代码
const (
	Reset      = "\033[0m"
	Bold       = "\033[1m"
	Dim        = "\033[2m"
	Italic     = "\033[3m"
	Underline  = "\033[4m"
	BlinkSlow  = "\033[5m"
	BlinkRapid = "\033[6m"
	Reverse    = "\033[7m"
	Hidden     = "\033[8m"
	
	Black   = "\033[30m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	White   = "\033[37m"

	BgBlack   = "\033[40m"
	BgRed     = "\033[41m"
	BgGreen   = "\033[42m"
	BgYellow  = "\033[43m"
	BgBlue    = "\033[44m"
	BgMagenta = "\033[45m"
	BgCyan    = "\033[46m"
	BgWhite   = "\033[47m"
)

// 应用颜色格式
func colorize(text, color string) string {
	if !isColorEnabled() {
		return text
	}
	return color + text + Reset
}

// 判断是否启用颜色
func isColorEnabled() bool {
	// 在非终端环境下禁用颜色
	fileInfo, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	
	// 检查是否是终端
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}

// GetTerminalWidth 获取终端宽度
func GetTerminalWidth() int {
	return getTerminalWidth()
}

// PrintCenteredTitle 居中显示标题
func PrintCenteredTitle(title string) {
	width := GetTerminalWidth()
	coloredTitle := colorize(title, Bold+Cyan)
	
	titleWidth := 0
	for _, r := range title {
		if r > 0x7F {
			titleWidth += 2 // 中文字符占用两个字符宽度
		} else {
			titleWidth += 1 // 英文字符占用一个字符宽度
		}
	}

	padding := (width - titleWidth) / 2
	if padding < 0 {
		padding = 0
	}
	paddedTitle := strings.Repeat(" ", padding) + coloredTitle
	fmt.Println(paddedTitle)
}

// PrintDivider 显示主分隔线
func PrintDivider() {
	width := GetTerminalWidth()
	divider := strings.Repeat("═", width)
	fmt.Println(colorize(divider, Bold+Cyan))
}

// PrintSubDivider 显示次级分隔线
func PrintSubDivider() {
	width := GetTerminalWidth()
	divider := strings.Repeat("─", width)
	fmt.Println(colorize(divider, Cyan))
}

// PrintEmptyLine 打印空行
func PrintEmptyLine() {
	fmt.Println()
}

// PrintInfo 打印信息行
func PrintInfo(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Println(colorize(msg, White))
}

// PrintHighlight 打印高亮信息
func PrintHighlight(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Println(colorize(msg, Bold+Yellow))
}

// PrintSection 打印带有分隔线的区块
func PrintSection(title string) {
	PrintEmptyLine()
	PrintDivider()
	PrintCenteredTitle(title)
	PrintDivider()
}

// PrintSubSection 打印带有次级分隔线的子区块
func PrintSubSection(title string) {
	PrintEmptyLine()
	PrintSubDivider()
	PrintCenteredTitle(title)
	PrintSubDivider()
}

// PrintSectionEnd 打印区块结束
func PrintSectionEnd() {
	PrintDivider()
}

// PrintFieldValue 打印字段和值
func PrintFieldValue(field, value string) {
	fieldColored := colorize(field, Bold+Green)
	valueColored := colorize(value, White)
	fmt.Printf("%-15s = %s\n", fieldColored, valueColored)
}

// PrintPrompt 打印用户提示
func PrintPrompt(prompt string) {
	fmt.Print(colorize(prompt, Bold+Yellow))
}

// PrintInputPrompt 打印用户输入提示
func PrintInputPrompt(prompt string) {
	fmt.Print(colorize(prompt, Bold+Yellow))
}

// PrintSuccess 打印成功信息
func PrintSuccess(message string) {
	prefix := colorize("[成功]", Bold+Green)
	msg := colorize(message, Green)
	fmt.Printf("%s %s\n", prefix, msg)
}

// PrintWarning 打印警告信息
func PrintWarning(message string) {
	prefix := colorize("[警告]", Bold+Yellow)
	msg := colorize(message, Yellow)
	fmt.Printf("%s %s\n", prefix, msg)
}

// PrintError 打印错误信息
func PrintError(message string) {
	prefix := colorize("[错误]", Bold+Red)
	msg := colorize(message, Red)
	fmt.Printf("%s %s\n", prefix, msg)
}

// PrintCommand 打印命令信息
func PrintCommand(command string) {
	msg := colorize(command, Bold+Magenta)
	fmt.Printf("$ %s\n", msg)
}

// PrintHeader 打印标题
func PrintHeader(header string) {
	msg := colorize(header, Bold+Blue)
	fmt.Println(msg)
}