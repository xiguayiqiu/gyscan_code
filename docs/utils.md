# utils - 通用工具函数库

网络安全渗透测试的通用工具函数库。

## 引入

```go
import "github.com/xiguayiqiu/gyscan_code/utils"
```

---

## 进度条 ProgressBar

### 快速函数

| 函数 | 说明 | 样式 |
|------|------|------|
| `utils.Progress(current, total)` | 简单进度条 | █░ |
| `utils.ProgressWithText(text, current, total)` | 带文本进度条 | █░ |
| `utils.ProgressArrow(current, total)` | 箭头进度条 | => |
| `utils.ProgressDot(current, total)` | 圆点进度条 | ●○ |
| `utils.ProgressLine(current, total)` | 线条进度条 | ━━ |
| `utils.ProgressSlash(current, total)` | 斜杠进度条 | /. |
| `utils.ProgressMini(current, total)` | 迷你进度条 | 仅百分比 |
| `utils.ProgressWithSpeed(current, total, speed)` | 带速度 | █░ + 速度 |
| `utils.ProgressStyle(style, current, total)` | 自定义样式 | 动态 |
| `utils.ProgressBar_(total)` | 一次性进度条 | █░ |
| `utils.ProgressStar(current, total)` | 星星进度条 | ★☆ |
| `utils.ProgressHash(current, total)` | 哈希进度条 | ## |
| `utils.ProgressDiamond(current, total)` | 菱形进度条 | ◆◇ |
| `utils.ProgressHeart(current, total)` | 爱心进度条 | ♥♡ |
| `utils.ProgressReverse(current, total)` | 反向进度条 | ░░ |
| `utils.ProgressBox(current, total)` | 盒子进度条 | ┣━┫ |
| `utils.ProgressBraille(current, total)` | 盲文进度条 |⣿⠂ |
| `utils.ProgressColor(current, total)` | 彩色进度条 | 红黄绿 |
| `utils.ProgressCyber(current, total)` | 赛博进度条 | █░ |
| `utils.ProgressPipe(current, total)` | 管道进度条 | █▒ |
| `utils.ProgressSharp(current, total)` | 井号进度条 | #### |
| `utils.ProgressSimple()` | 简单样式 | █▒▒▒▒ 10% |

### ProgressBar 结构体

```go
pb := utils.NewProgressBar(100).
    SetPrefix("扫描").
    SetWidth(50).
    SetStyle("dot")

for i := 0; i <= 100; i++ {
    pb.Set(i)
}
pb.Finish()
```

### 方法列表

| 方法 | 说明 |
|------|------|
| `SetPrefix(text)` | 设置前缀文本 |
| `SetWidth(width)` | 设置进度条宽度 |
| `SetStyle(style)` | 设置样式 (block/arrow/dot/line/slash/pipe/sharp/star/hash/diamond/heart/reverse/box/braille/cyber) |
| `Set(n)` | 设置当前进度 |
| `Increment()` | 进度+1 |
| `Finish()` | 完成并换行 |

---

## 进度条样式展示

### 1. Block 样式 █░
```
[██████████████████████████████████████████████████] 80.0%
```

### 2. Arrow 样式 =>
```
[==================================================>] 80.0%
```

### 3. Dot 样式 ●○
```
[●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●] 80.0%
```

### 4. Line 样式 ━━
```
[━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━] 80.0%
```

### 5. Slash 样式 /.
```
[//////////////////////////////////////////////////] 80.0%
```

### 6. Star 样式 ★☆
```
[★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★☆] 80.0%
```

### 7. Hash 样式 ##
```
[##################################################] 80.0%
```

### 8. Sharp 样式 ####
```
[##################################################] 80.0%
```

### 9. Pipe 样式 █▒
```
[████████████████████████████████████████████████▒] 80.0%
```

### 10. Diamond 样式 ◆◇
```
[◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◇] 80.0%
```

### 11. Heart 样式 ♥♡
```
[♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♡] 80.0%
```

### 12. Reverse 反向样式
```
[░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░] 80.0%
```

### 13. Box 样式 ┣━┫
```
[┣┣┣┣┣┣┣┣┣┣┣┣┣┣┣┣┣┣┣┣┣┣┣┣┣┣┣┣┣┣┣┣┣┣┣┣┣┣┣┫] 80.0%
```

### 14. Braille 样式
```
[⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠂⠂⠂⠂⠂⠂⠂⠂] 80.0%
```

### 15. Mini 样式
```
80.0%
```

### 16. WithSpeed 带速度
```
[██████████████████████████████████████████████████] 80.0% [80/100] 8.0/s
```

### 17. Color 彩色样式 (红→黄→绿)
```
[██████████████████████████████████████████████████] 80.0%
```

### 18. Cyber 赛博样式
```
[██████████████████████████████████████████████████]  80% ▓▒░
```

### 19. Simple 简单样式
```
█▒▒▒▒▒▒▒▒▒▒ 10%
```

---

## 使用示例

### 简单使用

```go
for i := 0; i <= 100; i++ {
    utils.Progress(i, 100)
    time.Sleep(10 * time.Millisecond)
}
```

### 带文本

```go
for i := 0; i <= 100; i++ {
    utils.ProgressWithText("下载文件", i, 100)
    time.Sleep(10 * time.Millisecond)
}
```

### 链式 ProgressBar

```go
pb := utils.NewProgressBar(100).
    SetPrefix("扫描端口").
    SetStyle("dot")

for i := 0; i <= 100; i++ {
    pb.Set(i)
    time.Sleep(10 * time.Millisecond)
}
pb.Finish()
```

### 自定义样式

```go
for i := 0; i <= 100; i++ {
    utils.ProgressStyle("line", i, 100)
    time.Sleep(10 * time.Millisecond)
}
```

### 带速度

```go
for i := 0; i <= 100; i++ {
    utils.ProgressWithSpeed(i, 100, float64(i)/10)
    time.Sleep(10 * time.Millisecond)
}
```

### 彩色进度条

```go
for i := 0; i <= 100; i++ {
    utils.ProgressColor(i, 100)
    time.Sleep(10 * time.Millisecond)
}
```

### 赛博风格

```go
for i := 0; i <= 100; i++ {
    utils.ProgressCyber(i, 100)
    time.Sleep(10 * time.Millisecond)
}
```

### 简单样式

```go
utils.ProgressSimple()
```

### 井号进度条

```go
for i := 0; i <= 100; i++ {
    utils.ProgressSharp(i, 100)
    time.Sleep(10 * time.Millisecond)
}
```

---

## License

Apache License 2.0