# 获取当前脚本所在目录

## 命令结构分解

```bash
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
```

### 1. 命令替换 `$(...)`
- 将括号内命令的执行结果赋值给 `SCRIPT_DIR` 变量

### 2. 内部命令链 `cd ... && pwd`
- `cd` 命令先切换目录
- `&&` 表示只有前一个命令成功才执行后面的
- `pwd` 打印当前工作目录

### 3. `cd -- "$( dirname -- "${BASH_SOURCE[0]}" )"`
**进一步分解：**

#### `"${BASH_SOURCE[0]}"`
- `BASH_SOURCE[0]`：包含当前执行脚本的路径
- 在脚本内使用时，指向脚本文件本身的路径
- 用双引号包裹防止路径中有空格

#### `dirname -- "${BASH_SOURCE[0]}"`
- `dirname`：提取路径中的目录部分
- `--`：选项结束符，确保后面的内容不被解析为选项
- 示例：如果脚本路径是 `/home/user/scripts/init.sh`
  - `dirname` 返回 `/home/user/scripts`

#### `cd -- "$( dirname -- "${BASH_SOURCE[0]}" )"`
- 切换到脚本所在的目录
- 再次使用 `--` 确保目录路径正确解析

### 4. `&> /dev/null`
- `&>`：重定向标准输出和标准错误
- `/dev/null`：Linux的空设备，丢弃所有输出
- 作用：静默执行，不显示任何cd命令的输出或错误

### 5. `&& pwd`
- 只有在cd命令成功执行后才运行pwd
- `pwd`：打印当前工作目录的绝对路径

## 完整执行流程

假设脚本路径：`/home/user/CRS/codeql/init.sh`

1. `"${BASH_SOURCE[0]}"` → `/home/user/CRS/codeql/init.sh`
2. `dirname -- "/home/user/CRS/codeql/init.sh"` → `/home/user/CRS/codeql`
3. `cd -- "/home/user/CRS/codeql"` → 切换到该目录
4. `pwd` → `/home/user/CRS/codeql`
5. 最终 `SCRIPT_DIR=/home/user/CRS/codeql`

## 设计目的

这个命令的巧妙之处在于：
- **位置无关**：无论从哪个目录调用脚本，都能正确找到脚本所在目录
- **健壮性**：使用 `--` 防止路径被误解析为选项
- **静默执行**：重定向到 `/dev/null` 避免干扰输出
- **错误处理**：使用 `&&` 确保只有成功切换目录后才获取路径

这是shell脚本中获取脚本自身目录的标准做法，确保脚本的可靠执行。