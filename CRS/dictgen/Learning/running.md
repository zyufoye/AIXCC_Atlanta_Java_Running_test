
## 环境准备

### 1. 安装依赖包
```bash
# 在虚拟环境中
pip install -r requirements.txt
```

### 2. 设置环境变量
```bash
export LITELLM_KEY=sk-...          # API密钥
export LITELLM_URL=...              # API地址
export WORKDIR=/path/to/CRS-multilang/workdir  # 工作目录
```
注意：`WORKDIR` 是可选的，可以在运行时指定

## 测试类型详解

### 1. 基础测试 (Basic Tests)
```bash
cd src
python3 dictgen.py --test basic
```
或者指定工作目录：
```bash
python3 dictgen.py --test basic --workdir /path/to/workdir
```

**特定语言测试：**
```bash
# 测试C语言
python3 dictgen.py --test c

# 测试Java
python3 dictgen.py --test java

# 测试Python
python3 dictgen.py --test python

# 测试Go
python3 dictgen.py --test go
```
支持的语言：`c`, `java`, `python`, `go`

### 2. 单个OSS-Fuzz项目测试
```bash
python3 dictgen.py --test oss-fuzz --test-dict /path/to/oss-fuzz/projects/jvm/fuzzy/.aixcc/dict/test_info.json
```

**测试信息文件格式 (`test_info.json`):**
```json
{
  "functions": ["getRatio","getConfigValue","getTagXPath"],
  "answers": ["xcost", ":", "'[^']+'"]
}
```
- `functions`: 要测试的函数列表
- `answers`: 期望生成的必要标记（正则表达式格式）

### 3. 所有OSS-Fuzz项目测试
```bash
python3 dictgen.py --test oss-fuzz-all --path /path/to/oss-fuzz
```
- 自动查找包含 `.aixcc/dict/test_info.json` 的项目
- 克隆源码到 `WORKDIR/oss-fuzz/PROJECT_NAME`
- 如果不指定 `--path`，使用根目录的 `benchmark` 目录

### 4. 完整测试套件
```bash
python3 dictgen.py --test all --path /path/to/oss-fuzz
```
运行所有测试，包括基础测试和OSS-Fuzz测试

## 实际运行字典生成器

### 生产环境使用
```bash
python3 dictgen.py --path /path/to/cp-java-fuzzy-source --func getRatio,getConfigValue,getTagXPath
```

**参数说明：**
- `--path`: 源代码路径
- `--func`: 要分析的函数名（逗号分隔）
- 注意：函数名不包含类名

## 测试流程总结

1. **环境配置** → 安装依赖，设置API密钥
2. **基础验证** → 运行基础测试确保功能正常
3. **项目测试** → 针对具体项目运行测试
4. **完整验证** → 运行所有测试确保质量
5. **生产使用** → 在实际项目上运行字典生成

## 测试成功标准

- **退出码为0**：所有测试通过
- **生成必要标记**：检查 `answers` 中的正则表达式是否匹配生成的字典
- **函数覆盖**：确保指定的函数都被正确分析

这个测试框架确保了字典生成器在不同语言和项目中的可靠性和准确性。