演示在OSS-Fuzz项目中设置和使用模糊测试。

## OSS-Fuzz Demo 项目结构

首先，让我为您创建一个完整的OSS-Fuzz测试demo：

```bash:create_ossfuzz_demo.sh
#!/bin/bash

# 创建OSS-Fuzz demo项目结构
mkdir -p ossfuzz-demo
cd ossfuzz-demo

# 创建项目目录结构
mkdir -p projects/demo-project
mkdir -p projects/demo-project/src
mkdir -p projects/demo-project/test
mkdir -p projects/demo-project/.aixcc/dict

# 创建示例项目源码
cat > projects/demo-project/src/parser.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 简单的配置解析器
typedef struct {
    char key[64];
    char value[256];
} ConfigEntry;

// 解析配置行的函数
int parse_config_line(const char* line, ConfigEntry* entry) {
    if (!line || !entry) return -1;
    
    // 查找分隔符
    char* delimiter = strchr(line, ':');
    if (!delimiter) return -1;
    
    // 提取key
    size_t key_len = delimiter - line;
    if (key_len >= sizeof(entry->key)) return -1;
    strncpy(entry->key, line, key_len);
    entry->key[key_len] = '\0';
    
    // 提取value (跳过空格)
    char* value_start = delimiter + 1;
    while (*value_start == ' ') value_start++;
    
    if (strlen(value_start) >= sizeof(entry->value)) return -1;
    strcpy(entry->value, value_start);
    
    return 0;
}

// URL解析函数
int parse_url(const char* url, char* protocol, char* hostname, int* port) {
    if (!url) return -1;
    
    // 查找协议分隔符
    char* protocol_end = strstr(url, "://");
    if (!protocol_end) return -1;
    
    // 提取协议
    size_t proto_len = protocol_end - url;
    if (proto_len >= 16) return -1;
    strncpy(protocol, url, proto_len);
    protocol[proto_len] = '\0';
    
    // 提取主机名和端口
    char* host_start = protocol_end + 3;
    char* port_start = strchr(host_start, ':');
    char* path_start = strchr(host_start, '/');
    
    if (port_start && (!path_start || port_start < path_start)) {
        // 有端口号
        size_t host_len = port_start - host_start;
        if (host_len >= 64) return -1;
        strncpy(hostname, host_start, host_len);
        hostname[host_len] = '\0';
        
        *port = atoi(port_start + 1);
    } else {
        // 无端口号
        size_t host_len = path_start ? (path_start - host_start) : strlen(host_start);
        if (host_len >= 64) return -1;
        strncpy(hostname, host_start, host_len);
        hostname[host_len] = '\0';
        *port = 80; // 默认端口
    }
    
    return 0;
}
EOF

# 创建模糊测试目标
cat > projects/demo-project/test/fuzz_parser.c << 'EOF'
#include <stdint.h>
#include <stddef.h>
#include "../src/parser.c"

// 配置解析器的模糊测试入口
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;
    
    // 将输入转换为C字符串
    char input[1024];
    if (size >= sizeof(input)) size = sizeof(input) - 1;
    memcpy(input, data, size);
    input[size] = '\0';
    
    // 测试配置解析
    ConfigEntry entry;
    parse_config_line(input, &entry);
    
    return 0;
}

// URL解析器的模糊测试入口
int LLVMFuzzerTestOneInput_url(const uint8_t *data, size_t size) {
    if (size < 5) return 0;
    
    // 将输入转换为C字符串
    char input[1024];
    if (size >= sizeof(input)) size = sizeof(input) - 1;
    memcpy(input, data, size);
    input[size] = '\0';
    
    // 测试URL解析
    char protocol[16];
    char hostname[64];
    int port;
    parse_url(input, protocol, hostname, &port);
    
    return 0;
}
EOF

# 创建项目配置文件
cat > projects/demo-project/project.yaml << 'EOF'
name: "demo-project"
language: c
primary_contact: "demo@example.com"
homepage: "https://github.com/example/demo-project"
file_github_issue: true
sanitizers:
  - address
  - undefined
fuzzing_engines:
  - libfuzzer
archives:
  - debian-zesty
  - debian-buster
  - debian-bullseye
fuzz_targets:
  - name: fuzz_parser
    path: test/fuzz_parser.c
    corpus: test/corpus
  - name: fuzz_parser_url
    path: test/fuzz_parser.c
    corpus: test/corpus_url
EOF

# 创建测试语料库
mkdir -p projects/demo-project/test/corpus
mkdir -p projects/demo-project/test/corpus_url

echo "key1:value1" > projects/demo-project/test/corpus/config1
echo "username: admin" > projects/demo-project/test/corpus/config2
echo "timeout: 30" > projects/demo-project/test/corpus/config3

echo "http://example.com" > projects/demo-project/test/corpus_url/url1
echo "https://localhost:8080" > projects/demo-project/test/corpus_url/url2
echo "ftp://fileserver.com:21/path" > projects/demo-project/test/corpus_url/url3

# 创建dictgen测试配置
cat > projects/demo-project/.aixcc/dict/test_info.json << 'EOF'
{
  "functions": ["parse_config_line", "parse_url"],
  "answers": [":", "://", "http", "https", "ftp"]
}
EOF

# 创建构建脚本
cat > projects/demo-project/build.sh << 'EOF'
#!/bin/bash
set -e

# 编译源码
$CC -c -o src/parser.o src/parser.c

# 编译模糊测试目标
$CXX $CXXFLAGS -c -o test/fuzz_parser.o test/fuzz_parser.c
$CXX $CXXFLAGS -o $OUT/fuzz_parser test/fuzz_parser.o src/parser.o $LIB_FUZZING_ENGINE

$CXX $CXXFLAGS -c -o test/fuzz_parser_url.o test/fuzz_parser.c -DLLVMFuzzerTestOneInput=LLVMFuzzerTestOneInput_url
$CXX $CXXFLAGS -o $OUT/fuzz_parser_url test/fuzz_parser_url.o src/parser.o $LIB_FUZZING_ENGINE

# 复制字典文件（如果有）
if [ -f src/dictionary.dict ]; then
    cp src/dictionary.dict $OUT/fuzz_parser.dict
    cp src/dictionary.dict $OUT/fuzz_parser_url.dict
fi
EOF

chmod +x projects/demo-project/build.sh

# 创建Dockerfile用于本地测试
cat > Dockerfile << 'EOF'
FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y make autoconf automake libtool

COPY projects/demo-project $SRC/demo-project
WORKDIR $SRC/demo-project

# 设置构建环境
ENV CC=clang
ENV CXX=clang++
ENV CFLAGS="-fsanitize=fuzzer-no-link"
ENV CXXFLAGS="-fsanitize=fuzzer-no-link"
EOF

# 创建测试运行脚本
cat > test_ossfuzz.sh << 'EOF'
#!/bin/bash
set -e

echo "=== OSS-Fuzz Demo 测试脚本 ==="

# 设置工作目录
export WORKDIR=$(pwd)/workdir
mkdir -p $WORKDIR

echo "1. 测试基础功能..."
cd dictgen/src
python3 dictgen.py --test basic

echo "2. 测试C语言特定功能..."
python3 dictgen.py --test c

echo "3. 测试OSS-Fuzz项目..."
python3 dictgen.py --test oss-fuzz --test-dict ../../projects/demo-project/.aixcc/dict/test_info.json

echo "4. 运行字典生成器..."
python3 dictgen.py --path ../../projects/demo-project --func parse_config_line,parse_url

echo "=== 测试完成 ==="
EOF

chmod +x test_ossfuzz.sh

# 创建README说明文档
cat > README.md << 'EOF'
# OSS-Fuzz Demo 项目

这是一个演示如何在OSS-Fuzz项目中设置模糊测试的示例。

## 项目结构

```
ossfuzz-demo/
├── projects/
│   └── demo-project/
│       ├── src/parser.c          # 示例解析器代码
│       ├── test/fuzz_parser.c    # 模糊测试目标
│       ├── project.yaml          # OSS-Fuzz项目配置
│       ├── build.sh              # 构建脚本
│       └── .aixcc/dict/test_info.json  # dictgen测试配置
├── test_ossfuzz.sh               # 测试运行脚本
└── Dockerfile                    # 用于本地测试的Docker配置
```

## 核心组件说明

### 1. 解析器代码 (src/parser.c)
- `parse_config_line()`: 解析配置行 (key:value格式)
- `parse_url()`: 解析URL (protocol://host:port格式)

### 2. 模糊测试目标 (test/fuzz_parser.c)
- `LLVMFuzzerTestOneInput()`: 配置解析的模糊测试入口
- `LLVMFuzzerTestOneInput_url()`: URL解析的模糊测试入口

### 3. OSS-Fuzz配置 (project.yaml)
- 项目元数据
- 支持的sanitizers
- 模糊测试引擎配置
- 目标定义

### 4. 测试语料库
- `test/corpus/`: 配置解析的初始测试用例
- `test/corpus_url/`: URL解析的初始测试用例

## 运行测试

```bash
# 运行完整的测试流程
./test_ossfuzz.sh

# 或者手动运行各个测试
cd dictgen/src

# 基础测试
python3 dictgen.py --test basic

# C语言测试
python3 dictgen.py --test c

# OSS-Fuzz项目测试
python3 dictgen.py --test oss-fuzz --test-dict ../../projects/demo-project/.aixcc/dict/test_info.json

# 生成字典
python3 dictgen.py --path ../../projects/demo-project --func parse_config_line,parse_url
```

## 在真实OSS-Fuzz环境中的使用

1. 将项目提交到OSS-Fuzz
2. OSS-Fuzz基础设施会自动：
   - 构建项目
   - 运行模糊测试
   - 监控崩溃
   - 报告漏洞

## 字典生成器集成

dictgen会自动分析代码并生成：
- 配置解析相关的字典条目（如 ":" 分隔符）
- URL解析相关的字典条目（如 "://" 协议标识）
EOF

echo "OSS-Fuzz demo项目创建完成！"
echo "项目位置: $(pwd)"
echo "运行测试: ./test_ossfuzz.sh"
```

## 运行Demo

```bash
# 创建demo项目
chmod +x create_ossfuzz_demo.sh
./create_ossfuzz_demo.sh

# 进入项目目录
cd ossfuzz-demo

# 运行测试
./test_ossfuzz.sh
```

## OSS-Fuzz 工作流程总结

这个demo展示了OSS-Fuzz的完整流程：

1. **项目配置** → 定义项目元数据和构建规则
2. **代码实现** → 编写要测试的库函数
3. **模糊测试目标** → 创建测试入口点
4. **初始语料库** → 提供基本的测试输入
5. **字典生成** → 使用dictgen生成优化字典
6. **自动化测试** → OSS-Fuzz基础设施运行模糊测试
7. **漏洞报告** → 自动报告发现的崩溃和漏洞

这个demo可以帮助您理解如何在真实项目中集成OSS-Fuzz和字典生成器。