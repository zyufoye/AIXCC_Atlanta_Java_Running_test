
## CodeQL Sink Analysis Tool 详解

### 工具概述
这是一个用于识别 Java 代码中安全漏洞点（sink）的 CodeQL 分析工具，能够将分析结果转换为坐标格式，便于后续分析。

### 核心功能
1. **运行 CodeQL 查询**：检测 Java 代码中的安全漏洞点
2. **格式转换**：将 CodeQL 结果转换为统一的坐标格式
3. **元数据检索**：通过 sink ID 获取漏洞详细信息

---

## 详细使用流程

### 1. 初始化设置
```bash
./init.sh
```
**初始化过程包括：**
- 安装 Python 依赖（PyYAML, Jinja2）
- 从集中化的 sink 定义生成 CodeQL 模型和查询文件
- 安装 CodeQL pack

**前提条件：**
- CodeQL CLI 已安装并在 PATH 中
- Python 3.x

### 2. 基本使用方法
```bash
./run.sh <database_path> <output_json_path>
```

**参数说明：**
- `database_path`：要分析的 CodeQL 数据库路径
- `output_json_path`：转换后的坐标格式 JSON 保存路径

**示例：**
```bash
./run.sh test-db results.json
```

### 3. 工具执行流程
1. **运行 CodeQL 查询**：对指定数据库执行 sink 检测查询
2. **解码结果**：将 BQRS 输出转换为 JSON 格式（临时）
3. **格式转换**：将 CodeQL JSON 格式转换为坐标格式
4. **输出结果**：保存最终的坐标格式到指定文件

---

## 输出格式详解

工具输出 JSON 坐标格式，每个条目包含：

```json
{
  "coord": {
    "line_num": 342,                    // 行号
    "method_name": "tokenizeRow",       // 方法名
    "file_name": "BasicCParser.java",   // 文件名
    "bytecode_offset": -1,              // 字节码偏移量
    "method_desc": "(Ljava/lang/String;)[Ljava/lang/String;",  // 方法描述符
    "mark_desc": "sink-RegexInjection", // 标记描述
    "method_signature": "org.apache.commons.imaging.common.BasicCParser: java.lang.String[] tokenizeRow(java.lang.String)",  // 完整方法签名
    "class_name": "org/apache/commons/imaging/common/BasicCParser"  // 类名
  },
  "id": "Sink: java.util.regex; Pattern; false; compile; (String); static; Argument[0]; regex-use; manual"  // sink ID
}
```

---

## 元数据检索功能

### 使用方法
```bash
./get_metadata.sh "<sink_id>"
```

**示例：**
```bash
./get_metadata.sh "Sink: java.io; File; false; <init>; (String); ; Argument[0]; path-injection; manual"
```

**输出示例：**
```yaml
category: file-system
cwe: CWE-22
description: File constructor that accepts a pathname string
severity: medium
```

---

## 架构设计

### 文件结构
```
├── sink_definitions.yml          # 集中化的 sink 定义（包含模型和元数据）
├── scripts/                     # Python 脚本
│   ├── generate_models.py       # 生成 CodeQL 模型和查询文件
│   ├── get_metadata.py          # 通过 sink ID 检索元数据
│   └── transform_results.py     # 转换 CodeQL 结果为坐标格式
├── templates/                   # Jinja2 代码生成模板
│   ├── model.yml.j2            # CodeQL 模型文件模板
│   └── sinks.ql.j2             # CodeQL 查询文件模板
├── sinks-pack/                 # 生成的 CodeQL pack
│   ├── models/                 # 生成的模型文件（每个包一个）
│   │   ├── java.io.model.yml
│   │   ├── java.lang.model.yml
│   │   └── ...
│   └── queries/
│       └── sinks.ql            # 生成的查询文件
├── init.sh                     # 初始化脚本
├── run.sh                      # 分析脚本
└── get_metadata.sh             # 元数据检索脚本
```

---

## 添加新的 Sink 定义

### 编辑 `sink_definitions.yml`
```yaml
sink_definitions:
  - model:
      package: "java.example"
      type: "ExampleClass"
      subtypes: false
      name: "vulnerableMethod"
      signature: "(String)"
      ext: ""
      input: "Argument[0]"
      kind: "example-injection"
      provenance: "manual"
    metadata:
      description: "Description of the sink"
      category: "example-category"
      severity: "medium"
      cwe: "CWE-XXX"
```

### 字段说明
**model 部分：**
- `package`：Java 包名
- `type`：类名
- `subtypes`：是否包含子类
- `name`：方法名
- `signature`：方法签名
- `ext`：扩展信息
- `input`：输入参数
- `kind`：漏洞类型
- `provenance`：来源

**metadata 部分：**
- `description`：漏洞描述
- `category`：分类
- `severity`：严重程度
- `cwe`：CWE 编号

### 重新生成
添加定义后运行：
```bash
./init.sh
```

---

## 在 CRS 系统中的角色

这个工具是 CRS-java 框架中的一个重要组件，主要负责：

1. **静态分析**：通过 CodeQL 识别潜在的漏洞点
2. **数据标准化**：将不同格式的分析结果统一为坐标格式
3. **元数据管理**：为每个 sink 提供详细的漏洞信息
4. **集成接口**：为其他组件（如 fuzzer、exploitation 工具）提供标准化的输入数据

这个工具的输出会被 CRS 系统的其他组件（如 fuzzer、exploitation 工具）使用，是整个漏洞检测流程的重要输入源。