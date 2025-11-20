`transform_results.py` 文件是一个 **CodeQL结果转换器**，它把CodeQL的原始分析结果转换成CRS系统需要的坐标格式。让我详细解读：

## 核心功能

**将CodeQL的JSON分析结果转换为统一的坐标格式**，供CRS系统中的其他模块使用。

## 详细解读

### 1. 输入输出格式

**输入**：CodeQL的原始JSON结果
```json
{
  "#select": {
    "columns": [{"name": "entity"}, {"name": "sink_type"}, ...],
    "tuples": [
      [entity_data, "path-traversal", true, "java.io.File", "File", ...]
    ]
  }
}
```

**输出**：CRS坐标格式
```json
[
  {
    "coord": {
      "line_num": 25,
      "method_name": "File",
      "file_name": "UserController.java",
      "bytecode_offset": -1,
      "method_desc": "...",
      "mark_desc": "path-traversal",
      "method_signature": "File(String)",
      "class_name": "java/io/File"
    },
    "id": "model_info"
  }
]
```

### 2. 关键转换函数

#### `transform_codeql_results()` (第23-95行)
这是主要的转换逻辑：

**步骤1：读取和验证输入**
```python
with open(input_file, 'r') as f:
    data = json.load(f)

if '#select' not in data or 'tuples' not in data['#select']:
    raise ValueError("Invalid CodeQL JSON format")
```

**步骤2：建立列映射**
```python
col_map = {col['name']: idx for idx, col in enumerate(columns) if 'name' in col}
```
- 创建列名到索引的映射，方便按名称访问数据

**步骤3：过滤和处理每个结果**
```python
for tuple_data in tuples:
    # 提取各个字段
    entity = tuple_data[col_map['entity']]
    sink_type = tuple_data[col_map['sink_type']]
    has_non_constant_args = tuple_data[col_map['has_non_constant_args']]
    # ... 其他字段
    
    # 关键过滤：只保留有非常量参数的结果
    if not has_non_constant_args:
        continue
```

**步骤4：格式转换**
```python
# 类名格式转换：java.io.File → java/io/File
jvm_class_name = convert_class_name_to_jvm_format(class_name)

# 创建坐标条目
coord_entry = {
    "coord": {
        "line_num": line_number,           # 源代码行号
        "method_name": method_name,        # 方法名
        "file_name": file_path,            # 文件名
        "bytecode_offset": -1,             # 字节码偏移（未使用）
        "method_desc": method_descriptor,  # 方法描述符
        "mark_desc": sink_type,            # 漏洞类型标记
        "method_signature": method_signature,  # 方法签名
        "class_name": jvm_class_name       # JVM格式类名
    },
    "id": model_info                       # 模型信息ID
}
```

### 3. 辅助函数

#### `convert_class_name_to_jvm_format()` (第18-20行)
```python
def convert_class_name_to_jvm_format(class_name):
    return class_name.replace('.', '/')
```
- 将Java的点分隔类名转换为JVM的斜杠格式
- 例如：`java.io.File` → `java/io/File`

#### `extract_filename_from_path()` (第13-15行)
```python
def extract_filename_from_path(file_path):
    return os.path.basename(file_path)
```
- 从完整路径中提取文件名（当前被注释掉了）

### 4. 主函数 (第98-116行)
处理命令行参数和错误处理：
```python
def main():
    if len(sys.argv) != 3:
        print("Usage: python3 transform_results.py <input_json> <output_json>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    # 文件存在性检查
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' does not exist")
        sys.exit(1)
    
    # 执行转换
    transform_codeql_results(input_file, output_file)
```

## 在CRS系统中的角色

这个转换器是 **CodeQL模块和CRS核心系统之间的桥梁**：

1. **标准化格式**：将CodeQL特有的结果格式转换为CRS统一的坐标格式
2. **数据过滤**：只保留真正有风险的漏洞（有非常量参数的）
3. **格式适配**：转换为JVM字节码分析所需的格式
4. **信息丰富**：保留所有必要的元数据供后续分析使用

## 使用示例

```bash
# 转换CodeQL结果
python3 transform_results.py codeql_results.json crs_coordinates.json

# 输出示例
Transformed 15 entries from codeql_results.json to crs_coordinates.json
```

这样转换后的结果可以被CRS系统中的模糊测试工具、Concolic执行器等模块直接使用，指导它们重点测试这些已识别的潜在漏洞点。