这两个文件是CodeQL分析系统的**核心配置文件**：

## 1. `sinks-pack/models/*.model.yml` - 模型文件

**作用：告诉CodeQL "哪些API是危险的"**

### 通俗理解
就像给CodeQL一本 **"危险API字典"**，里面列出了所有可能被黑客利用的Java方法。

### 具体内容示例
```yaml
# java.io.model.yml
extensions:
  data:
    - ["java.io", "File", false, "File", "File(String)", "", "0", "path-traversal", "manual"]
    # 包名   类名   包含子类? 方法名   方法签名       扩展 参数位置 漏洞类型      来源
```

**这个文件告诉CodeQL：**
- `java.io.File` 类的 `File(String)` 构造函数是危险的
- 第一个参数（位置0）如果来自用户输入，可能造成路径遍历攻击
- 漏洞类型标记为 "path-traversal"

## 2. `sinks-pack/queries/sinks.ql` - 查询文件

**作用：定义 "如何检测这些危险API的使用"**


### 通俗理解
这是 **"检测规则说明书"**，告诉CodeQL具体怎么在代码中找出这些危险API的滥用。

### 具体检测逻辑
```codeql
// 找到所有ApiSink（危险API调用）
from ApiSink sink
// 检查参数是不是非常量（可能来自用户输入）
where sink.hasNonConstantArgumentOrReceiverBoolean()
// 生成报告
select sink.getLocation(), sink.getSinkType()
```

**这个文件告诉CodeQL：**
- 找到代码中所有标记为危险的API调用
- 检查它们的参数是不是固定的常量值
- 如果不是常量，就报告为潜在漏洞

## 两者配合工作流程

### 步骤1：模型文件定义危险
```
模型文件说：new File(userInput) 是危险的
              ↑
          路径遍历漏洞
```

### 步骤2：查询文件执行检测
```
查询文件扫描代码：
找到：File file = new File(userInput);
检查：userInput 是不是常量？ → 不是！
报告：发现路径遍历漏洞！
```

## 实际检测示例

假设代码：
```java
String filename = request.getParameter("file");  // 用户输入
File f = new File(filename);  // 危险调用
```

**CodeQL分析过程：**
1. **模型文件**：知道 `new File(String)` 是危险API
2. **查询文件**：找到这个调用，检查 `filename` 不是常量
3. **结果**：报告"路径遍历漏洞风险"

## 总结比喻

- **模型文件** ≈ **通缉犯名单**（列出哪些API是"危险分子"）
- **查询文件** ≈ **警察巡逻手册**（告诉警察如何识别和抓捕这些危险分子）

这两个文件一起构成了CodeQL安全分析的核心能力，让系统能够自动发现代码中的安全漏洞。