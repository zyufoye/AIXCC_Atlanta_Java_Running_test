`exp_task.py` 模块是 **DeepGen模块的漏洞利用任务实现**，它使用AI模型（Claude）来自动生成漏洞利用代码。

## 模块整体功能

**使用AI大语言模型自动生成针对特定漏洞的利用脚本**

## 核心组件分析

### 1. 工作进程函数 `_worker()` (第12-20行)
```python
def _worker(repo_path: str, prompt: str, model: str):
    async def _main():
        claude = ClaudeCode(Path(repo_path))
        response = await claude.async_query(prompt)
        script = await extract_script_from_response(response, model)
        return script
    return asyncio.run(_main())
```
- **多进程执行**：在独立进程中运行AI模型，避免阻塞主线程
- **Claude调用**：使用ClaudeCode工具与AI模型交互
- **脚本提取**：从AI响应中提取可执行的代码脚本

### 2. ClaudeExpAgent 代理类 (第23-40行)
```python
class ClaudeExpAgent(AgentBase):
    def __init__(self, model: str, project_bundle: Project):
        super().__init__(project_bundle)
        self.project_bundle = project_bundle
        self.model = model

    async def run(self, prompt):
        loop = asyncio.get_event_loop()
        with ProcessPoolExecutor(max_workers=1) as pool:
            script = await loop.run_in_executor(
                pool, _worker, self.project_bundle.repo_path, prompt, self.model
            )
        return script
```
- **代理模式**：封装AI模型的调用逻辑
- **异步执行**：使用进程池执行AI生成任务
- **项目上下文**：包含代码库路径等信息

### 3. ClaudeExploitScriptTask 任务类 (第43-86行)
这是主要的漏洞利用任务实现：

**初始化参数：**
- `project_bundle`：项目信息包
- `harness_name`：测试用例名称
- `harness_entrypoint_func`：入口函数
- `weighted_models`：AI模型权重配置
- `task_id`：任务标识
- `prompt_content`：给AI的提示内容

**关键方法：**
```python
def _get_prompt(self) -> str:
    """使用提供的提示内容"""
    return self.prompt_content

async def _run_impl(self) -> (str, int):
    final_result = await self.coder.run(self.prompt_content)
    token_cost = 0  # TODO: 成本计算
    return final_result, token_cost
```

### 4. DeepGenExploitScriptTask 任务类 (第89-140行)
继承自 `AnyHarnessSeedGen` 的增强版本：
- 复用父类的JVM相关功能
- 专门用于Java漏洞利用
- 保持相同的接口但使用不同的底层实现

## 工作流程

### 1. 任务创建
```
漏洞信息 + 项目上下文 → 创建ClaudeExploitScriptTask
```

### 2. AI生成过程
```
提示内容 → ClaudeExpAgent → 多进程执行 → AI模型 → 生成利用脚本
```

### 3. 结果返回
```
生成的利用脚本 + 令牌成本 → 返回给调用者
```

## 在CRS系统中的角色

这个模块是 **AI驱动的漏洞利用生成器**，在CRS系统中：

1. **自动化利用**：当发现潜在漏洞时，自动生成利用代码
2. **PoC生成**：为验证漏洞创建概念验证代码
3. **测试用例扩展**：生成新的测试输入来触发漏洞
4. **智能模糊测试**：使用AI生成的输入提高测试效率

## 实际应用场景

假设CodeQL发现了一个SQL注入漏洞：
```java
// 漏洞代码
String query = "SELECT * FROM users WHERE id = " + userInput;
statement.executeQuery(query);
```

**DeepGen会：**
1. 接收漏洞信息和代码上下文
2. 构造提示："生成一个利用这个SQL注入漏洞的Java代码"
3. AI生成利用脚本：
```java
// AI生成的利用代码
String exploit = "1 OR 1=1";
// 触发漏洞的测试代码...
```

## 设计优势

- **多进程隔离**：AI调用在独立进程中，避免阻塞CRS主系统
- **模型灵活性**：支持加权模型选择，可以配置使用不同的AI模型
- **成本控制**：预留了令牌成本计算接口
- **任务管理**：集成到CRS的任务调度系统中

这个模块代表了**AI辅助安全测试**的先进方向，将大语言模型的能力集成到自动化安全测试流程中。