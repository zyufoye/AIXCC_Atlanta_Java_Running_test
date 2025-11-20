`cli.py` 文件是 **DeepGen模块的命令行接口**，提供了从命令行启动和管理AI生成任务的功能。

## 核心功能

**提供DeepGen引擎的命令行启动接口，配置和执行AI驱动的代码生成任务**

## 主要组件分析

### 1. 命令行参数解析 (第95-125行)

```python
parser = argparse.ArgumentParser(
    description="DeepGen Engine CLI tool for Java language"
)

parser.add_argument("--cores", type=int, nargs="+", default=[1], 
                   help="CPU core IDs to use (default: [1])")
parser.add_argument("--models", type=str, 
                   default="claude-3-7-sonnet-20250219:1,gpt-4o:1",
                   help="Model weights: 'model1:weight1,model2:weight2,...'")
parser.add_argument("--metadata", type=str, required=True, 
                   help="Path to the CP metadata JSON file")
parser.add_argument("--workdir", type=str, required=True,
                   help="Working directory for DeepGen artifacts")
parser.add_argument("--zmq-url", type=str, default=None,
                   help="ZeroMQ URL for seed submission")
parser.add_argument("--run-time", type=int, default=300,
                   help="Time limit in seconds (default: 300)")
parser.add_argument("--para", type=int, default=1,
                   help="Parallelism factor for task execution (default: 1)")
```

**支持的参数：**
- `--cores`：指定使用的CPU核心
- `--models`：AI模型配置（模型:权重）
- `--metadata`：项目元数据文件路径（必需）
- `--workdir`：工作目录（必需）
- `--zmq-url`：ZeroMQ通信地址
- `--run-time`：运行时间限制
- `--para`：并行度

### 2. 模型权重解析器 (第25-53行)

```python
def parse_model_weights(models_str: str) -> dict:
    """解析模型:权重对"""
    weighted_models = {}
    for pair in models_str.split(","):
        model, weight_str = pair.split(":", 1)
        weight = int(weight_str)
        weighted_models[model.strip()] = weight
    return weighted_models
```

**示例配置：**
```bash
--models "claude-3-7-sonnet-20250219:1,gpt-4o:1"
# 转换为: {'claude-3-7-sonnet-20250219': 1, 'gpt-4o': 1}
```

### 3. 共享内存清理 (第55-68行)

```python
def clean_shm_files(cp_name: str):
    """清理与CP名称相关的共享内存文件"""
    cp_shm_path = Path("/dev/shm")
    for item in cp_shm_path.iterdir():
        if cp_name in item.name:
            item.unlink()  # 删除文件
```

- 清理之前运行遗留的共享内存文件
- 避免资源冲突

### 4. 主运行函数 (第70-153行)

**核心执行流程：**

```python
async def run_deepgen(cores, weighted_models, metadata_path, workdir, zmq_url, run_time, para):
    # 1. 创建工作目录
    workdir_path = Path(workdir)
    workdir_path.mkdir(parents=True, exist_ok=True)
    
    # 2. 加载元数据
    cp_metadata = CPMetadata(metadata_path)
    tasks = cp_metadata.create_harness_tasks(workdir_path, weighted_models)
    
    # 3. 配置提交器
    submit_cls = ZeroMQSubmit
    submit_kwargs = {"bind_addr": zmq_url} if zmq_url else {}
    
    # 4. 启动引擎
    async with DeepGenEngine(
        core_ids=cores,
        workdir=workdir_path,
        submit_class=submit_cls,
        submit_kwargs=submit_kwargs,
        seed_pool_size=10000,
        n_exec=500,
        task_para=para,
        shm_label=shm_label,
    ) as engine:
        
        # 5. 添加初始任务
        for task in tasks:
            await engine.add_task(task)
        
        # 6. 运行引擎（有时间限制）
        await engine.run(time_limit=run_time)
```

## 使用示例

```bash
# 基本用法
python cli.py --metadata project_meta.json --workdir ./deepgen_work

# 完整配置
python cli.py \
    --cores 1 2 3 \
    --models "claude-3-7-sonnet-20250219:2,gpt-4o:1" \
    --metadata /path/to/metadata.json \
    --workdir /tmp/deepgen_output \
    --zmq-url tcp://localhost:5555 \
    --run-time 600 \
    --para 4
```

## 在CRS系统中的角色

这个CLI工具是 **DeepGen模块的独立启动器**，支持：

### 1. 独立运行模式
- 可以不依赖CRS主系统单独运行DeepGen
- 便于测试和调试DeepGen功能

### 2. 配置管理
- 统一的命令行参数配置
- 灵活的AI模型选择
- 资源控制（CPU、内存、时间）

### 3. 系统集成
- 通过ZeroMQ与CRS其他模块通信
- 生成的结果可以被模糊测试器等模块使用

## 设计特点

- **资源隔离**：指定CPU核心，避免资源竞争
- **模型加权**：支持多个AI模型的加权选择
- **时间控制**：可配置运行时间，避免无限运行
- **错误处理**：完善的异常捕获和日志记录
- **共享内存管理**：自动清理，避免资源泄漏

这个CLI工具使得DeepGen模块既可以**集成到CRS系统中**，也可以**独立运行进行AI生成任务**，提供了很大的灵活性。