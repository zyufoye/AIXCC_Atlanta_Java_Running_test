#!/usr/bin/env python3
"""
CRS Java 安全测试框架 - 模块导入初始化文件

本文件是 CRS (Challenge-Response Security) Java 安全测试平台的核心模块导入接口，
负责将所有功能模块暴露给上层调用者。这是一个基于多技术融合的Java漏洞检测框架，
集成了模糊测试、静态分析、符号执行、AI辅助等多种安全测试技术。

主要技术栈：
- 模糊测试：基于Jazzer的多引擎模糊测试
- 静态分析：CodeQL、字节码分析、污点追踪
- 符号执行：基于GraalVM的Concolic执行
- AI辅助：LLM驱动的POC生成、漏洞利用增强
- 分布式支持：种子共享、负载均衡、故障管理

架构设计：
- CP级模块：在整个挑战项目级别运行的模块
- Harness级模块：为每个测试用例运行的模块
- 协同工作：通过共享数据、任务调度、资源管理实现模块间协作
"""

# ================================
# 静态代码分析模块 (Static Analysis)
# ================================

from .codeql import CodeQL, CodeQLParams
"""
CodeQL模块：
- 功能：集成Microsoft CodeQL静态分析引擎
- 用途：进行语义分析、污点追踪、安全漏洞检测
- 特点：支持自定义查询规则，可识别复杂的安全漏洞模式
"""

# ================================
# 符号执行模块 (Symbolic Execution)  
# ================================

from .concolic import ConcolicExecutor, ConcolicExecutorParams
"""
Concolic模块：
- 功能：基于GraalVM Espresso的符号执行引擎
- 用途：路径探索、约束求解、精确的漏洞复现
- 特点：结合具体执行和符号执行，提高测试覆盖率
"""

# ================================
# 资源管理模块 (Resource Management)
# ================================

from .cpuallocator import CPUAllocator, CPUAllocatorParams
"""
CPUAllocator模块：
- 功能：CPU资源分配和负载均衡管理器
- 用途：在多模块并发执行时合理分配CPU资源
- 特点：支持动态调整、资源监控、负载预警
"""

from .crashmanager import CrashManager, CrashManagerParams
"""
CrashManager模块：
- 功能：崩溃信息收集、去重、分析管理器
- 用途：统一管理各模糊测试引擎发现的崩溃样本
- 特点：支持崩溃去重、相似性分析、自动分类
"""

# ================================
# 深度生成模块 (Deep Generation)
# ================================

from .deepgen import DeepGenModule, DeepGenParams
"""
DeepGen模块：
- 功能：基于AI的初始语料库生成工具
- 用途：为模糊测试生成高质量的初始种子文件
- 特点：使用强化学习优化种子质量，提高初始覆盖率
"""

from .dictgen import Dictgen, DictgenParams
"""
Dictgen模块：
- 功能：测试用例字典生成器
- 用途：根据目标API生成专门的输入格式字典
- 特点：支持多种输入格式、增量更新、格式验证
"""

# ================================
# 差异检测与调度模块 (Diff Analysis & Scheduling)
# ================================

from .diff_scheduler import DiffScheduler, DiffSchedulerParams
"""
DiffScheduler模块：
- 功能：差异分析和任务调度器
- 用途：对比分析不同版本间的安全差异，调度测试任务
- 特点：支持版本对比、影响分析、优先级调度
"""

# ================================
# 漏洞利用工具包 (Exploitation Toolkit)
# ================================

from .expkit import ExpKit, ExpKitParams
"""
ExpKit模块：
- 功能：基于LLM的漏洞利用辅助工具包
- 用途：分析beep种子（已到达漏洞点的测试用例），生成利用代码
- 特点：结合静态分析和AI推理，自动生成POC代码
"""

# ================================
# 模糊测试核心模块 (Fuzzing Core)
# ================================

from .jazzer import (
    AIxCCJazzer,              # AI增强的模糊测试引擎
    AIxCCJazzerParams,        
    AtlDirectedJazzer,        # 定向模糊测试引擎  
    AtlDirectedJazzerParams,
    AtlJazzer,                # 基础Jazzer模糊测试引擎
    AtlJazzerParams,
    AtlLibAFLJazzer,          # 基于LibAFL的模糊测试引擎
    AtlLibAFLJazzerParams,
    SeedMerger,               # 种子文件合并器
    SeedMergerParams,
    is_jazzer_module,         # Jazzer模块识别函数
)
"""
Jazzer系列模块是模糊测试的核心，包含多个引擎：
- AIxCCJazzer：集成AI增强功能的模糊测试引擎
- AtlJazzer：基于Jazzer的基础模糊测试引擎  
- AtlDirectedJazzer：定向模糊测试引擎，专注特定漏洞点
- AtlLibAFLJazzer：基于LibAFL的高性能模糊测试引擎
- SeedMerger：种子文件去重、合并、优化工具

设计理念：
- 多引擎协同：不同引擎针对不同类型的漏洞
- 种子共享：引擎间共享高质量测试种子
- 资源协调：统一管理CPU、内存、存储资源
"""

# ================================
# LLM增强模块 (LLM Enhancement)
# ================================

from .llmfuzzaug import LLMFuzzAugmentor, LLMFuzzAugmentorParams
"""
LLMFuzzAugmentor模块：
- 功能：基于LLM的模糊测试增强器
- 用途：分析覆盖率数据，智能生成新的测试输入
- 特点：结合程序行为和LLM推理，提高漏洞发现率
"""

from .llmpocgen import LLMPOCGenerator, LLMPOCGeneratorParams
"""
LLMPOCGenerator模块：
- 功能：基于Joern和LLM的POC生成器
- 用途：根据漏洞点信息生成具体的漏洞验证代码
- 特点：路径感知、上下文敏感、自动代码生成
"""

# ================================
# 漏洞点管理模块 (Sinkpoint Management)
# ================================

from .sariflistener import SARIFListener, SARIFListenerParams
"""
SARIFListener模块：
- 功能：SARIF格式静态分析结果监听器
- 用途：接收和处理静态分析工具的漏洞发现结果
- 特点：标准化格式支持、多工具兼容、实时监听
"""

from .seedsharer import SeedSharer, SeedSharerParams
"""
SeedSharer模块：
- 功能：测试种子文件共享器
- 用途：在分布式环境中共享高质量测试种子
- 特点：支持NFS存储、去重优化、增量同步
"""

from .sinkmanager import SinkManager, SinkManagerParams
"""
SinkManager模块：
- 功能：漏洞接收点管理器
- 用途：管理所有已识别的漏洞目标点，协调测试任务
- 特点：支持动态发现、分类管理、优先级排序
"""

from .staticanalysis import StaticAnalysis, StaticAnalysisParams
"""
StaticAnalysis模块：
- 功能：字节码级别的静态分析引擎
- 用途：分析Java字节码，识别潜在的漏洞模式
- 特点：污点追踪、控制流分析、数据流分析
"""

# ================================
# 工具模块 (Utility Modules)
# ================================

from .utils_leader import LeaderElectionManager
"""
LeaderElectionManager模块：
- 功能：领导者选举管理器
- 用途：在分布式CRS实例中选举主节点，协调全局任务
- 特点：支持Redis后端、故障转移、负载均衡
"""

# ================================
# 模块导出列表 (Module Exports)
# ================================

__all__ = [
    # ===============
    # Jazzer模块系列
    # ===============
    "is_jazzer_module",           # Jazzer模块识别函数
    
    # AI增强模糊测试
    "AIxCCJazzer",                # AI增强的Jazzer模糊测试引擎
    "AIxCCJazzerParams",          # AI增强Jazzer配置参数
    
    # 基础模糊测试引擎
    "AtlJazzer",                  # 基础Jazzer模糊测试引擎
    "AtlJazzerParams",            # 基础Jazzer配置参数
    
    # 定向模糊测试
    "AtlDirectedJazzer",          # 定向Jazzer模糊测试引擎
    "AtlDirectedJazzerParams",    # 定向Jazzer配置参数
    
    # LibAFL模糊测试引擎
    "AtlLibAFLJazzer",            # LibAFL基础Jazzer模糊测试引擎
    "AtlLibAFLJazzerParams",      # LibAFL配置参数
    
    # 种子管理工具
    "SeedMerger",                 # 种子文件合并器
    "SeedMergerParams",           # 种子合并器配置参数
    
    # ===================
    # CodeQL静态分析模块
    # ===================
    "CodeQL",                     # CodeQL静态分析引擎
    "CodeQLParams",               # CodeQL配置参数
    
    # ===============
    # LLM增强模块系列
    # ===============
    "LLMPOCGenerator",            # LLM驱动的POC生成器
    "LLMPOCGeneratorParams",      # POC生成器配置参数
    
    "LLMFuzzAugmentor",           # LLM模糊测试增强器
    "LLMFuzzAugmentorParams",     # 模糊增强器配置参数
    
    # ===================
    # 资源管理模块系列
    # ===================
    "CPUAllocator",               # CPU资源分配器
    "CPUAllocatorParams",         # CPU分配器配置参数
    
    "SeedSharer",                 # 种子文件共享器
    "SeedSharerParams",           # 种子共享器配置参数
    
    "CrashManager",               # 崩溃信息管理器
    "CrashManagerParams",         # 崩溃管理器配置参数
    
    # ===================
    # 符号执行模块系列
    # ===================
    "ConcolicExecutor",           # Concolic符号执行引擎
    "ConcolicExecutorParams",     # 符号执行器配置参数
    
    # ===============
    # 字典生成模块
    # ===============
    "Dictgen",                    # 字典生成器
    "DictgenParams",              # 字典生成器配置参数
    
    # ===================
    # 差异检测模块系列
    # ===================
    "DiffScheduler",              # 差异检测调度器
    "DiffSchedulerParams",        # 差异调度器配置参数
    
    # ===================
    # SARIF监听模块系列
    # ===================
    "SARIFListener",              # SARIF格式监听器
    "SARIFListenerParams",        # SARIF监听器配置参数
    
    # ===================
    # 漏洞点管理模块系列
    # ===================
    "SinkManager",                # 漏洞接收点管理器
    "SinkManagerParams",          # 漏洞点管理器配置参数
    
    # ===================
    # 静态分析模块系列
    # ===================
    "StaticAnalysis",             # 静态分析引擎
    "StaticAnalysisParams",       # 静态分析配置参数
    
    # ===================
    # 漏洞利用工具包
    # ===================
    "ExpKit",                     # 漏洞利用工具包
    "ExpKitParams",               # 利用工具包配置参数
    
    # ===================
    # 深度生成模块系列
    # ===================
    "DeepGenModule",              # 深度生成模块
    "DeepGenParams",              # 深度生成配置参数
    
    # ===================
    # 工具管理模块
    # ===================
    "LeaderElectionManager",      # 领导者选举管理器
]

# ================================
# 模块功能说明
# ================================

"""
模块架构设计理念：

1. **分层架构**：
   - CP级模块：为整个挑战项目服务，生命周期长
   - Harness级模块：为每个测试用例服务，生命周期短
   - 工具级模块：提供通用功能支持

2. **技术融合**：
   - 传统Fuzzing：基于Jazzer的多引擎模糊测试
   - 智能分析：AI驱动的漏洞发现和POC生成  
   - 静态分析：字节码级别安全检查
   - 符号执行：精确路径探索和约束求解

3. **协同工作**：
   - 资源共享：CPU、内存、存储资源的统一管理
   - 数据交换：测试种子、漏洞信息、覆盖率数据的共享
   - 任务调度：基于优先级和依赖关系的任务协调

4. **扩展性设计**：
   - 模块化：每个功能独立封装，便于维护和扩展
   - 配置化：支持灵活的参数配置和开关控制
   - 标准接口：统一的模块接口规范
"""
