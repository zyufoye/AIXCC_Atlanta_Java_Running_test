# AIXCC_Atlanta_Java_Running_test

Aixcc Atlanta战队的Java漏洞挖掘智能体代码复现。

## 1.1 项目结构
CRS-java 是一个以漏洞利用点为中心的 Java 漏洞检测框架。它的构建基于这样的理解：Java CPV 的发现本质上是一个漏洞利用任务。具体来说，它可以被分解为两个子任务：到达漏洞利用点和利用漏洞利用点。每个子任务都面临着各自的挑战。

首先，它利用我们构建的几种Fuzzers 进行集成模糊测试，以在目标 CP（挑战项目）中查找 CPV，然后利用 LLM、静态分析和运行时信息进行以汇聚点为中心的分析，通过向模糊器生成输入块来增强 CPV 的查找。

在 CRS-Java 中，我们拥有一些技术来辅助漏洞的探索和利用。一些代码位置被识别为漏洞，而那些到达漏洞种子（我们称之为 beep 种子）的代码将被提升到特定的利用阶段，以便进一步构建 PoC。此外，CRS-Java 中的所有组件都了解漏洞的运行时状态，这有助于它们避免对已到达/已利用的漏洞重复工作，并优先处理与 diff-task/sarif-task 相关的漏洞等等。

Sinkpoint exploration techniques:

- directed Jazzer
- libafl-based Jazzer
- llm-poc-gen, a Joern-based, path-based, LLM-based, input generator
- concolic executor
- deepgen, initial corpus generation agent
- dictgen, dictionary generator
- fuzzing ensembler

Sinkpoint exploitation techniques:

- expkit, an LLM-based beep seed exploitation agent
- llm-poc-gen, a Joern-based, path-based, LLM-based, input generator
- concolic executor

## 1.2 代码结构

CRS Component Source Code

- [javacrs_modules](./javacrs_modules)
  - CRS manager layer, gluing all CRS components, managing corpus, crashes, sinkpoints, callgraphs, CP metadata info, etc
- [fuzzers](./fuzzers)
  - jazzer, atl-jazzer, atl-directed-jazzer, atl-libafl-jazzer
- [llm-poc-gen](./llm-poc-gen)
  - Joern-based, path-based, LLM-based, sinkpoint-centered fuzzing input generator
- [static-analysis](./static-analysis)
  - bytecode analyzer for locating & filtering sinkpoints, generating and scheduling direct fuzzer targets
- [codeql](./codeql)
  - adding additional sinkpoints to crs
- [concolic](./concolic)
  - concolic executor
- [expkit](./expkit)
  - beep seed exploitation tool
- [deepgen](./deepgen)
  - fuzzing mutator generation agent (only for initial corpus generation)
- [dictgen](./dictgen)
  - harness dictionary generator
- [jazzer-llm-augmented](./jazzer-llm-augmented)
  - LLM-based coverage enhancer, disabled in competition



