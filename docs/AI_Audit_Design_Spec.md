# AI Audit Engine — 设计需求说明书

**文档版本：** v1.0  
**状态：** 草稿  
**适用项目：** CodeAudit — 多智能体 Golang 安全审计系统  

---

## 目录

1. [背景与目标](#1-背景与目标)  
2. [系统总体架构](#2-系统总体架构)  
3. [模块详细设计](#3-模块详细设计)  
   - 3.1 [Planner — 规划器](#31-planner--规划器)  
   - 3.2 [Multi-Scanner — 多扫描器层](#32-multi-scanner--多扫描器层)  
   - 3.3 [Deduplication — 去重合并层](#33-deduplication--去重合并层)  
   - 3.4 [Multi-Stage Validator — 多阶段验证器](#34-multi-stage-validator--多阶段验证器)  
   - 3.5 [Enhancer — 增强器](#35-enhancer--增强器)  
   - 3.6 [Knowledge Base — 知识库](#36-knowledge-base--知识库)  
   - 3.7 [Benchmarking System — 基准评测系统](#37-benchmarking-system--基准评测系统)  
   - 3.8 [Expert Review — 专家复核](#38-expert-review--专家复核)  
   - 3.9 [Feedback Loop — 反馈闭环](#39-feedback-loop--反馈闭环)  
4. [数据流与接口设计](#4-数据流与接口设计)  
5. [核心数据模型](#5-核心数据模型)  
6. [非功能性需求](#6-非功能性需求)  
7. [实现路线图](#7-实现路线图)  

---

## 1. 背景与目标

### 1.1 背景

传统代码安全审计依赖以下方式，各有局限：

| 方式 | 优点 | 局限 |
|------|------|------|
| 人工审计 | 理解业务语义 | 成本高、覆盖率低、难规模化 |
| 静态分析工具（SAST） | 快速、可自动化 | 误报率高、不理解业务逻辑、规则僵化 |
| 单一 LLM 调用 | 理解上下文 | 上下文窗口有限、幻觉、无系统验证 |

本系统通过**多扫描器并行 + 多阶段验证 + 知识库反馈**的闭环架构，将三种方式的优势融合，构建一套可持续改进的 AI 驱动安全审计引擎。

### 1.2 设计目标

| 目标 | 量化指标 |
|------|----------|
| **高覆盖率** | 已知漏洞类型覆盖率 ≥ 90% |
| **低误报率** | 经验证后误报率 ≤ 15% |
| **高精准度** | 严重级别判断误差 ≤ 1 级（Critical/High/Medium/Low）|
| **可扩展性** | 新增领域知识无需修改核心代码（Skill YAML 驱动） |
| **自我改进** | 每次专家复核后，同类漏洞检出率提升 ≥ 5% |
| **审计效率** | 10 万行代码全量扫描 ≤ 5 分钟（静态模式） |

### 1.3 核心设计原则

```
原则一：结果由多个独立扫描器共同产生，不依赖单一信号
原则二：每个 Finding 必须经过多阶段验证才能进入最终报告
原则三：知识库是系统的"记忆"，所有发现都回流至知识库
原则四：评测系统驱动迭代，所有改进必须有数据支撑
原则五：专家经验可编码为 Skill，实现知识的可复用转移
```

---

## 2. 系统总体架构

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Multi-Scanner AI Engine                             │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                           Planner                                    │  │
│  │   分析目标 → 选择扫描策略 → 分配 Scanner → 控制并发与超时            │  │
│  └──────────────────────────┬───────────────────────────────────────────┘  │
│                             │ ScanPlan                                      │
│  ┌──────────────────────────▼───────────────────────────────────────────┐  │
│  │                         Multi-Scanner                                 │  │
│  │                                                                       │  │
│  │  ┌──────────────────┐  ┌──────────────────┐  ┌───────────────────┐  │  │
│  │  │ Multi-Agent      │  │ Invariant        │  │ Project Type      │  │  │
│  │  │ Scanner          │  │ Scanner          │  │ Scanner           │  │  │
│  │  │ (7 专项 Agent)   │  │ (不变量约束检查)  │  │ (框架/协议识别)   │  │  │
│  │  └──────────────────┘  └──────────────────┘  └───────────────────┘  │  │
│  │  ┌──────────────────┐  ┌──────────────────┐                          │  │
│  │  │ LLM Scanner      │  │ RAG Scanner      │  │  ...                  │  │
│  │  │ (AI 语义分析)    │  │ (相似漏洞检索)   │                          │  │
│  │  └──────────────────┘  └──────────────────┘                          │  │
│  └──────────────────────────┬───────────────────────────────────────────┘  │
│                             │ RawFindings[]                                 │
│  ┌──────────────────────────▼───────────────────────────────────────────┐  │
│  │                       Deduplication                                   │  │
│  │   基于 File+Line+RuleID 去重 → 相似度合并 → 置信度加权               │  │
│  └──────────────────────────┬───────────────────────────────────────────┘  │
│                             │ DedupedFindings[]                             │
│  ┌──────────────────────────▼───────────────────────────────────────────┐  │
│  │                    Multi-Stage Validator                               │  │
│  │                                                                       │  │
│  │  ① Invalid Rules Check  →  ② Main Validation  →  ③ Missing Check    │  │
│  │                                        ↓                              │  │
│  │                          ④ Intended Design Check                      │  │
│  └──────────────────────────┬───────────────────────────────────────────┘  │
│                             │ ValidatedFindings[]                           │
│  ┌──────────────────────────▼───────────────────────────────────────────┐  │
│  │                         Enhancer                                      │  │
│  │   补充 PoC → 生成修复建议 → 关联 CVE/CWE → 评估业务影响              │  │
│  └──────────────────────────┬───────────────────────────────────────────┘  │
│                             │ EnrichedFindings[]                            │
│  ┌──────────────────────────▼───────────────────────────────────────────┐  │
│  │                      Preliminary Result                               │  │
│  │   生成 Text/JSON/Markdown/SARIF 报告 → 回流 Knowledge Base           │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
         │ Feeds                                    │ Evals
         ▼                                          ▼
┌──────────────────────┐              ┌──────────────────────────────────┐
│    Knowledge Base    │◄─ Improves ──│      Benchmarking System         │
│                      │              │                                  │
│ • Vulnerabilities    │              │ • Coverage Rate  • Hit Rate      │
│ • Exploit Patterns   │              │ • Precision/Recall               │
│ • Audit Findings     │◄─ Improves ──│ • Severity Distance              │
│ • Checklists         │              │ • Consistency    • Cost          │
│ • RAG Database       │              └──────────────┬───────────────────┘
└──────────────────────┘                             │ Improves
                                          ┌──────────▼──────────┐
                                          │    Expert Review     │
                                          │                      │
                                          │ 专家标注 → 反馈规则  │
                                          │ 错误纠正 → 新技术    │
                                          └─────────────────────┘
```

---

## 3. 模块详细设计

### 3.1 Planner — 规划器

#### 职责

Planner 是整个引擎的**入口决策节点**。它读取审计目标的元信息，生成一份 `ScanPlan`，决定哪些 Scanner 以什么参数运行。

#### 功能需求

| 编号 | 需求 | 优先级 |
|------|------|--------|
| P-01 | 扫描目标路径静态分析：识别 Go module、框架依赖（gin/grpc/echo 等）、是否有 Dockerfile/Helm chart | P0 |
| P-02 | 根据 `go.mod` 依赖图自动推断启用的框架 Agent 和 Domain | P0 |
| P-03 | 根据目标代码规模（文件数/行数）自适应分配并发 Worker 数 | P1 |
| P-04 | 支持"快速模式"（仅静态规则）和"深度模式"（静态 + LLM + RAG）的策略切换 | P0 |
| P-05 | 生成 ScanPlan 并记录到审计日志，支持复现和调试 | P1 |
| P-06 | 支持扫描范围限定：指定文件列表、diff 模式（仅扫描 PR 变更文件） | P1 |

#### 输入 / 输出

```
输入：AuditTarget { Path, Frameworks, Domains, SkipPaths, Mode }
输出：ScanPlan {
    Scanners: [ScannerConfig]       // 每个 Scanner 的启用配置
    AgentSet: [AgentID]             // 选中的 Agent 列表
    Skills: [SkillID]               // 注入的 Skill 列表
    Concurrency: int                // 并发数
    TimeoutPerScanner: duration     // 每个 Scanner 超时
    Mode: "fast" | "deep"           // 扫描模式
}
```

#### 框架识别逻辑（示例）

```
go.mod 包含 gin-gonic/gin          → 启用 FrameworkAgent(gin) + gin_security.yaml
go.mod 包含 google.golang.org/grpc → 启用 FrameworkAgent(grpc) + grpc_security.yaml
项目根有 Dockerfile                 → 启用 ContainerAgent + container_security.yaml
go.mod 包含 certificate-transparency-go → 启用 CTProtocolAgent + ct_protocol.yaml
```

---

### 3.2 Multi-Scanner — 多扫描器层

多扫描器是系统的**核心并行执行层**，多个 Scanner 独立运行、互不依赖，最终汇总结果。

#### 3.2.1 Multi-Agent Scanner（多智能体扫描器）

每个 Agent 代表一个**领域安全专家**，内置该领域的静态规则，并可被注入 Skill 文件。

| Agent ID | 领域 | 核心检测项 |
|----------|------|----------|
| `golang-general` | 通用 Golang | SQL 注入、命令注入、SSRF、路径穿越、硬编码密钥、不安全 TLS |
| `golang-crypto` | 密码学 | ECB 模式、静态 IV、CBC Padding Oracle、JWT 漏洞、弱随机数、时序攻击 |
| `golang-framework` | Web 框架 | Gin/Echo/Fiber/gRPC CORS、缺少认证中间件、调试端点暴露 |
| `golang-container` | 容器/K8s | 特权容器、宿主机命名空间、K8s RBAC 通配符、ServiceAccount 令牌 |
| `golang-ct-protocol` | CT 协议 | SCT 伪造、Merkle Tree 攻击、STH 验证缺失、RFC 6962 合规性 |
| `golang-concurrency` | 并发安全 | 数据竞争、Mutex 复制、Goroutine 泄漏、Channel 死锁 |
| `golang-business` | 业务逻辑 | IDOR/BOLA、支付竞态、MFA 绕过（**纯 Skill 驱动**） |

**功能需求：**

| 编号 | 需求 | 优先级 |
|------|------|--------|
| MA-01 | 每个 Agent 实现 `Analyze(ctx, target) AgentResult` 接口，保证独立可替换 | P0 |
| MA-02 | Agent 注册采用 `init()` 自动注册机制，新增 Agent 无需修改 Orchestrator | P0 |
| MA-03 | Skill 注入在 Agent 运行前完成，Agent 通过 `GetSkillPatterns()` / `GetSkillPrompts()` 获取注入的知识 | P0 |
| MA-04 | 每个 Agent 运行结果包含置信度分数（0.0–1.0），用于下游验证 | P1 |
| MA-05 | Agent 运行超时后返回已有结果（不阻塞整体流程） | P0 |

#### 3.2.2 Invariant Scanner（不变量检查扫描器）

检查代码中**应当始终成立的安全不变量**是否被违反。

| 编号 | 不变量规则 | 级别 |
|------|----------|------|
| INV-01 | 所有数据库操作必须使用参数化查询，不得存在字符串拼接 SQL | CRITICAL |
| INV-02 | 所有外部 HTTP 请求必须验证 TLS 证书 | HIGH |
| INV-03 | 所有密码存储必须使用 bcrypt/argon2 等自适应哈希函数 | CRITICAL |
| INV-04 | 所有 gRPC Server 启动时必须配置 credentials | HIGH |
| INV-05 | 所有对外 HTTP Handler 必须有 panic Recovery 中间件 | HIGH |
| INV-06 | 所有加密操作的 IV/Nonce 必须由 `crypto/rand` 生成 | CRITICAL |
| INV-07 | 所有 Context 的 cancel 函数必须被调用 | MEDIUM |

**实现方式：**

```
定义不变量规则集 → 针对全量 AST 图做符号执行验证 → 报告违反的不变量
```

**功能需求：**

| 编号 | 需求 | 优先级 |
|------|------|--------|
| INV-REQ-01 | 不变量规则集以 YAML 格式定义，支持热加载 | P0 |
| INV-REQ-02 | 支持跨文件不变量（如某函数调用链上必须经过某安全函数） | P1 |
| INV-REQ-03 | 违反不变量的 Finding 标记为 `source: invariant`，Validator 阶段给予更高信任权重 | P1 |

#### 3.2.3 Project Type Scanner（项目类型感知扫描器）

根据识别出的项目类型，加载对应的**专项检查清单**。

| 项目类型 | 识别特征 | 专项检查清单 |
|---------|---------|------------|
| Web API Server | `gin/echo/fiber` 依赖，`http.ListenAndServe` | API 安全 10 项清单（认证、限流、输入验证…） |
| gRPC 微服务 | `google.golang.org/grpc` | gRPC 安全 8 项清单 |
| CT Log Server | `certificate-transparency-go` | RFC 6962 合规 15 项清单 |
| K8s Operator | `controller-runtime`, `client-go` | K8s RBAC + Pod Security 12 项清单 |
| 支付系统 | 关键字：`payment`, `charge`, `refund` | PCI-DSS 相关 10 项清单 |
| CLI 工具 | `cobra`, `os.Args` 主要入口 | 本地权限、配置文件权限检查 |

**功能需求：**

| 编号 | 需求 | 优先级 |
|------|------|--------|
| PT-01 | 项目类型识别结果记录在 ScanPlan 中，影响后续所有 Scanner 的策略 | P0 |
| PT-02 | 支持多类型叠加（如一个项目既是 gRPC 服务又使用 K8s client-go） | P0 |
| PT-03 | 检查清单以 YAML Skill 文件定义，由 ProjectTypeScanner 自动加载对应文件 | P0 |

#### 3.2.4 LLM Scanner（大语言模型扫描器）

对**静态规则无法覆盖**的场景进行 AI 语义分析：跨文件数据流、业务逻辑漏洞、新型攻击模式。

**功能需求：**

| 编号 | 需求 | 优先级 |
|------|------|--------|
| LLM-01 | 支持 OpenAI、Azure OpenAI、Anthropic、本地 Ollama 等多 Provider，通过配置切换 | P0 |
| LLM-02 | 每个文件发送前先做"是否值得 LLM 分析"的预过滤（基于文件导入、复杂度评分），避免无效 API 调用 | P0 |
| LLM-03 | Prompt 模板从 Skill 文件加载，不硬编码在代码中，支持按 Domain 覆盖 | P0 |
| LLM-04 | LLM 响应结果使用结构化解析（FINDING/SEVERITY/LINE/DESCRIPTION/SUGGESTION 格式）| P0 |
| LLM-05 | Token 使用量记录到 metrics，用于 Benchmarking 的 Cost 指标 | P1 |
| LLM-06 | 单文件 LLM 调用支持重试（最多 2 次），失败后静默跳过不影响全局 | P0 |
| LLM-07 | 支持"批量文件"模式：将多个小文件合并为一次调用，降低延迟和成本 | P2 |

#### 3.2.5 RAG Scanner（检索增强生成扫描器）

利用**向量数据库**对历史漏洞和审计发现做相似性检索，找出与当前代码最相似的历史漏洞。

```
流程：
代码片段 → Embedding 向量化 → 向量数据库检索 → 返回 Top-K 相似漏洞
→ 将相似漏洞案例注入 LLM Prompt → 获得更精准的分析
```

**功能需求：**

| 编号 | 需求 | 优先级 |
|------|------|--------|
| RAG-01 | 向量数据库支持：pgvector、Chroma、Qdrant，通过接口抽象切换 | P1 |
| RAG-02 | 知识库中每次新增的 Audit Finding 自动向量化入库 | P1 |
| RAG-03 | 检索结果包含相似度分数，低于阈值（0.75）的结果不注入 Prompt | P1 |
| RAG-04 | RAG 检索结果作为独立 Source 的 Finding（置信度较低，需 Validator 验证）| P2 |

---

### 3.3 Deduplication — 去重合并层

多个 Scanner 可能对同一漏洞产生多个 Finding，去重合并层负责将它们归并。

#### 去重策略（三级）

```
Level 1 — 精确去重：
  Key = FilePath + Line + RuleID
  → 完全相同的 Finding 只保留置信度最高的一个

Level 2 — 模糊去重：
  Key = FilePath + (Line ± 3) + 相似 Title（Jaccard 相似度 > 0.85）
  → 合并为一个 Finding，置信度取最高值，Sources 字段记录所有来源 Scanner

Level 3 — 语义去重（可选，需 LLM）：
  两个 Finding 描述的是同一个根因但在不同代码位置体现
  → 合并为一个 Finding，附带完整的相关位置列表
```

#### 置信度加权

```
当同一 Finding 被多个 Scanner 检出时，置信度提升：

confidence_final = 1 - ∏(1 - confidence_i)

例：静态规则(0.85) + LLM(0.70) → 1 - (1-0.85)×(1-0.70) = 0.955
```

**功能需求：**

| 编号 | 需求 | 优先级 |
|------|------|--------|
| DEDUP-01 | Level 1 精确去重在 O(n) 时间内完成 | P0 |
| DEDUP-02 | 合并后的 Finding 保留所有原始 Source 信息（`sources: [scanner1, scanner2]`）| P0 |
| DEDUP-03 | 去重后的 Finding 按置信度降序排列，高置信度优先进入 Validator | P0 |
| DEDUP-04 | 去重统计（原始总数 vs 去重后数量）记录到审计日志 | P1 |

---

### 3.4 Multi-Stage Validator — 多阶段验证器

**这是系统降低误报率的核心模块**。每个 Finding 必须通过 4 个验证阶段才能进入最终报告。

```
DedupedFindings[]
        │
        ▼
┌───────────────────┐
│ ① Invalid Rules   │  快速过滤明确误报
│    Check          │  (规则语法检查、测试文件排除、注释排除)
└────────┬──────────┘
         │ 通过
         ▼
┌───────────────────┐
│ ② Main Validation │  主验证：确认漏洞确实存在
│                   │  (上下文验证、数据流验证、LLM 二次确认)
└────────┬──────────┘
         │ 通过
         ▼
┌───────────────────┐
│ ③ Missing Check   │  遗漏检查：发现扫描器可能遗漏的漏洞
│                   │  (检查清单对比、同类漏洞举一反三)
└────────┬──────────┘
         │ 通过
         ▼
┌───────────────────┐
│ ④ Intended Design │  意图设计检查：区分漏洞与刻意设计
│    Check          │  (测试代码、示例代码、已知豁免项)
└────────┬──────────┘
         │
         ▼
   ValidatedFindings[]
```

#### 3.4.1 Invalid Rules Check（无效规则检查）

目标：快速过滤**明确不是漏洞**的误报，减少后续阶段负担。

| 检查项 | 过滤条件 | 处理方式 |
|--------|---------|---------|
| 测试文件排除 | 文件路径包含 `_test.go` | 降低 1 个严重级别或标记 `suppressed` |
| 注释代码排除 | 匹配行在 `// nolint` 或 `//nolint:xxx` 注释中 | 标记 `suppressed`，记录豁免原因 |
| 示例代码排除 | 文件路径包含 `example`, `demo`, `sample` | 降低严重级别 |
| 规则语法验证 | 正则表达式规则格式校验 | 规则无效则跳过并告警 |
| 最小置信度过滤 | `confidence < 0.3` | 直接丢弃 |

#### 3.4.2 Main Validation（主验证）

目标：对留下的 Finding 进行**深度上下文验证**，确认漏洞确实可触达。

```
验证维度：

A. 上下文验证（静态）
   - 函数参数是否确实可能来自外部输入？
   - 是否已存在针对该问题的防护代码（如 html.EscapeString、validator.Validate）？
   - 漏洞代码是否在程序的可达路径上？

B. 数据流验证（轻量污点分析）
   - 追踪 Source（用户输入）→ Sink（危险函数）的数据流
   - 中间是否经过 Sanitizer？

C. LLM 二次确认
   - 将 Finding 连同上下文代码发给 LLM
   - Prompt：
     "以下是一个潜在的安全漏洞发现。请判断：
      1. 该漏洞是否真实存在？（True Positive / False Positive）
      2. 如果是 False Positive，原因是什么？
      3. 如果是 True Positive，实际可利用性如何？（Exploitable/Theoretical）"
   - LLM 返回 VALID/INVALID + 理由
```

**功能需求：**

| 编号 | 需求 | 优先级 |
|------|------|--------|
| VAL-01 | 主验证结果为 VALID 的 Finding 的 `validation_status` 字段设为 `confirmed` | P0 |
| VAL-02 | 主验证结果为 INVALID 的 Finding 不进入最终报告，但保留在 `suppressed_findings` 中供审计 | P0 |
| VAL-03 | 数据流追踪支持 3 层以内的函数调用链（超过则降级为上下文验证）| P1 |
| VAL-04 | LLM 验证调用的 Prompt 模板可配置，支持针对不同 Domain 使用不同验证策略 | P1 |

#### 3.4.3 Missing Check（遗漏检查）

目标：**举一反三**，发现扫描器可能遗漏的同类或相关漏洞。

```
策略：
1. 如果发现了一处 SQL 注入，检查同一文件/包中其他数据库调用是否也存在注入
2. 对比项目类型对应的"安全检查清单"，标记清单中尚未被任何 Scanner 覆盖的检查项
3. 对发现了漏洞的函数，检查其所有调用方（call sites）是否也有类似问题

输出：
- 新增 Finding（标记 source: "missing_check"，置信度默认 0.6，需人工确认）
- 检查清单覆盖率报告（已检查项 / 总项 = Coverage Rate）
```

**功能需求：**

| 编号 | 需求 | 优先级 |
|------|------|--------|
| MISS-01 | 检查清单与 Skill 文件中的 `checklist` 字段对应，支持扩展 | P1 |
| MISS-02 | Missing Check 新增的 Finding 在报告中单独标注，避免与主扫描结果混淆 | P0 |
| MISS-03 | 覆盖率报告（已覆盖检查项 / 检查清单总项）输出到 Summary | P1 |

#### 3.4.4 Intended Design Check（意图设计检查）

目标：过滤**开发者刻意为之**的"漏洞"，避免对合理设计的误报。

```
检查来源（优先级从高到低）：
1. .codeaudit-suppress.yaml 文件（项目级豁免）
2. 代码注释中的 // codeaudit:suppress <rule-id> <reason>
3. 知识库中已有"该项目/该文件对此规则豁免"的历史记录
4. LLM 判断：该代码是否是已知的安全最佳实践实现
   （如：刻意使用 InsecureSkipVerify 进行内网 mTLS 旁路测试）
```

豁免文件格式示例：

```yaml
# .codeaudit-suppress.yaml
suppressions:
  - rule_id: go-tls-insecure
    file: internal/testutil/mock_server.go
    reason: "Test-only mock server, never used in production"
    expiry: "2026-12-31"
    approved_by: "security-team"

  - rule_id: crypto-x509-skip-verify
    file: cmd/healthcheck/main.go
    reason: "Internal health check tool on isolated network"
    approved_by: "infra-security"
```

---

### 3.5 Enhancer — 增强器

对通过验证的 Finding 进行**信息富化**，提升报告的可操作性。

#### 增强内容

| 增强项 | 描述 | 数据来源 |
|--------|------|---------|
| PoC 生成 | 生成演示该漏洞可利用性的代码片段 | LLM + 知识库 |
| 修复建议 | 生成具体的修复代码（diff 格式） | LLM + Skill 文件 |
| CVE/CWE 关联 | 匹配相关 CVE 编号和 CWE 分类 | 知识库 + NVD API |
| 业务影响评估 | 根据代码位置和数据敏感性评估实际业务风险 | LLM + 项目上下文 |
| CVSS 评分 | 自动计算 CVSS 3.1 分数 | 基于 Severity + 可利用性 + 影响范围 |
| 相关 Finding 关联 | 将有共同根因的 Finding 分组 | Deduplication 层的 Source 信息 |

**功能需求：**

| 编号 | 需求 | 优先级 |
|------|------|--------|
| ENH-01 | PoC 生成仅对 CRITICAL/HIGH 级别 Finding 执行，避免 API 成本浪费 | P0 |
| ENH-02 | 修复建议以 Unified Diff 格式呈现，便于直接 apply | P1 |
| ENH-03 | CVSS 评分在 JSON 和 SARIF 报告中输出 | P1 |
| ENH-04 | 业务影响评估需要项目上下文（通过 Project Type Scanner 识别的类型）| P1 |
| ENH-05 | 所有增强内容可单独关闭（`--no-enhance`），保证基础扫描性能不受影响 | P0 |

---

### 3.6 Knowledge Base — 知识库

知识库是系统的**长期记忆**，驱动 RAG Scanner 和持续改进。

#### 数据类型

```
┌──────────────────────────────────────────────────────────┐
│                      Knowledge Base                      │
│                                                          │
│  Vulnerabilities        Exploit Patterns                 │
│  ─────────────────────  ────────────────────────────     │
│  CVE 数据库             已知利用链（exploit chain）       │
│  CWE 分类树             PoC 代码库                       │
│  CVSS 评分              绕过已知防护的技巧               │
│                                                          │
│  Audit Findings         Checklists                       │
│  ─────────────────────  ────────────────────────────     │
│  历史审计发现            框架安全检查清单                 │
│  标注后的 TP/FP         协议安全检查清单                 │
│  修复前/后代码对         合规要求映射                    │
│                                                          │
│  RAG Database                                            │
│  ─────────────────────                                   │
│  代码片段向量索引                                        │
│  相似漏洞聚类                                            │
│  Skill 文件版本历史                                      │
└──────────────────────────────────────────────────────────┘
```

**功能需求：**

| 编号 | 需求 | 优先级 |
|------|------|--------|
| KB-01 | 每次审计结束后，所有 ValidatedFindings 自动入库（含 TP/FP 标注） | P0 |
| KB-02 | 知识库提供 REST API，供 RAG Scanner 实时查询 | P1 |
| KB-03 | CVE 数据每日从 NVD 同步（Go 相关 CVE 优先） | P1 |
| KB-04 | 历史 Finding 支持"已修复"状态标记，避免在同项目重复报告已修复的漏洞 | P1 |
| KB-05 | 知识库数据导出为 Skill YAML，实现知识的可移植性 | P2 |
| KB-06 | 支持多租户隔离：各项目的私有 Finding 不跨项目共享（除非显式授权） | P1 |

---

### 3.7 Benchmarking System — 基准评测系统

基准评测系统是**质量保证**的核心，所有系统改进必须通过评测数据验证效果。

#### 评测指标体系

| 指标 | 定义 | 计算公式 | 目标值 |
|------|------|---------|--------|
| **Coverage Rate** | 已知漏洞集合中被检出的比例 | TP / (TP + FN) | ≥ 90% |
| **Hit Rate** | 单次扫描命中至少 1 个真实漏洞的概率 | 命中扫描次数 / 总扫描次数 | ≥ 80% |
| **Precision** | 报告的 Finding 中真实漏洞的比例 | TP / (TP + FP) | ≥ 85% |
| **Recall** | 真实漏洞被发现的比例 | TP / (TP + FN) | ≥ 88% |
| **Severity Distance** | 预测严重级别与真实级别的平均偏差 | avg(|pred - true|) | ≤ 0.5 级 |
| **Consistency** | 相同代码多次扫描结果的一致性 | 结果相同比例 | ≥ 95% |
| **Cost** | 每次扫描的 API 费用（美元） | Σ(tokens × price) | ≤ $0.5/次 |

#### 基准测试数据集

```
数据集构成：
├── benchmark/
│   ├── known_vulns/          # 已知漏洞的 Go 代码样本（带 Ground Truth 标注）
│   │   ├── sql_injection/    # SQL 注入样本（含 TP 标注）
│   │   ├── crypto_misuse/    # 密码学误用样本
│   │   ├── ct_protocol/      # CT 协议漏洞样本
│   │   └── container/        # 容器安全样本
│   ├── false_positives/      # 曾经被误报的代码（应返回 0 个 Finding）
│   └── regression/           # 历史 Bug 样本（确保修复后不回归）
```

**功能需求：**

| 编号 | 需求 | 优先级 |
|------|------|--------|
| BENCH-01 | 每次 Skill 文件更新后自动触发基准测试，生成评测报告 | P0 |
| BENCH-02 | 评测报告对比"本次"和"上次"各项指标，高亮回归项 | P0 |
| BENCH-03 | 基准测试数据集与代码同仓库管理，可版本追溯 | P0 |
| BENCH-04 | Cost 指标监控报警：单次扫描超过阈值时发出告警 | P1 |
| BENCH-05 | 支持"按 Agent 维度"的细粒度评测，定位表现差的 Agent | P1 |

---

### 3.8 Expert Review — 专家复核

专家复核是**知识注入系统**的人工入口，将安全专家的经验转化为可量化的改进。

#### 工作流

```
系统输出 Preliminary Result
        │
        ▼
专家复核界面（Web UI / CLI）
        │
   ┌────┴───────────────────────────────────────────┐
   │  对每个 Finding 进行标注：                      │
   │  ✅ True Positive  — 确认是漏洞                │
   │  ❌ False Positive — 误报，附注原因             │
   │  ⬆️ Escalate       — 升级严重级别               │
   │  ⬇️ Downgrade      — 降级严重级别               │
   │  ➕ Missing        — 标注漏掉的漏洞             │
   └────┬───────────────────────────────────────────┘
        │ 标注结果
        ▼
   回流至知识库（自动更新 Skill 规则权重）
        │
        ▼
   触发 Benchmarking 重新评测
        │
        ▼
   评测通过 → 发布新版 Skill 文件
```

**功能需求：**

| 编号 | 需求 | 优先级 |
|------|------|--------|
| EXP-01 | 专家标注界面支持 CLI 和 Web UI 两种形式 | P1 |
| EXP-02 | False Positive 标注后，系统自动分析该规则的 FP 率，超过阈值（30%）则建议修订规则 | P1 |
| EXP-03 | 专家"补充遗漏漏洞"操作，自动生成对应的 Skill Pattern 草稿供确认后合并 | P2 |
| EXP-04 | 专家标注支持"适用范围"：全局规则 / 特定项目类型 / 特定框架 | P1 |
| EXP-05 | 每位专家的历史标注记录存档，支持标注一致性分析（多专家对同一 Finding 的分歧）| P2 |

---

### 3.9 Feedback Loop — 反馈闭环

反馈闭环将右侧的**知识库 → 评测 → 专家复核**形成一个持续改进的闭环。

```
触发时机：
  1. 每次审计结束 → Finding 入库 → 自动触发增量评测
  2. 专家标注完成 → 规则权重更新 → 触发全量基准测试
  3. 每周定时 → 全量基准测试 → 生成趋势报告
  4. 新 Skill 文件提交 → CI 触发基准测试 → 通过后合并

改进机制：
  - 高 FP 率的规则 → 自动降低其置信度系数，Validator 阶段更严格验证
  - 多次遗漏的漏洞类型 → 自动生成新 Skill Pattern 草稿，推送给专家审核
  - 评测分数提升 → 更新 Skill 文件版本号，记录改进 changelog
```

**功能需求：**

| 编号 | 需求 | 优先级 |
|------|------|--------|
| FEED-01 | 规则置信度系数根据历史 TP/FP 比率自动调整（滑动窗口 30 天）| P1 |
| FEED-02 | 系统自动检测知识库中重复出现 3 次以上的遗漏漏洞，生成 Skill 草稿 | P2 |
| FEED-03 | 每周生成趋势报告：各指标历史曲线，标注重大改进节点 | P2 |
| FEED-04 | Skill 文件变更历史通过 git 管理，每次变更有对应的评测数据证明改进 | P0 |

---

## 4. 数据流与接口设计

### 4.1 核心数据流

```
① 输入层
AuditTarget → Planner → ScanPlan

② 扫描层（并行）
ScanPlan → [MultiAgentScanner || InvariantScanner || ProjectTypeScanner || LLMScanner || RAGScanner]
        → RawFindings[]

③ 去重层
RawFindings[] → Deduplication → DedupedFindings[]

④ 验证层（串行，四阶段）
DedupedFindings[]
  → InvalidRulesCheck → (通过) → MainValidation
  → (通过) → MissingCheck → IntendedDesignCheck
  → ValidatedFindings[]

⑤ 增强层
ValidatedFindings[] → Enhancer → EnrichedFindings[]

⑥ 输出层
EnrichedFindings[] → Report(Text|JSON|Markdown|SARIF)
                  → KnowledgeBase(入库)
                  → BenchmarkingSystem(评测)
```

### 4.2 Scanner 接口定义

```go
// Scanner 是所有扫描器必须实现的接口。
type Scanner interface {
    ID() string
    Name() string
    Priority() int                    // 越小越先执行
    Scan(ctx context.Context, plan *ScanPlan) ([]*RawFinding, error)
    Supports(target *AuditTarget) bool // 是否支持当前目标类型
}

// Validator 是验证阶段各步骤的接口。
type Validator interface {
    Stage() string                    // "invalid_rules" | "main" | "missing" | "intended"
    Validate(ctx context.Context, findings []*DedupedFinding) ([]*ValidatedFinding, error)
}

// KnowledgeStore 是知识库的接口。
type KnowledgeStore interface {
    Store(finding *ValidatedFinding) error
    Search(query string, topK int) ([]*KnowledgeEntry, error)
    SearchSimilar(embedding []float32, topK int, threshold float32) ([]*KnowledgeEntry, error)
    MarkFixed(findingID string) error
}
```

### 4.3 Finding 状态机

```
RawFinding
    │
    ▼ Deduplication
DedupedFinding { confidence: float64, sources: []string }
    │
    ▼ InvalidRulesCheck
    ├── suppressed → SuppressedFinding { reason: string }
    └── passed ──►
                │
                ▼ MainValidation
                ├── INVALID → SuppressedFinding { reason: "false_positive" }
                └── VALID ──►
                            │
                            ▼ MissingCheck / IntendedDesignCheck
                            │
                            ▼
                    ValidatedFinding { validation_status: "confirmed" }
                            │
                            ▼ Enhancer
                    EnrichedFinding {
                        poc: string,
                        fix_diff: string,
                        cvss_score: float64,
                        cve_ids: []string,
                        business_impact: string
                    }
```

---

## 5. 核心数据模型

```go
// Finding 是贯穿全系统的核心数据结构。
type Finding struct {
    ID               string            // UUID
    AgentID          string            // 产生该 Finding 的 Agent/Scanner
    SkillID          string            // 触发的 Skill 规则 ID
    RuleID           string            // 具体规则 ID
    Title            string
    Description      string
    Severity         Severity          // CRITICAL|HIGH|MEDIUM|LOW|INFO
    Category         Category          // injection|crypto|protocol|...
    FilePath         string
    Line             int
    Column           int
    CodeSnippet      string
    Suggestion       string
    FixDiff          string            // Enhancer 生成
    PoC              string            // Enhancer 生成
    CVSSScore        float64           // Enhancer 生成
    CVEIDs           []string          // Enhancer 关联
    CWEIDs           []string
    References       []string
    Confidence       float64           // 0.0–1.0
    Sources          []string          // 产生该 Finding 的所有 Scanner
    ValidationStatus string            // pending|confirmed|suppressed
    SuppressReason   string
    BusinessImpact   string            // Enhancer 生成
    Metadata         map[string]string
    CreatedAt        time.Time
}

// ScanPlan 是 Planner 的输出，驱动整个扫描流程。
type ScanPlan struct {
    ID              string
    Target          AuditTarget
    Scanners        []ScannerConfig
    AgentSet        []string
    Skills          []string
    ProjectTypes    []string          // ["web-api", "grpc-service", "k8s-operator"]
    Concurrency     int
    Mode            ScanMode          // fast | deep
    TimeoutPerScan  time.Duration
    CreatedAt       time.Time
}

// BenchmarkResult 记录一次基准评测的结果。
type BenchmarkResult struct {
    RunID           string
    Timestamp       time.Time
    SkillVersion    string
    CoverageRate    float64
    HitRate         float64
    Precision       float64
    Recall          float64
    SeverityDistance float64
    Consistency     float64
    TotalCostUSD    float64
    Regressions     []string          // 本次比上次变差的项
    Improvements    []string          // 本次比上次变好的项
}
```

---

## 6. 非功能性需求

### 6.1 性能需求

| 场景 | 指标 | 备注 |
|------|------|------|
| 小型项目（≤ 5K 行） | 静态模式 ≤ 10s | 全部 7 个 Agent |
| 中型项目（5K–50K 行） | 静态模式 ≤ 60s | 8 个并发 Worker |
| 大型项目（50K–500K 行） | 静态模式 ≤ 5min | 16 个并发 Worker |
| AI 深度模式（加 LLM） | 在静态模式基础上 × 3–5 倍 | 取决于 LLM 响应速度 |
| 单文件 LLM 分析 | ≤ 10s（含 API 往返）| 需要 API Key |

### 6.2 可用性需求

| 需求 | 描述 |
|------|------|
| 离线可用 | `--no-llm` 模式下完全离线运行，不需要任何外部服务 |
| LLM 降级 | LLM 不可用时自动降级为纯静态扫描，结果标注 `ai_analysis: false` |
| 部分失败容忍 | 某个 Agent 崩溃不影响其他 Agent 的结果 |
| 确定性 | 静态规则扫描结果在相同输入下完全一致（`Consistency = 100%`）|

### 6.3 安全需求

| 需求 | 描述 |
|------|------|
| 代码不出境 | 支持配置"不向 LLM 发送代码"模式（只发送代码摘要/结构信息）|
| API Key 安全 | API Key 只通过环境变量注入，不写入配置文件 |
| 知识库访问控制 | 各项目的私有 Finding 不跨项目泄漏 |
| 审计日志 | 所有 LLM 调用记录 request/response 哈希，用于合规审计 |

### 6.4 可维护性需求

| 需求 | 描述 |
|------|------|
| 零代码扩展 | 新增检测规则只需添加 Skill YAML，不需要修改 Go 代码 |
| Agent 热插拔 | 新增 Agent 通过 `init()` 自动注册，不修改 Orchestrator |
| Skill 版本管理 | Skill 文件有版本号，Breaking Change 触发 major 版本升级 |
| 可观测性 | 每次扫描输出结构化日志（zap），集成 OpenTelemetry Trace |

---

## 7. 实现路线图

### Phase 1：核心引擎（已完成）

```
✅ Planner（基础版：依赖 go.mod 识别框架）
✅ Multi-Agent Scanner（7 个 Agent）
✅ Deduplication（Level 1 精确去重）
✅ 静态 + LLM 双模式分析
✅ Skill YAML 加载与注入
✅ Report（Text / JSON / Markdown / SARIF）
✅ CLI（scan / list 命令）
```

### Phase 2：验证与知识库（下一步）

```
⬜ Invariant Scanner
⬜ Project Type Scanner（自动识别项目类型）
⬜ Multi-Stage Validator（4 阶段验证）
⬜ Knowledge Base（SQLite + pgvector 双模式）
⬜ RAG Scanner（基于向量检索的相似漏洞发现）
⬜ 豁免文件（.codeaudit-suppress.yaml）支持
```

### Phase 3：增强与评测（中期）

```
⬜ Enhancer（PoC 生成、Diff 格式修复建议、CVSS 自动评分）
⬜ Benchmarking System（评测数据集 + 自动化评测 CI）
⬜ 轻量级数据流追踪（3 层函数调用链污点分析）
⬜ diff 扫描模式（只扫描 PR 变更文件）
```

### Phase 4：闭环与生态（长期）

```
⬜ Expert Review Web UI
⬜ Feedback Loop 自动化（规则权重自动调整）
⬜ MCP Server 模式（IDE Agent 集成）
⬜ Semgrep 规则导入（兼容现有规则库）
⬜ VS Code 插件（内联 Finding 显示）
⬜ codeaudit skill pull <registry-url>（社区 Skill 生态）
```

---

*文档维护：CodeAudit Security Team*  
*最后更新：2026-04-01*
