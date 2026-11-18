---
name: redteam-engagement
description: Plan and document an authorized red team engagement. Use when scoping a penetration test, checking whether a target or technique is in scope, structuring recon through reporting, or turning findings into a client-ready report with MITRE ATT&CK mapping.
---

# redteam-engagement

把授权红队评估拆成可执行、可留证、可交付的流程，并在每次动目标之前先过授权闸门。

## 何时使用

- 拿到一个新项目，需要确认范围、时间窗口、禁止手法
- 准备对某个域名 / IP / 网段执行动作，想先确认是否越界
- 需要把散落的发现整理成客户能读的报告
- 复盘一次评估：哪些阶段做了、证据是否齐、结论是否站得住

## 前置条件（缺一不可）

1. **书面授权**：合同、授权书或 SOW，能指明目标、时间、允许手法
2. **单一联系人**：出问题能立刻找到决策人
3. **停止条件**：什么情况必须停（业务中断、敏感数据、越权访问到第三方）

没有书面授权就不进入执行阶段，只做方案设计。

## 流程

完整说明见 [references/phases.md](../../references/phases.md)，七个阶段：

| 阶段 | 核心产出 |
| --- | --- |
| 1. 范围与规则 | ROE、目标清单、排除项、时间窗口 |
| 2. 外部侦察 | 资产面、技术栈、公开信息、攻击面假设 |
| 3. 初始访问 | 已验证的入口、复现步骤、影响初判 |
| 4. 权限提升 | 当前权限、可提升路径、证据 |
| 5. 横向移动 | 可达资产、凭据/信任关系、边界 |
| 6. 目标达成 | 与演练目标对应的证明（不扩大范围） |
| 7. 清理与报告 | 清理记录、时间线、发现、修复建议 |

## 工具

### 授权闸门

```bash
python scripts/scope_check.py --scope scope.json --target api.example.com --technique web
```

- 校验目标是否在 `targets` 内、是否命中 `excludes`、当前时间是否在 `window` 内、手法是否被允许
- 输出 `ALLOW` / `DENY` 及原因；`DENY` 退出码 3，`ALLOW` 为 0，配置错误为 2
- 每个目标、每种手法执行前各跑一次，不要凭记忆判断

### 报告生成

```bash
python scripts/report_builder.py --findings findings.json --out report.md
```

- 按严重级排序，生成执行摘要、发现清单、逐条详情、ATT&CK 映射
- 缺少关键字段时给出警告；`--strict` 下警告也返回非零

## 输出契约

- 范围结论必须带**依据**：命中了哪条 targets、被哪条 excludes 排除、窗口起止
- 发现必须带**证据**：请求/响应、时间、账号、影响范围，缺证据的发现降级为"待验证"
- 报告不写未复现的推测；不确定的内容放"待确认"小节
- 不记录明文凭据；必要时只保留前后各 4 位

## 红线

- 不执行 DoS、社工欺骗、数据外带，除非 ROE 明确书面允许并有具体限制
- 不访问与演练目标无关的第三方系统；一旦踩到立即停止并上报
- 不建立长期持久化；确需验证持久化时，先约定清理方式并留清理记录
- 不把客户数据、内网拓扑、凭据写入公开仓库或工单系统

## 坑点

- `*.example.com` 只匹配子域名，不匹配 `example.com` 本身，范围要分别写
- 时间窗口按带时区的 ISO 8601 解析，跨时区项目务必写偏移量
- 排除项优先级高于目标清单：同时命中时一律拒绝
- 报告里的 ATT&CK ID 必须和实际手法对应，不要为了好看硬凑
