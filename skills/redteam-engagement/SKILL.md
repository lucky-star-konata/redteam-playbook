---
name: redteam-engagement
description: Plan, execute, and track a multi-stage authorized red team engagement. Use when scoping a penetration test, gating each target or technique before action, moving between recon, access, privilege escalation, lateral movement and reporting stages, resuming a paused engagement, or turning findings into a client-ready ATT&CK-mapped report.
---

# redteam-engagement

把授权红队评估拆成**有状态、可暂停、可恢复、可审计**的多阶段流程：每次动目标前过授权闸门，每个阶段结束必须留下产物才能推进。

## 何时使用

- 新项目启动，需要确认范围、时间窗口、禁止手法
- 准备对某个域名 / IP / 网段执行动作，想先确认是否越界
- 项目跨天、多人协作，需要交接当前进度和下一步
- 从侦察推进到访问、提权、横向，需要判断能否进入下一阶段
- 需要把散落的发现整理成客户能读的报告

## 前置条件（缺一不可）

1. **书面授权**：合同、授权书或 SOW，能指明目标、时间、允许手法
2. **单一联系人**：出问题能立刻找到决策人
3. **停止条件**：什么情况必须停（业务中断、敏感数据、越权访问到第三方）

没有书面授权就不进入执行阶段，只做方案设计。

## 多阶段模型

七个执行阶段加一个关闭态。完整动作说明见 [references/phases.md](../../references/phases.md)。

| ID | 阶段 | 进入条件 | 必留证据 | 产物 | 退出条件 |
| --- | --- | --- | --- | --- | --- |
| `scope` | 范围与规则 | 授权文件在手 | ROE、目标/排除项/窗口 | `01-scope.md` | 目标无歧义、窗口确认 |
| `recon` | 外部侦察 | scope 完成 | 数据来源、采集时间、置信度 | `02-recon.md` | 攻击面假设已排序 |
| `access` | 初始访问 | 动作前 scope_check 为 ALLOW | 请求/响应、时间线 | `03-access.md` | 至少一个入口可复现 |
| `privesc` | 权限提升 | 已获得立足点 | 身份前后对比、命令输出 | `04-privesc.md` | 权限结论明确 |
| `lateral` | 横向移动 | 新目标在授权范围内 | 路径图、登录记录 | `05-lateral.md` | 到达目标或路径阻断 |
| `objective` | 目标达成 | 横向结果明确 | 目标达成证明 | `06-objective.md` | 目标项均有结论 |
| `cleanup` | 清理与报告 | 目标阶段结束 | 清理确认、报告 | `07-cleanup-report.md` | 清理完成且报告交付 |
| `closed` | 关闭 | 报告交付 | 数据销毁记录 | `08-closed.md` | 数据按约定处理完毕 |

## 阶段推进规则

1. **单阶段推进**：未满足当前阶段退出条件，不进入下一阶段；不要为了赶进度跳步。
2. **阶段闸门**：进入 `access`、`privesc`、`lateral`、`objective` 前，对即将操作的目标和手法各跑一次 `scope_check`，用 `--json` 保存结果作为证据。
3. **允许回退**：横向移动发现新入口时退回 `access`，提权失败退回 `access` 重新选点；回退写入 `regressions`，不隐藏。
4. **允许跳过**：客户只要求部分阶段时写入 `skipped`（阶段 + 原因 + 授权方确认方式）；`scope` 与 `cleanup` 不可跳过。
5. **可并行**：多个独立目标可并行推进，但 `state.json` 中每个目标单独记录 `stage`。
6. **阻断即停**：触发停止条件时把 `status` 置为 `blocked`，记录触发点并联系授权方，不自行继续。

## 状态文件

在私有工作区维护 `.engagement/state.json`，不要提交到公开仓库：

```json
{
  "engagement": "示例项目",
  "updated_at": "2026-11-05T10:00:00+08:00",
  "status": "in_progress",
  "targets": [
    {
      "target": "api.example.com",
      "stage": "access",
      "status": "in_progress",
      "scope_checked_at": "2026-11-05T09:58:00+08:00",
      "artifact": "03-access.md"
    },
    {
      "target": "10.10.0.8",
      "stage": "recon",
      "status": "pending"
    }
  ],
  "artifacts": ["01-scope.md", "02-recon.md", "03-access.md"],
  "skipped": [],
  "regressions": [],
  "blockers": []
}
```

字段约定：

- `status`：`pending` / `in_progress` / `done` / `blocked`
- `skipped`：`[{"stage": "lateral", "reason": "...", "approved_by": "..."}]`
- `regressions`：`[{"from": "lateral", "to": "access", "reason": "..."}]`
- `blockers`：`[{"stage": "...", "reason": "...", "reported_at": "..."}]`

## 每次推进的执行循环

1. 读取 `state.json`，确认当前目标与阶段；无状态文件则从 `scope` 初始化
2. 判断本次动作是否会接触目标；会接触就先跑 `scope_check`
3. 执行本阶段动作，同步记录请求/响应、时间、账号
4. 写阶段产物，更新 `state.json`（阶段、状态、证据路径）
5. 对照退出条件自检：满足则推进，不满足则留在当前阶段并写明缺口

## 工具

### 授权闸门

```bash
python scripts/scope_check.py --scope scope.json --target api.example.com --technique web --json
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

- **阶段产物**：每个阶段至少一份 Markdown，包含时间、目标、动作、结果、证据位置、遗留问题
- **范围结论**：必须带依据（命中的 targets 规则、排除项、窗口起止）
- **发现**：必须带证据（请求/响应、时间、账号、影响范围）；缺证据降级为"待验证"
- **状态同步**：动作完成后立即更新 `state.json`，不事后补记
- **失败也记录**：被阻断、被检测、无结果的阶段同样写产物，不删空记录
- 报告不写未复现的推测；不确定内容放"待确认"小节
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
- 阶段回退后，旧阶段的结论要标记失效，不要继续引用
- 报告里的 ATT&CK ID 必须和实际手法对应，不要为了好看硬凑
