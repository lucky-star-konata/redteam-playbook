# redteam-playbook

[![CI](https://github.com/lucky-star-konata/redteam-playbook/actions/workflows/ci.yml/badge.svg)](https://github.com/lucky-star-konata/redteam-playbook/actions/workflows/ci.yml)

一套用于**授权红队评估**的 Agent Skill 与配套工具：把范围确认、执行约束、证据留存、报告输出固化成可执行流程，减少踩线和漏项。

> 仅限书面授权范围内的安全评估。禁止用于未授权目标。详见 [DISCLAIMER](#免责声明)。

## 这个仓库解决什么

红队项目真正容易出问题的不是技术，而是三件事：

1. **越界**：扫到了范围外的域名、在禁止时段打了生产、用了未授权的手法
2. **断证据**：打进去后没留下可复现的请求、时间线、影响证明，报告写不实
3. **报告散**：发现散落在聊天记录里，最后拼不出客户能看的东西

仓库里两个脚本分别管第 1 和第 3 件事，SKILL.md 管第 2 件事。

## 仓库结构

```
redteam-playbook/
├── VERSION
├── README.md
├── LICENSE
├── DISCLAIMER.md
├── skills/
│   └── redteam-engagement/
│       ├── SKILL.md                    # Agent Skill：何时用、怎么用、输出契约
│       └── scripts/
│           ├── scope_check.py          # 每个目标/手法执行前的授权闸门
│           └── report_builder.py       # findings JSON -> 客户可读的 Markdown 报告
├── references/
│   ├── phases.md                       # 七阶段流程：目标、动作、证据、退出条件
│   ├── roe-template.md                 # 授权书 / ROE 检查清单
│   └── case-study-template.md          # 项目经历模板（你自己填真实内容）
└── templates/
    ├── scope.example.json              # 授权范围示例
    └── findings.example.json           # 发现记录示例
```

## 快速开始

```bash
# 1. 校验某个目标当前是否可以动
python skills/redteam-engagement/scripts/scope_check.py \
  --scope templates/scope.example.json \
  --target api.example.com \
  --technique web

# 2. 生成报告
python skills/redteam-engagement/scripts/report_builder.py \
  --findings templates/findings.example.json \
  --out report.md
```

`scope_check.py` 的输出只有两种结论：`ALLOW` 或 `DENY`。`DENY` 时退出码为 3，可以直接串在自动化流程前面当硬闸门。

## Skill 的用法

把 `skills/redteam-engagement/` 复制到 Agent 的 skills 目录：

```bash
cp -r skills/redteam-engagement ~/.claude/skills/
```

之后在接到"帮我规划红队评估""这个目标能不能测""把发现整理成报告"这类请求时，Agent 会按 SKILL.md 的流程执行。

## 项目经历

仓库里的 [case-study-template.md](references/case-study-template.md) 是给**你自己**用的项目经历模板：

- 只写真实做过的事，量化数字必须有据可查
- 客户名默认脱敏为「某行业客户」
- 没有的内容留空或删行，不要凑字数

我不会替你编造项目背景和成果，这部分需要你填。

## 设计原则

- **默认拒绝**：范围、时间、手法任一不满足就 `DENY`，不做"善意猜测"
- **离线运行**：两个脚本都不联网、不解析目标，只做本地校验与格式化
- **证据优先**：流程的每一步都要求产出可复核的请求/响应或截图说明
- **无武器化代码**：仓库不包含 exp、免杀、C2、凭据窃取等攻击实现

## 免责声明

本项目仅用于**已获得书面授权**的安全评估与教学。使用者需自行确认目标授权、遵守当地法律与合同约定。作者不对未授权使用承担任何责任。详见 [DISCLAIMER.md](DISCLAIMER.md)。

## License

[MIT](LICENSE)
