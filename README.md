# Tailnet Agents

Discover heterogeneous agents across regions on a shared Tailscale network.

Status: **v0.10 prototype**. Automatic bridge registration/renewal, discovery,
Echo task submission, result polling and MCP stdio tools work. Real product
adapters and A2A transport are planned. The custom task API is not A2A.

## 项目目标

让不同地域的 OpenClaw、Claude Code、Codex、Qoder、自研 Agent 等在同一个
Tailscale 网络里自动注册、相互发现，并通过统一任务接口协作。
Grok 的模型 API 与产品 Agent 分开评估，不把模型调用当成完整 Agent 接入。

Tailscale 提供网络连接；目录维护 Agent 地址、技能与在线状态。
Agent Bridge 将具体产品接入网络；任务最终在伙伴之间直接传输。
不依赖跨 Tailnet 的 mDNS 广播，不要求公开公网端口。

## 当前可运行部分

- Python 3.11+ 标准库实现的 SQLite 注册目录，无运行时第三方依赖。
- 重启保留身份归属、主动注销与目录状态查询。
- 注册与续租、按技能查找、到期过滤。
- 每个节点独立 Bearer token，防止覆盖其他节点的 Agent ID。
- Bridge 启动后自动注册、20 秒续租，目录故障后自动重试。
- CLI 发现伙伴、提交 Echo 任务、查询异步结果。
- 按调用方隔离结果、幂等键去重、冲突检测和任务容量限制。
- 认证、租约、元数据与双 Bridge 端到端集成测试。

双节点部署步骤见 [Quickstart](docs/quickstart.md)，MCP 接入见 [MCP guide](docs/mcp.md)。

## 本地启动

```bash
export TAILNET_AGENT_TOKENS="$(python3 -c 'import json,secrets; print(json.dumps({"tokyo": secrets.token_hex(32)}))')"
python3 -m tailnet_agents.registry
```

默认监听 `127.0.0.1:8765`。在 Tailscale 主机上可用 Tailscale Serve 为该本地
服务提供 Tailnet 内的 HTTPS 地址。客户端统一配置这个目录地址。
只对允许的 Tailnet 设备开放访问，不使用 Funnel 暴露公网。

将对应节点 token 安全提供给客户端。下面 `REGISTRY_TOKEN` 是该 token，
`REGISTRY_URL` 是实际目录 URL；本地测试可用 `http://127.0.0.1:8765`。

```bash
curl -X POST "$REGISTRY_URL/v1/agents" \
  -H "Authorization: Bearer $REGISTRY_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"id":"tokyo-coder","name":"Tokyo Coder","endpoint":"https://coder.YOUR-TAILNET.ts.net/a2a/v1","protocol":"a2a","skills":["coding"],"ttl_seconds":60}'

curl "$REGISTRY_URL/v1/agents?skill=coding" \
  -H "Authorization: Bearer $REGISTRY_TOKEN"
```

注册的是示例元数据，不会启动 Agent。续租时重复提交同一记录，建议每 20 秒
续租一次 60 秒租约。目录不主动请求端点；租约在线不保证 Agent 能成功执行任务。

```bash
python3 -m unittest discover -s tests -v
```

## 限制与路线

目录使用 SQLite 保存记录和 ID 所有权；重启后旧租约失效，Bridge 续租后恢复在线。
目录没有配额、订阅推送或生产级 HTTP 服务，暂不适合不可信客户端。
任务及幂等记录也在内存中，重启丢失；任务容量默认 256，达到后拒绝新增。
登记的 URL 需要调用端在执行前验证允许的主机与权限。

1. 已实现 Bridge 自动注册、续租与目录重试；伙伴缓存待实现。
2. 已实现 MCP stdio `discover_agents` / `delegate_task` / `get_task_result`；产品实测待完成。
3. A2A 收发与异步任务状态、幂等、超时、取消语义。
4. OpenClaw、Claude Code、Codex、Qoder 适配器；逐个验证真实开放接口。
5. Grok 产品能力调查与自研 HTTP/CLI 适配器。
6. 已实现目录持久化与状态查询；任务持久化、细粒度节点权限、配额与指标待实现。

详细约定见 [protocol](docs/protocol.md)。尚未选择开源许可证，发布前由所有者决定。

目录运维、SQLite 备份与恢复见 [Operations](docs/operations.md)。

## Self-organizing groups: design and simulation

统一设计规格见 [Architecture ADR](docs/architecture.md)：覆盖 LAN/Tailscale 发现、
人的群聊与私聊入口、入群授权、重启恢复、分区同步、休眠和永久解散。

```bash
python3 -m tailnet_agents.mesh_sim
```

该命令仅运行确定性状态模拟，不连接网络，不验证签名，不授予真实 Agent 权限。
静态预授权 ID 由测试程序提供，不能当作生产认证。模拟检查成员记录合并、
版本冲突、退出、重启与解散状态；尚未实现网络 Mesh、凭证签发或聊天界面。
原有中心目录模式继续可用。

## Human chat UI (local simulation)

```bash
export TAILNET_UI_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
python3 -m tailnet_agents.ui
```

在本机打开 `http://127.0.0.1:8770`，输入上述环境变量的值。
界面提供群聊点名、三个模拟 Agent 的独立对话、模拟在线切换以及 SQLite 历史。
仅绑定回环地址，支持配置多个本地身份与角色；仍不是可公开部署的聊天服务。
完整说明见 [Human UI](docs/ui.md)。

v0.7 支持独立人类 token、管理员/参与者/观察者角色，以及后端按人隔离私聊。
角色和多用户配置见 [Human UI](docs/ui.md)。

v0.8 增加每 2 秒增量更新、旧历史分页与断线提示。设计规则已调整为：
新群组由人明确创建，Agent 仅自动恢复已授权的原群组；v0.9 已实现本地人类创建表单与初始成员选择，签名凭证仍待实现。

v0.9 新安装没有默认群组，管理员点击「创建群组」并选择允许进入的人。
不同群组的聊天与私聊独立保存；非成员（包括其他管理员）不能访问。
这是本地 UI 的成员授权，尚未连接网络 Agent 凭证或 Mesh。

v0.10 增加创建请求去重、创建者管理成员、撤销访问、显式解散和操作记录。
解散保留历史并永久关闭该群组 ID 的写入；这仍是本地数据库状态，尚未传播到 Mesh。
