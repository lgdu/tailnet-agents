# Tailnet Agents

Discover heterogeneous agents across regions on a shared Tailscale network.

Status: **v0.2 prototype**. Automatic bridge registration/renewal, discovery,
Echo task submission and result polling work. MCP tools, real product adapters
and A2A transport are planned. The custom task API is not A2A.

## 项目目标

让不同地域的 OpenClaw、Claude Code、Codex、Qoder、自研 Agent 等在同一个
Tailscale 网络里自动注册、相互发现，并通过统一任务接口协作。
Grok 的模型 API 与产品 Agent 分开评估，不把模型调用当成完整 Agent 接入。

Tailscale 提供网络连接；目录维护 Agent 地址、技能与在线状态。
Agent Bridge 将具体产品接入网络；任务最终在伙伴之间直接传输。
不依赖跨 Tailnet 的 mDNS 广播，不要求公开公网端口。

## 当前可运行部分

- Python 3.11+ 标准库实现的 HTTP 注册目录，无运行时第三方依赖。
- 注册与续租、按技能查找、到期过滤。
- 每个节点独立 Bearer token，防止覆盖其他节点的 Agent ID。
- Bridge 启动后自动注册、20 秒续租，目录故障后自动重试。
- CLI 发现伙伴、提交 Echo 任务、查询异步结果。
- 按调用方隔离结果、幂等键去重、冲突检测和任务容量限制。
- 认证、租约、元数据与双 Bridge 端到端集成测试。

双节点部署步骤见 [Quickstart](docs/quickstart.md)。

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

原型使用内存存储，重启清空所有记录和 ID 所有权，需要重新注册。
目录没有配额、持久化、订阅推送或生产级 HTTP 服务，暂不适合不可信客户端。
任务及幂等记录也在内存中，重启丢失；任务容量默认 256，达到后拒绝新增。
登记的 URL 需要调用端在执行前验证允许的主机与权限。

1. 已实现 Bridge 自动注册、续租与目录重试；伙伴缓存待实现。
2. MCP `discover_agents` / `delegate_task`，让交互式 Agent 能主动使用网络。
3. A2A 收发与异步任务状态、幂等、超时、取消语义。
4. OpenClaw、Claude Code、Codex、Qoder 适配器；逐个验证真实开放接口。
5. Grok 产品能力调查与自研 HTTP/CLI 适配器。
6. 持久化、节点权限、配额与可观测性。

详细约定见 [protocol](docs/protocol.md)。尚未选择开源许可证，发布前由所有者决定。
