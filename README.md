# 会话令牌签发与轮换（本地存储模拟）

在原有 FastAPI 服务（`GET /` 行为不变）之上新增一套会话令牌机制：

- 访问令牌（access token）与刷新令牌（refresh token）的签发、校验；
- 刷新令牌**一次性轮换**与**重放检测**，并发刷新结论唯一；
- 注销 / 会话吊销 / 时钟偏差容忍；
- 每类拒绝原因可区分，判定过程打印令牌标识、会话标识与依据。

会话状态保存在进程内、线程安全的本地存储中（`auth/store.py`），用内存模拟数据库。

## 目录结构

```
auth/
  errors.py   # 失败原因类型：过期 / 伪造 / 吊销 / 会话不存在 / 重放 ...
  tokens.py   # HMAC-SHA256 令牌编码、验签、过期与时钟偏差判断
  store.py    # 会话与刷新家族的线程安全内存存储
  service.py  # 签发、校验、轮换、注销的核心逻辑与判定日志
  api.py      # /auth/* HTTP 路由
tests/        # 令牌层 / 服务层 / 并发 / HTTP 四层单测
main.py       # FastAPI 入口（保留原 GET /）
```

## HTTP 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/auth/login?subject=<用户>` | 登录，返回 `access_token` / `refresh_token` / `session_id` |
| `GET` | `/auth/me` | 受保护资源，头 `Authorization: Bearer <access_token>` |
| `POST` | `/auth/refresh` | 刷新，头 `X-Refresh-Token: <refresh_token>`，返回新令牌对 |
| `POST` | `/auth/logout` | 注销，头 `X-Refresh-Token` 或 `X-Session-Id` 定位会话，幂等 |
| `GET` | `/` | 原有接口，返回 `{"Hello": "World"}` |

启动：

```bash
uv run uvicorn main:app --reload
# 或 uv run python main.py
```

## 令牌生命周期

- 令牌格式为 `base64url(payload).hmac_sha256(payload, secret)`，载荷含
  `jti`（令牌 id）、`sid`（会话 id）、`fid`（刷新家族 id）、`sub`、`iat`、`exp`、`typ`。
- 默认 TTL：访问令牌 **15 分钟**，刷新令牌 **7 天**（`auth/service.py` 可调）。
- 登录时创建一条 `Session` 和一个 `RefreshFamily`，家族记录
  `current_refresh_id`（当前有效刷新令牌 id）与 `used_refresh_ids`（已成功使用过的令牌 id 集合）。
- 每次 `/auth/refresh`：
  1. 旧刷新令牌必须恰好等于 `current_refresh_id`，才签发新令牌对；
  2. 成功后旧 id 进入 `used_refresh_ids`，`current_refresh_id` 推进为新 id；
  3. 旧访问令牌自然到期（短期），新访问令牌随刷新对一起发放。

## 重放与吊销规则

- **一次性使用**：同一刷新令牌只能成功刷新一次。再次提交即判定为重放
  （`refresh_replay`），并把整条刷新家族（含其会话）标记为吊销。
- **家族连带失效**：一旦重放发生，家族内所有访问令牌、以及赢家刚轮换出的新
  刷新令牌都立即失效。这是刷新令牌轮换的标准安全取舍——服务端无法区分
  “攻击者盗用旧令牌”与“合法客户端网络重试”，检测到重用时以“作废整条链”
  保证被盗令牌不可能继续换取访问凭证，用户需要重新登录。
- **并发唯一**：`refresh` 的“检查家族状态 + 轮换推进”整段持有同一把锁，
  N 个客户端并发使用同一个刷新令牌时**恰好 1 个成功**，其余按重放处理；
  不可能两边同时拿到新令牌，也不可能旧令牌换完还能继续用。
- **注销**：会话与其刷新家族一起吊销，吊销后该会话的访问/刷新令牌立刻不可用；
  重复注销、对不存在的会话注销、携带无法验签的令牌注销都**幂等**，返回 200 不报错。
- **会话不存在**：令牌签名有效但 `sid/fid` 在本地存储中查不到（或家族与会话
  对不上），单独报 `session_not_found`，与吊销区分。

### 失败原因对照

服务层异常（`auth/errors.py`）与 HTTP 响应 `detail.reason`：

| 场景 | 异常 | `detail.reason` | HTTP |
| --- | --- | --- | --- |
| 格式错误 / 签名伪造 / 令牌类型错 | `TokenMalformedError` | `token_malformed` | 401 |
| 访问令牌过期（超出偏差窗口） | `TokenExpiredError` | `token_expired` | 401 |
| 刷新令牌过期 | `RefreshTokenExpiredError` | `refresh_expired` | 401 |
| 已注销 / 家族被吊销 | `TokenRevokedError` | `token_revoked` | 401 |
| 会话或家族不存在 | `SessionNotFoundError` | `session_not_found` | 401 |
| 刷新令牌重放 | `RefreshReplayError` | `refresh_replay` | 401 |
| 缺少 Bearer / 刷新头 | — | `missing_bearer_token` / `missing_refresh_token` | 401 / 400 |

## 时钟偏差容忍

默认容忍 **30 秒**偏差（`auth/tokens.py: DEFAULT_CLOCK_SKEW_SECONDS`）：

- `now <= exp + 30s` 不判过期；
- `iat - 30s <= now` 才认可签发时间，远在未来的令牌按伪造类异常拒绝。

## 本地验证

```bash
# 安装依赖（首次会自动建 .venv）
uv sync

# 跑全部单测（40 个用例）
uv run pytest -q

# 并发与重放专项（-s 可查看 令牌/会话标识 + 判定依据 日志）
uv run pytest tests/test_concurrency.py -v -s
```

命令行手工走一遍：

```bash
uv run uvicorn main:app --port 8000 &

TOK=$(curl -s -X POST 'http://127.0.0.1:8000/auth/login?subject=alice')
AT=$(echo "$TOK" | python -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
RT=$(echo "$TOK" | python -c 'import sys,json;print(json.load(sys.stdin)["refresh_token"])')

curl -s http://127.0.0.1:8000/auth/me -H "Authorization: Bearer $AT"
curl -s -X POST http://127.0.0.1:8000/auth/refresh -H "X-Refresh-Token: $RT"
# 再用同一个 $RT 刷新一次 -> 401 refresh_replay，整条家族失效
curl -s -X POST http://127.0.0.1:8000/auth/refresh -H "X-Refresh-Token: $RT"
```

## 判定日志

所有关键判定经 `auth` logger 输出，格式：

```
判定=<judgment> token_id=<jti前8位> session_id=<sid前8位> family_id=<fid前8位> 依据=<...>
```

判定标签包括 `login_issued`、`access_ok`、`access_expired`、`access_revoked`、
`access_session_missing`、`refresh_rotated`、`refresh_replay_detected`、
`refresh_replay_after_revoke`、`refresh_revoked`、`logout_done` 等，
单测以 `-s` 运行即可看到完整决策链。
