# 会话令牌签发与轮换机制（本地存储模拟）

在原有 FastAPI 服务（根路由 `GET /` 行为保持不变）之上，新增一套自包含的
访问令牌 / 刷新令牌机制。会话状态保存在进程内存储中，用一把锁保证并发
轮换的原子性，不依赖数据库或第三方库（令牌签名使用标准库 HMAC-SHA256）。

## 目录结构

| 文件 | 职责 |
| --- | --- |
| `main.py` | FastAPI 入口，挂载 `/auth` 路由并配置判定日志；`GET /` 保持原样 |
| `app/errors.py` | 错误分类：过期 / 伪造 / 吊销 / 会话不存在 / 重放，各自独立 |
| `app/models.py` | `TokenFamily`（会话家族）与 `TokenPair`（令牌对）数据类型 |
| `app/storage.py` | 线程安全的本地存储（`RLock` 保护家族状态） |
| `app/tokens.py` | 令牌签发与校验原语（HMAC-SHA256，含过期与时钟偏差容差） |
| `app/service.py` | 核心规则：签发、校验、**原子轮换**、重放连带失效、注销 / 吊销 |
| `app/api.py` | HTTP 接口，把各类错误映射为可区分的响应 |
| `tests/` | 令牌、服务、并发、HTTP 四层测试（共 39 个用例） |

## 令牌生命周期

令牌格式为 `base64url(payload).base64url(hmac_sha256(secret, payload))`，
payload 含 `typ`（access/refresh）、`jti`（令牌唯一标识）、`fam`（会话/家族
标识）、`sub`（主体）、`iat`、`exp`。

1. **登录** `POST /auth/login`：创建一个新会话家族（`family_id`），签发
   首个访问令牌（默认 15 分钟）和刷新令牌（默认 7 天）。
2. **访问** `GET /auth/me`（Bearer 访问令牌）：校验通过即有效。
3. **轮换** `POST /auth/refresh`：刷新令牌**一次性**使用。服务端原子地
   - 把旧刷新令牌 jti 记入 `used_refresh_jtis`；
   - 推进 `latest_refresh_jti` 与 `current_access_jti`；
   - 下发全新的访问令牌与刷新令牌。
   旧刷新令牌与旧访问令牌在轮换成功后立即失效。
4. **注销** `POST /auth/logout` 或 `DELETE /auth/sessions/{family_id}`：
   家族标记为吊销，关联令牌立刻不可用。

默认参数可通过环境变量 / 构造参数调整：`SESSION_SECRET`，访问令牌 TTL、
刷新令牌 TTL、时钟偏差容差（默认 **30 秒**）。

## 失败原因如何区分

服务层抛出不同异常，HTTP 统一为 401，但响应体 `detail.code` 稳定可区分：

| code | 异常 | 判定依据 |
| --- | --- | --- |
| `invalid_signature` | `InvalidSignatureError` | HMAC 不一致（伪造 / 篡改 / 错误密钥） |
| `token_expired` | `TokenExpiredError` | `now > exp + 容差` |
| `session_not_found` | `SessionNotFoundError` | 令牌签名有效，但 `fam` 在存储中不存在 |
| `revoked` | `RevokedError` | 家族已注销 / 被连带吊销，或访问令牌已被轮换取代 |
| `refresh_replay` | `RefreshReplayError` | 刷新令牌已被使用过（重放） |
| `invalid_token` | `InvalidTokenError` | 结构 / 类型 / 字段非法（HTTP 400） |

判定顺序：先验结构与签名 → 再验过期（含容差）→ 再查会话是否存在 →
最后查吊销状态。因此"伪造"不会被误判为"过期"，"会话不存在"也不会被
笼统地当成"未授权"。

## 重放检测与家族连带失效

- 每个刷新令牌只能成功使用**一次**。轮换成功后该 jti 立刻进入已用集合。
- 第二次（及以后）提交同一刷新令牌即判定为**重放**，服务端立刻把整条
  家族置为 `revoked`。这意味着：
  - 并发刷新同一令牌时，**恰好一个**请求成功；其余全部得到
    `refresh_replay`；
  - 不会出现两个客户端同时拿到新令牌；
  - 即使是唯一成功分支刚拿到的新令牌，在重放发生后也立即不可用；
  - 旧令牌换完之后绝不能继续使用。
- 原子性由 `LocalStore` 的 `RLock` 保证：刷新的「读 → 判定 → 换发 →
  写状态」在同一个临界区内完成，50 线程并发抢同一令牌仍只有一个赢家
  （见 `tests/test_concurrency.py`）。
- 家族已吊销之后的区分：当前轮换链上的令牌得到 `revoked`；旧令牌再次
  出现仍是 `refresh_replay`（攻击结论不丢失）。

## 时钟偏差容忍

过期判定为 `now > exp + leeway`，默认容差 30 秒。客户端与服务端之间的
小幅时间差不会把仍在容差窗口内的令牌误判为过期；超出容差才是
`token_expired`。

## 注销与吊销的稳定处理

- 注销后关联令牌立即失效（访问令牌当场 401，刷新令牌无法再换）。
- 重复注销、对不存在的家族注销：接口稳定返回 `{"revoked": false}`，
  HTTP 200，不抛异常、不崩溃。
- 用访问令牌注销时不再以"令牌已过期"为由拒绝（签名仍必须有效），
  保证过期边缘也能完成登出。

## 本地验证

```bash
# 安装依赖
uv sync

# 运行全部测试（含 2/5/16/50 线程并发刷新场景）
uv run pytest

# 只看并发与重放，并打开实时判定日志（含 token_jti / family_id / reason）
uv run pytest tests/test_concurrency.py -s -o log_cli=true

# 启动服务
uv run python main.py          # 或：uv run uvicorn main:app --reload
```

手动调用示例：

```bash
# 登录
curl -s -X POST localhost:8000/auth/login -H 'Content-Type: application/json' \
  -d '{"subject":"alice"}'

# 校验访问令牌
curl -s localhost:8000/auth/me -H "Authorization: Bearer <access_token>"

# 轮换刷新令牌
curl -s -X POST localhost:8000/auth/refresh -H 'Content-Type: application/json' \
  -d '{"refresh_token":"<refresh_token>"}'

# 再次用同一个刷新令牌 -> 401 refresh_replay，家族连带失效
curl -s -X POST localhost:8000/auth/refresh -H 'Content-Type: application/json' \
  -d '{"refresh_token":"<refresh_token>"}'

# 注销（可带 Bearer 访问令牌，或给 family_id）
curl -s -X POST localhost:8000/auth/logout -H 'Content-Type: application/json' \
  -d '{"family_id":"<family_id>"}'
```

### 日志可观测性

每次判定都会输出 `event / family_id / token_jti / reason`，例如：

```
event=refresh_rotate family_id=abb4... token_jti=dfd4... reason=single_use_enforced new_refresh_jti=8004...
event=refresh_replay family_id=abb4... token_jti=dfd4... reason=replayed_refresh_token_family_compromised used_count=1
event=refresh_deny   family_id=abb4... token_jti=8004... reason=family_revoked
```

## HTTP 接口一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/auth/login` | 入参 `{"subject": "..."}`，返回令牌对 |
| GET | `/auth/me` | Bearer 访问令牌，返回主体 / 家族 / jti |
| POST | `/auth/refresh` | 入参 `{"refresh_token": "..."}`，原子轮换 |
| POST | `/auth/logout` | Bearer 访问令牌或 `{"family_id": "..."}`，幂等 |
| DELETE | `/auth/sessions/{family_id}` | 吊销整条家族，幂等 |

> 注意：本实现使用进程内内存存储，重启后会话全部消失，仅用于本地模拟与
> 测试；生产部署需替换为带条件写入（compare-and-swap）能力的持久存储。
