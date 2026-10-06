# WARC 1.1 Audit Service

数字保存机构导入网页取证包前的边界/摘要/引用一致性审计服务。收到 WARC 后逐字节严格校验，任何一条记录不合格即**拒绝整包**，杜绝容错解析让损坏证据进入归档。

仅依赖 Python 3.11 标准库。

## 审计规则

| 维度 | 规则 |
|------|------|
| 传输 | `POST /api/warc/audit`，`Content-Type: application/warc`，正文 ≤ 16 MiB，记录数 1–500 |
| 类型 | 仅接受 `warcinfo` / `request` / `response` / `revisit` |
| 边界 | 必须以 `WARC/1.1` 开头；全部使用 CRLF（裸 LF、obs-fold 一律拒绝）；记录以 CRLF CRLF 结尾，无尾随垃圾 |
| 头 | 必需头（WARC-Type/Record-ID/Date/Content-Length/Block-Digest 等）恰好出现一次；Record-ID 全文件唯一；Date 为合法 UTC 日历日 |
| 长度 | WARC `Content-Length` 必须与块正文的原始字节数完全一致（少一字节、多吞终止符都报错） |
| 块摘要 | `WARC-Block-Digest` 必须为 `sha256:` + 64 位小写十六进制，且等于对**声明的原始块字节**重算的 SHA-256 |
| 载荷摘要 | `response` / `revisit` 必须携带 `WARC-Payload-Digest`；response 的摘要覆盖解帧后的 HTTP 实体正文（支持 Content-Length 与 chunked）；`warcinfo`/`request` 禁止携带 |
| 引用 | `revisit` 只能通过 `WARC-Refers-To` 指向文件中**更早**的 `response`，且载荷摘要相同；前向引用、悬空引用、指向非 response、摘要不符全部拒绝 |

## 响应

成功 `200`，记录按原始顺序排列：

```json
{
  "status": "accepted",
  "record_count": 4,
  "records": [
    {"index": 1, "type": "warcinfo", "block_length": 57,
     "block_digest": "sha256:9d92…", "payload_digest": null}
  ]
}
```

失败（整包拒绝）返回稳定错误码与首个失败记录号：

```json
{"error": {"code": "DIGEST_MISMATCH",
           "message": "WARC-Block-Digest does not match the declared block bytes",
           "record": 2}}
```

| code | HTTP | 含义 |
|------|------|------|
| `MALFORMED_BOUNDARY` / `MALFORMED_HEADER` / `MALFORMED_HTTP` | 400 | 边界或格式错误 |
| `LENGTH_MISMATCH` | 400 | Content-Length 与块/实体字节不符 |
| `RECORD_LIMIT` / `EMPTY_ARCHIVE` | 400 | 超出 1–500 条范围 |
| `DIGEST_MISMATCH` | 422 | 块摘要或载荷摘要不符 |
| `REFERENCE_INVALID` | 422 | revisit 引用前向/悬空/类型错/摘要不符 |
| `FILE_TOO_LARGE` | 413 | 超过 16 MiB |
| `UNSUPPORTED_MEDIA_TYPE` | 415 | Content-Type 不是 application/warc |

健康检查：`GET /healthz` → `200 ok`。

## 运行

```bash
# 宿主机端口可配置（默认 8080）
HOST_PORT=9090 docker compose up --build api

curl -sS -X POST http://localhost:9090/api/warc/audit \
     -H 'Content-Type: application/warc' \
     --data-binary @capture.warc
```

本地无 Docker 时：`python3 -m app.server`（端口由 `PORT` 环境变量配置）。

## verify 一次性服务

`verify` 服务等待 `api` 健康检查通过后，依次运行**单元测试、构建检查（compileall）、合法包/坏摘要/坏引用 API 冒烟**，以退出码报告结果并自行退出：

```bash
docker compose build
docker compose up api -d
docker compose run --rm verify    # 退出码 0 即全部通过
docker compose down
```

容器外等价入口：`./verify.sh`（自起服务、自测、自清理）。

## 目录

```
app/warc.py      字节级严格解析与审计（无第三方依赖）
app/server.py    HTTP 服务（/api/warc/audit、/healthz）
tests/           单元测试 + HTTP 冒烟 + 跨容器冒烟脚本
verify.sh        一次性校验入口
Dockerfile, docker-compose.yml, .env.example
```
