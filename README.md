# Shadowrocket 规则转 v2rayN，并每天自动同步

本模板每天北京时间 08:00 从
[`Johnshall/Shadowrocket-ADBlock-Rules-Forever`](https://github.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever)
的 `release` 分支下载 12 份 `sr_*.conf`，转换为 v2rayN 可导入的路由 JSON，并提交到本仓库的 `rules/` 目录。

## 一、放到你自己的 GitHub 仓库

1. 新建一个公开 GitHub 仓库。
2. 把本模板的所有文件上传到仓库默认分支，保留 `.github/workflows/sync.yml` 的目录结构。
3. 打开仓库 `Settings -> Actions -> General`，在 `Workflow permissions` 中选择 `Read and write permissions`。
4. 打开 `Actions -> Sync v2rayN routing rules -> Run workflow`，先手动运行一次。
5. 成功后，仓库中会出现 `rules/*.json`、`rules/manifest.json` 和 `rules/template.json`。

计划任务使用 `0 0 * * *`。GitHub Actions 的 cron 按 UTC 计算，因此对应北京时间每天 08:00；GitHub 的计划任务可能排队，不能保证整点零秒执行。

## 二、在 v2rayN 中导入一份规则

推荐先用黑名单加去广告版：

```text
https://raw.githubusercontent.com/zuihaoai/v2rayn-rules-sync/main/rules/sr_top500_banlist_ad.json
```

在 v2rayN 中：

1. 打开 `设置 -> 路由设置 -> 高级功能`。
2. 新增一套路由，备注可填 `Johnshall 黑名单 + 去广告`。
3. 把上面的 Raw URL 填入 URL。
4. 选择“从 URL 导入规则”；如果询问追加还是替换，选择替换。
5. 保存，并把这套路由设为当前路由。

如果你不想拦广告，改用 `sr_top500_banlist.json`；如果希望未知国外网站默认走代理，可改用 `sr_top500_whitelist_ad.json`。

## 三、一次导入全部 12 套规则

首次 Action 成功后，使用：

```text
https://raw.githubusercontent.com/zuihaoai/v2rayn-rules-sync/main/rules/template.json
```

把它填入 v2rayN 设置中的“高级路由规则来源 URL”，然后在路由设置中执行“导入高级规则”。若你的默认分支不是 `main`，把 URL 中的 `main` 换成实际分支名。

注意：v2rayN 当前会在导入时下载 URL，但不会按这条 URL 自己每天后台刷新。每天 08:00 自动的是 GitHub 仓库中的转换结果；客户端更新时，需在该路由中再次执行“从 URL 导入规则”并选择替换。不要反复执行“导入全部 12 套规则”，否则可能产生重复路由项。

## 转换规则

| Shadowrocket | v2rayN / Xray |
| --- | --- |
| `DOMAIN` | `full:域名` |
| `DOMAIN-SUFFIX` | `domain:域名` |
| `DOMAIN-KEYWORD` | `keyword:关键词` |
| `IP-CIDR` / `IP-CIDR6` | `ip` CIDR |
| `GEOIP` | `geoip:代码` |
| `PROXY` | `outboundTag: proxy` |
| `DIRECT` | `outboundTag: direct` |
| `REJECT` | `outboundTag: block` |
| `FINAL` | 全端口最终规则 |
| `RULE-SET` | Action 构建时下载并展开 |

`URL-REGEX`、`USER-AGENT`、`SCRIPT`、`IP-ASN` 等 Shadowrocket 特有能力在 Xray 路由中没有等价表达，转换器会跳过并把明细写入 `rules/manifest.json`。当前上游的主要 `sr_*.conf` 以域名、CIDR、GEOIP 和 FINAL 为主。

## 本地运行

无需安装第三方 Python 包：

```bash
python -m unittest discover -s tests -v
python scripts/convert_shadowrocket.py --all --output-dir rules
```

也可以只转一份本地或远程规则：

```bash
python scripts/convert_shadowrocket.py \
  --input sr_top500_banlist_ad.conf \
  --output rules/sr_top500_banlist_ad.json
```
