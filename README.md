# 中文区广告拦截合并清单

由 9 份中文区广告过滤清单合并、去重、语法清理后生成的单一订阅文件，语法为 AdGuard / uBlock Origin 通用的 Adblock Plus 格式。

## 订阅地址

| 线路 | 地址 |
|---|---|
| GitHub Raw | `https://raw.githubusercontent.com/inanger/cn-adblock-list/main/adblock-merged.txt` |
| jsDelivr | `https://cdn.jsdelivr.net/gh/inanger/cn-adblock-list@main/adblock-merged.txt` |

> jsDelivr 的路径**必须带 `@main`**。不带版本号的 `/gh/user/repo/file` 会解析到仓库早期 tag 并长期缓存，拿到的是几年前的旧文件。

## 当前规模

- 265,888 条规则，约 9.6 MB
- 网络请求拦截 169,627 条 / 元素隐藏 79,469 条 / 例外 13,507 条 / 正则 30 条 / 路径模式 3,255 条
- 覆盖 138,311 个主机名

## 更新机制

`.github/workflows/update.yml` 每日定时执行 `merge.py`，重新拉取各上游、合并去重后提交。也可在 Actions 页面手动触发。

## 上游来源

| 来源 | 许可 |
|---|---|
| [TG-Twilight/AWAvenue-Ads-Rule](https://github.com/TG-Twilight/AWAvenue-Ads-Rule) | GPL-3.0 |
| [Cats-Team/AdRules](https://github.com/Cats-Team/AdRules) | 继承各上游原许可 |
| [8680/GOODBYEADS](https://github.com/8680/GOODBYEADS) | MIT |
| [privacy-protection-tools/anti-AD](https://github.com/privacy-protection-tools/anti-AD) | MIT |
| [zhiyuan1i/adblock_list](https://github.com/zhiyuan1i/adblock_list) | GPL-3.0 |
| [cjx82630/cjxlist](https://github.com/cjx82630/cjxlist) | LGPL-3.0 |
| [xinggsf/Adblock-Plus-Rule](https://github.com/xinggsf/Adblock-Plus-Rule) | 未声明许可证 |

## 处理规则

1. 逐行归一化后按「规则键」去重（网络规则按主机名归并，忽略大小写）
2. 丢弃上游自身生成的碎片行（如 `*.i3z.`、`_ad2.`、`#189`、缺 pattern 的 `$3p,...` 残句）
3. 丢弃单行超过 2000 字符的机器生成规则
4. 父子域收敛：已存在 `||b.com^` 时移除冗余的 `||a.b.com^`（仅对无选项的裸规则生效）
5. 按「网络拦截 / 元素隐藏 / 例外 / 正则 / 路径模式」分节输出，补齐 `! Title`、`! Expires`、`! Source` 元信息

## 使用提醒

- 体量偏大：AdGuard Home、AdGuard 桌面端可用；uBlock Origin 桌面端可加载但首次解析较慢；MV3 的 uBO Lite 不适合此量级。
- 清单内含 `$badfilter` 规则，会全局禁用其他订阅中的同名规则；内含 `$important`，优先级高于普通例外。
- 合并清单必然继承上游的误拦风险，关键业务域名请自建白名单。

## 许可与免责

本清单是上述上游的衍生集合，**不构成新的授权**。各段规则仍归原作者，按其原始许可证使用：

- GPL-3.0 与 LGPL-3.0 来源要求衍生作品保持同许可证并保留署名
- 乘风规则未声明许可证，默认保留所有权利，**再分发存在授权瑕疵**
- 本项目仅用于个人学习与自用；因使用本清单造成的任何问题由使用者自行承担

如用于商业场景或公开分发，请先自行完成许可证审查。
