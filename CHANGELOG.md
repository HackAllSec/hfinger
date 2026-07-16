# Changelog

## [1.1.0] - 2026-07-16

- 完成规则库 YAML 化和内置规则源重构，核心规则统一维护在 `rulesets/core/`，支持外置 YAML 规则加载
- 新增规则治理能力，支持 `rules lint`、`rules test`、`rules stats`、`rules doctor` 和 JSON Schema 校验
- 新增证据化输出模型，JSON/JSONL 结果包含 category、version、confidence、evidence、DNS、TLS、行为信号和资源 Hash 信息
- 新增完整 JA3S ServerHello 探测、QUIC Version Negotiation 探测、DNS 边缘网络识别、WAF 行为矩阵、API 语义规则和跨资产聚类能力
- 新增蜜罐识别评分，覆盖明确蜜罐产品、冲突指纹、万能响应、相似响应、响应延迟和行为信号
- 新增 LLM/Agent 集成元数据，提供 `llm manifest`、`llm skills`、结果 Schema 和 Skill Schema，便于外部 Agent 做资产分诊、工具链编排、规则草案生成和蜜罐复核
- 优化主动/被动 TLS/TLCP 支持，主动模式默认 auto，支持标准 TLS 到 TLCP fallback，被动 MITM 支持标准 TLS/TLCP 握手阶段自动分流
- 优化被动 JSONL 存储，支持查询过滤、limit、轮转和流式读取
- 优化规则匹配性能，增加运行时预编译、Header 索引、响应缓存、Aho-Corasick 多模式匹配和资源 Hash 缓存
- 删除非 HTTP service scan 子命令，保持 HFinger 聚焦 Web、HTTP/TLS、DNS、WAF/CDN、API、蜜罐和跨资产服务端指纹识别
- 更新中英文 README 和规则 Wiki，补充合法使用声明、LLM/Skill 使用边界、规则编写规范和工具链联动示例

## [1.0.9] - 2025-07-15

- 新增检查更新参数，改善用户体验，现在不会默认检查更新了
- 新增国密支持，主动模式和被动模式均支持智能选择标准 TLS 和 TLCP
- 新增双向 TLS/TLCP 客户端证书参数，支持 TLCP 单证书和签名/加密双证书认证
- 新增独立 GM CA，GM/TLS 被动代理证书链不再复用标准 RSA CA
- 新增主动请求 TLS 模式控制，默认 auto，并支持强制 gm 或 std
- 优化主动请求 TLS 决策层，标准 TLS、TLCP 与 auto fallback 路径独立可测
- 明确内置 TLCP 支持范围，并在不支持的国密协议栈或套件失败时输出能力诊断
- 选择 GoTLCP 作为唯一内置国密传输 provider，主动模式支持标准 TLS 到 TLCP fallback，被动 MITM 支持标准 TLS/TLCP 握手阶段自动分流
- 新增重定向扩展
- 优化连接复用，提升性能
- 优化被动模式代理功能，优化大文件代理，大大提升响应速率
- 优化错误处理和日志输出
- 修复HTTP2支持问题

## [1.0.8] - 2025-07-13

- 新增 ZIP 文件内容完整性校验
- 新增更新失败自动回滚机制，更新成功清理临时文件
- 修复([Issues#11](https://github.com/HackAllSec/hfinger/issues/11))，增加重定向深度控制
- 清理无效请求，优化并发安全，提升性能

## [1.0.7] - 2025-07-11

- 修复([Issues#10](https://github.com/HackAllSec/hfinger/issues/10))
- 修复sheet名称超长问题
- 新增部分指纹

## [1.0.6] - 2024-09-08

- 增加xlsx输出结果，根据指纹生成sheet功能
- 增加部分指纹

## [1.0.5] - 2024-08-22

- 增加并优化指纹
- 优化代码，显著提升性能
- 修复同一目标无法匹配多个指纹的bug
- 修复自动跟随跳转导致漏报和被动模式异常的bug


## [1.0.4] - 2024-08-19

- 增加并优化指纹
- 新增被动模式下其它HTTP请求方法
- 修复无法代理某些HTTPS网站的情况

## [1.0.3] - 2024-08-14

- 增加并优化指纹
- 新增指纹库更新检测功能
- 新增收录的产品、Web框架和CMS总数输出功能


## [1.0.2] - 2024-08-06

- 优化了部分指纹，增加了部分指纹
- 上游代理支持身份认证，用户名密码中特殊字符需要进行url编码，如-p http://admin:admin%40123@proxyhost:proxyport
- 新增更新指纹库功能--update，更新失败请检查是否可以访问Github
- 新增升级功能--upgrade，升级失败请检查是否可以访问Github

## [1.0.1] - 2024-07-26

- 优化了部分指纹，增加了部分指纹
- 修复一些Bug
- 增加被动识别模式
- 重新实现icon_hash

## [1.0.0] - 2024-07-18

- 优化了部分指纹，解决EHole识别不到某些二次开发的CMS
- 增加同一目标匹配多个框架指纹识别
- 增加了finger.go自定义规则匹配逻辑
- 增加了XML文件输出
