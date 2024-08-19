## v1.0.0-2024-07-18

- 优化了部分指纹，解决EHole识别不到某些二次开发的CMS
- 增加同一目标匹配多个框架指纹识别
- 增加了finger.go自定义规则匹配逻辑
- 增加了XML文件输出

## v1.0.1-2024-07-26

- 优化了部分指纹，增加了部分指纹
- 修复一些Bug
- 增加被动识别模式
- 重新实现icon_hash

## v1.0.2-2024-08-06

- 优化了部分指纹，增加了部分指纹
- 上游代理支持身份认证，用户名密码中特殊字符需要进行url编码，如-p http://admin:admin%40123@proxyhost:proxyport
- 新增更新指纹库功能--update，更新失败请检查是否可以访问Github
- 新增升级功能--upgrade，升级失败请检查是否可以访问Github

## v1.0.3-2024-08-14

- 增加并优化指纹
- 新增指纹库更新检测功能
- 新增收录的产品、Web框架和CMS总数输出功能

## v1.0.4-2024-08-19

- 增加并优化指纹
- 新增被动模式下其它HTTP请求方法
- 修复无法代理某些HTTPS网站的情况