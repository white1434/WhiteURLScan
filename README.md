# WhiteURLScan 网站信息扫描工具

## 项目简介

WhiteURLScan 是一款多线程高效的网站 URL 扫描与信息采集工具，支持递归爬取、自动拼接、敏感信息检测、外部 URL 收集、批量扫描等功能。适用于安全测试、信息收集、资产梳理等场景。

## 主要功能

- 递归扫描网站所有可达 URL，自动去重
- 智能识别并拼接各种相对/绝对路径
- 支持自定义基地址、API 路由、路径路由拼接（fuzz 模式）
- 检测页面中的敏感信息（如身份证号、手机号、API 密钥等）
- 外部 URL 自动收集与访问结果统计
- 多线程并发扫描，速度快
- 批量 URL 扫描
- 实时彩色输出，结果自动保存为 CSV 文件
- 支持自定义请求头、代理、黑名单域名、扩展名过滤等
- 丰富的调试与日志输出，便于问题排查

## 安装依赖

建议使用 Python 3.7 及以上版本。

```bash
pip install -r requirements.txt
```

**主要依赖包：**
- requests
- beautifulsoup4
- tldextract
- colorama

如缺少依赖，可手动安装：

```bash
pip install requests beautifulsoup4 tldextract colorama
```

## 配置说明

首次运行会自动生成 `config.json`，可根据实际需求修改：

- `start_url`：起始扫描 URL
- `max_workers`：最大线程数
- `timeout`：请求超时时间（秒）
- `max_depth`：最大递归深度（深度过大爬取所有链接后将直接结束程序）
- `output_file`：实时输出结果文件
- `blacklist_domains`：黑名单域名
- `extension_blacklist`：过滤的文件扩展名
- `max_urls`：最大扫描 URL 数量
- `smart_concatenation`：智能 URL 拼接
- `debug_mode`：调试模式（0 关闭，1 开启）
- `scope`：URL 扫描范围模式 0 主域、 1 外部链接只访问一次 、2 无限制 、3 白名单模式（只访问白名单域名）
- `whitelist_domains`：白名单域名（scope=3 时使用）
- `danger_api_list`：危险 API 过滤列表
- `is_duplicate`：是否输出重复链接（返回内容相同即视为重复，0 关闭 1 开启）
- `custom_base_url`：自定义基地址列表（fuzz 模式下生效）
- `path_route`：自定义路径路由列表（fuzz 模式下生效）
- `api_route`：自定义 API 路由列表（fuzz 模式下生效）
- `fuzz`：是否启用自定义 URL 拼接参数（0 关闭，1 启用）
- 其他参数详见 config.json

## 使用方法

### 1. 单个 URL 扫描

```bash
python WhiteURLScan.py -u https://example.com -workers 20 -delay 1 -timeout 8 -depth 3
```

![运行](https://raw.githubusercontent.com/white1434/WhiteURLScan/refs/heads/main/images/1.jpg)

### 2. 批量 URL 扫描

将多个 URL 写入 `url.txt`，每行一个，然后：

```bash
python WhiteURLScan.py -f url.txt -workers 20 -delay 1 -timeout 8 -depth 3
```

### 3. 启用自定义 URL 拼接（fuzz 模式）

需要在配置文件中配置自定义参数custom_base_url、path_route、api_route

```bash
python WhiteURLScan.py -f url.txt -fuzz 1 -scope 3 -danger 1 -proxy http://127.0.0.1:8080
```

- `-u`       起始URL
- `-f`       批量URL文件
- `-delay`    延迟时间（秒）
- `-workers` 最大线程数（如 30）
- `-timeout` 请求超时（秒）
- `-depth`   最大递归深度
- `-out`     实时输出文件路径
- `-proxy`   代理（如 http://127.0.0.1:8080）
- `-debug`   调试模式（1开启，0关闭）
- `-scope`   URL扫描范围模式 0主域 1外部一次 2全放开 3白名单模式
- `-danger`  危险接口过滤（1开启，0关闭）
- `-fuzz`   自定义 URL 拼接
  

## 输出说明

- 实时扫描结果会输出到控制台，并保存到 `results/` 目录下的 CSV 文件
- 外部 URL 访问结果也会自动追加到报告文件
- 日志文件为 `results/output.out`

![运行结果](https://raw.githubusercontent.com/white1434/WhiteURLScan/refs/heads/main/images/2.jpg)

## 常见问题与建议

- 建议合理设置线程数、递归深度、延迟时间，避免对目标站点造成压力
- 递归深度过大时，程序会扫描所有页面链接后自动结束，注意最大 URL 数量限制
- 敏感信息检测基于正则表达式，结果仅供参考，欢迎补充
- fuzz 模式适合接口批量爆破、路径探测等高级用法，普通扫描建议关闭
- 请勿将本工具用于非法用途

## TODO
- [x] 多线程功能
- [x] 代理功能
- [x] 正则匹配功能
- [x] 文件保存功能
- [x] 参数配置功能
- [x] 敏感信息检测功能
- [x] 危险接口过滤功能
- [x] 域名黑名单检测功能
- [x] 域名白名单模式
- [x] 自定义请求头功能
- [x] 指定基地址进行拼接（fuzz）
- [x] 自定义 fuzz 列表
- [x] 自定义 api 路径
- [ ] webpack 打包网站 js 提取
- [ ] 指纹识别功能
- [ ] POST 请求检测
- [ ] 动态 api 加载
- [ ] 浏览器模拟访问
- [ ] 网页返回类型细分
- [ ] 优化敏感信息匹配
- [ ] 优化路径匹配
- [ ] 优化拼接方式
- [ ] 优化代码结构

## 参考与致谢
- AI 编写
- https://github.com/pingc0y/URLFinder
- https://github.com/gh0stkey/HaE
- https://github.com/momosecurity/FindSomething
- https://github.com/Str1am/Auto_JsFinder
- https://github.com/Threezh1/JSFinder
- https://github.com/GerbenJavado/LinkFinder
- https://github.com/ttstormxx/jjjjjjjjjjjjjs
- https://github.com/0x727/ChkApi_0x727
- https://github.com/Snow-Mountain-Passengers/Rotor-Goddess

## 联系方式

如有建议或问题，欢迎反馈！ 
