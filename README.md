# WhiteURLScan网站信息扫描工具

## 项目简介

本项目是一个多线程高效的网站URL扫描与信息采集工具，支持递归爬取、自动拼接、敏感信息检测、外部URL收集、批量扫描等功能。适用于安全测试、信息收集、资产梳理等场景。

## 主要功能

- 支持递归扫描网站所有可达URL，自动去重
- 智能识别并拼接各种相对/绝对路径
- 检测页面中的敏感信息（如身份证号、手机号、API密钥等）
- 支持外部URL自动收集与访问结果统计
- 支持多线程并发扫描，速度快
- 支持批量URL扫描
- 实时彩色输出，结果自动保存为CSV文件
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

- `start_url`：起始扫描URL
- `max_workers`：最大线程数
- `timeout`：请求超时时间（秒）
- `max_depth`：最大递归深度（深度过大爬取所有链接后将直接结束程序）
- `output_file`：实时输出结果文件
- `blacklist_domains`：黑名单域名
- `extension_blacklist`：过滤的文件扩展名
- `max_urls`：最大扫描URL数量
- `smart_concatenation`：智能URL拼接
- `debug_mode`：调试模式（0关闭，1开启）
- `scope`：URL扫描范围模式 0主域 1外部一次 2全放开
- 其他参数详见 config.json

## 使用方法

### 1. 单个URL扫描

```bash
python WhiteURLScan.py -u https://example.com
```
![运行](https://raw.githubusercontent.com/white1434/WhiteURLScan/refs/heads/main/images/1.jpg)
### 2. 批量URL扫描

将多个URL写入 `url.txt`，每行一个，然后：

```bash
python WhiteURLScan.py -f url.txt
```

### 3. 常用命令行参数

- `-u`       起始URL
- `-f`       批量URL文件
- `-delay`    延迟时间（秒）
- `-workers` 最大线程数（如 30）
- `-timeout` 请求超时（秒）
- `-depth`   最大递归深度
- `-out`     实时输出文件路径
- `-proxy`   代理（如 http://127.0.0.1:8080）
- `-debug`   调试模式（1开启，0关闭）
- `-scope`   URL扫描范围模式 0主域 1外部一次 2全放开
- `-danger`  危险接口过滤（1开启，0关闭）
  
示例：

```bash
python WhiteURLScan.py -u https://example.com -workers 20 -timeout 8 -depth 3 -debug 1
```

## 输出说明

- 实时扫描结果会输出到控制台，并保存到 `results/` 目录下的CSV文件
- 外部URL访问结果也会自动追加到报告文件
- 日志文件为 `debug.log`（调试模式下）
![运行结果](https://raw.githubusercontent.com/white1434/WhiteURLScan/refs/heads/main/images/2.jpg)

## 注意事项

- 建议合理设置线程数、递归深度、延迟时间，避免对目标站点造成压力
- 递归深度如果过大，程序扫描玩所有页面链接后会直接结束，但可能陷入循环直到达到上限，请根据需求进行设置
- 敏感信息检测基于正则表达式，结果仅供参考，欢迎补充
- 请勿将本工具用于非法用途

## TODO
- 过滤危险接口
- 自定义提取路径
- 自定义拼接路径
- POST请求检测
- POST参数检测
- 动态api加载
- 拼接路径方式优化
- 浏览器模拟访问

## 感谢参考
- AI编写
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