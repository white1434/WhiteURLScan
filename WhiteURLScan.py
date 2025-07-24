import threading
import os
import sys
import argparse
import json
from colorama import Fore, Style
# 拆分结构导入
from core.scanner import UltimateURLScanner
from core.output import OutputHandler
from core.config import ScannerConfig
from core.url_matcher import URLMatcher
from core.sensitive import SensitiveDetector
from core.url_concat import URLConcatenator
from utils.logger import OutputLogger

output_logger = OutputLogger()  # 提升到全局作用域

output_lock = threading.Lock()

# 创建输出日志记录器
import sys
from datetime import datetime
# 禁用SSL警告
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLOR_SUPPORT = True
except ImportError:
    COLOR_SUPPORT = False
    Fore = Style = type('', (), {'__getattr__': lambda *args: ''})()


try:
    import tldextract
    DOMAIN_EXTRACTION = True
except ImportError:
    DOMAIN_EXTRACTION = False
# ====================== 异常处理装饰器 ======================
def handle_exceptions(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            if hasattr(args[0], '_debug_print'):
                args[0]._debug_print(f"异常: {str(e)}")
            return None
    return wrapper

def main():
    try:
        print(f"{Fore.YELLOW}=============================================={Style.RESET_ALL}")
        print(f"{Fore.YELLOW}=== WhiteURLScan v1.7.2 ===")
        print(f"{Fore.YELLOW}=== BY: white1434  GitHub: https://github.com/white1434/WhiteURLScan")
        print(f"{Fore.YELLOW}=== 重复的URL不会重复扫描, 结果返回相同的URL不会重复展示")
        print(f"{Fore.CYAN}=== 所有输出将同时记录到 results/output.out 文件中")
        print(f"{Fore.CYAN}=== 扫描开始时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        try:
            parser = argparse.ArgumentParser(description="WhiteURLScan 扫描工具")
            parser.add_argument('-u', dest='start_url', type=str, help='起始URL')
            parser.add_argument('-f', dest='url_file', type=str, help='批量URL文件，每行一个URL')
            parser.add_argument('-workers', dest='max_workers', type=int, help='最大线程数')
            parser.add_argument('-delay', dest='delay', type=float, help='请求延迟（秒）')
            parser.add_argument('-timeout', dest='timeout', type=int, help='请求超时（秒）')
            parser.add_argument('-depth', dest='max_depth', type=int, help='最大递归深度')
            parser.add_argument('-out', dest='output_file', type=str, help='实时输出文件')
            parser.add_argument('-proxy', dest='proxy', type=str, help='代理设置')
            parser.add_argument('-debug', dest='debug_mode', type=int, help='调试模式 1开启 0关闭')
            parser.add_argument('-scope', dest='url_scope_mode', type=int, help='URL扫描范围模式 0主域 1外部一次 2全放开 3白名单模式')
            parser.add_argument('-danger', dest='danger_filter_enabled', type=int, default=1, help='危险接口过滤 1开启 0关闭 (默认: 1)')
            parser.add_argument('-fuzz', dest='fuzz', type=int, default=0, help='是否启用自定义URL拼接参数 1启用 0关闭 (默认: 0)')
            args = parser.parse_args()
        except Exception as e:
            print(f"{Fore.RED}解析命令行参数时出错: {type(e).__name__}: {e}{Style.RESET_ALL}")
            sys.exit(1)

        # 必须至少输入 --start_url 或 --url_file
        if not args.start_url and not args.url_file:
            print(f"{Fore.RED}错误：-h查看帮助 , 必须通过 -u 或 -f 至少指定一个扫描目标！{Style.RESET_ALL}")
            sys.exit(1) 

        # 固定从config.json读取配置
        try:
            config_path = 'config.json'
            default_config = {
                "start_url": None,
                "proxy": None,
                "delay": 0.1,
                "max_workers": 30,
                "timeout": 5,
                "max_depth": 5,
                "blacklist_domains": ["www.w3.org", "www.baidu.com", "github.com"],
                "whitelist_domains": ["example.com", "test.com"],  # 新增白名单域名
                "headers": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                    "Connection": "keep-alive",
                    "Upgrade-Insecure-Requests": "1"
                },
                "output_file": "results/实时输出文件.csv",
                "color_output": True,
                "verbose": True,
                "extension_blacklist": [".css", ".mp4"],
                # "extension_blacklist": [
                #     ".css", ".jpg", ".jpeg", ".png", ".gif", ".svg", ".woff", ".woff2", 
                #     ".ttf", ".eot", ".ico", ".mp4", ".mp3", ".avi", ".mov", ".pdf", 
                #     ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".zip", ".rar",
                #     ".gz", ".tar", ".7z", ".exe", ".dll", ".bin", ".swf", ".flv"
                # ],
                "max_urls": 10000,
                "smart_concatenation": True,
                "debug_mode": 0,
                "url_scope_mode": 0,
                "danger_filter_enabled": 1,
                "danger_api_list": ["del","delete","insert","logout","loginout","remove","drop","shutdown","stop","poweroff","restart","rewrite","terminate","deactivate","halt","disable"]
            }
            if not os.path.exists(config_path):
                with open(config_path, 'w', encoding='utf-8') as f:
                    json.dump(default_config, f, ensure_ascii=False, indent=2)
                print(f"{Fore.YELLOW}=== 未检测到config.json，已自动创建默认配置文件！请根据需要修改。{Style.RESET_ALL}")
            with open(config_path, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
        except Exception as e:
            print(f"{Fore.RED}读取配置文件时出错: {type(e).__name__}: {e}{Style.RESET_ALL}")
            sys.exit(1)

        # 命令行参数优先级高于配置文件
        def get_config_value(key, default=None):
            return getattr(args, key, None) if getattr(args, key, None) is not None else config_data.get(key, default)

        try:
            print(f"{Fore.CYAN}=== 正在初始化扫描器...{Style.RESET_ALL}")
            # 创建配置
            config = ScannerConfig(
                start_url=get_config_value('start_url'),
                proxy=get_config_value('proxy'),
                delay=get_config_value('delay', 0.1),
                max_workers=get_config_value('max_workers', 30),
                timeout=get_config_value('timeout', 5),
                max_depth=get_config_value('max_depth', 5),
                blacklist_domains=get_config_value('blacklist_domains'),
                whitelist_domains=get_config_value('whitelist_domains'),
                headers=get_config_value('headers'),
                output_file=get_config_value('output_file', 'results/实时输出文件.csv'),
                color_output=get_config_value('color_output', True),
                verbose=get_config_value('verbose', True),
                extension_blacklist=get_config_value('extension_blacklist', ['.css','.mp4']),
                max_urls=get_config_value('max_urls', 10000),
                smart_concatenation=get_config_value('smart_concatenation', True),
                debug_mode=get_config_value('debug_mode', 0),
                url_scope_mode=get_config_value('url_scope_mode', 0),
                danger_filter_enabled=get_config_value('danger_filter_enabled', 1),
                danger_api_list=get_config_value('danger_api_list'),
                is_duplicate=get_config_value('is_duplicate', 0),
                custom_base_url=get_config_value('custom_base_url', []),
                path_route=get_config_value('path_route', []),
                api_route=get_config_value('api_route', []),
                fuzz=get_config_value('fuzz', 0),
                domain_extraction=DOMAIN_EXTRACTION
            )

            # 打印所有配置
            print(f"{Fore.CYAN}=============================================={Style.RESET_ALL}")    
            print(f"{Fore.CYAN}=== 开始链接: {config.start_url}")
            print(f"{Fore.CYAN}=== 代理设置: {config.proxy}")
            print(f"{Fore.CYAN}=== 延迟设置: {config.delay}")
            print(f"{Fore.CYAN}=== 最大线程: {config.max_workers}")
            print(f"{Fore.CYAN}=== 请求超时: {config.timeout}")
            print(f"{Fore.CYAN}=== 最大深度: {config.max_depth}")
            print(f"{Fore.CYAN}=== 黑域名单: {config.blacklist_domains}")
            print(f"{Fore.CYAN}=== 白域名单: {config.whitelist_domains}")
            print(f"{Fore.CYAN}=== 请求的头: {config.headers}")
            print(f"{Fore.CYAN}=== 实时文件: {config.output_file}")
            print(f"{Fore.CYAN}=== 彩色输出: {config.color_output}")
            print(f"{Fore.CYAN}=== 详细输出: {config.verbose}")
            print(f"{Fore.CYAN}=== 跳过扩展: {config.extension_blacklist}")
            print(f"{Fore.CYAN}=== 最大请求: {config.max_urls}")
            print(f"{Fore.CYAN}=== 智能拼接: {config.smart_concatenation}")
            print(f"{Fore.CYAN}=== 调试模式: {config.debug_mode}")
            print(f"{Fore.CYAN}=== 扫描范围: {config.url_scope_mode}")
            print(f"{Fore.CYAN}=== 危险过滤: {config.danger_filter_enabled}")
            print(f"{Fore.CYAN}=== 危险接口: {config.danger_api_list}")
            print(f"{Fore.CYAN}=== 开启重复: {config.is_duplicate}")
            print(f"{Fore.CYAN}=== 自定地址: {config.custom_base_url}")
            print(f"{Fore.CYAN}=== 自定路径: {config.path_route}")
            print(f"{Fore.CYAN}=== 自定API: {config.api_route}")
            print(f"{Fore.CYAN}=== 启用fuzz: {config.fuzz}")
            print(f"{Fore.CYAN}=============================================={Style.RESET_ALL}")
            
            # 如果输入的是-u, 则直接开始扫描
            if args.start_url:
                print(f"{Fore.YELLOW}开始扫描: {args.start_url}{Style.RESET_ALL}")
                scanner = UltimateURLScanner(config, output_lock=output_lock)
                scanner.start_scanning()
            # 如果输入的是-f 则读取url_file文件, 遍历更新config.start_url, 然后循环开始扫描
            elif args.url_file:
                try:
                    if not os.path.exists(args.url_file):
                        print(f"{Fore.RED}错误：URL文件 {args.url_file} 不存在！{Style.RESET_ALL}")
                        sys.exit(1)
                    
                    with open(args.url_file, 'r', encoding='utf-8') as f:
                        urls = [line.strip() for line in f if line.strip()]
                    
                    print(f"{Fore.YELLOW}从文件读取到 {len(urls)} 个URL，开始批量扫描...{Style.RESET_ALL}")
                    
                    all_results = []  # 新增：用于汇总所有扫描结果
                    all_external_results = []  # 新增：用于汇总所有外链结果
                    all_danger_results = []  # 新增：用于汇总所有危险接口
                    batch_summary_file = f"results/all_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
                    for i, url in enumerate(urls, 1):
                        try:
                            print(f"{Fore.CYAN}=============================================={Style.RESET_ALL}")
                            print(f"{Fore.CYAN}[{i}/{len(urls)}] 开始扫描: {url}{Style.RESET_ALL}")
                            # 为每个URL创建独立的配置实例
                            url_config = ScannerConfig(
                                start_url=url,
                                proxy=get_config_value('proxy'),
                                delay=get_config_value('delay', 0.1),
                                max_workers=get_config_value('max_workers', 30),
                                timeout=get_config_value('timeout', 5),
                                max_depth=get_config_value('max_depth', 5),
                                blacklist_domains=get_config_value('blacklist_domains'),
                                whitelist_domains=get_config_value('whitelist_domains'),
                                headers=get_config_value('headers'),
                                output_file=get_config_value('output_file', 'results/实时输出文件.csv'),
                                color_output=get_config_value('color_output', True),
                                verbose=get_config_value('verbose', True),
                                extension_blacklist=get_config_value('extension_blacklist', ['.css','.mp4']),
                                max_urls=get_config_value('max_urls', 10000),
                                smart_concatenation=get_config_value('smart_concatenation', True),
                                debug_mode=get_config_value('debug_mode', 0),
                                url_scope_mode=get_config_value('url_scope_mode', 0),
                                danger_filter_enabled=get_config_value('danger_filter_enabled', 1),
                                danger_api_list=get_config_value('danger_api_list'),
                                is_duplicate=get_config_value('is_duplicate', 0),
                                custom_base_url=get_config_value('custom_base_url', []),
                                path_route=get_config_value('path_route', []),
                                api_route=get_config_value('api_route', []),
                                fuzz=get_config_value('fuzz', 0),
                                domain_extraction=DOMAIN_EXTRACTION
                            )
                            scanner = UltimateURLScanner(url_config, output_lock=output_lock)
                            scanner.start_scanning()
                            # 新增：收集每个URL的扫描结果
                            if hasattr(scanner, 'results'):
                                all_results.extend(scanner.results)
                            # 新增：收集外链结果
                            if hasattr(scanner, 'external_results'):
                                # print(f"{Fore.CYAN}收集到外链结果: {scanner.external_results}{Style.RESET_ALL}")
                                all_external_results.extend(scanner.external_results)
                            # 新增：收集危险接口（全局集合，需转为结果格式）
                            if hasattr(scanner, 'config') and hasattr(scanner, 'output_handler'):
                                for danger_url in URLMatcher.danger_api_filtered:
                                    # 检测危险类型
                                    danger_types = []
                                    for danger_api in scanner.config.danger_api_list:
                                        if danger_api in danger_url and not danger_url.endswith(".js"):
                                            danger_types.append(danger_api)
                                    danger_type_str = ", ".join(danger_types) if danger_types else "未知"
                                    danger_result = {
                                        'url': danger_url,
                                        'status': '危险',
                                        'title': '危险接口',
                                        'length': 0,
                                        'redirects': '',
                                        'depth': 0,
                                        'time': 0,
                                        'sensitive': danger_type_str,
                                        'sensitive_raw': [{'type': danger_type_str, 'count': 1, 'samples': [danger_url]}],
                                        'is_duplicate_signature': False,
                                        'content_type': '',
                                        'headers_count': 0,
                                        'error_type': None,
                                        'original_url': url,
                                    }
                                    all_danger_results.append(danger_result)
                        except Exception as e:
                            print(f"{Fore.RED}扫描URL {url} 时出错: {type(e).__name__}: {e}{Style.RESET_ALL}")
                            continue
                    # 新增：批量扫描结束后，统一输出汇总文件（主域+外链+危险接口）
                    output_handler = OutputHandler(config, output_lock=output_lock)
                    if all_results:
                        output_handler.generate_report(all_results, batch_summary_file)
                    if all_external_results:
                        output_handler.append_results(all_external_results, batch_summary_file)
                    if all_danger_results:
                        output_handler.append_results(all_danger_results, batch_summary_file)
                    if all_results or all_external_results or all_danger_results:
                        print(f"{Fore.GREEN}所有扫描结果（含外链/危险接口）已汇总到: {batch_summary_file}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.YELLOW}未收集到任何扫描结果，未生成汇总文件。{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}处理URL文件时出错: {type(e).__name__}: {e}{Style.RESET_ALL}")
                    sys.exit(1)
        except Exception as e:
            print(f"{Fore.RED}初始化扫描器时出错: {type(e).__name__}: {e}{Style.RESET_ALL}")
            sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}程序运行出错: {type(e).__name__}: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    finally:
        # 恢复原始的stdout和stderr
        sys.stdout = output_logger.original_stdout
        sys.stderr = output_logger.original_stderr
        # 关闭日志文件
        output_logger.close()
        print(f"{Fore.GREEN}输出日志已保存到: results/output.out{Style.RESET_ALL}")
        print(f"{Fore.GREEN}扫描结束时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
    
