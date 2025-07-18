import re
import time
import queue
import threading
import csv
import requests
import os
import sys
import urllib.parse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
import logging
import hashlib
import warnings
from bs4 import XMLParsedAsHTMLWarning, MarkupResemblesLocatorWarning
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)
import argparse
import json

output_lock = threading.Lock()
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

# ====================== 通用调试输出 Mixin ======================
class DebugMixin:
    def _debug_print(self, message):
        if hasattr(self, 'debug_mode') and self.debug_mode:
            debug_prefix = f"{Fore.MAGENTA}[DEBUG]{Style.RESET_ALL}"
            print(f"{debug_prefix} {message}")
            try:
                logging.debug(message)
            except Exception:
                pass

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

# ====================== 配置模块 ======================
class ScannerConfig(DebugMixin):
    def __init__(self, start_url, proxy=None, delay=0, max_workers=10, timeout=10,
                 max_depth=1, blacklist_domains=None, headers=None, output_file=None,
                 sensitive_patterns=None, color_output=True, verbose=True,
                 extension_blacklist=None, max_urls=5000, smart_concatenation=True,
                 debug_mode=False, url_scope_mode=0):  # 新增 url_scope_mode
        self.start_url = start_url
        self.proxy = {'http': proxy, 'https': proxy} if proxy else None
        self.delay = delay
        self.max_workers = max_workers
        self.timeout = timeout
        self.max_depth = max_depth
        self.blacklist_domains = set(blacklist_domains or [])
        self.output_file = output_file
        self.color_output = color_output and COLOR_SUPPORT
        self.verbose = verbose
        self.max_urls = max_urls
        self.smart_concatenation = smart_concatenation
        self.debug_mode = debug_mode
        self.url_scope_mode = int(url_scope_mode)  # 新增
        if start_url and DOMAIN_EXTRACTION:
            ext = tldextract.extract(start_url)
            self.base_domain = f"{ext.domain}.{ext.suffix}"
        elif start_url:
            parsed = urllib.parse.urlparse(start_url)
            self.base_domain = parsed.netloc
        else:
            self.base_domain = None
        # 如果没有配置，则默认过滤下面的类型
        self.extension_blacklist = set(extension_blacklist or [
            '.css', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.woff', '.woff2', 
            '.ttf', '.eot', '.ico', '.mp4', '.mp3', '.avi', '.mov', '.pdf', 
            '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.zip', '.rar',
            '.gz', '.tar', '.7z', '.exe', '.dll', '.bin', '.swf', '.flv'
        ])
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        if headers:
            self.headers.update(headers)
        self.sensitive_patterns = sensitive_patterns or self.default_sensitive_patterns()
        if self.debug_mode:
            logging.basicConfig(
                filename='debug.log',
                filemode='a',
                format='%(asctime)s %(levelname)s %(message)s',
                level=logging.DEBUG,
                encoding='utf-8'
            )
            self._debug_print(f"配置初始化完成: 起始URL: {start_url} 基础域名: {self.base_domain} 代理: {proxy} 最大深度: {max_depth} 最大URL数: {max_urls} 线程数: {max_workers} 调试: {debug_mode}")
    @staticmethod
    def default_sensitive_patterns():
        return {
            '身份证号': r'\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b',
            '手机号': r'\b1(?:3\d|4[5-9]|5[0-35-9]|6[5-7]|7[0-8]|8\d|9[189])\d{8}\b',
            'API密钥': r'(?i)(api[_-]?key|access[_-]?key|secret[_-]?key)\s*[:=]\s*[\'\"][a-zA-Z0-9_\-]{10,}[\'\"]',
            'JWT令牌': r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9._-]{10,}\.[a-zA-Z0-9._-]{10,}',
            '邮箱': r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.(?!js|css|jpg|jpeg|png|ico|svg|gif|woff|ttf|eot|mp4|mp3|json|map|zip|rar|exe|dll|bin|swf|flv)[a-zA-Z]{2,10}\b',
            '密码': r'(?i)(password|passwd|pwd|pass|passcode|userpass)\s*[:=]\s*[\'\"][^\'\"]{6,}[\'\"]',
            '阿里云密钥': r'\bLTAI[a-zA-Z0-9]{12,20}\b',
            '腾讯云密钥': r'\bAKID[a-zA-Z0-9]{16,28}\b',
            '百度云密钥': r'\bAK[a-zA-Z0-9]{32}\b',
            '数据库连接': r'(?i)(mysql|postgresql|mongodb|redis|oracle|sqlserver)://[a-zA-Z0-9_]+:[^@]+@[a-zA-Z0-9.-]+:[0-9]+/[a-zA-Z0-9_]+',
            '统一社会信用代码': r'\b[0-9A-Z]{18}\b',
            '企业注册号': r'\b\d{13,15}\b',
            '内网IP': r'\b(127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b',
            'MAC地址': r'\b([a-fA-F0-9]{2}[:-]){5}[a-fA-F0-9]{2}\b',
            'Windows路径': r'(?:[a-zA-Z]:\\\\(?:[^<>:"/\\\\|?*\r\n]+\\\\)*[^<>:"/\\\\|?*\r\n]*)',
            'JDBC连接': r'jdbc:[a-z:]+://[a-zA-Z0-9_\-.:;=/@?,&]+',
            'Authorization': r'(?i)(basic [a-z0-9=:_\+/-]{5,100}|bearer [a-z0-9_.=:_\+/-]{5,100})',
            '敏感字段': r'(?i)(key|secret|token|config|auth|access|admin|ticket)\s*[:=]\s*[\'\"][^\'\"]{6,}[\'\"]',
        }

# ====================== URL拼接模块 ======================
class URLConcatenator(DebugMixin):
    def __init__(self, debug_mode=False):
        self.debug_mode = debug_mode
    
    def smart_concatenation(self, base_url, relative_url):
        if self.debug_mode:
            self._debug_print(f"开始拼接URL: base={base_url}, relative={relative_url}")
        
        # 处理协议相对URL (//example.com/path)
        if relative_url.startswith('//'):
            base = urllib.parse.urlparse(base_url)
            result = f"{base.scheme}:{relative_url}"
            if self.debug_mode:
                self._debug_print(f"协议相对URL处理: {result}")
            return result
        
        # 处理hash路由（SPA应用）
        if relative_url.startswith('#/'):
            base = urllib.parse.urlparse(base_url)
            # 保留原始URL的hash部分
            result = f"{base.scheme}://{base.netloc}{base.path}{relative_url}"
            if self.debug_mode:
                self._debug_print(f"Hash路由处理: {result}")
            return result
        
        # 处理绝对路径
        if relative_url.startswith('/'):
            base = urllib.parse.urlparse(base_url)
            # 确保路径不以双斜杠开头
            clean_path = relative_url.lstrip('/')
            result = f"{base.scheme}://{base.netloc}/{clean_path}"
            if self.debug_mode:
                self._debug_print(f"绝对路径处理: {result}")
            return result
        
        # 处理相对路径
        if relative_url.startswith('./'):
            base = urllib.parse.urlparse(base_url)
            base_path = os.path.dirname(base.path) if not base.path.endswith('/') else base.path
            # 确保路径不以双斜杠开头
            clean_relative = relative_url[2:].lstrip('/')
            result = f"{base.scheme}://{base.netloc}{base_path}/{clean_relative}"
            if self.debug_mode:
                self._debug_print(f"相对路径处理: {result}")
            return result
        
        # 处理上级目录
        if relative_url.startswith('../'):
            base = urllib.parse.urlparse(base_url)
            path_parts = base.path.split('/')
            rel_parts = relative_url.split('/')
            
            # 计算新的路径深度
            back_count = 0
            new_parts = []
            for part in rel_parts:
                if part == '..':
                    back_count += 1
                else:
                    new_parts.append(part)
            
            # 构建新路径
            if len(path_parts) > back_count:
                # 确保路径不以双斜杠开头
                clean_parts = [p for p in path_parts[:len(path_parts)-back_count] if p]
                new_path = '/'.join(clean_parts) + '/' + '/'.join(new_parts)
            else:
                new_path = '/' + '/'.join(new_parts)
            
            # 确保路径格式正确
            if new_path.startswith('//'):
                new_path = new_path[1:]
            result = f"{base.scheme}://{base.netloc}{new_path}"
            if self.debug_mode:
                self._debug_print(f"上级目录处理: {result}")
            return result
        
        # 处理完整URL
        if relative_url.startswith('http'):
            if self.debug_mode:
                self._debug_print(f"完整URL直接返回: {relative_url}")
            return relative_url
        
        # 默认拼接 - 使用urljoin但清理双斜杠
        joined = urllib.parse.urljoin(base_url, relative_url)
        parsed = urllib.parse.urlparse(joined)
        # 清理路径中的双斜杠
        clean_path = re.sub(r'/{2,}', '/', parsed.path)
        result = urllib.parse.urlunparse((
            parsed.scheme,
            parsed.netloc,
            clean_path,
            parsed.params,
            parsed.query,
            parsed.fragment
        ))
        if self.debug_mode:
            self._debug_print(f"默认拼接处理: {result}")
        return result


# ====================== URL匹配模块 ======================
class URLMatcher(DebugMixin):
    def __init__(self, config, scanner=None):
        self.config = config
        self.concatenator = URLConcatenator(config.debug_mode)
        self.scanner = scanner  # 新增：可选scanner实例
    
    def is_valid_domain(self, url):
        if self.config.url_scope_mode == 2:
            return True  # 完全放开
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc
        
        if self.config.debug_mode:
            self._debug_print(f"检查域名有效性: {domain}")
        
        # 检查黑名单
        for black_domain in self.config.blacklist_domains:
            if black_domain in domain:
                if self.config.debug_mode:
                    self._debug_print(f"域名在黑名单中: {domain} (匹配: {black_domain})")
                return False

        # 检查是否属于同一主域或其子域
        if DOMAIN_EXTRACTION:
            ext = tldextract.extract(url)
            url_domain = f"{ext.domain}.{ext.suffix}"
            is_valid = url_domain == self.config.base_domain
            # print(url)
        else:
            is_valid = domain == self.config.base_domain or domain.endswith('.' + self.config.base_domain)
        
        if self.config.debug_mode:
            self._debug_print(f"域名检查结果: {domain} -> {'有效' if is_valid else '无效'}")
   
        return is_valid
    
    def should_skip_url(self, url):
        """检查URL是否应该跳过（基于扩展名）"""
        parsed = urllib.parse.urlparse(url)
        path = parsed.path.lower()
        
        if self.config.debug_mode:
            self._debug_print(f"检查URL是否跳过: {url}")
        
        # 检查扩展名黑名单
        for ext in self.config.extension_blacklist:
            if path.endswith(ext):
                if self.config.debug_mode:
                    self._debug_print(f"URL因扩展名跳过: {url} (扩展名: {ext})")
                return True
        
        if self.config.debug_mode:
            self._debug_print(f"URL检查通过: {url}")
        
        return False
    
    def extract_urls(self, content, base_url):
        """从内容中提取URL - 全新匹配逻辑，专注于路径字符串"""
        urls = set()
        
        if self.config.debug_mode:
            self._debug_print(f"开始从内容提取URL: base_url={base_url}")
        
        # 处理文本内容
        text_content = content.decode('utf-8', 'ignore') if isinstance(content, bytes) else content
        
        # 主要匹配模式：捕获引号内的路径字符串
        # 匹配形式："/path/to/resource" 或 '/path/to/resource' 或 `/path/to/resource`
        path_patterns = [
            r'["\'](/[^"\'\s]+)["\']',  # 双引号或单引号包裹的绝对路径
            r'["\'](\.{1,2}/[^"\'\s]+)["\']',  # 双引号或单引号包裹的相对路径
            r'`(/([^`\s]+))`',  # 反引号包裹的绝对路径
            r'`(\.{1,2}/[^`\s]+)`',  # 反引号包裹的相对路径
            r'\b(?:href|src|action)\s*=\s*["\']?([^"\'\s>]+)',  # HTML属性值
            # 新增：匹配assets下的静态资源（js/css/img等）
            r'(assets/[a-zA-Z0-9_\-./]+\.(js|css|png|jpg|jpeg|svg|gif|woff2?|ttf|eot|mp4|mp3|json|map))',
            # 完整URL
            r'[\'"`]((?:https?://|//)[^\s\'"`]+)[\'"`]',
            # 绝对路径
            r'[\'"`](/[^\s\'"`]+)[\'"`]',
            # 相对路径
            r'[\'"`](\.{1,2}/[^\s\'"`]+)[\'"`]',
            # CSS url()
            r'url\([\'"]?([^\s\'")]+)[\'"]?\)',
            # JS动态URL
            r'\.(?:get|post|put|delete|patch|options|head|connect)\([\'"`]([^\s\'"`]+)[\'"`]',
            r'window\.location\s*=\s*[\'"`]([^\s\'"`]+)[\'"`]',
            r'window\.open\([\'"`]([^\s\'"`]+)[\'"`]',
            r'fetch\([\'"`]([^\s\'"`]+)[\'"`]',
            r'axios\.(?:get|post|put|delete|patch|options|head|connect)\([\'"`]([^\s\'"`]+)[\'"`]',
            r'\.src\s*=\s*[\'"`]([^\s\'"`]+)[\'"`]',
            r'\.href\s*=\s*[\'"`]([^\s\'"`]+)[\'"`]',
            r'\.action\s*=\s*[\'"`]([^\s\'"`]+)[\'"`]',
            # JSON格式URL
            r'[\'"`]url[\'"`]\s*:\s*[\'"`]([^\s\'"`]+)[\'"`]',
            r'[\'"`](?:src|href)[\'"`]\s*:\s*[\'"`]([^\s\'"`]+)[\'"`]',
            # 模板字符串中的URL
            r'`(https?://[^`]+)`',
            r'`(?:/{1,2}|\.{1,2}/)[^`]+`',
            # 单页面应用路由
            r'router\.(?:push|replace)\([\'"`]([^\s\'"`]+)[\'"`]',
            r'<Route\s+path=[\'"`]([^\s\'"`]+)[\'"`]',
            # API端点模式
            r'[\'"`]/api/v\d+/[^\s\'"`]+[\'"`]',
            r'[\'"`]/\w+/\w+\.(?:php|aspx|jsp)[\?]?[^\s\'"`]*[\'"`]',
            # 新增: 匹配无引号的相对路径 (如 $.get(entrance))
            r'(?:\.get|\.post|\.ajax|fetch|axios\.get|axios\.post)\s*\(\s*([\'"`]?)([a-zA-Z0-9_\/-]+)\1',  # 新增DataInterface.do专用
            r'[\'"`](/?DataInterface\\.do(?:\?[^\s\'"`]*)?)[\'"`]',  # 新增DataInterface.do路径
            # 新增: 匹配jQuery风格的调用 ($.get("entrance"))
            r'\$\.(?:get|post|ajax)\s*\(\s*[\'"`]([^\s\'"`]+)[\'"`]',          
            # 新增: 匹配JSX/React路由 (如 <Route path="/admin">)
            r'<Route\s+path=[\'"`]([^\s\'"`]+)[\'"`]',
            # 增强模板字符串匹配: 支持相对路径
            r'`(?:https?://[^`]+|/{1,2}[^`]+|\.{1,2}/[^`]+)`',
            # 新增: 匹配JS中的动态路由定义
            r'router\.(?:addRoute|addRoutes)\s*\(\s*[\'"`]([^\s\'"`]+)[\'"`]',
            # 新增: 匹配CommonJS导入 (如 require("./api"))
            r'require\s*\(\s*[\'"`](\.[^\s\'"`]+)[\'"`]',
            # 新增: 匹配ES6动态导入 (如 import("./module"))
            r'import\s*\(\s*[\'"`](\.[^\s\'"`]+)[\'"`]'
        ]
        
        # 辅助匹配模式：捕获HTML标签中的路径属性（支持属性顺序任意，增加常用标签）
        tag_patterns = [
            # 兼容单双引号、无引号、属性顺序变化
            r'<script\b[^>]*?\bsrc\s*=\s*([\'\"])(.*?)\1',   # script标签的src属性（单双引号）
            r'<script\b[^>]*?\bsrc\s*=\s*([^\s>]+)',           # script标签的src属性（无引号）
            r'<link\b[^>]*?\bhref\s*=\s*([\'\"])(.*?)\1',    # link标签的href属性（单双引号）
            r'<link\b[^>]*?\bhref\s*=\s*([^\s>]+)',             # link标签的href属性（无引号）
            r'<img\b[^>]*?\bsrc\s*=\s*([\'\"])(.*?)\1',      # img标签的src属性（单双引号）
            r'<img\b[^>]*?\bsrc\s*=\s*([^\s>]+)',               # img标签的src属性（无引号）
            r'<a\b[^>]*?href\s*=\s*([\'\"])(.*?)\1',          # a标签的href属性（单双引号）
            r'<a\b[^>]*?href\s*=\s*([^\s>]+)',                   # a标签的href属性（无引号）
            r'<form\b[^>]*?\baction\s*=\s*([\'\"])(.*?)\1',   # form标签的action属性（单双引号）
            r'<form\b[^>]*?\baction\s*=\s*([^\s>]+)',            # form标签的action属性（无引号）
            r'<iframe\b[^>]*?\bsrc\s*=\s*([\'\"])(.*?)\1',    # iframe标签的src属性（单双引号）
            r'<iframe\b[^>]*?\bsrc\s*=\s*([^\s>]+)',             # iframe标签的src属性（无引号）
            r'<video\b[^>]*?\bsrc\s*=\s*([\'\"])(.*?)\1',     # video标签的src属性（单双引号）
            r'<video\b[^>]*?\bsrc\s*=\s*([^\s>]+)',              # video标签的src属性（无引号）
            r'<audio\b[^>]*?\bsrc\s*=\s*([\'\"])(.*?)\1',     # audio标签的src属性（单双引号）
            r'<audio\b[^>]*?\bsrc\s*=\s*([^\s>]+)',              # audio标签的src属性（无引号）
            r'<source\b[^>]*?\bsrc\s*=\s*([\'\"])(.*?)\1',    # source标签的src属性（单双引号）
            r'<source\b[^>]*?\bsrc\s*=\s*([^\s>]+)',             # source标签的src属性（无引号）
            r'<embed\b[^>]*?\bsrc\s*=\s*([\'\"])(.*?)\1',     # embed标签的src属性（单双引号）
            r'<embed\b[^>]*?\bsrc\s*=\s*([^\s>]+)',              # embed标签的src属性（无引号）
            r'<object\b[^>]*?\bdata\s*=\s*([\'\"])(.*?)\1',   # object标签的data属性（单双引号）
            r'<object\b[^>]*?\bdata\s*=\s*([^\s>]+)',            # object标签的data属性（无引号）
            r'<track\b[^>]*?\bsrc\s*=\s*([\'\"])(.*?)\1',     # track标签的src属性（单双引号）
            r'<track\b[^>]*?\bsrc\s*=\s*([^\s>]+)',              # track标签的src属性（无引号）
            r'<applet\b[^>]*?\bcode\s*=\s*([\'\"])(.*?)\1',   # applet标签的code属性（单双引号）
            r'<applet\b[^>]*?\bcode\s*=\s*([^\s>]+)',            # applet标签的code属性（无引号）
            r'<frame\b[^>]*?\bsrc\s*=\s*([\'\"])(.*?)\1',     # frame标签的src属性（单双引号）
            r'<frame\b[^>]*?\bsrc\s*=\s*([^\s>]+)',              # frame标签的src属性（无引号）
            r'<portal\b[^>]*?\bsrc\s*=\s*([\'\"])(.*?)\1',    # portal标签的src属性（单双引号）
            r'<portal\b[^>]*?\bsrc\s*=\s*([^\s>]+)',             # portal标签的src属性（无引号）
            r'<button\b[^>]*?\bformaction\s*=\s*([\'\"])(.*?)\1', # button标签的formaction属性（单双引号）
            r'<button\b[^>]*?\bformaction\s*=\s*([^\s>]+)',          # button标签的formaction属性（无引号）
            r'<input\b[^>]*?\bsrc\s*=\s*([\'\"])(.*?)\1',     # input标签的src属性（单双引号）
            r'<input\b[^>]*?\bsrc\s*=\s*([^\s>]+)',              # input标签的src属性（无引号）
            r'<input\b[^>]*?\bformaction\s*=\s*([\'\"])(.*?)\1', # input标签的formaction属性（单双引号）
            r'<input\b[^>]*?\bformaction\s*=\s*([^\s>]+)',          # input标签的formaction属性（无引号）
            r'<area\b[^>]*?\bhref\s*=\s*([\'\"])(.*?)\1',      # area标签的href属性（单双引号）
            r'<area\b[^>]*?\bhref\s*=\s*([^\s>]+)',               # area标签的href属性（无引号）
            r'<base\b[^>]*?\bhref\s*=\s*([\'\"])(.*?)\1',      # base标签的href属性（单双引号）
            r'<base\b[^>]*?\bhref\s*=\s*([^\s>]+)',               # base标签的href属性（无引号）
            r'<meta\b[^>]*?\bcontent\s*=\s*([\'\"])(.*?)\1',   # meta标签的content属性（单双引号）
            r'<meta\b[^>]*?\bcontent\s*=\s*([^\s>]+)',            # meta标签的content属性（无引号）
        ]
        
        # 匹配主要路径模式
        for pattern in path_patterns:
            self._match_and_add(pattern, text_content, base_url, urls)
        
        # 匹配HTML标签中的路径属性
        for pattern in tag_patterns:
            self._match_and_add(pattern, text_content, base_url, urls)
        
        # 使用BeautifulSoup作为备选方案
        self._extract_with_bs(text_content, base_url, urls)
        
        if self.config.debug_mode:
            self._debug_print(f"URL提取完成，共找到 {len(urls)} 个URL")
        
        return urls
    
    def _match_and_add(self, pattern, text_content, base_url, url_set):
        """使用正则表达式匹配并添加URL"""
        try:
            matches = re.findall(pattern, text_content, re.IGNORECASE)
            if self.config.debug_mode and matches:
                self._debug_print(f"正则匹配模式 '{pattern}' 找到 {len(matches)} 个匹配")
            
            for match in matches:
                # 处理可能的元组结果
                if isinstance(match, tuple):
                    # 取第一个非空匹配组
                    url = next((m for m in match if m), "")
                else:
                    url = match
                
                if self.config.debug_mode:
                    self._debug_print(f"处理匹配结果: {url}")
                
                self._process_url(url, base_url, url_set, f"Regex: {pattern}")
        except Exception as e:
            if self.config.verbose:
                print(f"URL匹配错误 (模式: {pattern}): {str(e)}")
    
    def _extract_with_bs(self, text_content, base_url, url_set):
        """使用BeautifulSoup提取URL"""
        try:
            if self.config.debug_mode:
                self._debug_print("开始使用BeautifulSoup提取URL")
            
            soup = BeautifulSoup(text_content, 'html.parser')
            
            # 提取所有标签中可能包含URL的属性
            tags = {
                'a': 'href',
                'link': 'href',
                'script': 'src',
                'img': 'src',
                'iframe': 'src',
                'form': 'action',
                'meta': 'content',
                'object': 'data',
                'embed': 'src',
                'source': 'src',
                'audio': 'src',
                'video': 'src',
                'track': 'src',
                'applet': 'code',
                'frame': 'src',
                'portal': 'src',
                'button': 'formaction',
                'input': ['src', 'formaction'],
                'area': 'href',
                'base': 'href'
            }
            
            bs_count = 0
            for tag, attrs in tags.items():
                if not isinstance(attrs, list):
                    attrs = [attrs]
                
                for element in soup.find_all(tag):
                    for attr in attrs:
                        if element.has_attr(attr):
                            url = element[attr]
                            bs_count += 1
                            if self.config.debug_mode:
                                self._debug_print(f"BeautifulSoup找到: {tag}[{attr}] = {url}")
                            self._process_url(url, base_url, url_set, "BeautifulSoup")
            
            if self.config.debug_mode:
                self._debug_print(f"BeautifulSoup提取完成，共处理 {bs_count} 个属性")
                
        except Exception as e:
            if self.config.verbose:
                print(f"BeautifulSoup解析错误: {str(e)}")
    
    def _process_url(self, url, base_url, url_set, source=""):
        """!!!处理单个接口，拼接成URL，添加到集合中"""

                # 新增：去除首尾引号和空格
        url = url.strip().strip('\'"')

        # 如果有多个http, 匹配字符串分割成多个URL，分别添加到集合中
        urls = re.findall(r'http[s]?://[^ ]+', url)
        for url in urls:
            if url:
                # 新增：外部URL收集逻辑
                # print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!', url)

                if not self.is_valid_domain(url):
                    if self.scanner is not None:
                        with self.scanner.external_urls_lock:
                            if url not in self.scanner.external_urls:
                                self.scanner.external_urls.add(url)
                                self.scanner.external_url_queue.put(url)
                    if self.config.debug_mode:
                        self._debug_print(f"外部URL已收集: {url}")
                    return  # 外部URL不加入主扫描集合



        # 新增：只保留URL允许的字符，遇到第一个不合法字符就截断
        m = re.match(r'^[a-zA-Z0-9:/?&=._~#%\\-]+', url)
        if m:
            url = m.group(0)
        else:
            return  # 如果没有合法URL部分，直接跳过

        if not url or url.strip() == "":
            if self.config.debug_mode:
                self._debug_print(f"跳过空URL")
            return
    

        # 跳过常见无效URL
        if url.startswith(('javascript:', 'data:', 'mailto:', 'tel:')):
            if self.config.debug_mode:
                self._debug_print(f"跳过无效URL: {url}")
            return
        
        # print(url)
        # 如果已经是绝对URL，直接添加到集合中
        # if url.startswith(('http://', 'https://')):
        #     url_set.add(url)
        #     return


        # 特殊处理：如果URL以//开头，添加协议
        if url.startswith('//'):
            parsed_base = urllib.parse.urlparse(base_url)
            url = f"{parsed_base.scheme}:{url}"
            if self.config.debug_mode:
                self._debug_print(f"协议相对URL处理: {url}")
        
        # 应用智能拼接
        if self.config.smart_concatenation:
            full_url = self.concatenator.smart_concatenation(base_url, url)
        else:
            full_url = urllib.parse.urljoin(base_url, url)
    
        # print(full_url)

        normalized = full_url

        if self.config.debug_mode:
            self._debug_print(f"URL处理结果: {url} -> {normalized}")

        if normalized and self.is_valid_domain(normalized) and not self.should_skip_url(normalized):
            url_set.add(normalized)
            if self.config.debug_mode:
                self._debug_print(f"URL已添加到集合: {normalized}")
        else:
            if self.config.debug_mode:
                self._debug_print(f"URL被过滤: {normalized}")


# ====================== 敏感信息检测模块 ======================
class SensitiveDetector(DebugMixin):
    def __init__(self, sensitive_patterns, debug_mode=False):
        self.sensitive_patterns = sensitive_patterns
        self.debug_mode = debug_mode
    
    def detect(self, content):
        """检测响应中的敏感信息 - 增强国内重点"""
        if not content:
            if self.debug_mode:
                self._debug_print("内容为空，跳过敏感信息检测")
            return []
        
        if self.debug_mode:
            self._debug_print("开始敏感信息检测")
        
        text_content = content.decode('utf-8', 'ignore') if isinstance(content, bytes) else content
        detected = []
        
        for name, pattern in self.sensitive_patterns.items():
            try:
                matches = re.findall(pattern, text_content)
                if matches:
                    # 去重并限制显示数量
                    unique_matches = set(matches)
                    sample = list(unique_matches)[:3]  # 只显示前3个样本
                    detected_item = f"{name} (x{len(unique_matches)}: {', '.join(sample)}{'...' if len(unique_matches) > 3 else ''}"
                    detected.append(detected_item)
                    
                    if self.debug_mode:
                        self._debug_print(f"发现敏感信息: {detected_item}")
                else:
                    if self.debug_mode:
                        self._debug_print(f"未发现敏感信息: {name}")
            except re.error as e:
                if self.debug_mode:
                    self._debug_print(f"正则表达式错误 ({name}): {str(e)}")
                continue  # 跳过无效的正则表达式
        
        if self.debug_mode:
            self._debug_print(f"敏感信息检测完成，共发现 {len(detected)} 种敏感信息")
        
        return detected

# ====================== 输出处理模块 ======================
class OutputHandler(DebugMixin):
    def __init__(self, config):
        self.config = config
        self.url_count = 0
        self.start_time = time.time()
        self.request_signature_count = {}  # 记录请求签名出现次数
        
        # 准备输出文件
        if config.output_file:
            os.makedirs(os.path.dirname(os.path.abspath(config.output_file)), exist_ok=True)
            with open(config.output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['URL', 'Status', 'Title', 'Length', 'Redirects', 'Depth', 'Sensitive Data', 'Is Duplicate'])
            
            if self.config.debug_mode:
                self._debug_print(f"输出文件已初始化: {config.output_file}")
    
    def get_status_color(self, status):
        """获取状态码对应的颜色"""
        if not self.config.color_output:
            return ''
        
        if isinstance(status, int):
            if 200 <= status < 300:
                return Fore.GREEN
            elif 300 <= status < 400:
                return Fore.YELLOW
            elif 400 <= status < 500:
                return Fore.RED
            elif 500 <= status < 600:
                return Fore.MAGENTA
        elif "Error" in str(status):
            return Fore.RED + Style.BRIGHT
        
        return Fore.CYAN
    
    def realtime_output(self, result):
        """彩色实时输出扫描结果"""
        self.url_count += 1
        elapsed_time = time.time() - self.start_time
        
        if self.config.debug_mode:
            self._debug_print(f"处理扫描结果 #{self.url_count}: {result['url']}")
        
        if isinstance(result['status'], str) and 'Error' in result['status']:
            result['status'] = 'Error'

        # 生成请求签名（长度、状态、返回内容hash）
        content_hash = ''
        if 'content' in result and result['content'] is not None:
            try:
                if isinstance(result['content'], bytes):
                    content_hash = hashlib.md5(result['content']).hexdigest()
                else:
                    content_hash = hashlib.md5(result['content'].encode('utf-8', errors='ignore')).hexdigest()
            except Exception:
                content_hash = ''
        req_signature = f"{result['length']}|{result['status']}|{content_hash}"
        count = self.request_signature_count.get(req_signature, 0)
        self.request_signature_count[req_signature] = count + 1
        is_duplicate_signature = count > 0
        # 记录到debug.log
        if self.config.debug_mode:
            log_line = (
                f"URL: {result['url']} | 状态: {result['status']} | 长度: {result['length']} | 内容hash: {content_hash} | 重复签名: {is_duplicate_signature} | 深度: {result['depth']}"
            )
            try:
                logging.debug(log_line)
            except Exception:
                pass
        # 构建输出行
        depth_str = f"[深度:{result['depth']}]"
        status_str = f"[{result['status']}]"
        length_str = f"[{result['length']}]"
        title_str = f"[{result['title'][:30]}]" if result['title'] else "[]"
        time_str = f"[{result['time']:.2f}s]"
        
        # 状态码颜色
        status_color = self.get_status_color(result['status'])
        
        # 敏感信息显示
        sensitive_str = ""
        if result['sensitive']:
            # 只显示【类型X数量】，不展示具体内容和字段名
            sensitive_types = []
            for s in result['sensitive']:
                # 兼容旧格式（如 "邮箱 (x1: xxx..."），只取类型和数量
                if "(" in s and "x" in s:
                    t = s.split('(')[0].strip()
                    n = s.split('x')[-1].split(':')[0].replace(')', '').strip()
                    sensitive_types.append(f"{t}X{n}")
                else:
                    # 只保留类型
                    sensitive_types.append(s)
            sensitive_str = Fore.RED + Style.BRIGHT + f" -> [{'，'.join(sensitive_types)}]"

            if self.config.debug_mode:
                self._debug_print(f"发现敏感信息: {'，'.join(sensitive_types)}")
            result['sensitive'] = sensitive_str
        # 重复URL标记 - 使用紫色显示
        is_duplicate = result.get('is_duplicate', False) or result.get('status') == '重复'
        if is_duplicate or is_duplicate_signature:
            # 整行都用紫色
            # output_line = (
            #     f"{Fore.MAGENTA}{depth_str}{status_str}{length_str}{title_str}{result['url']}{time_str}{sensitive_str}{Style.RESET_ALL}"
            # )
            # 跳过重复请求的输出
            return
        else:
            # 拼接输出行，新增文件类型标签但不影响原有逻辑
            url_path = result['url'].split('?')[0] if 'url' in result else ''
            if '.' in url_path.split('/')[-1]:
                ext = url_path.split('.')[-1].upper()
                file_type_str = f"[{ext}]"
                file_type_color = Fore.LIGHTCYAN_EX
                link_type = ext
            else:
                file_type_str = "[接口]"
                file_type_color = Fore.RED
                link_type = "接口"
            output_line = (
                f"{Fore.BLUE}{depth_str}{Style.RESET_ALL} "
                f"{status_color}{status_str}{Style.RESET_ALL} "
                f"{Fore.WHITE}{length_str}{Style.RESET_ALL} "
                f"{Fore.CYAN}{title_str}{Style.RESET_ALL} "
                f"{Fore.WHITE}{result['url']}{Style.RESET_ALL} "
                f"{file_type_color}{file_type_str}{Style.RESET_ALL} "
                f"{Fore.YELLOW}{time_str}{Style.RESET_ALL}"
                f"{sensitive_str}"
            )
            result['link_type'] = link_type  # 新增：写入结果中
        
        # 显示进度
        if self.config.verbose:
            with output_lock:
                print(output_line)
        else:
            with output_lock:
                print(output_line)
        
        # 写入CSV文件
        if self.config.output_file:
            with open(self.config.output_file, 'a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow([
                    result['url'],
                    result['status'],
                    result['title'],
                    result['length'],
                    result['redirects'],
                    result['depth'],
                    result['sensitive'],  # 保存为完整内容
                    '是' if result.get('is_duplicate', False) else '否',  # 添加重复标记列
                    result.get('link_type', '')  # 新增：链接类型
                ])
            
            if self.config.debug_mode:
                self._debug_print(f"结果已写入CSV文件")
    
    def generate_report(self, results, report_file="full_report.csv"):
        """生成最终扫描报告"""
        if self.config.debug_mode:
            self._debug_print(f"开始生成最终报告: {report_file}")
            self._debug_print(f"报告包含 {len(results)} 个扫描结果")
        
        os.makedirs(os.path.dirname(os.path.abspath(report_file)), exist_ok=True)
        with open(report_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['URL', '状态', '标题', '长度', '重定向', '深度', '敏感信息', '是否重复', '链接类型'])  # 新增链接类型
            for result in results:
                # 自动补充link_type
                url_path = result['url'].split('?')[0] if 'url' in result else ''
                if '.' in url_path.split('/')[-1]:
                    ext = url_path.split('.')[-1].upper()
                    link_type = ext
                else:
                    link_type = "接口"
                writer.writerow([
                    result['url'],
                    result['status'],
                    result['title'],
                    result['length'],
                    result['redirects'],
                    result['depth'],
                    result['sensitive'],
                    '是' if result.get('is_duplicate', False) else '否',
                    result.get('link_type', link_type)  # 新增：链接类型
                ])
        
        if self.config.debug_mode:
            self._debug_print(f"最终报告生成完成: {report_file}")
        
        # print(results)
        # 统计重复URL信息
        duplicate_count = len([r for r in results if r.get('is_duplicate', True)])
        total_duplicates = len([r for r in results if not r.get('is_duplicate', True)])
        
        with output_lock:
            print(f"\n\n扫描完成! 共扫描 {len(results)} 个URL")
            print(f"重复URL统计: {duplicate_count} 个重复结果, {total_duplicates} 个唯一URL")
            print(f"完整报告已保存至: {report_file}")

    def append_results(self, results, report_file="full_report.csv"):
        """追加写入扫描结果到报告文件（不写表头）"""
        with open(report_file, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            for result in results:
                url_path = result['url'].split('?')[0] if 'url' in result else ''
                if '.' in url_path.split('/')[-1]:
                    ext = url_path.split('.')[-1].upper()
                    link_type = ext
                else:
                    link_type = "接口"
                writer.writerow([
                    result['url'],
                    result['status'],
                    result['title'],
                    result['length'],
                    result['redirects'],
                    result['depth'],
                    result['sensitive'],
                    '是' if result.get('is_duplicate', False) else '否',
                    result.get('link_type', link_type)  # 新增：链接类型
                ])

    def output_external_unvisited(self, urls, report_file=None):
        """输出未访问的外部URL，全部紫色，写入文件"""
        from colorama import Fore, Style
        for url in urls:
            output_line = (
                f"{Fore.MAGENTA}[外部][外部][外部][外部][外部]{url}[外部][外部]{Style.RESET_ALL}"
            )
            with output_lock:
                print(output_line)
            # 写入文件
            if report_file:
                with open(report_file, 'a', newline='', encoding='utf-8') as f:
                    import csv
                    writer = csv.writer(f)
                    writer.writerow([
                        url, '外部', '外部', '外部', '外部', '外部', '外部', '外部', '外部'
                    ])

# ====================== 扫描核心模块 ======================
class UltimateURLScanner(DebugMixin):
    # 全局共享的已访问URL集合和锁
    visited_urls_global = set()
    visited_urls_lock = threading.Lock()

    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.session.headers = config.headers
        self.url_queue = queue.Queue()
        self.results = []
        self.lock = threading.Lock()
        self.running = True
        self.duplicate_urls = set()
        self.url_request_count = {}
        self.out_of_domain_urls = []
        self.external_urls = set()
        self.external_urls_lock = threading.Lock()
        self.external_url_queue = queue.Queue()
        self.external_results = []
        self.external_running = True
        self.url_matcher = URLMatcher(config, scanner=self)
        self.sensitive_detector = SensitiveDetector(config.sensitive_patterns, config.debug_mode)
        self.output_handler = OutputHandler(config)
        if self.config.debug_mode:
            self._debug_print("扫描器初始化完成")

    def _http_request(self, url):
        """统一的HTTP请求和异常处理，返回response或异常信息"""
        max_retries = 3
        response = None
        last_exception = None
        for attempt in range(max_retries):
            try:
                response = self.session.get(
                    url,
                    proxies=self.config.proxy,
                    timeout=self.config.timeout,
                    verify=False,
                    allow_redirects=True
                )
                return response, None
            except Exception as e:
                last_exception = e
                if self.config.debug_mode:
                    self._debug_print(f"HTTP请求失败，重试第{attempt+1}次: {e}")
                if attempt < max_retries - 1:
                    time.sleep(0.5)
        return None, last_exception

    def _build_result(self, url, response=None, error=None, depth=0):
        """统一构建扫描结果字典"""
        start_time = time.time()
        elapsed = 0
        redirect_chain = []
        final_url = url
        sensitive_info = []
        status = 'Error'
        title = ''
        content = b''
        if response is not None:
            try:
                elapsed = getattr(response, 'elapsed', None)
                if elapsed:
                    elapsed = elapsed.total_seconds()
                else:
                    elapsed = 0
            except Exception:
                elapsed = 0
            try:
                redirect_chain = [r.url for r in response.history] if response.history else []
            except Exception:
                redirect_chain = []
            try:
                final_url = response.url
            except Exception:
                final_url = url
            try:
                content = getattr(response, 'content', b'')
            except Exception:
                content = b''
            try:
                sensitive_info = self.sensitive_detector.detect(content)
            except Exception:
                sensitive_info = []
            status = getattr(response, 'status_code', 'Error')
            # 提取标题
            try:
                if 'text/html' in response.headers.get('Content-Type', ''):
                    with warnings.catch_warnings():
                        warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
                        if 'xml' in response.headers.get('Content-Type', '').lower():
                            soup = BeautifulSoup(content, 'lxml-xml')
                        else:
                            soup = BeautifulSoup(content, 'html.parser')
                    t = soup.title
                    title = t.string.strip() if t else ''
            except Exception:
                title = ''
        elif error is not None:
            status = f"Error: {str(error)}"
        result = {
            'url': final_url,
            'status': status,
            'title': title,
            'length': len(content),
            'redirects': ' → '.join([str(x) for x in redirect_chain]),
            'depth': depth,
            'time': elapsed,
            'sensitive': sensitive_info,
            'is_duplicate': False
        }
        return result

    def scan_url(self, url, depth=0):
        """扫描单个URL，整合请求、内容处理、递归、重复判断"""
        if not self.running or depth > self.config.max_depth:
            if self.config.debug_mode:
                self._debug_print(f"跳过URL扫描: {url} (深度: {depth}, 最大深度: {self.config.max_depth})")
            return None
        if self.url_matcher.should_skip_url(url):
            if self.config.debug_mode:
                self._debug_print(f"URL被过滤跳过: {url}")
            return None
        # url_scope_mode 0: 只允许主域/子域
        if self.config.url_scope_mode == 0:
            if not self.url_matcher.is_valid_domain(url):
                if self.config.debug_mode:
                    self._debug_print(f"外部URL跳过: {url}")
                return None
        # url_scope_mode 1: 外部链接访问一次，不递归
        elif self.config.url_scope_mode == 1:
            if not self.url_matcher.is_valid_domain(url):
                with UltimateURLScanner.visited_urls_lock:
                    if url in UltimateURLScanner.visited_urls_global:
                        return None
                    UltimateURLScanner.visited_urls_global.add(url)
                if self.config.debug_mode:
                    self._debug_print(f"外部URL只访问一次: {url}")
                response, error = self._http_request(url)
                result = self._build_result(url, response, error, depth)
                try:
                    self.output_handler.realtime_output(result)
                except Exception:
                    pass
                return result
        if self.config.debug_mode:
            self._debug_print(f"开始扫描URL: {url} (深度: {depth})")
        time.sleep(self.config.delay)
        response, error = self._http_request(url)
        result = self._build_result(url, response, error, depth)
        try:
            self.output_handler.realtime_output(result)
        except Exception:
            pass
        # 递归内容提取
        if response is not None and depth < self.config.max_depth:
            content = getattr(response, 'content', b'')
            content_type = response.headers.get('Content-Type', '') if hasattr(response, 'headers') else ''
            if content:
                if self.config.debug_mode:
                    self._debug_print(f"开始从内容提取URL: {result['url']} (内容类型: {content_type})")
                try:
                    new_urls = self.url_matcher.extract_urls(content, result['url'])
                except Exception as e:
                    if self.config.debug_mode:
                        self._debug_print(f"[内容URL提取] 异常: {e}, url={url}, depth={depth}")
                    new_urls = []
                if self.config.debug_mode:
                    self._debug_print(f"从内容中提取到 {len(new_urls)} 个新URL")
                added_count = 0
                for new_url in new_urls:
                    with UltimateURLScanner.visited_urls_lock:
                        try:
                            if new_url not in UltimateURLScanner.visited_urls_global and not self.url_matcher.should_skip_url(new_url):
                                self.url_queue.put((new_url, depth + 1))
                                UltimateURLScanner.visited_urls_global.add(new_url)
                                added_count += 1
                        except Exception as e:
                            if self.config.debug_mode:
                                self._debug_print(f"[新URL入队] 异常: {e}, url={url}, depth={depth}, new_url={new_url}")
                if self.config.debug_mode:
                    self._debug_print(f"将 {added_count} 个新URL加入队列")
            else:
                if self.config.debug_mode:
                    self._debug_print(f"无法获取内容，跳过URL提取: {result['url']}")
        return result

    def worker(self):
        if self.config.debug_mode:
            self._debug_print(f"工作线程启动: {threading.current_thread().name}")
        while self.running:
            try:
                if self.output_handler.url_count >= self.config.max_urls:
                    if self.config.debug_mode:
                        self._debug_print("达到最大URL数量，停止工作线程")
                    self.running = False
                    break
                url, depth = self.url_queue.get(timeout=10)
                if self.config.debug_mode:
                    self._debug_print(f"工作线程处理URL: {url} (深度: {depth})")
                result = self.scan_url(url, depth)
                if result:
                    with self.lock:
                        self.results.append(result)
                self.url_queue.task_done()
            except queue.Empty:
                if not self.running:
                    if self.config.debug_mode:
                        self._debug_print("工作线程队列为空，退出")
                    break
            except Exception as e:
                if self.config.debug_mode:
                    self._debug_print(f"工作线程错误: {str(e)}")
                self.url_queue.task_done()

    def external_worker(self):
        if self.config.debug_mode:
            self._debug_print(f"外部URL线程启动: {threading.current_thread().name}")
        while self.external_running or not self.external_url_queue.empty():
            try:
                ext_url = self.external_url_queue.get(timeout=2)
                if self.config.debug_mode:
                    self._debug_print(f"外部URL线程处理: {ext_url}")
                result = self.scan_url(ext_url, depth=0)
                if result:
                    with self.lock:
                        self.external_results.append(result)
                self.external_url_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                if self.config.debug_mode:
                    self._debug_print(f"外部URL线程错误: {str(e)}")
                self.external_url_queue.task_done()

    def start_scan(self):
        if self.config.debug_mode:
            self._debug_print("开始扫描过程")
        self.url_queue.put((self.config.start_url, 0))
        if self.config.debug_mode:
            self._debug_print(f"起始URL已加入队列: {self.config.start_url}")
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            if self.config.debug_mode:
                self._debug_print(f"创建线程池，工作线程数: {self.config.max_workers}")
            workers = [executor.submit(self.worker) for _ in range(min(self.config.max_workers, 100))]
            if self.config.debug_mode:
                self._debug_print(f"已启动 {len(workers)} 个工作线程")
            self.url_queue.join()
            self.running = False
            if self.config.debug_mode:
                self._debug_print("所有任务已完成，停止工作线程")
            for worker in workers:
                try:
                    worker.cancel()
                except:
                    pass

    def generate_report(self, report_file="full_report.csv"):
        if self.config.debug_mode:
            self._debug_print(f"生成最终报告: {report_file}")
        self.output_handler.generate_report(self.results, report_file)
        if hasattr(self, 'external_urls'):
            with UltimateURLScanner.visited_urls_lock:
                unvisited = [u for u in self.external_urls if u not in UltimateURLScanner.visited_urls_global]
            if unvisited:
                print(f"\n{Fore.MAGENTA}未访问的外部URL如下:{Style.RESET_ALL}")
                self.output_handler.output_external_unvisited(unvisited, report_file)

def scanner_start(config):
    """启动扫描器"""
    # 创建扫描器
    scanner = UltimateURLScanner(config)
    
    print(f"{Fore.GREEN}扫描器已就绪，开始扫描目标: {config.start_url}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}配置: 最大深度={config.max_depth}, 最大URL数={config.max_urls}, 线程数={config.max_workers}{Style.RESET_ALL}")
    start_time = time.time()
    
    # 启动外部URL线程
    external_thread = threading.Thread(target=scanner.external_worker, name="ExternalURLThread", daemon=True)
    external_thread.start()

    try:
        scanner.start_scan()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}扫描被用户中断!{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}扫描出错: {str(e)}{Style.RESET_ALL}")
    finally:
        # 自动生成报告文件名：主域名_日期时间.csv
        from datetime import datetime
        import re as _re
        parsed_url = urllib.parse.urlparse(config.start_url)
        domain = parsed_url.netloc or config.start_url
        # 只保留域名部分，去除端口
        domain = domain.split(':')[0]
        # 去除非字母数字和点
        domain = _re.sub(r'[^a-zA-Z0-9.]', '', domain)
        dt_str = datetime.now().strftime('%Y%m%d_%H%M')
        report_filename = f"results/{domain}_{dt_str}.csv"
        scanner.generate_report(report_filename)
        total_time = time.time() - start_time
        print(f"{Fore.YELLOW}总耗时: {total_time:.2f}秒 | 平均速度: {scanner.output_handler.url_count/total_time:.1f} URL/秒{Style.RESET_ALL}")
        print(f"{Fore.GREEN}扫描结束!{Style.RESET_ALL}")
        # 优雅关闭外部线程
        scanner.external_running = False
        external_thread.join(timeout=10)
        
        # 生成外部URL访问报告
        if scanner.external_results:
            scanner.output_handler.append_results(scanner.external_results, report_filename)
            print(f"{Fore.GREEN}外部URL访问结束，结果已追加写入: {report_filename}{Style.RESET_ALL}")
        # 新增：输出未访问的外部URL
        # 已在 generate_report 中处理

def main():

    print(f"{Fore.YELLOW}=== WhiteURLScan v1.1 ===")
    print(f"{Fore.YELLOW}=== 重复的URL不会重复扫描, 结果返回相同的URL不会重复展示 ===")
    parser = argparse.ArgumentParser(description="WhiteURLScan v1.1")
    parser.add_argument('-u', dest='start_url', type=str, help='起始URL')
    parser.add_argument('-uf', dest='url_file', type=str, help='批量URL文件，每行一个URL')
    parser.add_argument('-workers', dest='max_workers', type=int, help='最大线程数')
    parser.add_argument('-timeout', dest='timeout', type=int, help='请求超时（秒）')
    parser.add_argument('-depth', dest='max_depth', type=int, help='最大递归深度')
    parser.add_argument('-out', dest='output_file', type=str, help='实时输出文件')
    parser.add_argument('-proxy', dest='proxy', type=str, help='代理设置')
    parser.add_argument('-debug', dest='debug_mode', type=int, help='调试模式 1开启 0关闭')
    parser.add_argument('-scope', dest='url_scope_mode', type=int, help='URL扫描范围模式 0主域 1外部一次 2全放开')
    args = parser.parse_args()

    # 必须至少输入 --start_url 或 --url_file
    if not args.start_url and not args.url_file:
        print(f"{Fore.RED}错误：-h查看帮助 , 必须通过 -u 或 -uf 至少指定一个扫描目标！{Style.RESET_ALL}")
        sys.exit(1) 

    # 固定从config.json读取配置
    config_path = 'config.json'
    default_config = {
        "start_url": None,
        "proxy": None,
        "delay": 0.1,
        "max_workers": 30,
        "timeout": 10,
        "max_depth": 5,
        "blacklist_domains": ["www.w3.org"],
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
        "max_urls": 10000,
        "smart_concatenation": True,
        "debug_mode": 0,
        "url_scope_mode": 0
    }
    if not os.path.exists(config_path):
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(default_config, f, ensure_ascii=False, indent=2)
        print(f"{Fore.YELLOW}未检测到config.json，已自动创建默认配置文件！请根据需要修改。{Style.RESET_ALL}")
    with open(config_path, 'r', encoding='utf-8') as f:
        config_data = json.load(f)

    # 命令行参数优先级高于配置文件
    def get_config_value(key, default=None):
        return getattr(args, key, None) if getattr(args, key, None) is not None else config_data.get(key, default)


    print(f"{Fore.CYAN}正在初始化扫描器...{Style.RESET_ALL}")
    
    # 创建配置
    config = ScannerConfig(
        start_url=get_config_value('start_url'),
        proxy=get_config_value('proxy'),
        delay=config_data.get('delay', 0.1),
        max_workers=get_config_value('max_workers', 30),
        timeout=get_config_value('timeout', 10),
        max_depth=get_config_value('max_depth', 5),
        blacklist_domains=config_data.get('blacklist_domains'),
        headers=config_data.get('headers'),
        output_file=get_config_value('output_file', 'results/实时输出文件.csv'),
        color_output=config_data.get('color_output', True),
        verbose=config_data.get('verbose', True),
        extension_blacklist=get_config_value('extension_blacklist', ['.css','.mp4']),
        max_urls=config_data.get('max_urls', 10000),
        smart_concatenation=config_data.get('smart_concatenation', True),
        debug_mode=get_config_value('debug_mode', 0),
        url_scope_mode=get_config_value('url_scope_mode', 0)  # 新增
    )
    # 如果输入的是-u, 则直接开始扫描
    if args.start_url:
        print(f"{Fore.YELLOW}开始扫描: {args.start_url}{Style.RESET_ALL}")
        scanner_start(config)
    # 如果输入的是-uf 则读取url_file文件, 遍历更新config.start_url, 然后循环开始扫描
    elif args.url_file:
        if not os.path.exists(args.url_file):
            print(f"{Fore.RED}错误：URL文件 {args.url_file} 不存在！{Style.RESET_ALL}")
            sys.exit(1)
        
        with open(args.url_file, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
        
        print(f"{Fore.YELLOW}从文件读取到 {len(urls)} 个URL，开始批量扫描...{Style.RESET_ALL}")
        
        for i, url in enumerate(urls, 1):
            print(f"{Fore.CYAN}[{i}/{len(urls)}] 开始扫描: {url}{Style.RESET_ALL}")
            # 为每个URL创建独立的配置实例
            url_config = ScannerConfig(
                start_url=url,
                proxy=get_config_value('proxy'),
                delay=config_data.get('delay', 0.1),
                max_workers=get_config_value('max_workers', 30),
                timeout=get_config_value('timeout', 10),
                max_depth=get_config_value('max_depth', 5),
                blacklist_domains=config_data.get('blacklist_domains'),
                headers=config_data.get('headers'),
                output_file=get_config_value('output_file', 'results/实时输出文件.csv'),
                color_output=config_data.get('color_output', True),
                verbose=config_data.get('verbose', True),
                extension_blacklist=get_config_value('extension_blacklist', ['.css','.mp4']),
                max_urls=config_data.get('max_urls', 10000),
                smart_concatenation=config_data.get('smart_concatenation', True),
                debug_mode=get_config_value('debug_mode', 0),
                url_scope_mode=get_config_value('url_scope_mode', 0)  # 新增
            )
            scanner_start(url_config)

if __name__ == "__main__":
    main()
    
