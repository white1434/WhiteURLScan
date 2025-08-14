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
import chardet  # 新增自动编码检测

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



class OutputLogger:
    def __init__(self, log_file="results/output.out"):
        self.log_file = log_file
        self.original_stdout = sys.stdout
        self.original_stderr = sys.stderr
        
        # 确保日志目录存在
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        # 创建文件输出流
        self.log_stream = open(log_file, 'a', encoding='utf-8')
        
    def write(self, text):
        # 写入到原始stdout（保持彩色）
        self.original_stdout.write(text)
        # 同时写入到日志文件（去除颜色代码）
        try:
            # 去除ANSI颜色代码
            import re
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            clean_text = ansi_escape.sub('', text)
            self.log_stream.write(clean_text)
            self.log_stream.flush()
        except Exception:
            pass
    
    def flush(self):
        self.original_stdout.flush()
        try:
            self.log_stream.flush()
        except Exception:
            pass
    
    def close(self):
        try:
            self.log_stream.close()
        except Exception:
            pass

# 初始化输出日志记录器
output_logger = OutputLogger()

# 重定向stdout和stderr到日志记录器
sys.stdout = output_logger
sys.stderr = output_logger

try:
    import tldextract
    DOMAIN_EXTRACTION = True
except ImportError:
    DOMAIN_EXTRACTION = False

# ====================== 通用调试输出 Mixin ======================
class DebugMixin:
    def __init__(self, debug_mode=False):
        self.debug_mode = debug_mode

    def _debug_print(self, message):
        """调试信息输出"""
        if hasattr(self, 'debug_mode') and self.debug_mode:
            debug_prefix = f"{Fore.MAGENTA}[DEBUG]{Style.RESET_ALL}"
            print(f"{debug_prefix} {message}")
            try:
                logging.debug(message)
            except Exception as e:
                print(f"Debug输出异常: {e}")
                pass

# ====================== 异常处理装饰器 ======================
def handle_exceptions(func):
    """异常处理装饰器"""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            # 尝试调用对象的_debug_print方法输出异常信息
            if args and hasattr(args[0], '_debug_print'):
                args[0]._debug_print(f"异常: {str(e)}")
            elif args and hasattr(args[0], 'debug_mode') and args[0].debug_mode:
                # 如果对象有debug_mode属性但没有_debug_print方法
                print(f"{Fore.MAGENTA}[DEBUG] 异常: {str(e)}{Style.RESET_ALL}")
            return None
    return wrapper

# ====================== 配置模块 ======================
class ScannerConfig(DebugMixin):
    def __init__(self, start_url, proxy=None, delay=0, max_workers=10, timeout=10,
                 max_depth=1, blacklist_domains=None, whitelist_domains=None, headers=None, output_file=None,
                 sensitive_patterns=None, color_output=True, verbose=True,
                 extension_blacklist=None, max_urls=5000, smart_concatenation=True,
                 debug_mode=False, url_scope_mode=0, danger_filter_enabled=1,
                 danger_api_list=None, is_duplicate=0,
                 custom_base_url=None, path_route=None, api_route=None,
                 fuzz=0):  # 新增 fuzz 参数
        # 基础配置
        self.start_url = start_url
        self.proxy = self._init_proxy(proxy)
        self.delay = delay
        self.max_workers = max_workers
        self.timeout = timeout
        self.max_depth = max_depth
        self.output_file = output_file
        self.color_output = color_output and COLOR_SUPPORT
        self.verbose = verbose
        self.max_urls = max_urls
        self.smart_concatenation = smart_concatenation
        self.debug_mode = debug_mode
        
        # 域名和URL配置
        self.url_scope_mode = int(url_scope_mode)
        self.blacklist_domains = set(blacklist_domains or [])
        self.whitelist_domains = set(whitelist_domains or [])
        self.base_domain = self._init_base_domain(start_url)
        
        # 自定义URL拼接配置
        self.danger_filter_enabled = int(danger_filter_enabled)
        self.danger_api_list = danger_api_list
        self.is_duplicate = int(is_duplicate)
        self.fuzz = int(fuzz)
        self.custom_base_url, self.path_route, self.api_route = self._init_fuzz_config(
            fuzz, custom_base_url, path_route, api_route)
        
        # 扩展名过滤配置
        self.extension_blacklist = self._init_extension_blacklist(extension_blacklist)
        
        # 请求头配置
        self.headers = self._init_headers(headers)
        
        # 敏感信息检测配置
        self.sensitive_patterns = sensitive_patterns or self.default_sensitive_patterns()
        
        # 调试配置
        self._init_debug_logging()
        
        if self.debug_mode:
            self._debug_print(f"配置初始化完成: 起始URL: {start_url} 基础域名: {self.base_domain} 代理: {proxy} 最大深度: {max_depth} 最大URL数: {max_urls} 线程数: {max_workers} 调试: {debug_mode}")
    
    def _init_proxy(self, proxy):
        """初始化代理配置"""
        return {'http': proxy, 'https': proxy} if proxy else None
    
    def _init_base_domain(self, start_url):
        """初始化基础域名"""
        if start_url and DOMAIN_EXTRACTION:
            ext = tldextract.extract(start_url)
            return f"{ext.domain}.{ext.suffix}"
        elif start_url:
            parsed = urllib.parse.urlparse(start_url)
            return parsed.netloc
        else:
            return None
    
    def _init_fuzz_config(self, fuzz, custom_base_url, path_route, api_route):
        """初始化fuzz配置"""
        if int(fuzz) == 1:
            return custom_base_url, path_route, api_route
        else:
            return [], [], []
    
    def _init_extension_blacklist(self, extension_blacklist):
        """初始化扩展名黑名单"""
        # 如果没有配置，则默认过滤下面的类型
        return set(extension_blacklist or [
            '.css', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.woff', '.woff2', 
            '.ttf', '.eot', '.ico', '.mp4', '.mp3', '.avi', '.mov', '.pdf', 
            '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.zip', '.rar',
            '.gz', '.tar', '.7z', '.exe', '.dll', '.bin', '.swf', '.flv'
        ])
    
    def _init_headers(self, headers):
        """初始化请求头"""
        default_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        if headers:
            default_headers.update(headers)
        return default_headers
    
    def _init_debug_logging(self):
        """初始化调试日志"""
        if self.debug_mode:
            logging.basicConfig(
                filename='results/debug.log',
                filemode='a',
                format='%(asctime)s %(levelname)s %(message)s',
                level=logging.DEBUG,
                encoding='utf-8'
            )
    @staticmethod
    def default_sensitive_patterns():
        return {
            # 国内敏感信息
            '身份证号': r'\b[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b',
            '手机号': r'\b1(?:3\d|4[5-9]|5[0-35-9]|6[5-7]|7[0-8]|8\d|9[189])\d{8}\b',
            '统一社会信用代码': r'\b[0-9A-Z]{18}\b',
            '企业注册号': r'\b\d{13,15}\b',
            '内网IP': r'\b(127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b',
            'IP地址': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            'MAC地址': r'\b([a-fA-F0-9]{2}[:-]){5}[a-fA-F0-9]{2}\b',
            
            # 邮箱和认证
            '邮箱': r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.(?!js|css|jpg|jpeg|png|ico|svg|gif|woff|ttf|eot|mp4|mp3|json|map|zip|rar|exe|dll|bin|swf|flv)[a-zA-Z]{2,10}\b',
            'Basic认证': r'\b(?:basic|bearer)\s+[a-zA-Z0-9=:_\+/-]{5,100}\b',
            'Authorization': r'(?i)(basic [a-z0-9=:_\+/-]{5,100}|bearer [a-z0-9_.=:_\+/-]{5,100})',
            
            # 云服务密钥
            '阿里云密钥': r'\bLTAI[a-zA-Z0-9]{12,20}\b',
            '腾讯云密钥': r'\bAKID[a-zA-Z0-9]{16,28}\b',
            '百度云密钥': r'\bAK[a-zA-Z0-9]{32}\b',
            'AWS访问密钥': r'\bA[SK]IA[0-9A-Z]{16}\b',
            'AWS密钥ID': r'(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
            'Google API密钥': r'\bAIza[0-9A-Za-z\-_]{35}\b',
            'Firebase密钥': r'\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b',
            'Google验证码': r'\b6L[0-9A-Za-z\-_]{38}\b',
            'Google OAuth': r'\bya29\.[0-9A-Za-z\-_]+\b',
            
            # 第三方服务密钥
            'Twilio API密钥': r'\bSK[0-9a-fA-F]{32}\b',
            'Twilio账户SID': r'\bAC[a-zA-Z0-9_\-]{32}\b',
            'Twilio应用SID': r'\bAP[a-zA-Z0-9_\-]{32}\b',
            'Stripe标准API': r'\bsk_live_[0-9a-zA-Z]{24}\b',
            'Stripe限制API': r'\brk_live_[0-9a-zA-Z]{24}\b',
            'GitHub访问令牌': r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com',
            'Slack令牌': r'\bxox[baprs]-[0-9a-zA-Z]{10,48}\b',
            'Slack Webhook': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
            'Mailgun API密钥': r'\bkey-[0-9a-zA-Z]{32}\b',
            'Square访问令牌': r'\bsqOatp-[0-9A-Za-z\-_]{22}\b',
            'Square OAuth密钥': r'\bsq0csp-[0-9A-Za-z\-_]{43}\b',
            'PayPal Braintree令牌': r'\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b',
            'Facebook访问令牌': r'\bEAACEdEose0cBA[0-9A-Za-z]+\b',
            
            # 社交媒体密钥
            'Facebook客户端ID': r'(?i)(facebook|fb)(.{0,20})?[\'"][0-9]{13,17}[\'"]',
            'Facebook密钥': r'(?i)(facebook|fb)(.{0,20})?[\'"][0-9a-f]{32}[\'"]',
            'Twitter OAuth': r'[t|T][w|W][i|I][t|T][t|T][e|E][r|R].{0,30}[\'"\s][0-9a-zA-Z]{35,44}[\'"\s]',
            'Twitter密钥': r'(?i)twitter(.{0,20})?[\'"][0-9a-z]{35,44}[\'"]',
            'LinkedIn密钥': r'(?i)linkedin(.{0,20})?[\'"][0-9a-z]{16}[\'"]',
            'Github密钥': r'(?i)github(.{0,20})?[\'"][0-9a-zA-Z]{35,40}[\'"]',
            
            # 云存储和数据库
            '阿里云OSS': r'[\\w.]\.oss\.aliyuncs\.com',
            'AWS S3': r's3\.amazonaws\.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws\.com',
            'AWS S3 URL': r'[a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com|s3://[a-zA-Z0-9-\.\_]+|s3-[a-zA-Z0-9-\.\_\/]+|s3\.amazonaws\.com/[a-zA-Z0-9-\.\_]+|s3\.console\.aws\.amazon\.com/s3/buckets/[a-zA-Z0-9-\.\_]+',
            'Cloudinary认证': r'cloudinary://[0-9]{15}:[0-9A-Za-z]+@[a-z]+',
            '数据库连接': r'(?i)(mysql|postgresql|mongodb|redis|oracle|sqlserver)://[a-zA-Z0-9_]+:[^@]+@[a-zA-Z0-9.-]+:[0-9]+/[a-zA-Z0-9_]+',
            'JDBC连接': r'jdbc:[a-z:]+://[a-zA-Z0-9_\-.:;=/@?,&]+',
            
            # 密钥和令牌
            'JWT令牌': r'\bey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b',
            'RSA私钥': r'-----BEGIN RSA PRIVATE KEY-----',
            'SSH私钥': r'-----BEGIN [^\s]+ PRIVATE KEY-----',
            'PGP私钥': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
            'SSH私钥块': r'([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)',
            
            # 通用敏感字段
            'API密钥': r'(?i)(api[_-]?key|access[_-]?key|secret[_-]?key)\s*[:=]\s*[\'\"][a-zA-Z0-9_\-]{10,}[\'\"]',
            '密码': r'(?i)(password|passwd|pwd|pass|passcode|userpass)\s*[:=]\s*[\'\"][^\'\"]{6,}[\'\"]',
            '密钥字段': r'(?i)(key|secret|token|config|auth|access|admin|ticket)\s*[:=]\s*[\'\"][^\'\"]{6,}[\'\"]',
            'OSS云存储桶': r'([A|a]ccess[K|k]ey[I|i]d|[A|a]ccess[K|k]ey[S|s]ecret|[Aa]ccess-[Kk]ey)|[A|a]ccess[K|k]ey',
            'Secret Key': r'[Ss](ecret|ECRET)_?[Kk](ey|EY)',
            
            # 文件路径
            'Windows路径': r'(?:[a-zA-Z]:\\\\(?:[^<>:"/\\\\|?*\r\n]+\\\\)*[^<>:"/\\\\|?*\r\n]*)',
            
            # 通用密钥模式
            'Secrets': r'(access_key|Access-Key|access_token|SecretKey|SecretId|admin_pass|admin_user|algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key|amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|api_key|api_key_secret|api_key_sid|api_secret|api\.googlemaps|AIza|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret|application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket|aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc|password|bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key|bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver|cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_secret|client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password|cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|config|conn\.login|connectionstring|consumer_key|consumer_secret|credentials|cypress_record_key|database_password|database_schema_test|datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password|digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd|docker_password|dockerhub_password|dockerhubpassword|dot|files|dotfiles|droplet_travis_password|dynamoaccesskeyid|dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password|env\.heroku_api_key|env\.sonatype_password|eureka\.awssecretkey)[a-z0-9_.\-,]{0,25}[a-z0-9A-Z_ .\-,]{0,25}(=|>|:=|\||:|<=|=>|:).{0,5}[\'"]([0-9a-zA-Z\-_=]{6,64})[\'"]',
        }

# ====================== URL拼接模块 ======================
class URLConcatenator(DebugMixin):
    def __init__(self, debug_mode=False, base_url=None, relative_url=None, custom_base_url=None, path_route=None, api_route=None):
        self.debug_mode = debug_mode
        # self.debug_mode = False
        # 支持字符串或列表，统一转为列表
        self.base_url = base_url if isinstance(base_url, list) else [base_url] if base_url else []
        self.relative_url = relative_url if isinstance(relative_url, list) else [relative_url] if relative_url else []
        self.custom_base_url = custom_base_url if isinstance(custom_base_url, list) else [custom_base_url] if custom_base_url else []
        self.path_route = path_route if isinstance(path_route, list) else [path_route] if path_route else []
        self.api_route = api_route if isinstance(api_route, list) else [api_route] if api_route else []
        self.url_list = set()

        if self.debug_mode:
            self._debug_print(f"[URLConcatenator]初始化URLConcatenator: base_url={self.base_url}, relative_url={self.relative_url}, custom_base_url={self.custom_base_url}, path_route={self.path_route}, api_route={self.api_route}")

    def smart_concatenation(self):
        """智能URL拼接"""
        results = set()
        for base_url in self.base_url:
            for relative_url in self.relative_url:
                if self.debug_mode:
                    self._debug_print(f"[smart_concatenation]开始拼接URL: base={base_url}, relative={relative_url}")
                
                # 根据不同类型的URL进行处理
                result = self._process_url_type(base_url, relative_url)
                if result:
                    results.add(result)
        return list(results)

    def _process_url_type(self, base_url, relative_url):
        """根据URL类型进行处理"""
        # 处理协议相对URL (//example.com/path)
        if relative_url.startswith('//'):
            base = urllib.parse.urlparse(base_url)
            return f"{base.scheme}:{relative_url}"
        
        # 处理hash路由（SPA应用）
        if relative_url.startswith('#/'):
            base = urllib.parse.urlparse(base_url)
            return f"{base.scheme}://{base.netloc}{base.path}{relative_url}"
        
        # 处理绝对路径
        if relative_url.startswith('/'):
            base = urllib.parse.urlparse(base_url)
            clean_path = relative_url.lstrip('/')
            return f"{base.scheme}://{base.netloc}/{clean_path}"
        
        # 处理相对路径
        if relative_url.startswith('./'):
            base = urllib.parse.urlparse(base_url)
            base_path = os.path.dirname(base.path) if not base.path.endswith('/') else base.path
            clean_relative = relative_url[2:].lstrip('/')
            return f"{base.scheme}://{base.netloc}{base_path}/{clean_relative}"
        
        # 处理上级目录
        if relative_url.startswith('../'):
            return self._process_parent_directory_url(base_url, relative_url)
        
        # 处理完整URL
        if relative_url.startswith(('http://', 'https://')):
            return relative_url
        
        # 默认拼接 - 使用urljoin但清理双斜杠
        joined = urllib.parse.urljoin(base_url, relative_url)
        parsed = urllib.parse.urlparse(joined)
        clean_path = re.sub(r'/{2,}', '/', parsed.path)
        return urllib.parse.urlunparse((
            parsed.scheme,
            parsed.netloc,
            clean_path,
            parsed.params,
            parsed.query,
            parsed.fragment
        ))

    def _process_parent_directory_url(self, base_url, relative_url):
        """
        处理上级目录URL
        
        Args:
            base_url: 基础URL，如 http://example.com/admin/login.aspx
            relative_url: 相对URL，如 ../scripts/jquery/jquery-1.11.2.min.js
            
        Returns:
            拼接后的完整URL
        """
        # 解析基础URL
        base = urllib.parse.urlparse(base_url)
        
        # 获取基础URL的目录路径（去掉文件名）
        base_path = base.path
        if not base_path.endswith('/'):
            # 如果不是以/结尾，说明是文件，需要获取其目录
            path_parts = base_path.split('/')
            if len(path_parts) > 1:
                base_path = '/'.join(path_parts[:-1])
            else:
                base_path = ''
        
        # 确保路径以/开头
        if base_path and not base_path.startswith('/'):
            base_path = '/' + base_path
        
        # 将基础路径分割成部分
        base_parts = [part for part in base_path.split('/') if part]
        
        # 处理相对URL中的../和./
        rel_parts = relative_url.split('/')
        back_count = 0
        new_parts = []
        
        for part in rel_parts:
            if part == '..':
                back_count += 1
            elif part == '.' or part == '':
                # 忽略当前目录和空字符串
                pass
            else:
                new_parts.append(part)
        
        # 计算新的基础路径（回退指定级数）
        if back_count > 0:
            if len(base_parts) >= back_count:
                # 回退指定级数
                remaining_parts = base_parts[:-back_count]
                new_base_path = '/' + '/'.join(remaining_parts) if remaining_parts else '/'
            else:
                # 如果回退次数超过路径深度，则回到根目录
                new_base_path = '/'
        else:
            # 没有回退，保持原路径
            new_base_path = '/' + '/'.join(base_parts) if base_parts else '/'
        
        # 添加新的路径部分
        if new_parts:
            if new_base_path.endswith('/'):
                final_path = new_base_path + '/'.join(new_parts)
            else:
                final_path = new_base_path + '/' + '/'.join(new_parts)
        else:
            final_path = new_base_path
        
        # 清理双斜杠
        final_path = re.sub(r'/{2,}', '/', final_path)
        
        # 构建完整URL
        return f"{base.scheme}://{base.netloc}{final_path}"

    def api_concatenation(self):
        """API路由拼接"""
        results = set()
        for base in self.custom_base_url:
            for route in self.api_route:
                for rel in self.relative_url:
                    if rel.startswith(('http://', 'https://')):
                        results.add(rel)
                        continue
                    base_clean = base.rstrip('/')
                    route_clean = route.strip('/')
                    rel_clean = rel.lstrip('/')
                    if route_clean:
                        result = f"{base_clean}/{route_clean}/{rel_clean}"
                    else:
                        result = f"{base_clean}/{rel_clean}"
                    if self.debug_mode:
                        self._debug_print(f"[api_concatenation]API拼接结果: {result}")
                    results.add(result)
        return list(results)

    def path_concatenation(self):
        """路径路由拼接"""
        results = set()
        for base in self.custom_base_url:
            for route in self.path_route:
                for rel in self.relative_url:
                    if rel.startswith(('http://', 'https://')):
                        results.add(rel)
                        continue
                    base_clean = base.rstrip('/')
                    route_clean = route.strip('/')
                    rel_clean = rel.lstrip('/')
                    if route_clean:
                        result = f"{base_clean}/{route_clean}/{rel_clean}"
                    else:
                        result = f"{base_clean}/{rel_clean}"
                    if self.debug_mode:
                        self._debug_print(f"[path_concatenation]路径拼接结果: {result}")
                    results.add(result)
        return list(results)

    def concatenate_urls(self):
        """拼接URL返回列表"""
        if self.debug_mode:
            self._debug_print(f"[concatenate_urls]开始拼接: base={self.base_url}, relative_url={self.relative_url} , custom_base_url={self.custom_base_url} , api_route={self.api_route} , path_route={self.path_route}")
        
        results = set()
        # 智能拼接
        if self.relative_url and self.base_url:
            results.update(self.smart_concatenation())
        # API拼接
        if self.api_route and self.custom_base_url:
            results.update(self.api_concatenation())
        # 路径拼接
        if self.path_route and self.custom_base_url:
            results.update(self.path_concatenation())
        if self.debug_mode:
            self._debug_print(f"[concatenate_urls]批量拼接完成，成功拼接 {len(results)} 个URL")
        return list(results)

    def url_check(self, url):
        """简单检查URL格式是否符合规范"""
        try:
            # 基本格式检查
            if not url or not isinstance(url, str):
                self._debug_print(f"URL格式不符合规范: {url} (空值或非字符串)")
                return False
            
            # 去除首尾空格
            url = url.strip()
            if not url:
                self._debug_print(f"URL格式不符合规范: {url} (空字符串)")
                return False
            
            # 检查URL解析
            parsed = urllib.parse.urlparse(url)
            
            # 检查协议
            if not parsed.scheme:
                self._debug_print(f"URL格式不符合规范: {url} (缺少协议)")
                return False
            
            # 检查协议是否有效
            valid_schemes = ['http', 'https', 'ftp', 'sftp', 'ws', 'wss']
            if parsed.scheme.lower() not in valid_schemes:
                self._debug_print(f"URL格式不符合规范: {url} (协议无效: {parsed.scheme})")
                return False
            
            # 检查域名
            if not parsed.netloc:
                self._debug_print(f"URL格式不符合规范: {url} (缺少域名)")
                return False
            
            # 检查域名格式
            domain_parts = parsed.netloc.split('.')
            if len(domain_parts) < 2:
                self._debug_print(f"URL格式不符合规范: {url} (域名格式无效: {parsed.netloc})")
                return False
            
            # 检查顶级域名
            tld = domain_parts[-1]
            if len(tld) < 2:
                self._debug_print(f"URL格式不符合规范: {url} (顶级域名无效: {tld})")
                return False
            
            # 检查端口号（如果存在）
            if ':' in parsed.netloc:
                host_port = parsed.netloc.split(':')
                if len(host_port) == 2:
                    try:
                        port = int(host_port[1])
                        if port < 1 or port > 65535:
                            self._debug_print(f"URL格式不符合规范: {url} (端口号无效: {port})")
                            return False
                    except ValueError:
                        self._debug_print(f"URL格式不符合规范: {url} (端口号格式无效: {host_port[1]})")
                        return False
            
            # 检查URL总长度
            if len(url) > 2048:
                self._debug_print(f"URL格式不符合规范: {url} (URL过长: {len(url)}字符)")
                return False
            
            return True
            
        except Exception as e:
            self._debug_print(f"URL格式检查异常: {url} (错误: {e})")
            return False
    
    def process_and_return_urls(self):
        """处理URL列表并返回结果"""
        # 清空当前列表
        self.url_list = set()  

        self._debug_print(f"[process_and_return_urls]开始处理URL列表: base={self.base_url}, path={self.relative_url}")
        
        # 拼接URL
        concatenated_urls = self.concatenate_urls()
        
        # 添加到内部列表
        for url in concatenated_urls:
            if self.url_check(url):
                self.url_list.add(url)
        
        self._debug_print(f"[process_and_return_urls]处理完成，返回 {len(self.url_list)} 个URL")
        
        return list(self.url_list)


# ====================== URL匹配模块 ======================
class URLMatcher(DebugMixin):
    # 全局危险接口过滤集合和锁
    danger_api_filtered = set()
    danger_api_lock = threading.Lock()
    
    def __init__(self, config, scanner=None):
        self.config = config
        self.debug_mode = config.debug_mode  # 设置debug_mode属性
        self.scanner = scanner  # 新增：可选scanner实例
        self.visited_urls_global = set()
    
    def is_valid_domain(self, url):
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc
        
        self._debug_print(f"检查域名有效性: {domain}")
        
        # 检查黑名单（无论scope模式如何，都应该检查黑名单）
        for black_domain in self.config.blacklist_domains:
            if black_domain in domain:
                # 紫色输出
                # print(f"\033[95m{domain}域名在黑名单中: {domain} (匹配: {black_domain})\033[0m")
                self._debug_print(f"域名在黑名单中: {domain} (匹配: {black_domain})")
                return False

        # 如果scope模式为2，则跳过域名范围检查，但仍然会检查黑名单
        if self.config.url_scope_mode == 2:
            self._debug_print(f"域名检查通过 (scope模式2): {domain}")
            return True
        
        # 如果scope模式为3，则只允许白名单域名
        if self.config.url_scope_mode == 3:
            for white_domain in self.config.whitelist_domains:
                if white_domain in domain:
                    self._debug_print(f"域名在白名单中 (scope模式3): {domain} (匹配: {white_domain})")
                    return True
            self._debug_print(f"域名不在白名单中 (scope模式3): {domain}")
            return False

        # scope=0: 只允许主域和子域
        if self.config.url_scope_mode == 0:
            if DOMAIN_EXTRACTION:
                ext = tldextract.extract(url)
                url_domain = f"{ext.domain}.{ext.suffix}"
                # 确保只匹配主域
                is_valid = url_domain == self.config.base_domain
            else:
                # 匹配主域或子域
                is_valid = domain == self.config.base_domain or domain.endswith('.' + self.config.base_domain)
        # 其他scope模式使用默认验证（主域匹配）
        else:
            if DOMAIN_EXTRACTION:
                ext = tldextract.extract(url)
                url_domain = f"{ext.domain}.{ext.suffix}"
                is_valid = url_domain == self.config.base_domain
            else:
                is_valid = domain == self.config.base_domain or domain.endswith('.' + self.config.base_domain)
        
        self._debug_print(f"域名检查结果: {domain} -> {'有效' if is_valid else '无效'} (scope={self.config.url_scope_mode})")
   
        return is_valid
    
    def should_skip_url(self, url):
        """检查URL是否应该跳过（基于扩展名）"""
        parsed = urllib.parse.urlparse(url)
        path = parsed.path.lower()
        
        # self._debug_print(f"检查URL是否跳过: {url}")
        
        # 检查扩展名黑名单
        for ext in self.config.extension_blacklist:
            if path.endswith(ext):
                self._debug_print(f"URL因扩展名跳过: {url} (扩展名: {ext})")
                return True
        
        self._debug_print(f"URL检查通过: {url}")
        
        return False
    
    def extract_urls(self, content, base_url):
        """从内容中提取URL - 全新匹配逻辑，专注于路径字符串"""
        try:
            urls = set()
            
            self._debug_print(f"开始从内容提取URL: base_url={base_url}")
            
            # 处理文本内容
            text_content = self._process_content(content)
            if text_content is None:
                return set()
        except Exception as e:
            self._debug_print(f"初始化URL提取时出错: {type(e).__name__}: {e}")
            return set()
        
        # 按类别匹配URL模式
        self._match_path_patterns(text_content, base_url, urls)
        self._match_tag_patterns(text_content, base_url, urls)
        self._match_webpack_patterns(text_content, base_url, urls)
        
        # 使用BeautifulSoup作为备选方案
        try:
            self._extract_with_bs(text_content, base_url, urls)
        except Exception as e:
            self._debug_print(f"BeautifulSoup提取时出错: {type(e).__name__}: {e}")
        
        self._debug_print(f"URL提取完成，共找到 {len(urls)} 个URL")
        
        return urls
    
    def _process_content(self, content):
        """处理内容，确保是字符串格式"""
        try:
            return content.decode('utf-8', 'ignore') if isinstance(content, bytes) else content
        except Exception as e:
            self._debug_print(f"内容解码失败: {type(e).__name__}: {e}")
            return str(content) if content else ""
    
    def _match_path_patterns(self, text_content, base_url, urls):
        """匹配路径模式"""
        # 主要regex匹配模式：捕获引号内的路径字符串
        path_patterns = [
            # !!! 新增: HAE Linkfinder 匹配 , 加上误报太多, 暂时关闭
            # r'''(?:"|')(((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})|((?:/|\.\./|\./)[^"'><,;|*()(%%$^/\\\[\]][^"'><,;|()]{1,})|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-]{1,}\.(?:\w)(?:[\?|#][^"|']{0,}|)))(?:"|')''',
            
            r'["\'](/[^"\'\s]+)["\']',  # 双引号或单引号包裹的绝对路径
            r'["\'](\.{1,2}/[^"\'\s]+)["\']',  # 双引号或单引号包裹的相对路径
            r'["\'](\\\\*/[^"\'\s]+)["\']',  # 匹配这种"href":"\/admin\/Auth\/adminList.html"
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
            # 增强模板字符串匹配: 支持相对路径
            r'`(?:https?://[^`]+|/{1,2}[^`]+|\.{1,2}/[^`]+)`',
            # 新增: 匹配JS中的动态路由定义
            r'router\.(?:addRoute|addRoutes)\s*\(\s*[\'"`]([^\s\'"`]+)[\'"`]',
            # 新增: 匹配CommonJS导入 (如 require("./api"))
            r'require\s*\(\s*[\'"`](\.[^\s\'"`]+)[\'"`]',
            # 新增: 匹配ES6动态导入 (如 import("./module"))
            r'import\s*\(\s*[\'"`](\.[^\s\'"`]+)[\'"`]'
        ]
        
        # 匹配主要路径模式
        try:
            for pattern in path_patterns:
                self._match_and_add(pattern, text_content, base_url, urls)
        except Exception as e:
            self._debug_print(f"匹配主要路径模式时出错: {type(e).__name__}: {e}")
    
    def _match_tag_patterns(self, text_content, base_url, urls):
        """匹配HTML标签中的路径属性"""
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
        
        # 匹配HTML标签中的路径属性
        try:
            for pattern in tag_patterns:
                self._match_and_add(pattern, text_content, base_url, urls)
        except Exception as e:
            self._debug_print(f"匹配HTML标签模式时出错: {type(e).__name__}: {e}")
    
    def _match_webpack_patterns(self, text_content, base_url, urls):
        """匹配webpack模式"""
        # webpack 匹配
        webpack_patterns = [
            # r'"?([\w].*?)"?:"(.*?)"'  # !!! HAE 匹配规则，效率太低，大页面匹配re函数会卡死，暂时关闭
            r'"(chunk-[\w\d]+)":"([\w\d]+)"'
        ]
        # !!!! webpack 单独匹配
        try:
            for pattern in webpack_patterns:
                self._match_webpack_add(pattern, text_content, base_url, urls)
        except Exception as e:
            self._debug_print(f"匹配webpack模式时出错: {type(e).__name__}: {e}")
    
    def _match_webpack_add(self, pattern, text_content, base_url, url_set):
        """使用webpack匹配 并添加URL"""
        try:
            matches = re.findall(pattern, text_content, re.IGNORECASE)
            if self.config.debug_mode and matches:
                self._debug_print(f"使用webpack匹配 '{pattern}' 找到 {len(matches)} 个匹配")
            if matches:
                for match in matches:
                    # match匹配结果 ('chunk-a2d74a98', '1ea71fd1') 拼接成chunk.a2d74a98.1ea71fd1.js
                    url = f"{match[0]}.{match[1]}.js"
                    if self._is_valid_webpack_url(url):
                        # 对base_url进行处理，只保留根路径，然后拼接url
                        parsed = urllib.parse.urlparse(base_url)
                        root_url = f"{parsed.scheme}://{parsed.netloc}/"
                         # !!! 暂时固定死拼接路径，后期可以优化
                        full_url = urllib.parse.urljoin(root_url, f"static/js/{url}") 
                        if full_url not in UltimateURLScanner.visited_urls_global and 'chunk' in full_url:
                            url_set.add(full_url)
        except Exception as e:
            self._debug_print(f"URL匹配错误 (模式: {pattern}): {str(e)}")
    
    def _is_valid_webpack_url(self, url):
        """检查webpack生成的URL是否有效"""
        return len(url) < 28 and len(url) > 20
    
    def _match_and_add(self, pattern, text_content, base_url, url_set):
        """使用正则表达式匹配并添加URL"""
        try:
            matches = re.findall(pattern, text_content, re.IGNORECASE)
            if self.config.debug_mode and matches:
                self._debug_print(f"正则匹配模式 '{pattern}' 找到 {len(matches)} 个匹配")
            # print(matches)
            for match in matches:
                # 处理可能的元组结果
                url = self._extract_url_from_match(match)
                if url:
                    # self._debug_print(f"处理匹配结果: {url}  匹配规则 -> {pattern} , base_url -> {base_url}")
                    try:
                        self._process_url(url, base_url, url_set, f"Regex: {pattern}")
                    except Exception as e:
                        self._debug_print(f"[_match_and_add]: 正则失败，{e}")
        except Exception as e:
            # print("system====================",e, pattern, text_content, base_url)
            self._debug_print(f"URL匹配错误 (模式: {pattern}): {str(e)}")
    
    def _extract_url_from_match(self, match):
        """从匹配结果中提取URL"""
        # 处理可能的元组结果
        if isinstance(match, tuple):
            # 取第一个非空匹配组
            return next((m for m in match if m), "")
        else:
            return match
    
    def _extract_with_bs(self, text_content, base_url, url_set):
        """使用BeautifulSoup提取URL"""
        try:
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
                            self._debug_print(f"BeautifulSoup找到: {tag}[{attr}] = {url}")
                            self._process_url(url, base_url, url_set, "BeautifulSoup")
            
            self._debug_print(f"BeautifulSoup提取完成，共处理 {bs_count} 个属性")
                
        except Exception as e:
            self._debug_print(f"BeautifulSoup解析错误: {str(e)}")
    
    def _process_url(self, url, base_url, url_set, source=""):
        """处理单个接口，拼接成URL，添加到集合中"""
        self._debug_print(f"处理单个接口: {url} , base_url -> {base_url} , source -> {source}")

        # 预处理URL
        processed_url = self._preprocess_url(url)
        if not processed_url:
            return
    
        # 处理完整URL（包含http/https）
        if 'http' in processed_url:
            self._process_full_urls(processed_url, url_set)
            return

        # 处理协议相对URL
        processed_url = self._handle_protocol_relative_url(processed_url, base_url)
        
        # 清理URL
        processed_url = self._clean_url(processed_url)

        # 应用智能拼接
        self._apply_url_concatenation(processed_url, base_url, url_set)

    def _preprocess_url(self, url):
        """预处理URL，清理和验证"""
        if not url or url.strip() == "":
            self._debug_print(f"跳过空URL")
            return None
    
        # 跳过常见无效URL
        if url.startswith(('javascript:', 'data:', 'mailto:', 'tel:')):
            self._debug_print(f"跳过无效URL: {url}")
            return None
        
        # 只保留URL允许的字符，遇到第一个不合法字符就截断
        m = re.match(r'^[a-zA-Z0-9:/?&=._~#%\\-]+', url)
        if m:
            url = m.group(0)
        else:
            return None  # 如果没有合法URL部分，直接跳过

        # 去除首尾引号和空格
        return url.strip().strip('\'"')

    def _process_full_urls(self, url, url_set):
        """处理包含完整协议的URL"""
        # 如果有多个http, 匹配字符串分割成多个URL，分别添加到集合中
        urls = re.findall(r'http[s]?://[^ ]+', url)
        for full_url in urls:
            if full_url:
                # 外部URL收集逻辑
                if not self.is_valid_domain(full_url):
                    # 只有当url_scope_mode不是0时，才收集外部URL
                    if self.scanner is not None and self.config.url_scope_mode != 0:
                        with self.scanner.external_urls_lock:
                            if full_url not in self.scanner.external_urls:
                                self.scanner.external_urls.add(full_url)
                                self.scanner.external_url_queue.put(full_url)
                    self.scanner.external_urls.add(full_url)
                    self._debug_print(f"外部URL已收集: {full_url}")
                    return  # 外部URL不加入主扫描集合
                else:
                    # 内部完整URL直接添加
                    if full_url not in url_set and not self.should_skip_url(full_url):
                        url_set.add(full_url)
                        self._debug_print(f"完整URL已添加到集合: {full_url}")

    def _handle_protocol_relative_url(self, url, base_url):
        """处理协议相对URL"""
        if url.startswith('//'):
            parsed_base = urllib.parse.urlparse(base_url)
            new_url = f"{parsed_base.scheme}:{url}"
            self._debug_print(f"协议相对URL处理: {new_url}")
            return new_url
        return url

    def _clean_url(self, url):
        """清理URL中的特殊字符"""
        # 去掉url中的所有的'\'
        return url.replace('\\', '')

    def _apply_url_concatenation(self, url, base_url, url_set):
        """应用URL拼接逻辑"""
        concatenator = URLConcatenator(self.config.debug_mode)
        concatenator.base_url = [base_url]  # 确保是列表格式
        concatenator.relative_url = [url]  # 确保是列表格式
        concatenator.custom_base_url = self.config.custom_base_url
        concatenator.path_route = self.config.path_route
        concatenator.api_route = self.config.api_route
        url_list = concatenator.process_and_return_urls()

        for normalized in url_list:
            self._debug_print(f"URL处理结果:{base_url} + {url} -> {normalized}")
            # 危险接口过滤检测
            if self.config.danger_filter_enabled:
                if self._is_dangerous_url(normalized):
                    self._handle_dangerous_url(normalized)
                    return

            if normalized and self.is_valid_domain(normalized) and not self.should_skip_url(normalized):
                url_set.add(normalized)
                self._debug_print(f"URL已添加到集合: {normalized}")
            else:
                self._debug_print(f"URL被过滤: {normalized}")
    
    def _is_dangerous_url(self, url):
        """检查URL是否为危险接口"""
        if not url.endswith(".js"):  # 排除JS文件
            for danger_api in self.config.danger_api_list:
                if danger_api.lower() in url.lower():
                    return True
        return False
    
    def _handle_dangerous_url(self, url):
        """处理危险URL"""
        # 使用线程锁确保输出安全，并过滤重复
        with URLMatcher.danger_api_lock:
            if url not in URLMatcher.danger_api_filtered:
                URLMatcher.danger_api_filtered.add(url)
                # 紫色输出 - 使用全局输出锁确保不与其他输出混合
                with output_lock:
                    print(Fore.MAGENTA + f"[危险] [危险] [危险] [危险] [跳过危险接口] {url} 包含 ({danger_api})" + Style.RESET_ALL)
                self._debug_print(f"[危险] [危险] [危险] [危险] [跳过危险接口] {url} 包含 ({danger_api})")
            else:
                # 重复的危险接口，只记录debug信息
                self._debug_print(f"[危险] [危险] [危险] [危险] [重复危险接口] {url} 包含 ({danger_api})")


# ====================== 敏感信息检测模块 ======================
class SensitiveDetector(DebugMixin):
    def __init__(self, sensitive_patterns, debug_mode=False):
        self.sensitive_patterns = sensitive_patterns
        self.debug_mode = debug_mode
    
    def detect(self, content):
        """检测响应中的敏感信息 - 返回结构化格式"""
        try:
            if not content:
                self._debug_print("内容为空，跳过敏感信息检测")
                return []
            
            self._debug_print("开始敏感信息检测")
            
            text_content = self._process_content(content)
            if text_content is None:
                return []
            
            detected = []
            
            for name, pattern in self.sensitive_patterns.items():
                detected_item = self._detect_pattern(name, pattern, text_content)
                if detected_item:
                    detected.append(detected_item)
            
            self._debug_print(f"敏感信息检测完成，共发现 {len(detected)} 种敏感信息")
            
            return detected
        except Exception as e:
            self._debug_print(f"敏感信息检测过程中出错: {type(e).__name__}: {e}")
            return []
    
    def _process_content(self, content):
        """处理内容，确保是字符串格式"""
        try:
            return content.decode('utf-8', 'ignore') if isinstance(content, bytes) else content
        except Exception as e:
            self._debug_print(f"内容解码失败: {type(e).__name__}: {e}")
            return str(content) if content else ""
    
    def _detect_pattern(self, name, pattern, text_content):
        """检测单个敏感信息模式"""
        try:
            matches = re.findall(pattern, text_content)
            if matches:
                return self._create_detected_item(name, matches)
            else:
                pass # 减少输出
                # self._debug_print(f"未发现敏感信息: {name}")
        except re.error as e:
            self._debug_print(f"正则表达式错误 ({name}): {str(e)}")
            return None  # 跳过无效的正则表达式
        except Exception as e:
            self._debug_print(f"处理敏感信息模式时出错 ({name}): {type(e).__name__}: {e}")
            return None
        return None
    
    def _create_detected_item(self, name, matches):
        """创建检测结果项"""
        # 去重并获取样本
        unique_matches = set(matches)
        count = len(unique_matches)
        
        # 获取样本
        samples = list(unique_matches)
    
        # 构建结构化结果
        detected_item = {
            'type': name,  # 敏感信息类型
            'count': count,  # 发现数量
            'samples': samples,  # 样本清单
            'total': len(unique_matches)  # 总数量
        }
        
        self._debug_print(f"发现敏感信息: {name} x{count} 个样本")
        return detected_item

# ====================== 输出处理模块 ======================
class OutputHandler(DebugMixin):
    def __init__(self, config):
        self.config = config
        self.debug_mode = config.debug_mode  # 设置debug_mode属性
        self.url_count = 0
        self.start_time = time.time()
        self.request_signature_count = {}  # 记录请求签名出现次数
        self.is_duplicate = getattr(config, 'is_duplicate', 0)
        
        # 准备输出文件
        if config.output_file:
            os.makedirs(os.path.dirname(os.path.abspath(config.output_file)), exist_ok=True)
            with open(config.output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['URL', 'Status', 'Title', 'Length', 'Redirects', 'Depth', 'Sensitive Types', 'Sensitive Counts', 'Sensitive Details', 'Is Duplicate'])
            
            self._debug_print(f"输出文件已初始化: {config.output_file}")
    
    def _format_sensitive_data_for_csv(self, sensitive_raw):
        """格式化敏感信息数据用于CSV保存 - 返回三个字段：类型、数量、详细清单"""
        try:
            if not sensitive_raw:
                return "", "", ""
            
            sensitive_types = []
            sensitive_counts = []
            sensitive_details = []
            
            for item in sensitive_raw:
                try:
                    if isinstance(item, dict):
                        # 结构化格式
                        sensitive_type = item.get('type', '未知')
                        count = item.get('count', 0)
                        samples = item.get('samples', [])
                        
                        sensitive_types.append(sensitive_type)
                        sensitive_counts.append(str(count))
                        
                        # 详细清单：样本内容（最多显示前3个，用分号分隔）
                        if samples:
                            # detail_samples = samples[:3]  # 最多显示3个样本
                            detail_samples = samples  # 显示全部样本
                            # 确保所有样本都是字符串类型
                            detail_samples_str = [str(sample) for sample in detail_samples]
                            detail_str = f"{sensitive_type}:{'; '.join(detail_samples_str)}"
                            # 如果样本数量大于3，显示..., 暂不启用
                            # if len(samples) > 3:
                            #     detail_str += f"...(共{count}个)"
                        else:
                            detail_str = f"{sensitive_type}:无样本"
                        
                        sensitive_details.append(detail_str)
                    else:
                        # 其他格式
                        item_str = str(item)
                        sensitive_types.append("未知类型")
                        sensitive_counts.append("1")
                        sensitive_details.append(item_str)
                except Exception as e:
                    if self.config.debug_mode:
                        self._debug_print(f"处理敏感信息项时出错: {type(e).__name__}: {e}")
                    sensitive_types.append("处理错误")
                    sensitive_counts.append("0")
                    sensitive_details.append(f"处理错误: {type(e).__name__}")
            
            return "|".join(sensitive_types), "|".join(sensitive_counts), "|".join(sensitive_details)
        except Exception as e:
            if self.config.debug_mode:
                self._debug_print(f"格式化敏感信息数据时出错: {type(e).__name__}: {e}")
            return "格式化错误", "0", f"格式化错误: {type(e).__name__}"
    
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
        elif "Err" in str(status):
            return Fore.RED + Style.BRIGHT
        
        return Fore.CYAN
    
    def format_result_line(self, result):
        """格式化终端输出行，返回字符串（含颜色）"""
        try:
            # 提取基本信息
            depth_str = f"[深度:{result['depth']}]"
            status_str = f"[{result['status']}]"
            length_str = f"[{result['length']}]"
            time_str = f"[{result['time']:.2f}s]"
            
            # 获取状态颜色
            status_color = self.get_status_color(result['status'])
            
            # 处理标题
            title_str = self._format_title(result.get('title', ''))
            
            # 处理文件类型
            file_type_str, file_type_color = self._format_file_type(result.get('url', ''))
            
            # 处理敏感信息
            sensitive_str = self._format_sensitive_info(result.get('sensitive_raw', []))
            
            # 重复URL标记
            is_duplicate_signature = result.get('is_duplicate_signature', False)
            if is_duplicate_signature and self.is_duplicate == 1:
                return (f"{Fore.MAGENTA}{depth_str} {status_str} {length_str} {title_str} {result['url']} {time_str} {sensitive_str} {Style.RESET_ALL}")
            
            # 正常输出
            return (
                f"{Fore.BLUE}{depth_str}{Style.RESET_ALL} "
                f"{status_color}{status_str}{Style.RESET_ALL} "
                f"{Fore.WHITE}{length_str}{Style.RESET_ALL} "
                f"{file_type_color}{file_type_str}{Style.RESET_ALL} "
                f"{Fore.CYAN}{title_str}{Style.RESET_ALL} "
                f"{Fore.WHITE}{result['url']}{Style.RESET_ALL} "
                f"{Fore.YELLOW}{time_str}{Style.RESET_ALL}"
                f"{sensitive_str}"
            )
        except Exception as e:
            return f"{Fore.RED}格式化输出行出错: {type(e).__name__}: {e}{Style.RESET_ALL}"
    
    def _format_title(self, title):
        """格式化标题显示"""
        if title:
            return f"[{str(title)[:30]:^10}]"  # 确保title是字符串
        else:
            return "[===========]"
    
    def _format_file_type(self, url):
        """格式化文件类型显示"""
        url_path = url.split('?')[0] if url else ''
        filename = url_path.split('/')[-1]
        if '.' in filename:
            ext = filename.split('.')[-1].upper()
            return f"[{ext}]", Fore.LIGHTCYAN_EX
        else:
            return "[接口]", Fore.RED
    
    def _format_sensitive_info(self, sensitive_raw):
        """格式化敏感信息显示"""
        if not sensitive_raw:
            return ""
        
        sensitive_types = []
        for item in sensitive_raw:
            if isinstance(item, dict):
                sensitive_type = item.get('type', '未知')
                count = item.get('count', 0)
                display_format = f"{sensitive_type}X{count}"
                sensitive_types.append(display_format)
            else:
                sensitive_types.append(str(item))
        
        return Fore.RED + Style.BRIGHT + f" -> [{'，'.join(sensitive_types)}]"

    def print_result_line(self, line):
        """只负责终端输出"""
        with output_lock:
            print(line)

    def write_result_to_csv(self, result, file_path=None):
        """只负责写入一行到CSV"""
        try:
            if not file_path:
                file_path = self.config.output_file
            with open(file_path, 'a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                sensitive_types, sensitive_counts, sensitive_details = self._format_sensitive_data_for_csv(result.get('sensitive_raw'))
                link_type = self._get_link_type(result.get('url', ''))
                writer.writerow([
                    result.get('url', ''),
                    result.get('status', ''),
                    result.get('title', ''),
                    result.get('length', 0),
                    link_type,
                    result.get('redirects', ''),
                    result.get('depth', 0),
                    sensitive_types,
                    sensitive_counts,
                    sensitive_details,
                    '是' if result.get('is_duplicate_signature', False) else '否'
                ])
        except Exception as e:
            if self.config.debug_mode:
                self._debug_print(f"写入CSV文件时出错: {type(e).__name__}: {e}")
            print(f"{Fore.RED}写入CSV文件失败: {type(e).__name__}: {e}{Style.RESET_ALL}")
    
    def _get_link_type(self, url):
        """获取链接类型"""
        if not url:
            return "接口"
        
        url_path = url.split('?')[0]
        filename = url_path.split('/')[-1]
        if '.' in filename:
            return filename.split('.')[-1].upper()
        else:
            return "接口"

    def realtime_output(self, result):
        """彩色实时输出扫描结果，调度格式化、输出、写入文件"""
        try:
            self.url_count += 1
            if self.config.debug_mode:
                self._debug_print(f"处理扫描结果 #{self.url_count}: {result.get('url', '未知URL')}")
            
            # 处理错误状态
            if isinstance(result.get('status'), str) and 'Err' in result['status']:
                result['status'] = 'Err'
                
            # 生成请求签名用于重复检测
            is_duplicate_signature = self._check_duplicate_signature(result)
            result['is_duplicate_signature'] = is_duplicate_signature
            
            # 处理重复URL
            if is_duplicate_signature:
                if self.is_duplicate == 1:
                    line = self.format_result_line(result)
                    self.print_result_line(line)
                return
            
            # 正常输出
            line = self.format_result_line(result)
            if self.config.verbose:
                self.print_result_line(line)
            else:
                self.print_result_line(line)
                
            # 写入CSV文件
            if self.config.output_file:
                self.write_result_to_csv(result, self.config.output_file)
        except Exception as e:
            if self.config.debug_mode:
                self._debug_print(f"初始化输出处理时出错: {type(e).__name__}: {e}")
            return
    
    def _check_duplicate_signature(self, result):
        """检查是否为重复请求签名"""
        # 生成请求签名
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
        return count > 0

    def generate_report(self, results, report_file="full_report.csv"):
        """生成最终扫描报告，遍历结果调用write_result_to_csv"""
        try:
            if self.config.debug_mode:
                self._debug_print(f"开始生成最终报告: {report_file}")
                self._debug_print(f"报告包含 {len(results)} 个扫描结果")
            
            # 确保目录存在
            os.makedirs(os.path.dirname(os.path.abspath(report_file)), exist_ok=True)
            
            # 写入表头
            with open(report_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['URL', '状态', '标题', '长度', '链接类型', '重定向', '深度', '敏感信息类型', '敏感信息数量', '敏感信息详细清单', '是否重复'])
            
            # 写入数据
            for result in results:
                self.write_result_to_csv(result, report_file)
        except Exception as e:
            if self.config.debug_mode:
                self._debug_print(f"生成报告时出错: {type(e).__name__}: {e}")
            print(f"{Fore.RED}生成报告失败: {type(e).__name__}: {e}{Style.RESET_ALL}")
            return
        
        if self.config.debug_mode:
            self._debug_print(f"最终报告生成完成: {report_file}")
        
        # 输出完成信息
        with output_lock:
            print(f"\n\n{Fore.GREEN}扫描完成! 共扫描 {len(results)} 个URL{Style.RESET_ALL} ")
            print(f"{Fore.GREEN}完整报告已保存至: {report_file}{Style.RESET_ALL} ")
            print(f"{Fore.GREEN}=============================================={Style.RESET_ALL} ")

    def append_results(self, results, report_file="full_report.csv"):
        """追加写入扫描结果到报告文件（不写表头），遍历结果调用write_result_to_csv"""
        try:
            for result in results:
                self.write_result_to_csv(result, report_file)
        except Exception as e:
            if self.config.debug_mode:
                self._debug_print(f"追加结果到文件时出错: {type(e).__name__}: {e}")
            print(f"{Fore.RED}追加结果到文件失败: {type(e).__name__}: {e}{Style.RESET_ALL}")

    def output_external_unvisited(self, urls, report_file=None):
        """输出未访问的外部URL，全部紫色，写入文件（标准格式）"""
        try:
            from colorama import Fore, Style
            for url in urls:
                try:
                    output_line = (
                        f"{Fore.MAGENTA}[外部] [外部] [外部] [外部] [外部] {url} [外部] [外部] {Style.RESET_ALL}"
                    )
                    with output_lock:
                        print(output_line)
                    # 构造标准result字典
                    result = {
                        'url': url,
                        'status': '外部',
                        'title': '外部',
                        'length': 0,
                        'redirects': '',
                        'depth': 0,
                        'time': 0,
                        'sensitive': '',
                        'sensitive_raw': [],
                        'is_duplicate_signature': False,
                        'content_type': '',
                        'headers_count': 0,
                        'error_type': None,
                        'original_url': url,
                    }
                    if report_file:
                        self.write_result_to_csv(result, report_file)
                except Exception as e:
                    if self.config.debug_mode:
                        self._debug_print(f"处理外部URL时出错: {type(e).__name__}: {e}")
                    print(f"{Fore.RED}处理外部URL时出错: {type(e).__name__}: {e}{Style.RESET_ALL}")
        except Exception as e:
            if self.config.debug_mode:
                self._debug_print(f"输出外部URL时出错: {type(e).__name__}: {e}")
            print(f"{Fore.RED}输出外部URL失败: {type(e).__name__}: {e}{Style.RESET_ALL}")

# ====================== 扫描核心模块 ======================
class UltimateURLScanner(DebugMixin):
    # 全局共享的已访问URL集合和锁
    visited_urls_global = set()
    visited_urls_lock = threading.Lock()

    def __init__(self, config):
        self.config = config
        self.debug_mode = config.debug_mode  # 设置debug_mode属性
        
        # 请求链接计数器
        self.request_count = 0
        self.request_count_lock = threading.Lock()
        self.max_requests = config.max_urls # 最大请求数
        
        # 初始化连接池
        self._init_connection_pool()
        
        # 初始化队列和状态
        self._init_queues_and_state()
        
        # 初始化组件
        self._init_components()
        
        if self.config.debug_mode:
            self._debug_print("扫描器初始化完成")

    def _init_connection_pool(self):
        """初始化连接池配置"""
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        
        # 创建会话并配置连接池
        self.session = requests.Session()
        
        # 配置连接池大小 - 根据线程数调整
        pool_size = max(50, self.config.max_workers * 2)  # 至少50个连接，或线程数的2倍
        max_pool_size = max(100, self.config.max_workers * 3)  # 最大连接数
        
        # 创建HTTP适配器
        adapter = HTTPAdapter(
            pool_connections=pool_size,
            pool_maxsize=max_pool_size,
            max_retries=Retry(
                total=3,
                backoff_factor=0.1,
                status_forcelist=[500, 502, 503, 504]
            )
        )
        
        # 为HTTP和HTTPS都配置适配器
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        
        # 设置会话头
        self.session.headers = self.config.headers
        
        # 设置连接超时和读取超时
        self.session.timeout = (self.config.timeout, self.config.timeout)
        
        if self.config.debug_mode:
            self._debug_print(f"连接池配置: pool_connections={pool_size}, pool_maxsize={max_pool_size}")
            self._debug_print(f"最大请求数配置: max_requests={self.max_requests}")

    def _init_queues_and_state(self):
        """初始化队列和状态变量"""
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

    def _init_components(self):
        """初始化扫描组件"""
        self.url_matcher = URLMatcher(self.config, scanner=self)
        self.sensitive_detector = SensitiveDetector(self.config.sensitive_patterns, self.config.debug_mode)
        self.output_handler = OutputHandler(self.config)

    def _check_request_limits(self):
        """检查请求限制，返回是否应该继续处理"""
        # 检查URL数量限制
        if self.output_handler.url_count >= self.config.max_urls:
            self._debug_print(f"达到最大URL数量限制: {self.output_handler.url_count}/{self.config.max_urls}")
            return False
        
        # 检查请求数量限制
        with self.request_count_lock:
            if self.request_count >= self.max_requests:
                self._debug_print(f"达到最大请求数限制: {self.request_count}/{self.max_requests}")
                return False
        
        return True

    def _periodic_cleanup(self, processed_count, last_cleanup_time):
        """定期清理连接池"""
        current_time = time.time()
        if processed_count % 1000 == 0 and processed_count > 0 and (current_time - last_cleanup_time) > 60:
            try:
                self._cleanup_connections()
                self._debug_print(f"定期清理连接池 - 线程: {threading.current_thread().name}")
                return current_time
            except Exception as e:
                self._debug_print(f"清理连接池失败: {type(e).__name__}: {e} - 线程: {threading.current_thread().name}")
        
        return last_cleanup_time

    def _safe_queue_get(self, queue_obj, timeout=10):
        """安全地从队列获取项目"""
        try:
            return queue_obj.get(timeout=timeout)
        except queue.Empty:
            return None
        except Exception as e:
            self._debug_print(f"队列获取异常: {type(e).__name__}: {e}")
            return None

    def _safe_queue_task_done(self, queue_obj):
        """安全地标记队列任务完成"""
        try:
            queue_obj.task_done()
        except Exception as e:
            self._debug_print(f"task_done异常: {e}")

    def _process_url_result(self, url, depth, result, result_list, lock=None):
        """统一处理URL扫描结果"""
        if result:
            if lock:
                with lock:
                    result_list.append(result)
            else:
                result_list.append(result)
            self._debug_print(f"成功处理URL: {url}")
            return True
        else:
            self._debug_print(f"URL处理返回None: {url}")
            return False

    def _http_request(self, url):
        """统一的HTTP请求和异常处理，返回response或异常信息 - 精简版"""
        max_retries = 3
        response = None
        last_exception = None
        
        # 检查是否在黑名单中
        for black_domain in self.config.blacklist_domains:
            if black_domain in url:
                self._debug_print(f"[_http_request] 域名在黑名单中，跳过请求: {url} (匹配: {black_domain})")
                return None, Exception(f"域名在黑名单中: {url}")
        
        # 检查是否在白名单中（scope模式3）
        if self.config.url_scope_mode == 3:
            in_whitelist = False
            for white_domain in self.config.whitelist_domains:
                if white_domain in url:
                    in_whitelist = True
                    self._debug_print(f"[_http_request] 域名在白名单中: {url} (匹配: {white_domain})")
                    break
            if not in_whitelist:
                self._debug_print(f"[_http_request] 域名不在白名单中，跳过请求: {url}")
                return None, Exception(f"域名不在白名单中: {url}")

        # 检查请求数量限制
        with self.request_count_lock:
            if self.request_count >= self.max_requests:
                self._debug_print(f"[_http_request] 达到最大请求数限制: {self.request_count}/{self.max_requests}")
                return None, Exception("达到最大请求数限制")
            self.request_count += 1
            current_request_count = self.request_count

        # 输出当前线程情况
        try:    
            self._debug_print(f"[_http_request] 开始请求: {url} (请求计数: {current_request_count}/{self.max_requests})\n"
                            f"[_http_request] 配置: proxy={self.config.proxy}, timeout={self.config.timeout}\n"
                            f"[_http_request] 目前线程和队列情况: {threading.active_count()}, 主队列: {self.url_queue.qsize()}, 外部队列: {self.external_url_queue.qsize()}")
        except Exception as e:
            self._debug_print(f"[_http_request] 输出请求信息失败: {type(e).__name__}: {e}")
        
        for attempt in range(max_retries):
            try:
                self._debug_print(f"[_http_request] 第{attempt+1}次尝试请求: {url}")
                
                # 使用会话的超时设置，避免重复设置
                response = self.session.get(
                    url,
                    timeout=self.config.timeout,
                    proxies=self.config.proxy,
                    verify=False,
                    allow_redirects=True
                )
            
                self._debug_print(f"[_http_request] 请求成功: url={url}, status_code={response.status_code}, elapsed={response.elapsed}")
                
                return response, None
                
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout, 
                   requests.exceptions.SSLError, requests.exceptions.RequestException) as e:
                last_exception = e
                self._debug_print(f"[_http_request] 网络异常 (第{attempt+1}次): {type(e).__name__}: {e}")
                if attempt < max_retries - 1:
                    time.sleep(0.5)
                    
            except requests.exceptions.TooManyRedirects as e:
                last_exception = e
                self._debug_print(f"[_http_request] 重定向过多: {e}")
                break  # 重定向过多不重试
                    
            except Exception as e:
                last_exception = e
                self._debug_print(f"[_http_request] 未知异常 (第{attempt+1}次): {type(e).__name__}: {e}")
                if attempt < max_retries - 1:
                    time.sleep(0.5)
        
        self._debug_print(f"[_http_request] 所有重试失败: {type(last_exception).__name__}: {last_exception}")
        
        return None, last_exception

    def _cleanup_connections(self):
        """清理连接池中的连接"""
        try:
            if hasattr(self.session, 'poolmanager'):
                # 清理连接池
                self.session.poolmanager.clear()
                self._debug_print("连接池已清理")
        except Exception as e:
            self._debug_print(f"清理连接池时出错: {type(e).__name__}: {e}")

    def get_request_stats(self):
        """获取请求统计信息"""
        with self.request_count_lock:
            return {
                'current_requests': self.request_count,
                'max_requests': self.max_requests,
                'remaining_requests': max(0, self.max_requests - self.request_count),
                'url_count': self.output_handler.url_count,
                'max_urls': self.config.max_urls
            }

    def _build_result(self, url, response=None, error=None, depth=0):
        """统一构建扫描结果字典 - 增强错误处理和调试信息"""
        self._debug_print(f"[_build_result] 开始构建结果: url={url}, depth={depth}, response={response is not None}, error={error}")
        
        # 初始化结果字段
        elapsed = 0
        redirect_chain = []
        final_url = url
        sensitive_info = []
        status = 'Err'
        title = ''
        content = ''
        content_type = ''
        headers_info = {}
        
        if response is not None:
            # 处理成功的响应
            elapsed = self._extract_response_time(response)
            redirect_chain = self._extract_redirect_chain(response)
            final_url = self._extract_final_url(response, url)
            content = self._extract_response_content(response)
            headers_info, content_type = self._extract_headers_info(response)
            sensitive_info = self._detect_sensitive_info(content)
            status = self._extract_status_code(response)
            title = self._extract_title(response)
        elif error is not None:
            # 处理错误情况
            status = self._format_error_status(error)
            if self.config.debug_mode:
                self._debug_print(f"[_build_result] 处理错误: {type(error).__name__}: {error}")
        else:
            # 处理异常情况
            if self.config.debug_mode:
                self._debug_print(f"[_build_result] 警告: response和error都为None")
            status = "Error: No response and no error"
        
        # 构建结果字典
        result = {
            'url': final_url,
            'status': status,
            'title': title,
            'length': len(content),
            'redirects': ' → '.join([str(x) for x in redirect_chain]),
            'depth': depth,
            'time': elapsed,
            'sensitive': sensitive_info,  # 用于显示
            'sensitive_raw': sensitive_info,  # 保存原始结构化数据
            'is_duplicate': False,
            'content_type': content_type,  # 新增：内容类型
            'headers_count': len(headers_info),  # 新增：响应头数量
            'error_type': type(error).__name__ if error else None,  # 新增：错误类型
            'original_url': url,  # 新增：原始URL
        }
        
        if self.config.debug_mode:
            self._debug_print(f"[_build_result] 结果构建完成: status={status}, length={len(content)}, sensitive_count={len(sensitive_info)}")
        
        return result
    
    def _extract_response_time(self, response):
        """提取响应时间"""
        try:
            elapsed = getattr(response, 'elapsed', None)
            if elapsed:
                elapsed = elapsed.total_seconds()
            else:
                elapsed = 0
            if self.config.debug_mode:
                self._debug_print(f"[_build_result] 响应时间: {elapsed}秒")
            return elapsed
        except Exception as e:
            if self.config.debug_mode:
                self._debug_print(f"[_build_result] 获取响应时间失败: {e}")
            return 0
    
    def _extract_redirect_chain(self, response):
        """提取重定向链"""
        try:
            redirect_chain = [r.url for r in response.history] if response.history else []
            if self.config.debug_mode:
                self._debug_print(f"[_build_result] 重定向链: {len(redirect_chain)} 个重定向")
            return redirect_chain
        except Exception as e:
            if self.config.debug_mode:
                self._debug_print(f"[_build_result] 获取重定向链失败: {e}")
            return []
    
    def _extract_final_url(self, response, original_url):
        """提取最终URL"""
        try:
            final_url = response.url
            if self.config.debug_mode:
                self._debug_print(f"[_build_result] 最终URL: {final_url}")
            return final_url
        except Exception as e:
            if self.config.debug_mode:
                self._debug_print(f"[_build_result] 获取最终URL失败: {e}, 使用原始URL: {original_url}")
            return original_url
    
    def _extract_response_content(self, response):
        """提取响应内容"""
        try:
            # 默认先用 requests 推断的编码
            content_bytes = response.content
            encoding = None

            # 优先用 response.encoding（但有些网站会错误地标成 ISO-8859-1）
            if response.encoding and response.encoding.lower() != 'iso-8859-1':
                encoding = response.encoding
            else:
                # 用 chardet 检测编码
                detected = chardet.detect(content_bytes)
                encoding = detected.get('encoding', 'utf-8')

            try:
                content = content_bytes.decode(encoding, errors='replace')
            except Exception:
                # 兜底用 utf-8
                content = content_bytes.decode('utf-8', errors='replace')

            if self.config.debug_mode:
                self._debug_print(f"[_build_result] 响应内容长度: {len(content)} 字节, 编码: {encoding}")
            return content
        except Exception as e:
            if self.config.debug_mode:
                self._debug_print(f"[_build_result] 获取响应内容失败: {e}")
            return ''
    
    def _extract_headers_info(self, response):
        """提取响应头信息"""
        try:
            headers_info = dict(response.headers) if hasattr(response, 'headers') else {}
            content_type = headers_info.get('Content-Type', '')
            if self.config.debug_mode:
                self._debug_print(f"[_build_result] Content-Type: {content_type}")
            return headers_info, content_type
        except Exception as e:
            if self.config.debug_mode:
                self._debug_print(f"[_build_result] 获取响应头失败: {e}")
            return {}, ''
    
    def _detect_sensitive_info(self, content):
        """检测敏感信息"""
        try:
            sensitive_info = self.sensitive_detector.detect(content)
            if self.config.debug_mode:
                self._debug_print(f"[_build_result] 敏感信息检测结果: {len(sensitive_info)} 项")
            return sensitive_info
        except Exception as e:
            if self.config.debug_mode:
                self._debug_print(f"[_build_result] 敏感信息检测失败: {e}")
            return []
    
    def _extract_status_code(self, response):
        """提取状态码"""
        try:
            status = getattr(response, 'status_code', 'Err')
            if self.config.debug_mode:
                self._debug_print(f"[_build_result] 状态码: {status}")
            return status
        except Exception as e:
            if self.config.debug_mode:
                self._debug_print(f"[_build_result] 获取状态码失败: {e}")
            return 'Err'
    
    def _extract_title(self, response):
        """提取页面标题，优化编码判断逻辑"""
        try:
            if response.status_code != 200:
                return f"请求失败，状态码: {response.status_code}", None
            
            # 检测响应内容的编码
            raw_content = response.content
            # self._debug_print(f"响应内容长度: {len(raw_content)} 字节")
            
            detected_encoding = chardet.detect(raw_content)['encoding']
            self._debug_print(f"chardet检测到的编码: {detected_encoding}, chardet检测可信度: {chardet.detect(raw_content)['confidence']}")
            
            # 尝试使用不同编码解码
            encodings_to_try = ['utf-8', 'gbk', 'gb2312', 'utf-16']
            if detected_encoding and detected_encoding not in encodings_to_try:
                encodings_to_try.append(detected_encoding)
            
            best_title = None
            best_encoding = None
            
            for encoding in encodings_to_try:
                try:
                    content = raw_content.decode(encoding)
                    soup = BeautifulSoup(content, 'html.parser')
                    title = soup.title.string.strip() if soup.title else ''
                    # print(f"使用 {encoding} 解码的标题: {title}")
                    
                    # 保存最佳结果
                    if best_title is None or len(title) > len(best_title):
                        best_title = title
                        best_encoding = encoding
                except UnicodeDecodeError:
                    # print(f"{encoding} 解码失败")
                    continue
                                    
            # 处理 str 类型标题
            best_title = str(best_title).strip().replace('\n', '').replace('\r', '')
            if self.config.debug_mode:
                self._debug_print(f"[_build_result] 提取到标题: {best_title[:50]}...")

            return best_title if best_title else ''

        except Exception as e:
            # print(f"[_build_result] 标题提取失败: {e}")
            if self.config.debug_mode:
                self._debug_print(f"[_build_result] 标题提取失败: {e}")
            return ''
    
    def _format_error_status(self, error):
        """格式化错误状态"""
        error_type = type(error).__name__
        error_msg = str(error)
        
        if isinstance(error, requests.exceptions.ConnectionError):
            return f"ConnectionError: {error_msg}"
        elif isinstance(error, requests.exceptions.Timeout):
            return f"TimeoutError: {error_msg}"
        elif isinstance(error, requests.exceptions.SSLError):
            return f"SSLError: {error_msg}"
        elif isinstance(error, requests.exceptions.TooManyRedirects):
            return f"TooManyRedirects: {error_msg}"
        elif isinstance(error, requests.exceptions.RequestException):
            return f"RequestError: {error_msg}"
        else:
            return f"Error({error_type}): {error_msg}"

    def _extract_and_process_urls(self, content, base_url, depth):
        """提取和处理URL的统一方法"""
        if not content:
            self._debug_print(f"无法获取内容，跳过URL提取: {base_url}")
            return
        
        try:
            new_urls = self.url_matcher.extract_urls(content, base_url)
            self._debug_print(f"从内容中提取到 {len(new_urls)} 个新URL")
        except Exception as e:
            self._debug_print(f"内容URL提取异常: {type(e).__name__}: {e}, url={base_url}, depth={depth}")
            new_urls = []
        
        # print(new_urls)
        # 处理新URL
        added_count = 0
        skipped_count = 0
        error_count = 0
        
        for new_url in new_urls:
            try:
                with UltimateURLScanner.visited_urls_lock:
                    if new_url not in UltimateURLScanner.visited_urls_global and not self.url_matcher.should_skip_url(new_url):
                        self.url_queue.put((new_url, depth + 1))
                        UltimateURLScanner.visited_urls_global.add(new_url)
                        added_count += 1
                    else:
                        skipped_count += 1
            except Exception as e:
                error_count += 1
                self._debug_print(f"新URL入队异常: {type(e).__name__}: {e}, url={base_url}, depth={depth}, new_url={new_url}")
        
        self._debug_print(f"URL处理统计: 添加={added_count}, 跳过={skipped_count}, 错误={error_count}")

    def scan_url(self, url, depth=0):
        """扫描单个URL，整合请求、内容处理、递归、重复判断 - 增强错误处理"""
        if self.config.debug_mode:
            self._debug_print(f"[scan_url] 开始扫描: url={url}, depth={depth}")
        
        # 预检查URL是否应该扫描
        check_result = self._pre_check_url(url, depth)
        if check_result is not None:
            return check_result
        
        if self.config.debug_mode:
            self._debug_print(f"[scan_url] 开始扫描URL: {url} (深度: {depth})")
        
        # 延迟处理
        time.sleep(self.config.delay)
        
        # HTTP请求
        response, error = self._http_request(url)
        
        # 输出请求统计信息（仅在debug模式下）
        self._log_request_stats()
        
        # 构建结果
        result = self._build_result(url, response, error, depth)
        
        # 实时输出
        self._realtime_output_result(result)
        
        # 递归内容提取
        self._recursive_extract_urls(response, result, depth)
        
        if self.config.debug_mode:
            self._debug_print(f"[scan_url] 扫描完成: url={url}, status={result.get('status', 'Unknown')}")
        
        return result
    
    def _pre_check_url(self, url, depth):
        """预检查URL是否应该扫描"""
        # 检查扫描状态
        if not self.running or depth > self.config.max_depth:
            if self.config.debug_mode:
                self._debug_print(f"[scan_url] 跳过URL扫描: {url} (深度: {depth}, 最大深度: {self.config.max_depth}, running: {self.running})")
            return None
        
        # 检查域名是否在黑名单中
        for black_domain in self.config.blacklist_domains:
            if black_domain in url:
                self._debug_print(f"[scan_url] 域名在黑名单中，跳过扫描: {url} (匹配: {black_domain})")
                return None
                
        # 检查URL是否应该跳过
        if self.url_matcher.should_skip_url(url):
            if self.config.debug_mode:
                self._debug_print(f"[scan_url] URL被过滤跳过: {url}")
            return None

        # 检查域名是否在白名单中（scope模式3）
        if self.config.url_scope_mode == 3:
            in_whitelist = False
            for white_domain in self.config.whitelist_domains:
                if white_domain in url:
                    in_whitelist = True
                    self._debug_print(f"[scan_url] 域名在白名单中: {url} (匹配: {white_domain})")
                    break
            if not in_whitelist:
                self._debug_print(f"[scan_url] 域名不在白名单中，跳过扫描: {url}")
                return None
        

        
        # url_scope_mode 0: 只允许主域/子域
        if self.config.url_scope_mode == 0:
            if not self.url_matcher.is_valid_domain(url):
                if self.config.debug_mode:
                    self._debug_print(f"[scan_url] 外部URL跳过: {url}")
                return None
        
        # url_scope_mode 1: 外部链接访问一次，不递归
        elif self.config.url_scope_mode == 1:
            return self._handle_external_url_once(url, depth)
        
        return None  # 继续扫描
    
    def _handle_external_url_once(self, url, depth):
        """处理只访问一次的外部URL"""
        if not self.url_matcher.is_valid_domain(url):
            with UltimateURLScanner.visited_urls_lock:
                if url in UltimateURLScanner.visited_urls_global:
                    if self.config.debug_mode:
                        self._debug_print(f"[scan_url] 外部URL已访问过: {url}")
                    return None
                UltimateURLScanner.visited_urls_global.add(url)
            if self.config.debug_mode:
                self._debug_print(f"[scan_url] 外部URL只访问一次: {url}")
            response, error = self._http_request(url)
            result = self._build_result(url, response, error, depth)
            try:
                self.output_handler.realtime_output(result)
            except Exception as e:
                if self.config.debug_mode:
                    self._debug_print(f"[scan_url] 外部URL输出失败: {e}")
            return result
        return None
    
    def _log_request_stats(self):
        """记录请求统计信息"""
        if self.config.debug_mode:
            stats = self.get_request_stats()
            self._debug_print(f"[scan_url] 请求统计: {stats['current_requests']}/{stats['max_requests']} 请求, {stats['url_count']}/{stats['max_urls']} URL")
    
    def _realtime_output_result(self, result):
        """实时输出结果"""
        try:
            self.output_handler.realtime_output(result)
        except Exception as e:
            if self.config.debug_mode:
                self._debug_print(f"[scan_url] 实时输出失败: {e}")
    
    def _recursive_extract_urls(self, response, result, depth):
        """递归提取URL"""
        if response is not None and depth < self.config.max_depth:
            try:
                content = getattr(response, 'content', b'')
                content_type = response.headers.get('Content-Type', '') if hasattr(response, 'headers') else ''
                
                if self.config.debug_mode:
                    self._debug_print(f"[scan_url] 开始从内容提取URL: {result['url']} (内容类型: {content_type}, 内容长度: {len(content)})")
                
                self._extract_and_process_urls(content, result['url'], depth)
                        
            except Exception as e:
                if self.config.debug_mode:
                    self._debug_print(f"[scan_url] 递归处理异常: {type(e).__name__}: {e}, url={result.get('url', 'Unknown')}, depth={depth}")
        else:
            if self.config.debug_mode:
                if response is None:
                    self._debug_print(f"[scan_url] 响应为空，跳过递归")
                elif depth >= self.config.max_depth:
                    self._debug_print(f"[scan_url] 达到最大深度，跳过递归: depth={depth}, max_depth={self.config.max_depth}")

    def _worker_loop(self, queue_obj, result_list, lock=None, is_external=False):
        """统一的工作线程循环"""
        thread_name = threading.current_thread().name
        if self.config.debug_mode:
            self._debug_print(f"[worker_loop] {'外部URL' if is_external else '工作'}线程启动: {thread_name}")
        
        processed_count = 0
        error_count = 0
        last_cleanup_time = time.time()
        
        while (self.external_running if is_external else self.running) or not queue_obj.empty():
            try:
                # 获取并处理队列项目
                item = self._get_and_process_queue_item(
                    queue_obj, result_list, lock, is_external, thread_name,
                    processed_count, last_cleanup_time)
                
                if item is False:  # 线程应该退出
                    break
                    
                # 更新计数器和清理时间
                if item is True:  # 成功处理了一个项目
                    processed_count += 1
                    last_cleanup_time = self._update_cleanup_time(processed_count, last_cleanup_time)
                    
            except Exception as e:
                error_count += 1
                if self.config.debug_mode:
                    self._debug_print(f"[worker_loop] {'外部URL' if is_external else '工作'}线程主循环异常: {type(e).__name__}: {e}, 线程: {thread_name}")
                self._safe_queue_task_done(queue_obj)
        
        if self.config.debug_mode:
            self._debug_print(f"[worker_loop] {'外部URL' if is_external else '工作'}线程结束: {thread_name}, 处理={processed_count}, 错误={error_count}")
    
    def _get_and_process_queue_item(self, queue_obj, result_list, lock, is_external, thread_name, processed_count, last_cleanup_time):
        """获取并处理队列中的项目"""
        # 从队列获取URL
        item = self._safe_queue_get(queue_obj, timeout=2 if is_external else 10)
        if not item:
            if not (self.external_running if is_external else self.running):
                if self.config.debug_mode:
                    self._debug_print(f"[worker_loop] {'外部URL' if is_external else '工作'}线程队列为空，退出: {thread_name}")
                return False  # 表示线程应该退出
            return None  # 继续循环
        
        url, depth = item if isinstance(item, tuple) else (item, 0)
        
        # 检查请求限制
        if not self._check_request_limits():
            if self.config.debug_mode:
                self._debug_print(f"[worker_loop] 达到限制，跳过扫描URL: {url} (深度: {depth}) - 线程: {thread_name}")
            self._safe_queue_task_done(queue_obj)
            return None  # 继续循环
        
        # 定期清理连接池
        last_cleanup_time = self._periodic_cleanup(processed_count, last_cleanup_time)
        
        if self.config.debug_mode:
            self._debug_print(f"[worker_loop] 处理URL: {url} (深度: {depth}) - 线程: {thread_name}")
        
        # 扫描URL
        try:
            result = self.scan_url(url, depth)
            # 处理结果
            self._handle_scan_result(result, url, depth, result_list, lock, is_external)
            self._debug_print(f"成功处理URL: {url}")
            self._safe_queue_task_done(queue_obj)
            return True  # 表示成功处理了一个项目
        except Exception as e:
            if self.config.debug_mode:
                self._debug_print(f"[worker_loop] URL扫描异常: {type(e).__name__}: {e}, url={url}, depth={depth}, 线程={thread_name}")
            self._safe_queue_task_done(queue_obj)
            return None  # 继续循环
    
    def _handle_scan_result(self, result, url, depth, result_list, lock, is_external):
        """处理扫描结果"""
        if is_external:
            # 外部线程收集的结果全部标准化
            if result is None:
                # 构造标准外链result
                result = {
                    'url': url,
                    'status': '外部',
                    'title': '外部',
                    'length': 0,
                    'redirects': '',
                    'depth': depth,
                    'time': 0,
                    'sensitive': '',
                    'sensitive_raw': [],
                    'is_duplicate_signature': False,
                    'content_type': '',
                    'headers_count': 0,
                    'error_type': None,
                    'original_url': url,
                }
            if lock:
                with lock:
                    result_list.append(result)
            else:
                result_list.append(result)
        else:
            self._process_url_result(url, depth, result, result_list, lock)
    
    def _update_cleanup_time(self, processed_count, last_cleanup_time):
        """更新清理时间"""
        current_time = time.time()
        if processed_count % 1000 == 0 and processed_count > 0 and (current_time - last_cleanup_time) > 60:
            try:
                self._cleanup_connections()
                self._debug_print(f"定期清理连接池 - 线程: {threading.current_thread().name}")
                return current_time
            except Exception as e:
                self._debug_print(f"清理连接池失败: {type(e).__name__}: {e} - 线程: {threading.current_thread().name}")
        
        return last_cleanup_time

    def worker(self):
        """工作线程 - 增强错误处理"""
        self._worker_loop(self.url_queue, self.results, self.lock, is_external=False)

    def external_worker(self):
        """外部URL工作线程 - 增强错误处理"""
        self._worker_loop(self.external_url_queue, self.external_results, self.lock, is_external=True)

    def start_scan(self):
        """开始扫描过程 - 增强错误处理"""
        if self.config.debug_mode:
            self._debug_print(f"[start_scan] 开始扫描过程: start_url={self.config.start_url}")
            # 输出初始配置信息
            stats = self.get_request_stats()
            self._debug_print(f"[start_scan] 初始配置: 最大请求数={stats['max_requests']}, 最大URL数={stats['max_urls']}")
        
        try:
            # 添加起始URL到队列
            self.url_queue.put((self.config.start_url, 0))
            if self.config.debug_mode:
                self._debug_print(f"[start_scan] 起始URL已加入队列: {self.config.start_url}")
            
            # 创建线程池
            with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
                if self.config.debug_mode:
                    self._debug_print(f"[start_scan] 创建线程池，工作线程数: {self.config.max_workers}")
                
                # 启动工作线程
                workers = []
                try:
                    workers = [executor.submit(self.worker) for _ in range(min(self.config.max_workers, 100))]
                    if self.config.debug_mode:
                        self._debug_print(f"[start_scan] 已启动 {len(workers)} 个工作线程")
                except Exception as e:
                    if self.config.debug_mode:
                        self._debug_print(f"[start_scan] 启动工作线程失败: {type(e).__name__}: {e}")
                    raise
                
                # 等待所有任务完成
                try:
                    if self.config.debug_mode:
                        self._debug_print(f"[start_scan] 等待队列任务完成...")
                    self.url_queue.join()
                    if self.config.debug_mode:
                        self._debug_print(f"[start_scan] 队列任务已完成")
                except Exception as e:
                    if self.config.debug_mode:
                        self._debug_print(f"[start_scan] 等待队列完成时异常: {type(e).__name__}: {e}")
                
                # 停止扫描
                self.running = False
                if self.config.debug_mode:
                    self._debug_print(f"[start_scan] 扫描已停止，取消工作线程")
                
                # 取消工作线程
                for i, worker in enumerate(workers):
                    try:
                        worker.cancel()
                        if self.config.debug_mode:
                            self._debug_print(f"[start_scan] 已取消工作线程 {i+1}")
                    except Exception as e:
                        if self.config.debug_mode:
                            self._debug_print(f"[start_scan] 取消工作线程 {i+1} 失败: {e}")
                
                if self.config.debug_mode:
                    self._debug_print(f"[start_scan] 所有工作线程已处理")
                
                # 扫描结束时清理连接池
                try:
                    self._cleanup_connections()
                    if self.config.debug_mode:
                        self._debug_print(f"[start_scan] 扫描结束，连接池已清理")
                except Exception as e:
                    if self.config.debug_mode:
                        self._debug_print(f"[start_scan] 清理连接池失败: {type(e).__name__}: {e}")
                    
        except Exception as e:
            if self.config.debug_mode:
                self._debug_print(f"[start_scan] 扫描过程异常: {type(e).__name__}: {e}")
            self.running = False
            # 异常时也清理连接池
            try:
                self._cleanup_connections()
                if self.config.debug_mode:
                    self._debug_print(f"[start_scan] 异常退出，连接池已清理")
            except Exception as cleanup_e:
                if self.config.debug_mode:
                    self._debug_print(f"[start_scan] 异常退出时清理连接池失败: {type(cleanup_e).__name__}: {cleanup_e}")
            raise

    def generate_report(self, report_file="full_report.csv"):
        if self.config.debug_mode:
            self._debug_print(f"生成最终报告: {report_file}")
        self.output_handler.generate_report(self.results, report_file)
        # print(f"{Fore.MAGENTA}========生成最终报告===={Style.RESET_ALL}")
        # print(self.external_results)
        if hasattr(self, 'external_urls'):
            with UltimateURLScanner.visited_urls_lock:
                unvisited = [u for u in self.external_urls if u not in UltimateURLScanner.visited_urls_global]
            if unvisited:
                print(f"{Fore.MAGENTA}=============================================={Style.RESET_ALL}")
                print(f"{Fore.MAGENTA}未访问的外部URL如下:\n{Style.RESET_ALL}")
                self.output_handler.output_external_unvisited(unvisited, report_file)
                print(f"\n{Fore.MAGENTA}外部URL已经追加到报告文件: {report_file}{Style.RESET_ALL}")

    def _generate_report_filename(self):
        """生成报告文件名"""
        from datetime import datetime
        import re as _re
        parsed_url = urllib.parse.urlparse(self.config.start_url)
        domain = parsed_url.netloc or self.config.start_url
        # 只保留域名部分，去除端口
        domain = domain.split(':')[0]
        # 去除非字母数字和点
        domain = _re.sub(r'[^a-zA-Z0-9.]', '', domain)
        dt_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        return f"results/{domain}_{dt_str}.csv"

    def _handle_scan_completion(self, start_time, external_thread):
        """处理扫描完成后的清理工作"""
        try:
            # 自动生成报告文件名
            report_filename = self._generate_report_filename()
            
            if self.config.debug_mode:
                print(f"{Fore.CYAN}[start_scanning] 生成报告: {report_filename}{Style.RESET_ALL}")
            
            self.generate_report(report_filename)
            total_time = time.time() - start_time
            
            if total_time > 0:
                avg_speed = self.output_handler.url_count / total_time
            else:
                avg_speed = 0

            # 输出所有发现的危险链接
            if URLMatcher.danger_api_filtered:
                with output_lock:
                    print(f"\n{Fore.MAGENTA}=== 扫描过程中发现的危险链接汇总 ==={Style.RESET_ALL}")
                    print(f"{Fore.MAGENTA}共发现 {len(URLMatcher.danger_api_filtered)} 个危险链接:{Style.RESET_ALL}")
                    for i, danger_url in enumerate(sorted(URLMatcher.danger_api_filtered), 1):
                        print(f"{Fore.MAGENTA}[{i:3d}] {danger_url}{Style.RESET_ALL}")
                
                # 将危险链接写入CSV文件
                try:
                    with open(report_filename, 'a', newline='', encoding='utf-8') as f:
                        writer = csv.writer(f)
                        
                        # 写入每个危险链接，使用与正常扫描结果相同的格式
                        for i, danger_url in enumerate(sorted(URLMatcher.danger_api_filtered), 1):
                            # 检测危险类型
                            danger_types = []
                            for danger_api in self.config.danger_api_list:
                                if danger_api in danger_url and not danger_url.endswith(".js"):
                                    danger_types.append(danger_api)
                            
                            danger_type_str = ", ".join(danger_types) if danger_types else "未知"
                            
                            # 使用与正常扫描结果相同的列格式：URL, 状态, 标题, 长度, 链接类型, 重定向, 深度, 敏感信息类型, 敏感信息数量, 敏感信息详细清单, 是否重复
                            writer.writerow([
                                danger_url,           # URL
                                '危险',               # 状态
                                '危险接口',           # 标题
                                0,                    # 长度
                                '危险',               # 链接类型
                                '',                   # 重定向
                                0,                    # 深度
                                danger_type_str,      # 敏感信息类型
                                '1',                  # 敏感信息数量
                                f'危险接口: {danger_type_str}',  # 敏感信息详细清单
                                '否'                  # 是否重复
                            ])
                    print(f"{Fore.MAGENTA}\n危险链接已经追加到报告文件: {report_filename} \n {Style.RESET_ALL}")
                    if self.config.debug_mode:
                        self._debug_print(f"危险链接已经追加到报告文件: {report_filename}")
                        
                except Exception as e:
                    if self.config.debug_mode:
                        self._debug_print(f"写入危险链接汇总到CSV文件时出错: {type(e).__name__}: {e}")
                    with output_lock:
                        print(f"{Fore.RED}写入危险链接汇总到CSV文件失败: {type(e).__name__}: {e}{Style.RESET_ALL}")
            else:
                with output_lock:
                    print(f"{Fore.YELLOW}=============================================={Style.RESET_ALL}")
                    print(f"{Fore.GREEN}未发现危险链接{Style.RESET_ALL}")
            
            print(f"{Fore.YELLOW}=============================================={Style.RESET_ALL}")
            print(f"{Fore.YELLOW}总耗时: {total_time:.2f}秒 | 平均速度: {avg_speed:.1f} URL/秒{Style.RESET_ALL}")
            print(f"{Fore.GREEN}扫描结束!{Style.RESET_ALL}")
            
            # 优雅关闭外部线程
            try:
                self.external_running = False
                external_thread.join(timeout=10)
                if self.config.debug_mode:
                    print(f"{Fore.CYAN}[start_scanning] 外部URL线程已关闭{Style.RESET_ALL}")
            except Exception as e:
                if self.config.debug_mode:
                    print(f"{Fore.RED}[start_scanning] 关闭外部URL线程失败: {e}{Style.RESET_ALL}")
            
            # 生成外部URL访问报告
            try:
                if hasattr(self, 'external_results') and self.external_results:
                    self.output_handler.append_results(self.external_results, report_filename)
                    print(f"{Fore.GREEN}外部URL访问结束，结果已追加写入: {report_filename}{Style.RESET_ALL}")
            except Exception as e:
                if self.config.debug_mode:
                    print(f"{Fore.RED}[start_scanning] 处理外部URL结果失败: {e}{Style.RESET_ALL}")
            
            # 最终清理连接池
            try:
                self._cleanup_connections()
                if self.config.debug_mode:
                    print(f"{Fore.CYAN}[start_scanning] 最终清理连接池完成{Style.RESET_ALL}")
            except Exception as e:
                if self.config.debug_mode:
                    print(f"{Fore.RED}[start_scanning] 最终清理连接池失败: {e}{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}生成报告时出错: {str(e)}{Style.RESET_ALL}")
            if self.config.debug_mode:
                print(f"{Fore.RED}[start_scanning] 报告生成异常详情: {type(e).__name__}: {e}{Style.RESET_ALL}")
                import traceback
                traceback.print_exc()
            
            # 异常时也清理连接池
            try:
                self._cleanup_connections()
                if self.config.debug_mode:
                    print(f"{Fore.CYAN}[start_scanning] 异常退出时清理连接池完成{Style.RESET_ALL}")
            except Exception as cleanup_e:
                if self.config.debug_mode:
                    print(f"{Fore.RED}[start_scanning] 异常退出时清理连接池失败: {cleanup_e}{Style.RESET_ALL}")

    def start_scanning(self):
        """启动扫描器 - 增强错误处理"""
        if self.config.debug_mode:
            print(f"{Fore.CYAN}[start_scanning] 开始初始化扫描器...{Style.RESET_ALL}")
        
        try:
            if self.config.debug_mode:
                print(f"{Fore.CYAN}[start_scanning] 扫描器创建成功{Style.RESET_ALL}")
            
            print(f"{Fore.GREEN}扫描器已就绪，开始扫描目标: {self.config.start_url}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}配置: 最大深度={self.config.max_depth}, 最大URL数={self.config.max_urls}, 线程数={self.config.max_workers}{Style.RESET_ALL}")
            start_time = time.time()
            
            # 启动外部URL线程
            try:
                external_thread = threading.Thread(target=self.external_worker, name="ExternalURLThread", daemon=True)
                external_thread.start()
                if self.config.debug_mode:
                    print(f"{Fore.CYAN}[start_scanning] 外部URL线程已启动{Style.RESET_ALL}")
            except Exception as e:
                if self.config.debug_mode:
                    print(f"{Fore.RED}[start_scanning] 启动外部URL线程失败: {e}{Style.RESET_ALL}")
                # 继续执行，不因为外部线程失败而停止

            try:
                self.start_scan()
            except KeyboardInterrupt:
                print(f"\n{Fore.RED}扫描被用户中断!{Style.RESET_ALL}")
                if self.config.debug_mode:
                    print(f"{Fore.YELLOW}[start_scanning] 用户中断扫描{Style.RESET_ALL}")
            except Exception as e:
                print(f"\n{Fore.RED}扫描出错: {str(e)}{Style.RESET_ALL}")
                if self.config.debug_mode:
                    print(f"{Fore.RED}[start_scanning] 扫描异常详情: {type(e).__name__}: {e}{Style.RESET_ALL}")
                    import traceback
                    traceback.print_exc()
            finally:
                self._handle_scan_completion(start_time, external_thread)
        
        except Exception as e:
            print(f"{Fore.RED}扫描器初始化失败: {str(e)}{Style.RESET_ALL}")
            if self.config.debug_mode:
                print(f"{Fore.RED}[start_scanning] 初始化异常详情: {type(e).__name__}: {e}{Style.RESET_ALL}")
                import traceback
                traceback.print_exc()



def main():
    try:
        # 打印程序信息
        _print_program_info()
        
        # 解析命令行参数
        args = _parse_arguments()
        
        # 验证参数
        _validate_arguments(args)
        
        # 加载配置
        config_data = _load_config()
        
        # 获取配置值的辅助函数
        def get_config_value(key, default=None):
            return getattr(args, key, None) if getattr(args, key, None) is not None else config_data.get(key, default)
        
        # 创建配置对象
        config = _create_config(args, config_data, get_config_value)
        
        # 打印配置信息
        _print_config_info(config)
        
        # 执行扫描
        if args.start_url:
            _scan_single_url(config, args.start_url)
        elif args.url_file:
            _scan_multiple_urls(config, args.url_file, get_config_value)
            
    except Exception as e:
        print(f"{Fore.RED}程序运行出错: {type(e).__name__}: {e}{Style.RESET_ALL}")
        sys.exit(1)

def _print_program_info():
    """打印程序信息"""
    print(f"{Fore.YELLOW}=============================================={Style.RESET_ALL}")
    print(f"{Fore.YELLOW}=== WhiteURLScan v1.7.4 ===")
    print(f"{Fore.YELLOW}=== BY: white1434  GitHub: https://github.com/white1434/WhiteURLScan")
    print(f"{Fore.YELLOW}=== 重复的URL不会重复扫描, 结果返回相同的URL不会重复展示")
    print(f"{Fore.CYAN}=== 所有输出将同时记录到 results/output.out 文件中")
    print(f"{Fore.CYAN}=== 扫描开始时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

def _parse_arguments():
    """解析命令行参数"""
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
        return parser.parse_args()
    except Exception as e:
        print(f"{Fore.RED}解析命令行参数时出错: {type(e).__name__}: {e}{Style.RESET_ALL}")
        sys.exit(1)

def _validate_arguments(args):
    """验证命令行参数"""
    # 必须至少输入 --start_url 或 --url_file
    if not args.start_url and not args.url_file:
        print(f"{Fore.RED}错误：-h查看帮助 , 必须通过 -u 或 -f 至少指定一个扫描目标！{Style.RESET_ALL}")
        sys.exit(1)

def _load_config():
    """加载配置文件"""
    try:
        config_path = 'config.json'
        default_config = {
            "start_url": None,
            "proxy": None,
            "delay": 0.1,
            "max_workers": 30,
            "timeout": 3,
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
            "is_duplicate": 0,
            "url_scope_mode": 0,
            "danger_filter_enabled": 1,
            "danger_api_list": ["del","delete","insert","logout","loginout","remove","drop","shutdown","stop","poweroff","restart","rewrite","terminate","deactivate","halt","disable"],
            "custom_base_url": ["https://www.canopyu.com/"],
            "path_route": ["/api/v1/user/login"],
            "api_route": ["/api/v1/user/login"],
            "fuzz": 0
        }
        if not os.path.exists(config_path):
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(default_config, f, ensure_ascii=False, indent=2)
            print(f"{Fore.YELLOW}=== 未检测到config.json，已自动创建默认配置文件！请根据需要修改。{Style.RESET_ALL}")
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"{Fore.RED}读取配置文件时出错: {type(e).__name__}: {e}{Style.RESET_ALL}")
        sys.exit(1)

def _create_config(args, config_data, get_config_value):
    """创建配置对象"""
    print(f"{Fore.CYAN}=== 正在初始化扫描器...{Style.RESET_ALL}")
    return ScannerConfig(
        start_url=get_config_value('start_url'),
        proxy=get_config_value('proxy'),
        delay=get_config_value('delay', 0.1),
        max_workers=get_config_value('max_workers', 30),
        timeout=get_config_value('timeout', 3),
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
        fuzz=get_config_value('fuzz', 0)
    )

def _print_config_info(config):
    """打印配置信息"""
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

def _scan_single_url(config, start_url):
    """扫描单个URL"""
    print(f"{Fore.YELLOW}开始扫描: {start_url}{Style.RESET_ALL}")
    scanner = UltimateURLScanner(config)
    scanner.start_scanning()

def _scan_multiple_urls(config, url_file, get_config_value):
    """扫描多个URL"""
    try:
        if not os.path.exists(url_file):
            print(f"{Fore.RED}错误：URL文件 {url_file} 不存在！{Style.RESET_ALL}")
            sys.exit(1)
        
        with open(url_file, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
        
        print(f"{Fore.YELLOW}从文件读取到 {len(urls)} 个URL，开始批量扫描...{Style.RESET_ALL}")
        
        all_results = []  # 新增：用于汇总所有扫描结果
        all_external_results = []  # 新增：用于汇总所有外链结果
        all_danger_results = []  # 新增：用于汇总所有危险接口
        batch_summary_file = f"results/all_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        for i, url in enumerate(urls, 1):
            try:
                print(f"{Fore.CYAN}[{i}/{len(urls)}] 开始扫描: {url}{Style.RESET_ALL}")
                # 为每个URL创建独立的配置实例
                url_config = ScannerConfig(
                    start_url=url,
                    proxy=get_config_value('proxy'),
                    delay=get_config_value('delay', 0.1),
                    max_workers=get_config_value('max_workers', 30),
                    timeout=get_config_value('timeout', 3),
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
                    fuzz=get_config_value('fuzz', 0)
                )
                scanner = UltimateURLScanner(url_config)
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
        output_handler = OutputHandler(url_config)
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
    
