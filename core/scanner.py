import threading
import queue
import warnings
from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning, XMLParsedAsHTMLWarning
import requests
from concurrent.futures import ThreadPoolExecutor
from core.url_matcher import URLMatcher
from core.sensitive import SensitiveDetector
from core.output import OutputHandler
import time
import os
import urllib.parse
import csv
import hashlib
import chardet
from datetime import datetime
from colorama import Fore, Style
from utils.debug import DebugMixin
import tldextract


# ====================== 扫描核心模块 ======================
class ExternalUrlManager:
    def __init__(self):
        self.external_urls = set()
        self.external_url_queue = queue.Queue()
        self.external_urls_lock = threading.Lock()
    def add_external_url(self, url):
        with self.external_urls_lock:
            if url not in self.external_urls:
                self.external_urls.add(url)
                self.external_url_queue.put(url)

class UltimateURLScanner(DebugMixin):
    # 全局共享的已访问URL集合和锁
    visited_urls_global = set()
    visited_urls_lock = threading.Lock()

    def __init__(self, config, output_lock=None):
        self.output_lock = output_lock if output_lock is not None else threading.Lock()
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
        self.external_url_manager = ExternalUrlManager()
        self.external_results = []
        self.external_running = True

    def _init_components(self):
        self.output_handler = OutputHandler(self.config, output_lock=self.output_lock)
        self.url_matcher = URLMatcher(self.config, output_handler=self.output_handler, external_url_manager=self.external_url_manager, output_lock=self.output_lock)
        self.sensitive_detector = SensitiveDetector(self.config.sensitive_patterns, self.config.debug_mode)

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
        
        start_time = time.time()
        elapsed = 0
        redirect_chain = []
        final_url = url
        sensitive_info = []
        status = 'Err'
        title = ''
        content = b''
        content_type = ''
        headers_info = {}


        
        if response is not None:
            self._debug_print(f"[_build_result] 处理响应对象: status_code={getattr(response, 'status_code', 'N/A')}")
    
            # 获取响应时间
            try:
                elapsed = getattr(response, 'elapsed', None)
                if elapsed:
                    elapsed = elapsed.total_seconds()
                else:
                    elapsed = 0
                if self.config.debug_mode:
                    self._debug_print(f"[_build_result] 响应时间: {elapsed}秒")
            except Exception as e:
                if self.config.debug_mode:
                    self._debug_print(f"[_build_result] 获取响应时间失败: {e}")
                elapsed = 0
            
            # 获取重定向链
            try:
                redirect_chain = [r.url for r in response.history] if response.history else []
                if self.config.debug_mode:
                    self._debug_print(f"[_build_result] 重定向链: {len(redirect_chain)} 个重定向")
            except Exception as e:
                if self.config.debug_mode:
                    self._debug_print(f"[_build_result] 获取重定向链失败: {e}")
                redirect_chain = []
            
            # 获取最终URL
            try:
                final_url = response.url
                if self.config.debug_mode:
                    self._debug_print(f"[_build_result] 最终URL: {final_url}")
            except Exception as e:
                if self.config.debug_mode:
                    self._debug_print(f"[_build_result] 获取最终URL失败: {e}, 使用原始URL: {url}")
                final_url = url

            # 获取响应内容
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
            except Exception as e:
                if self.config.debug_mode:
                    self._debug_print(f"[_build_result] 获取响应内容失败: {e}")
                content = ''

            # 获取响应头信息
            try:
                headers_info = dict(response.headers) if hasattr(response, 'headers') else {}
                content_type = headers_info.get('Content-Type', '')
                if self.config.debug_mode:
                    self._debug_print(f"[_build_result] Content-Type: {content_type}")
            except Exception as e:
                if self.config.debug_mode:
                    self._debug_print(f"[_build_result] 获取响应头失败: {e}")
                headers_info = {}
                content_type = ''
            
            # 检测敏感信息
            try:
                sensitive_info = self.sensitive_detector.detect(content)
                if self.config.debug_mode:
                    self._debug_print(f"[_build_result] 敏感信息检测结果: {len(sensitive_info)} 项")
            except Exception as e:
                if self.config.debug_mode:
                    self._debug_print(f"[_build_result] 敏感信息检测失败: {e}")
                sensitive_info = []
            
            # 获取状态码
            try:
                status = getattr(response, 'status_code', 'Err')
                if self.config.debug_mode:
                    self._debug_print(f"[_build_result] 状态码: {status}")
            except Exception as e:
                if self.config.debug_mode:
                    self._debug_print(f"[_build_result] 获取状态码失败: {e}")
                status = 'Err'
            
            # 提取标题
            try:
                if content and content_type and 'text/html' in content_type:
                    if self.config.debug_mode:
                        self._debug_print(f"[_build_result] 开始解析HTML标题")
                    
                    with warnings.catch_warnings():
                        warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
                        warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)
                        
                        if 'xml' in content_type.lower():
                            soup = BeautifulSoup(content, 'lxml-xml')
                        else:
                            soup = BeautifulSoup(content, 'html.parser')
                    
                    t = soup.title
                    # 处理标题中的特殊字符和换行符，并防止乱码
                    if t and t.string:
                        title = t.string
                        # 处理 bytes 类型标题
                        if isinstance(title, bytes):
                            detected = chardet.detect(title)
                            encoding = detected.get('encoding', 'utf-8')
                            try:
                                title = title.decode(encoding, errors='replace')
                            except Exception:
                                title = title.decode('utf-8', errors='replace')
                        # 处理 str 类型标题
                        title = str(title).strip().replace('\n', '').replace('\r', '')
                        if self.config.debug_mode:
                            self._debug_print(f"[_build_result] 提取到标题: {title[:50]}...")
                    else:
                        if self.config.debug_mode:
                            self._debug_print(f"[_build_result] 未找到标题标签")
                else:
                    if self.config.debug_mode:
                        self._debug_print(f"[_build_result] 跳过标题提取: content_type={content_type}, content_length={len(content)}")
            except Exception as e:
                if self.config.debug_mode:
                    self._debug_print(f"[_build_result] 标题提取失败: {e}")
                title = ''
        
        elif error is not None:
            if self.config.debug_mode:
                self._debug_print(f"[_build_result] 处理错误: {type(error).__name__}: {error}")
            
            # 详细错误信息
            error_type = type(error).__name__
            error_msg = str(error)
            
            if isinstance(error, requests.exceptions.ConnectionError):
                status = f"ConnectionError: {error_msg}"
            elif isinstance(error, requests.exceptions.Timeout):
                status = f"TimeoutError: {error_msg}"
            elif isinstance(error, requests.exceptions.SSLError):
                status = f"SSLError: {error_msg}"
            elif isinstance(error, requests.exceptions.TooManyRedirects):
                status = f"TooManyRedirects: {error_msg}"
            elif isinstance(error, requests.exceptions.RequestException):
                status = f"RequestError: {error_msg}"
            else:
                status = f"Error({error_type}): {error_msg}"
            
            if self.config.debug_mode:
                self._debug_print(f"[_build_result] 最终错误状态: {status}")
        else:
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
        
        # 检查URL是否应该跳过
        if self.url_matcher.should_skip_url(url):
            if self.config.debug_mode:
                self._debug_print(f"[scan_url] URL被过滤跳过: {url}")
            return None
        
        # url_scope_mode 0: 只允许主域/子域
        if self.config.url_scope_mode == 0:
            if not self.url_matcher.is_valid_domain(url):
                if self.config.debug_mode:
                    self._debug_print(f"[scan_url] 外部URL跳过: {url}")
                return None
        
        # url_scope_mode 1: 外部链接访问一次，不递归
        elif self.config.url_scope_mode == 1:
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
        
        if self.config.debug_mode:
            self._debug_print(f"[scan_url] 开始扫描URL: {url} (深度: {depth})")
        
        # 延迟处理
        time.sleep(self.config.delay)
        
        # HTTP请求
        response, error = self._http_request(url)

        
        # 输出请求统计信息（仅在debug模式下）
        if self.config.debug_mode:
            stats = self.get_request_stats()
            self._debug_print(f"[scan_url] 请求统计: {stats['current_requests']}/{stats['max_requests']} 请求, {stats['url_count']}/{stats['max_urls']} URL")
        
        # 构建结果
        result = self._build_result(url, response, error, depth)
        
        # 实时输出
        try:
            self.output_handler.realtime_output(result)
        except Exception as e:
            if self.config.debug_mode:
                self._debug_print(f"[scan_url] 实时输出失败: {e}")
        
        # 递归内容提取
        if response is not None and depth < self.config.max_depth:
            try:
                content = getattr(response, 'content', b'')
                content_type = response.headers.get('Content-Type', '') if hasattr(response, 'headers') else ''
                
                if self.config.debug_mode:
                    self._debug_print(f"[scan_url] 开始从内容提取URL: {result['url']} (内容类型: {content_type}, 内容长度: {len(content)})")
                
                self._extract_and_process_urls(content, result['url'], depth)
                        
            except Exception as e:
                if self.config.debug_mode:
                    self._debug_print(f"[scan_url] 递归处理异常: {type(e).__name__}: {e}, url={url}, depth={depth}")
        else:
            if self.config.debug_mode:
                if response is None:
                    self._debug_print(f"[scan_url] 响应为空，跳过递归")
                elif depth >= self.config.max_depth:
                    self._debug_print(f"[scan_url] 达到最大深度，跳过递归: depth={depth}, max_depth={self.config.max_depth}")
        
        if self.config.debug_mode:
            self._debug_print(f"[scan_url] 扫描完成: url={url}, status={result.get('status', 'Unknown')}")
        
        return result

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
                # 从队列获取URL
                item = self._safe_queue_get(queue_obj, timeout=2 if is_external else 10)
                if not item:
                    if not (self.external_running if is_external else self.running):
                        if self.config.debug_mode:
                            self._debug_print(f"[worker_loop] {'外部URL' if is_external else '工作'}线程队列为空，退出: {thread_name}")
                        break
                    continue
                
                url, depth = item if isinstance(item, tuple) else (item, 0)
                
                # 检查请求限制
                if not self._check_request_limits():
                    if self.config.debug_mode:
                        self._debug_print(f"[worker_loop] 达到限制，跳过扫描URL: {url} (深度: {depth}) - 线程: {thread_name}")
                    self._safe_queue_task_done(queue_obj)
                    continue
                
                # 定期清理连接池
                last_cleanup_time = self._periodic_cleanup(processed_count, last_cleanup_time)
                
                if self.config.debug_mode:
                    self._debug_print(f"[worker_loop] 处理URL: {url} (深度: {depth}) - 线程: {thread_name}")
                
                # 扫描URL
                try:
                    result = self.scan_url(url, depth)
                    # 优化：外部线程收集的结果全部标准化
                    if is_external:
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
                    self._debug_print(f"成功处理URL: {url}")
                except Exception as e:
                    error_count += 1
                    if self.config.debug_mode:
                        self._debug_print(f"[worker_loop] URL扫描异常: {type(e).__name__}: {e}, url={url}, depth={depth}, 线程={thread_name}")
                # 标记任务完成
                self._safe_queue_task_done(queue_obj)
            except Exception as e:
                error_count += 1
                if self.config.debug_mode:
                    self._debug_print(f"[worker_loop] {'外部URL' if is_external else '工作'}线程主循环异常: {type(e).__name__}: {e}, 线程: {thread_name}")
                self._safe_queue_task_done(queue_obj)
        if self.config.debug_mode:
            self._debug_print(f"[worker_loop] {'外部URL' if is_external else '工作'}线程结束: {thread_name}, 处理={processed_count}, 错误={error_count}")

    def worker(self):
        """工作线程 - 增强错误处理"""
        self._worker_loop(self.url_queue, self.results, self.lock, is_external=False)

    def external_worker(self):
        """外部URL工作线程 - 增强错误处理"""
        self._worker_loop(self.external_url_manager.external_url_queue, self.external_results, self.lock, is_external=True)

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
        # 修正外部链接集合变量
        external_urls = self.external_url_manager.external_urls
        if external_urls:
            with UltimateURLScanner.visited_urls_lock:
                unvisited = [u for u in external_urls if u not in UltimateURLScanner.visited_urls_global]
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
                with self.output_lock:
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
                    with self.output_lock:
                        print(f"{Fore.RED}写入危险链接汇总到CSV文件失败: {type(e).__name__}: {e}{Style.RESET_ALL}")
            else:
                with self.output_lock:
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
