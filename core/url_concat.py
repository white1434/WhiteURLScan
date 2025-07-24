import urllib.parse
import os
import re
from colorama import Fore, Style
from utils.debug import DebugMixin

# ====================== URL拼接模块 ======================
class URLConcatenator(DebugMixin):
    def __init__(self, debug_mode=False, base_url=None, relative_url=None, custom_base_url=None, path_route=None, api_route=None):
        # self.debug_mode = debug_mode
        self.debug_mode = False
        # 支持字符串或列表，统一转为列表
        self.base_url = base_url
        self.relative_url = relative_url
        self.custom_base_url = custom_base_url
        self.path_route = path_route
        self.api_route = api_route
        self.url_list = set()

        if self.debug_mode:
            self._debug_print(f"[URLConcatenator]初始化URLConcatenator: base_url={self.base_url}, relative_url={self.relative_url}, custom_base_url={self.custom_base_url}, path_route={self.path_route}, api_route={self.api_route}")

    def smart_concatenation(self):
        results = set()
        for base_url in self.base_url:
            for relative_url in self.relative_url:
                if self.debug_mode:
                    self._debug_print(f"[smart_concatenation]开始拼接URL: base={base_url}, relative={relative_url}")
                # 处理协议相对URL (//example.com/path)
                if relative_url.startswith('//'):
                    base = urllib.parse.urlparse(base_url)
                    result = f"{base.scheme}:{relative_url}"
                    results.add(result)
                    continue
                # 处理hash路由（SPA应用）
                if relative_url.startswith('#/'):
                    base = urllib.parse.urlparse(base_url)
                    result = f"{base.scheme}://{base.netloc}{base.path}{relative_url}"
                    results.add(result)
                    continue
                # 处理绝对路径
                if relative_url.startswith('/'):
                    base = urllib.parse.urlparse(base_url)
                    clean_path = relative_url.lstrip('/')
                    result = f"{base.scheme}://{base.netloc}/{clean_path}"
                    results.add(result)
                    continue
                # 处理相对路径
                if relative_url.startswith('./'):
                    base = urllib.parse.urlparse(base_url)
                    base_path = os.path.dirname(base.path) if not base.path.endswith('/') else base.path
                    clean_relative = relative_url[2:].lstrip('/')
                    result = f"{base.scheme}://{base.netloc}{base_path}/{clean_relative}"
                    results.add(result)
                    continue
                # 处理上级目录
                if relative_url.startswith('../'):
                    base = urllib.parse.urlparse(base_url)
                    path_parts = base.path.split('/')
                    rel_parts = relative_url.split('/')
                    back_count = 0
                    new_parts = []
                    for part in rel_parts:
                        if part == '..':
                            back_count += 1
                        else:
                            new_parts.append(part)
                    if len(path_parts) > back_count:
                        clean_parts = [p for p in path_parts[:len(path_parts)-back_count] if p]
                        new_path = '/'.join(clean_parts) + '/' + '/'.join(new_parts)
                    else:
                        new_path = '/' + '/'.join(new_parts)
                    if new_path.startswith('//'):
                        new_path = new_path[1:]
                    result = f"{base.scheme}://{base.netloc}{new_path}"
                    results.add(result)
                    continue
                # 处理完整URL
                if relative_url.startswith('http'):
                    results.add(relative_url)
                    continue
                # 默认拼接 - 使用urljoin但清理双斜杠
                joined = urllib.parse.urljoin(base_url, relative_url)
                parsed = urllib.parse.urlparse(joined)
                clean_path = re.sub(r'/{2,}', '/', parsed.path)
                result = urllib.parse.urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    clean_path,
                    parsed.params,
                    parsed.query,
                    parsed.fragment
                ))
                results.add(result)
        return list(results)

    def api_concatenation(self):
        results = set()
        for base in self.custom_base_url:
            for route in self.api_route:
                for rel in self.relative_url:
                    if rel.startswith('http'):
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
        results = set()
        for base in self.custom_base_url:
            for route in self.path_route:
                for rel in self.relative_url:
                    if rel.startswith('http'):
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

    def custom_api_concatenation(self):
        """使用自定义基础链接和API路由进行拼接"""
        if self.debug_mode:
            self._debug_print(f"[custom_api_concatenation]开始自定义API拼接: path={self.relative_url}")
        
        # 确保自定义基础链接以/结尾
        if not self.custom_base_url.endswith('/'):
            base_url = self.custom_base_url + '/'
        else:
            base_url = self.custom_base_url
        
        # 构建完整的API路由路径
        full_api_route = self.api_route
        if full_api_route and not full_api_route.endswith('/'):
            full_api_route += '/'
        
        # 确保相对路径不以/开头
        if self.relative_url.startswith('/'):
            self.relative_url = self.relative_url[1:]
        
        # 拼接：自定义基础链接 + API路由 + 相对路径
        result = base_url + full_api_route + self.relative_url
        
        if self.debug_mode:
            self._debug_print(f"自定义API拼接结果: {result}")
        
        return result
    

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

        # 如果不是列表，则转为列表
        if not isinstance(self.base_url, list):
            self.base_url = [self.base_url]
        if not isinstance(self.relative_url, list):
            self.relative_url = [self.relative_url]
        if not isinstance(self.custom_base_url, list):
            self.custom_base_url = [self.custom_base_url]
        if not isinstance(self.path_route, list):
            self.path_route = [self.path_route]
        if not isinstance(self.api_route, list):
            self.api_route = [self.api_route]

        self._debug_print(f"[process_and_return_urls]开始处理URL列表: base={self.base_url}, path={self.relative_url}")
        
        # 拼接URL
        concatenated_urls = self.concatenate_urls()
        
        # 添加到内部列表
        for url in concatenated_urls:
            if self.url_check(url):
                self.url_list.add(url)
        
        self._debug_print(f"[process_and_return_urls]处理完成，返回 {len(self.url_list)} 个URL")
        
        return list(self.url_list)

