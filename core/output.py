import csv
import os
import hashlib
import time
from colorama import Fore, Style
import threading
from utils.debug import DebugMixin

# ====================== 输出处理模块 ======================
class OutputHandler(DebugMixin):
    def __init__(self, config, output_lock=None):
        self.config = config
        self.debug_mode = config.debug_mode  # 设置debug_mode属性
        self.url_count = 0
        self.start_time = time.time()
        self.request_signature_count = {}  # 记录请求签名出现次数
        self.is_duplicate = getattr(config, 'is_duplicate', 0)
        self.output_lock = output_lock if output_lock is not None else threading.Lock()
        
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
            depth_str = f"[深度:{result['depth']}]"
            status_str = f"[{result['status']}]"
            length_str = f"[{result['length']}]"
            title_str = f"[{result['title'][:30]:^10}]" if result['title'] else "[===========]"
            time_str = f"[{result['time']:.2f}s]"
            status_color = self.get_status_color(result['status'])
            url_path = result['url'].split('?')[0] if 'url' in result else ''
            filename = url_path.split('/')[-1]
            if '.' in filename:
                ext = filename.split('.')[-1].upper()
                file_type_str = f"[{ext}]"
                file_type_color = Fore.LIGHTCYAN_EX
            else:
                file_type_str = "[接口]"
                file_type_color = Fore.RED
            # 敏感信息显示
            sensitive_str = ""
            if result.get('sensitive_raw'):
                sensitive_types = []
                for item in result['sensitive_raw']:
                    if isinstance(item, dict):
                        sensitive_type = item.get('type', '未知')
                        count = item.get('count', 0)
                        display_format = f"{sensitive_type}X{count}"
                        sensitive_types.append(display_format)
                    else:
                        sensitive_types.append(str(item))
                sensitive_str = Fore.RED + Style.BRIGHT + f" -> [{'，'.join(sensitive_types)}]"
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

    def print_result_line(self, line):
        """只负责终端输出"""
        with self.output_lock:
            print(line)

    def write_result_to_csv(self, result, file_path=None):
        """只负责写入一行到CSV"""
        try:
            if not file_path:
                file_path = self.config.output_file
            with open(file_path, 'a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                sensitive_types, sensitive_counts, sensitive_details = self._format_sensitive_data_for_csv(result.get('sensitive_raw'))
                url_path = result.get('url', '').split('?')[0] if result.get('url') else ''
                filename = url_path.split('/')[-1]
                if '.' in filename:
                    ext = filename.split('.')[-1].upper()
                    link_type = ext
                else:
                    link_type = "接口"
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

    def realtime_output(self, result):
        """彩色实时输出扫描结果，调度格式化、输出、写入文件"""
        try:
            self.url_count += 1
            elapsed_time = time.time() - self.start_time
            if self.config.debug_mode:
                self._debug_print(f"处理扫描结果 #{self.url_count}: {result.get('url', '未知URL')}")
            if isinstance(result.get('status'), str) and 'Err' in result['status']:
                result['status'] = 'Err'
        except Exception as e:
            if self.config.debug_mode:
                self._debug_print(f"初始化输出处理时出错: {type(e).__name__}: {e}")
            return
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
        is_duplicate_signature = count > 0
        result['is_duplicate_signature'] = is_duplicate_signature
        if is_duplicate_signature:
            if self.is_duplicate == 1:
                line = self.format_result_line(result)
                self.print_result_line(line)
            return
        else:
            line = self.format_result_line(result)
            if self.config.verbose:
                self.print_result_line(line)
            else:
                self.print_result_line(line)
        if self.config.output_file:
            self.write_result_to_csv(result, self.config.output_file)

    def generate_report(self, results, report_file="full_report.csv"):
        """生成最终扫描报告，遍历结果调用write_result_to_csv"""
        try:
            if self.config.debug_mode:
                self._debug_print(f"开始生成最终报告: {report_file}")
                self._debug_print(f"报告包含 {len(results)} 个扫描结果")
            os.makedirs(os.path.dirname(os.path.abspath(report_file)), exist_ok=True)
            with open(report_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['URL', '状态', '标题', '长度', '链接类型', '重定向', '深度', '敏感信息类型', '敏感信息数量', '敏感信息详细清单', '是否重复'])
            for result in results:
                self.write_result_to_csv(result, report_file)
        except Exception as e:
            if self.config.debug_mode:
                self._debug_print(f"生成报告时出错: {type(e).__name__}: {e}")
            print(f"{Fore.RED}生成报告失败: {type(e).__name__}: {e}{Style.RESET_ALL}")
        if self.config.debug_mode:
            self._debug_print(f"最终报告生成完成: {report_file}")
        with self.output_lock:
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
                    with self.output_lock:
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
