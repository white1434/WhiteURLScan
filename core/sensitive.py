import re
from colorama import Fore, Style
from utils.debug import DebugMixin

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
            
            try:
                text_content = content.decode('utf-8', 'ignore') if isinstance(content, bytes) else content
            except Exception as e:
                self._debug_print(f"内容解码失败: {type(e).__name__}: {e}")
                text_content = str(content) if content else ""
            
            detected = []
            
            for name, pattern in self.sensitive_patterns.items():
                try:
                    matches = re.findall(pattern, text_content)
                    if matches:
                        # 去重并获取样本
                        unique_matches = set(matches)
                        count = len(unique_matches)
                        
                        # 获取样本（最多5个）
                        samples = list(unique_matches)
                    
                        # 构建结构化结果
                        detected_item = {
                            'type': name,  # 敏感信息类型
                            'count': count,  # 发现数量
                            'samples': samples,  # 样本清单
                            'total': len(unique_matches)  # 总数量
                        }
                    
                        detected.append(detected_item)
                        
                        self._debug_print(f"发现敏感信息: {name} x{count} 个样本")
                    else:
                        pass # 减少输出
                        # self._debug_print(f"未发现敏感信息: {name}")
                except re.error as e:
                    self._debug_print(f"正则表达式错误 ({name}): {str(e)}")
                    continue  # 跳过无效的正则表达式
                except Exception as e:
                    self._debug_print(f"处理敏感信息模式时出错 ({name}): {type(e).__name__}: {e}")
                    continue
            
            self._debug_print(f"敏感信息检测完成，共发现 {len(detected)} 种敏感信息")
            
            return detected
        except Exception as e:
            self._debug_print(f"敏感信息检测过程中出错: {type(e).__name__}: {e}")
            return []
