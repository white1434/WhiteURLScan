import json
import warnings
import os
import sys
from urllib.parse import urlparse
from traceback import print_exc
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By

warnings.filterwarnings("ignore")


def create_webdriver(cookies):
    print("=== 开始创建WebDriver ===")
    print(f"当前工作目录: {os.getcwd()}")
    print(f"Python版本: {sys.version}")
    
    options = Options()
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--headless')
    options.add_argument('--disable-gpu')
    options.add_argument('--window-size=1920x1080')
    options.add_argument('--ignore-certificate-errors')  # 忽略证书错误
    options.add_argument('--ignore-ssl-errors')  # 忽略SSL错误
    options.set_capability('goog:loggingPrefs', {'performance': 'ALL'})
    
    print("Chrome选项配置完成")
    print(f"Chrome选项: {options.arguments}")

    # Windows系统自动检测ChromeDriver
    try:
        print("正在尝试创建Chrome WebDriver...")
        # 尝试使用自动检测的ChromeDriver
        driver = webdriver.Chrome(options=options)
        print("✓ Chrome WebDriver创建成功")
        print(f"WebDriver信息: {driver.capabilities}")
    except Exception as e:
        print(f"✗ ChromeDriver检测失败: {e}")
        print("详细错误信息:")
        import traceback
        traceback.print_exc()
        print("\n=== 解决方案 ===")
        print("请确保已安装Chrome浏览器和ChromeDriver")
        print("Windows解决方案:")
        print("1. 下载ChromeDriver: https://chromedriver.chromium.org/")
        print("2. 将chromedriver.exe放在当前目录或添加到PATH环境变量")
        print("3. 或者安装webdriver-manager: pip install webdriver-manager")
        print("4. 检查Chrome浏览器是否已安装")
        raise

    # Set user agent
    print("正在设置User-Agent...")
    driver.execute_cdp_cmd(
        'Network.setUserAgentOverride',
        {
            "userAgent": f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"}
    )
    print("✓ User-Agent设置完成")

    if cookies:
        # Set cookie header
        print(f"正在设置Cookie: {cookies[:50]}...")
        driver.execute_cdp_cmd(
            'Network.setExtraHTTPHeaders',
            {"headers": {"Cookie": cookies}}
        )
        print("✓ Cookie设置完成")
    else:
        print("未提供Cookie，跳过Cookie设置")

    print("=== WebDriver创建完成 ===")
    return driver


def check_network_url(url):
    print(f"检查网络URL: {url}")
    
    if not url or url.count('?') > 1 or not url.startswith('http'):
        print(f"  ✗ URL无效或格式错误")
        return False, ''
    
    url_parse = urlparse(url)
    path = url_parse.path
    print(f"  URL路径: {path}")
    
    if path.lower().endswith(".js"):
        print(f"  ✓ 检测到JS文件")
        return 'js', url
    
    if url.startswith('data'):
        print(f"  ✗ 跳过data URL")
        return False, ''
    
    if '.' not in path.lower().rsplit('/')[-1]:
        print(f"  ✓ 检测到无扩展名路径")
        clean_url = f"{url_parse.scheme}://{url_parse.netloc}{url_parse.path}"
        return 'no_js', clean_url
    
    print(f"  ✗ 不匹配任何规则")
    return False, ''


def get_response_body(driver, request_id):
    """尝试获取响应内容"""
    try:
        # 使用CDP命令获取响应体
        response_body = driver.execute_cdp_cmd('Network.getResponseBody', {'requestId': request_id})
        return response_body.get('body', '')
    except Exception as e:
        return f"无法获取响应内容: {e}"

def process_network_events(log_entries, driver=None):
    print(f"=== 开始处理网络事件 ===")
    print(f"网络事件总数: {len(log_entries)}")
    
    all_load_url = []
    processed_count = 0
    valid_count = 0
    
    # 创建请求ID到响应信息的映射
    request_response_map = {}
    
    # 第一遍：收集所有请求和响应信息
    print("第一遍：收集请求和响应信息...")
    for entry in log_entries:
        try:
            log = json.loads(entry['message'])['message']
            
            # 处理请求发送事件
            if 'Network.requestWillBeSent' in log['method']:
                request_id = log['params'].get('requestId', '')
                params_request = log['params'].get("request", {})
                url = params_request.get("url", "")
                method = params_request.get("method", "")
                headers = params_request.get("headers", {})
                
                request_response_map[request_id] = {
                    'url': url,
                    'method': method,
                    'headers': headers,
                    'response': None,
                    'response_headers': None,
                    'status_code': None,
                    'content_length': None,
                    'response_body': None
                }
            
            # 处理响应接收事件
            elif 'Network.responseReceived' in log['method']:
                request_id = log['params'].get('requestId', '')
                if request_id in request_response_map:
                    response = log['params'].get('response', {})
                    request_response_map[request_id]['response'] = response
                    request_response_map[request_id]['response_headers'] = response.get('headers', {})
                    request_response_map[request_id]['status_code'] = response.get('status', 0)
                    request_response_map[request_id]['content_length'] = response.get('headers', {}).get('content-length', '0')
                    
                    # 尝试获取响应内容
                    if driver and response.get('status', 0) == 200:
                        try:
                            response_body = get_response_body(driver, request_id)
                            request_response_map[request_id]['response_body'] = response_body
                        except Exception as e:
                            request_response_map[request_id]['response_body'] = f"获取响应内容失败: {e}"
            
        except Exception as e:
            print(f"处理网络事件时出错: {e}")
            print_exc()
    
    print(f"收集到 {len(request_response_map)} 个请求信息")
    
    # 第二遍：处理有效URL并输出详细信息
    print("\n第二遍：处理有效URL并输出详细信息...")
    for request_id, request_info in request_response_map.items():
        try:
            processed_count += 1
            url = request_info['url']
            method = request_info['method']
            headers = request_info['headers']
            response = request_info['response']
            response_headers = request_info['response_headers']
            status_code = request_info['status_code']
            content_length = request_info['content_length']
            response_body = request_info['response_body']
            
            print(f"\n{'='*60}")
            print(f"处理第 {processed_count} 个网络请求:")
            print(f"{'='*60}")
            print(f"请求ID: {request_id}")
            print(f"请求方法: {method}")
            print(f"请求URL: {url}")
            print(f"请求头: {headers}")
            
            if response:
                print(f"\n响应信息:")
                print(f"  状态码: {status_code}")
                print(f"  内容长度: {content_length}")
                print(f"  响应头: {response_headers}")
                
                if response_body:
                    print(f"\n响应内容:")
                    if len(response_body) > 500:
                        print(f"  内容预览: {response_body[:500]}...")
                        print(f"  完整内容长度: {len(response_body)} 字符")
                    else:
                        print(f"  内容: {response_body}")
            else:
                print(f"\n响应信息: 未收到响应")
            
            # 检查URL是否有效
            url_type, new_url = check_network_url(url)
            if url_type:
                valid_count += 1
                print(f"\n✓ 有效URL: {new_url}")
                print(f"URL类型: {url_type}")
                
                # 添加到结果列表
                all_load_url.append({
                    'url': new_url.rstrip('/'), 
                    'referer': headers.get('Referer', ''), 
                    'url_type': url_type,
                    'method': method,
                    'status_code': status_code,
                    'content_length': content_length,
                    'request_id': request_id,
                    'response_body': response_body
                })
            else:
                print(f"\n✗ 跳过无效URL")
                
        except Exception as e:
            print(f"处理请求 {request_id} 时出错: {e}")
            print_exc()

    print(f"\n{'='*60}")
    print(f"=== 网络事件处理完成 ===")
    print(f"{'='*60}")
    print(f"处理请求数: {processed_count}")
    print(f"有效URL数: {valid_count}")
    print(f"返回URL列表长度: {len(all_load_url)}")
    
    return all_load_url


def get_final_url(driver, url):
    print(f"=== 开始访问URL ===")
    print(f"目标URL: {url}")
    
    try:
        print("正在加载页面...")
        driver.get(url)
        print("✓ 页面加载完成")
        
        print("等待页面元素加载...")
        WebDriverWait(driver, 20).until(EC.presence_of_element_located((By.TAG_NAME, 'body')))
        print("✓ 页面元素加载完成")
        
        
        final_url = driver.current_url
        print(f"最终URL: {final_url}")
        # print(f"内容: {driver.page_source}")
        # print(f"标题: {driver.title}")
        
        if final_url != url:
            print(f"✓ 检测到URL重定向: {url} -> {final_url}")
        else:
            print("✓ 无URL重定向")
            
        return final_url
    except Exception as e:
        print(f"✗ 页面加载失败: {e}")
        print("详细错误信息:")
        import traceback
        traceback.print_exc()
        return url


def webdriverFind(url, cookies):
    print("=" * 50)
    print("=== 开始WebDriver查找 ===")
    print("=" * 50)
    print(f"目标URL: {url}")
    print(f"Cookie: {cookies if cookies else '无'}")
    
    all_load_url = []
    driver = None
    
    try:
        print("\n1. 创建WebDriver...")
        driver = create_webdriver(cookies)
        
        print("\n2. 访问目标URL...")
        final_url = get_final_url(driver, url)
        print(f"最终跳转URL: {final_url}")

        print("\n3. 获取性能日志...")
        logs = driver.get_log('performance')
        print(f"✓ 获取到 {len(logs)} 条性能日志")

        print("\n4. 处理网络事件...")
        all_load_url = process_network_events(logs, driver)
        
        print("\n5. 处理完成")
        print(f"发现的有效URL数量: {len(all_load_url)}")
        
    except Exception as e:
        print(f"\n✗ WebDriver查找过程中出错: {e}")
        print("详细错误信息:")
        import traceback
        traceback.print_exc()
    finally:
        if driver:
            print("\n6. 关闭WebDriver...")
            try:
                driver.quit()
                print("✓ WebDriver已关闭")
            except Exception as e:
                print(f"✗ 关闭WebDriver时出错: {e}")

    print("=" * 50)
    print("=== WebDriver查找完成 ===")
    print("=" * 50)
    return all_load_url


if __name__ == "__main__":
    print("=" * 60)
    print("=== WebDriver URL查找工具 ===")
    print("=" * 60)
    print("系统信息:")
    print(f"  操作系统: {os.name}")
    print(f"  工作目录: {os.getcwd()}")
    print(f"  Python版本: {sys.version}")
    print("=" * 60)
    
    test_url = "https://555109.top/#/welcomeHall"
    test_cookies = ""
    
    print(f"测试URL: {test_url}")
    print(f"测试Cookie: {test_cookies if test_cookies else '无'}")
    print("=" * 60)
    
    result = webdriverFind(test_url, test_cookies)
    
    print("\n" + "=" * 60)
    print("=== 最终结果 ===")
    print("=" * 60)
    if result:
        print(f"发现 {len(result)} 个有效URL:")
        for i, item in enumerate(result, 1):
            print(f"{i}. URL: {item['url']}")
            print(f"   类型: {item['url_type']}")
            print(f"   请求方法: {item.get('method', 'GET')}")
            print(f"   状态码: {item.get('status_code', 'N/A')}")
            print(f"   内容长度: {item.get('content_length', 'N/A')}")
            print(f"   Referer: {item.get('referer', 'N/A')}")
            print(f"   请求ID: {item.get('request_id', 'N/A')}")
            if item.get('response_body'):
                content_preview = item['response_body']
                # content_preview = item['response_body'][:300]
                # if len(item['response_body']) > 300:
                #     content_preview += "..."
                print(f"   响应内容预览: {content_preview}")
            print()
    else:
        print("未发现有效URL")
    print("=" * 60)