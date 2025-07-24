from colorama import Fore, Style
import logging

class DebugMixin:
    def __init__(self, debug_mode=False):
        self.debug_mode = debug_mode
    def _debug_print(self, message):
        if hasattr(self, 'debug_mode') and self.debug_mode:
            debug_prefix = f"{Fore.MAGENTA}[DEBUG]{Style.RESET_ALL}"
            print(f"{debug_prefix} {message}")
            try:
                logging.debug(message)
            except Exception as e:
                print(f"Debug输出异常: {e}")
                pass 