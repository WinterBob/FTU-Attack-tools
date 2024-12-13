import tkinter as tk
from tkinter import scrolledtext
import threading
import time
import send
import logging
from Fetchandparse import IEC104PacketHandler
from send import IEC104_Client



class App:
    def __init__(self, root):
        self.root = root
        self.root.title("FTU攻击工具")

        self.root.state('zoomed')

        # 设置主框架
        self.main_frame = tk.Frame(root)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # 创建左侧框架
        self.left_frame = tk.Frame(self.main_frame)
        self.left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 创建上方文本框
        self.label1 = tk.Label(self.left_frame, text="捕获解析:")
        self.label1.pack(fill=tk.X)

        self.text_box1 = scrolledtext.ScrolledText(self.left_frame, wrap=tk.WORD, width=40, height=10)
        self.text_box1.pack(fill=tk.BOTH, expand=True, pady=(0, 10))  # 添加垂直间距

        # 创建下方文本框
        self.label2 = tk.Label(self.left_frame, text="重放:")
        self.label2.pack(fill=tk.X)

        self.text_box2 = scrolledtext.ScrolledText(self.left_frame, wrap=tk.WORD, width=40, height=10)
        self.text_box2.pack(fill=tk.BOTH, expand=True)

        # 创建按钮框架
        self.button_frame = tk.Frame(self.main_frame)
        self.button_frame.pack(side=tk.RIGHT, fill=tk.Y, expand=False, padx=10, pady=10)

        # 设置按钮宽度
        button_width = 15

        self.button1 = tk.Button(self.button_frame, text="信号嗅探", command=self.run_code1, width=button_width)
        self.button1.pack(fill=tk.Y, expand=True, pady=5)

        self.button2 = tk.Button(self.button_frame, text="信号重放", command=self.run_code2, width=button_width)
        self.button2.pack(fill=tk.Y, expand=True, pady=5)

        self.stop_button = tk.Button(self.button_frame, text="停止", command=self.stop_processes, width=button_width)
        self.stop_button.pack(fill=tk.Y, expand=True, pady=5)

        self.clear_button = tk.Button(self.button_frame, text="清除", command=self.clear_text_boxes, width=button_width)
        self.clear_button.pack(fill=tk.Y, expand=True, pady=5)

        # 初始化线程和事件变量
        self.process1 = None
        self.process2 = None
        self.stop_event1 = threading.Event()
        self.stop_event2 = threading.Event()

    def run_code1(self):
        def capture():
            self.text_box1.insert(tk.END, "开始捕获\n")
            self.text_box1.see(tk.END)  # 确保文本框滚动到最新内容

            handler = IEC104PacketHandler()
            INTERFACE_NAME = "Realtek Gaming USB 2.5GbE Family Controller"

            def callback(message):
                if not self.stop_event1.is_set():  # 检查停止事件
                    self.text_box1.insert(tk.END, message + "\n")
                    self.text_box1.see(tk.END)

            try:
                handler.capture_packets(INTERFACE_NAME,callback)
            except Exception as e:
                self.text_box1.insert(tk.END, f"捕获失败: {e}\n")
                self.text_box1.see(tk.END)

        if self.process1 is None or not self.process1.is_alive():
            self.stop_event1.clear()
            self.process1 = threading.Thread(target=capture)
            self.process1.start()

    def run_code2(self):
        def code2_function():
            server_ip = '192.168.1.100'  # Replace with the server's actual IP
            server_port = 2404  # Default IEC 104 port
            client = IEC104_Client(rt_host=server_ip, rt_port=server_port, text_widget=self.text_box2)
            client.extract_frames_from_textbox(self.text_box1)
            # 验证帧是否提取成功
            if not client.frame1 or not client.frame2:
                self.text_box2.insert(tk.END, "未在文本框1中找到有效的帧，请重试。\n")
                self.text_box2.see(tk.END)
                return
            try:
                client.connect()
                client.start_communication()
            except Exception as e:
                self.text_box2.insert(tk.END, f"重放失败: {e}\n")
                self.text_box2.see(tk.END)
            finally:
                client.stop()

        if self.process2 is None or not self.process2.is_alive():
            self.stop_event2.clear()
            self.process2 = threading.Thread(target=code2_function)
            self.process2.start()


        if self.process2 is None or not self.process2.is_alive():
            self.stop_event2.clear()
            self.process2 = threading.Thread(target=code2_function)
            self.process2.start()

    def stop_processes(self):
        self.stop_event1.set()
        self.stop_event2.set()
        self.text_box1.insert(tk.END, "捕获完成\n")
        self.text_box1.see(tk.END)  # 确保文本框滚动到最新内容
        if self.process1 is not None:
            threading.Thread(target=self._wait_for_thread, args=(self.process1,)).start()
        if self.process2 is not None:
            threading.Thread(target=self._wait_for_thread, args=(self.process2,)).start()
        self.process1 = None
        self.process2 = None

    def _wait_for_thread(self, thread):
        thread.join()

    def clear_text_boxes(self):
        self.text_box1.delete(1.0, tk.END)
        self.text_box2.delete(1.0, tk.END)