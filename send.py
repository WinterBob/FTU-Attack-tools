import socket
import time
import logging
import tkinter as tk

class TextBoxHandler(logging.Handler):
    """Custom logging handler to output log messages to a Tkinter text widget."""

    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget

    def emit(self, record):
        message = self.format(record)
        self.text_widget.insert(tk.END, message + "\n")
        self.text_widget.see(tk.END)

class IEC104_Client:
    def __init__(self, rt_host, rt_port, text_widget):
        self.rt_host = rt_host
        self.rt_port = rt_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.send_sequence_number = 0
        self.receive_sequence_number = 0

        self.frame1 = None
        self.frame2 = None

        # Set up logger
        self.logger = logging.getLogger("IEC104_Client")
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(TextBoxHandler(text_widget))

    def connect(self):
        try:
            self.sock.connect((self.rt_host, self.rt_port))
            self.logger.info("Connection established")
        except Exception as e:
            self.logger.error(f"Connection error: {e}")

    def send_frame(self, frame):
        try:
            self.sock.sendall(frame)
            self.logger.info(f"Sent frame: {frame.hex()}")
            self.send_sequence_number = (self.send_sequence_number + 1) % 32768
        except Exception as e:
            self.logger.error(f"Error sending frame: {e}")

    def receive_frame(self):
        try:
            response = self.sock.recv(1024)
            if response:
                self.logger.info(f"Received frame: {response.hex()}")

                self.receive_sequence_number = (self.receive_sequence_number + 1) % 32768
                return response
            else:
                self.logger.warning("No data received, connection might be closed.")
                return None
        except Exception as e:
            self.logger.error(f"Error receiving frame: {e}")
            return None

    def construct_frame(self, base_frame):
        """Constructs a frame by inserting the current send and receive sequence numbers."""
        send_seq = (self.send_sequence_number << 1) & 0xFFFF
        recv_seq = (self.receive_sequence_number << 1) & 0xFFFF

        frame = bytearray(base_frame)
        frame[2] = send_seq & 0xFF
        frame[3] = (send_seq >> 8) & 0xFF
        frame[4] = recv_seq & 0xFF
        frame[5] = (recv_seq >> 8) & 0xFF

        return bytes(frame)

    def extract_frames_from_textbox(self, text_widget):
        """
        从文本框中提取符合条件的帧。
        条件：
        - frame1: 开头为 \x68\x0e，结尾为 \x2d\x01\x06\x00\x01\x00\x01\x60\x00\x81
        - frame2: 开头为 \x68\x0e，结尾为 \x2d\x01\x06\x00\x01\x00\x01\x60\x00\x01
        """
        self.frame1 = None
        self.frame2 = None

        # 读取文本框内容
        text_content = text_widget.get("1.0", tk.END).strip()
        lines = text_content.splitlines()

        for line in lines:
            # 尝试将文本行转换为十六进制数据
            try:
                frame = bytes.fromhex(line.strip())
            except ValueError:
                continue  # 忽略非十六进制内容的行

            # 检查 frame1 的匹配条件
            if frame.startswith(b'\x68\x0e') and frame.endswith(b'\x2d\x01\x06\x00\x01\x00\x01\x60\x00\x81'):
                self.frame1 = frame
                self.logger.info(f"已提取 Frame1: {self.frame1.hex()}")

            # 检查 frame2 的匹配条件
            elif frame.startswith(b'\x68\x0e') and frame.endswith(b'\x2d\x01\x06\x00\x01\x00\x01\x60\x00\x01'):
                self.frame2 = frame
                self.logger.info(f"已提取 Frame2: {self.frame2.hex()}")

            # 如果两个帧都提取成功，结束循环
            if self.frame1 and self.frame2:
                break

        # 如果未找到帧，记录警告日志
        if not self.frame1:
            self.logger.warning("未在文本框内容中找到 Frame1。")
        if not self.frame2:
            self.logger.warning("未在文本框内容中找到 Frame2。")

    def start_communication(self):
        # Initialization frame (STARTDT_ACT)
        init_frame = b'\x68\x04\x07\x00\x00\x00'
        self.send_frame(init_frame)

        # Wait for STARTDT_CON
        response = self.receive_frame()
        if response and response.startswith(b'\x68\x04\x0B'):
            self.logger.info("STARTDT_CON received, communication initialized")
        else:
            self.logger.error("Failed to receive STARTDT_CON, stopping communication")
            return

        # Send and receive frames
        if self.frame1:
            constructed_frame1 = self.construct_frame(self.frame1)
            self.send_frame(constructed_frame1)
            self.receive_frame()

        if self.frame2:
            constructed_frame2 = self.construct_frame(self.frame2)
            self.send_frame(constructed_frame2)
            self.receive_frame()

    def stop(self):
        self.logger.info("Stopping client...")
        try:
            self.sock.close()
            self.logger.info("Socket closed.")
        except Exception as e:
            self.logger.error(f"Error closing socket: {e}")
