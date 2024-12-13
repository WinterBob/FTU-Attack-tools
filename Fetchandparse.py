from scapy.all import sniff, Raw
import binascii

class IEC104PacketHandler:
    MASTER_IP = "192.168.1.101"
    SLAVE_IP = "192.168.1.100"
    IEC104_PORT = 2404

    TI_COMMANDS = {
        0x2d: "单点遥控命令",
        0x2f: "双点遥控命令",
        0x01: "单点遥信",
        0x03: "双点遥信",
        0x46: "初始化结束",
        0x64: "总命令召唤",
        0x65: "电能脉冲召唤命令"
    }

    CAUSE_MESSAGES = {
        0x06: "激活",
        0x07: "激活确认",
        0x04: "初始化",
        0x05: "请求与被请求",
        0x08: "停止激活",
        0x09: "停止激活确认",
        0x0A: "激活结束",
        0x14: "响应总召唤"
    }

    def is_iec104_packet(self, packet):
        if packet.haslayer('IP') and packet.haslayer('TCP'):
            ip_src = packet['IP'].src
            ip_dst = packet['IP'].dst
            tcp_dport = packet['TCP'].dport
            tcp_sport = packet['TCP'].sport

            if (ip_src == self.MASTER_IP or ip_src == self.SLAVE_IP) and \
               (ip_dst == self.MASTER_IP or ip_dst == self.SLAVE_IP) and \
               (tcp_dport == self.IEC104_PORT or tcp_sport == self.IEC104_PORT):
                return True
        return False

    def parse_i_frame(self, payload):
        if len(payload) < 6:
            return "Invalid frame, insufficient length"

        start_byte = payload[0]
        apdu_length = payload[1]
        control_field = payload[2:6]

        if start_byte != 0x68:
            return "Not an IEC104 I frame"

        send_seq = ((control_field[1] << 8) | (control_field[0] & 0xFE)) >> 1
        recv_seq = ((control_field[3] << 8) | (control_field[2] & 0xFE)) >> 1

        ti = payload[6]
        vsq = payload[7]
        sq = (vsq & 0x80) >> 7

        cot = payload[8]
        cause = cot & 0x3f
        coa = int.from_bytes(payload[10:12], byteorder='little')
        ioa = int.from_bytes(payload[12:15], byteorder='little')

        command = self.TI_COMMANDS.get(ti, "未知命令")
        reason = self.CAUSE_MESSAGES.get(cause, "未知类型")

        info_str = (f"起始字节=0x{start_byte:X} 数据单元长度(APDU)={apdu_length} 发送序号(NS)={send_seq} 接收序号(NR)={recv_seq} 信息对象地址(IOA)={ioa} VSQ={vsq} COT={cot} COA={coa}\n"
                    f"I格式帧 类型标识(TI)={ti} ({command}) 实际传输原因(COT)={cause} ({reason}) 对应点位={ioa}")
        return info_str

    def parse_u_frame(self, frame):
        if len(frame) < 6:
            return "Invalid frame, insufficient length"

        start_byte = frame[0]
        apdu_length = frame[1]
        control_field = frame[2:6]

        u_frame_types = {
            b'\x07\x00\x00\x00': "STARTDT ACT",
            b'\x0B\x00\x00\x00': "STARTDT CON",
            b'\x43\x00\x00\x00': "TESTFR ACT",
            b'\x83\x00\x00\x00': "TESTFR CON",
            b'\x13\x00\x00\x00': "STOPDT ACT",
            b'\x23\x00\x00\x00': "STOPDT CON",
        }

        for cf, name in u_frame_types.items():
            if control_field == cf:
                if start_byte == 0x68 and apdu_length == 4:
                    return name
                else:
                    return "Invalid frame format, check start byte and length"

        return "Unknown U frame type"

    def parse_s_frame(self, payload):
        if len(payload) < 6:
            return "Invalid frame, insufficient length"

        start_byte = payload[0]
        apdu_length = payload[1]
        control_field = payload[2:6]

        if start_byte != 0x68 or apdu_length != 4:
            return "Not an IEC104 S frame"

        recv_seq = ((control_field[3] << 8) | (control_field[2] & 0xFE)) >> 1

        info_str = (f"起始字节=0x{start_byte:X} 数据单元长度(APDU)={apdu_length} S格式帧 接收序号(NR)={recv_seq}\n")
        return info_str

    def handle_packet(self, packet,callback):
        if Raw in packet:
            payload = bytes(packet[Raw].load)
            if len(payload) > 0:
                ip_src = packet['IP'].src
                sender = "主站发送" if ip_src == self.MASTER_IP else "从站发送"

                control_field = payload[2]
                if control_field & 0x01 == 0:
                    result = self.parse_i_frame(payload)
                    print(result)
                elif control_field & 0x03 == 1:
                    result = self.parse_s_frame(payload)
                    print(result)
                elif control_field & 0x03 == 3:
                    result = self.parse_u_frame(payload)
                    print(result)
                else:
                    print(f"Unknown frame type, raw data: {binascii.hexlify(payload).decode('ascii')}")

                callback(f"\n--- {sender} ---\n{binascii.hexlify(payload).decode('ascii')}\n{result}\n")


    def capture_packets(self, interface,callback):
        print(f"Starting packet capture on {interface} for IEC104 protocol...")

        sniff(
            iface=interface,
            filter=f"tcp port {self.IEC104_PORT}",
            prn=lambda pkt: self.handle_packet(pkt,callback),
            store=False
        )
