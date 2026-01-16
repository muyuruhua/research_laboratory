#!/usr/bin/env python3
"""
Layer 3-4 真实SUT验证器（采样验证模式）

功能：
  1. 启动Docker容器中的SUT（FTP/SMTP/HTTP/RTSP/SIP/DAAP）
  2. 发送LLM生成的输入
  3. 验证Layer 3（状态可达性）和Layer 4（覆盖增益）
  4. 采样验证：只验证10-20%的候选（避免性能开销）

集成方式：
  - 作为独立进程运行（Unix socket通信）
  - 或编译为共享库供afl-fuzz.c调用
"""

import socket
import subprocess
import time
import json
import argparse
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import random

@dataclass
class SUTConfig:
    """SUT配置"""
    protocol: str
    container_name: str
    host: str
    port: int
    timeout: float = 2.0


class SUTTester:
    """真实SUT测试器"""
    
    # 协议→SUT映射
    SUT_CONFIGS = {
        "FTP": SUTConfig("FTP", "lightftp-fuzz", "localhost", 2100, 2.0),
        "SMTP": SUTConfig("SMTP", "exim-fuzz", "localhost", 2125, 2.0),
        "HTTP": SUTConfig("HTTP", "nginx-fuzz", "localhost", 8088, 1.0),
        "RTSP": SUTConfig("RTSP", "live555-fuzz", "localhost", 8554, 3.0),
        "SIP": SUTConfig("SIP", "kamailio-fuzz", "localhost", 5060, 2.0),
    }
    
    def __init__(self, protocol: str, sampling_rate: float = 0.15):
        """
        Args:
            protocol: 协议名称
            sampling_rate: 采样率（0.15 = 验证15%的输入，降低开销）
        """
        self.protocol = protocol.upper()
        if self.protocol not in self.SUT_CONFIGS:
            raise ValueError(f"Unsupported protocol: {protocol}")
        
        self.config = self.SUT_CONFIGS[self.protocol]
        self.sampling_rate = sampling_rate
        self.stats = {
            "total_requests": 0,
            "sampled_tests": 0,
            "new_states_found": 0,
            "new_responses_found": 0,
            "errors": 0
        }
        
        # 状态追踪
        self.known_responses = set()
        self.known_states = set()
        
    def should_sample(self) -> bool:
        """采样决策（15%概率验证）"""
        return random.random() < self.sampling_rate
    
    def ensure_sut_running(self) -> bool:
        """确保SUT容器正在运行"""
        try:
            result = subprocess.run(
                ["docker", "ps", "--filter", f"name={self.config.container_name}", "--format", "{{.Names}}"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if self.config.container_name in result.stdout:
                return True
            
            # 尝试启动容器
            print(f"[INFO] Starting SUT container: {self.config.container_name}")
            subprocess.run(
                ["docker", "start", self.config.container_name],
                capture_output=True,
                timeout=10
            )
            time.sleep(2)  # 等待服务启动
            return True
            
        except Exception as e:
            print(f"[ERROR] Failed to ensure SUT running: {e}")
            return False
    
    def send_to_sut(self, data: bytes) -> Tuple[Optional[bytes], Optional[str], Optional[str]]:
        """
        发送数据到真实SUT
        
        Returns:
            (response_bytes, response_code, inferred_state)
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)
            
            sock.connect((self.config.host, self.config.port))
            
            # 接收banner（如果有）
            try:
                banner = sock.recv(4096)
            except socket.timeout:
                banner = b""
            
            # 发送测试数据
            sock.sendall(data)
            
            # 接收响应
            response = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 65536:  # 限制最大接收
                        break
            except socket.timeout:
                pass
            
            sock.close()
            
            # 解析响应码和状态
            response_code = self._extract_response_code(response)
            inferred_state = self._infer_state(data, response, response_code)
            
            return response, response_code, inferred_state
            
        except Exception as e:
            # print(f"[DEBUG] SUT test error: {e}")
            return None, None, None
    
    def _extract_response_code(self, response: bytes) -> Optional[str]:
        """提取响应码"""
        if not response:
            return None
        
        try:
            text = response.decode('utf-8', errors='ignore')
        except:
            return None
        
        # FTP/SMTP: 3位数字开头
        if self.protocol in ["FTP", "SMTP"]:
            match = re.match(r'^(\d{3})', text)
            if match:
                return match.group(1)
        
        # HTTP: "HTTP/1.x 200"
        elif self.protocol == "HTTP":
            match = re.search(r'HTTP/[\d.]+\s+(\d{3})', text)
            if match:
                return match.group(1)
        
        # RTSP: "RTSP/1.0 200"
        elif self.protocol == "RTSP":
            match = re.search(r'RTSP/[\d.]+\s+(\d{3})', text)
            if match:
                return match.group(1)
        
        return None
    
    def _infer_state(self, request: bytes, response: bytes, code: Optional[str]) -> Optional[str]:
        """推断协议状态"""
        try:
            req_text = request.decode('utf-8', errors='ignore')
        except:
            return None
        
        # FTP状态推断
        if self.protocol == "FTP":
            if b"220" in response:
                return "CONNECTED"
            elif b"USER" in request and b"331" in response:
                return "USER_OK"
            elif b"PASS" in request and b"230" in response:
                return "LOGGED_IN"
            elif b"PASV" in request or b"PORT" in request:
                return "DATA_CONN_SETUP"
            elif b"LIST" in request or b"RETR" in request:
                return "TRANSFER"
        
        # SMTP状态推断
        elif self.protocol == "SMTP":
            if b"220" in response:
                return "GREETED"
            elif b"MAIL FROM" in request and b"250" in response:
                return "MAIL_OK"
            elif b"RCPT TO" in request and b"250" in response:
                return "RCPT_OK"
            elif b"DATA" in request and b"354" in response:
                return "DATA_MODE"
        
        # HTTP: 状态码即状态
        elif self.protocol == "HTTP":
            return f"HTTP_{code}" if code else None
        
        # RTSP状态推断
        elif self.protocol == "RTSP":
            if b"DESCRIBE" in request:
                return "DESCRIBED"
            elif b"SETUP" in request and code == "200":
                return "READY"
            elif b"PLAY" in request and code == "200":
                return "PLAYING"
            elif b"PAUSE" in request and code == "200":
                return "PAUSED"
        
        return None
    
    def verify_layer3_layer4(self, data: bytes) -> Dict:
        """
        Layer 3 & 4 验证（核心函数）
        
        Returns:
            {
                "layer3_passed": bool,  # 是否触发新状态
                "layer4_passed": bool,  # 是否有新响应码
                "new_state": str or None,
                "response_code": str or None,
                "should_keep": bool  # 综合判断：是否保留此输入
            }
        """
        self.stats["total_requests"] += 1
        
        # 采样策略：只验证部分输入
        if not self.should_sample():
            return {
                "layer3_passed": None,  # 未采样
                "layer4_passed": None,
                "new_state": None,
                "response_code": None,
                "should_keep": True,  # 默认保留（启发式判断）
                "sampled": False
            }
        
        self.stats["sampled_tests"] += 1
        
        # 确保SUT运行
        if not self.ensure_sut_running():
            self.stats["errors"] += 1
            return {
                "layer3_passed": False,
                "layer4_passed": False,
                "new_state": None,
                "response_code": None,
                "should_keep": False,
                "sampled": True,
                "error": "SUT not available"
            }
        
        # 发送到真实SUT
        response, code, state = self.send_to_sut(data)
        
        if response is None:
            self.stats["errors"] += 1
            return {
                "layer3_passed": False,
                "layer4_passed": False,
                "new_state": None,
                "response_code": None,
                "should_keep": False,
                "sampled": True,
                "error": "Connection failed"
            }
        
        # Layer 3: 状态可达性
        layer3_new_state = False
        if state and state not in self.known_states:
            self.known_states.add(state)
            self.stats["new_states_found"] += 1
            layer3_new_state = True
        
        # Layer 4: 覆盖增益（通过响应码多样性近似）
        layer4_new_response = False
        if code and code not in self.known_responses:
            self.known_responses.add(code)
            self.stats["new_responses_found"] += 1
            layer4_new_response = True
        
        should_keep = layer3_new_state or layer4_new_response
        
        return {
            "layer3_passed": layer3_new_state,
            "layer4_passed": layer4_new_response,
            "new_state": state if layer3_new_state else None,
            "response_code": code,
            "should_keep": should_keep,
            "sampled": True
        }
    
    def get_stats(self) -> Dict:
        """获取统计信息"""
        return self.stats.copy()


class SUTVerifierServer:
    """Unix Socket服务器（供afl-fuzz调用）"""
    
    def __init__(self, socket_path: Path, protocol: str, sampling_rate: float = 0.15):
        self.socket_path = socket_path
        self.tester = SUTTester(protocol, sampling_rate)
        self.running = False
        
    def start(self):
        """启动服务器"""
        if self.socket_path.exists():
            self.socket_path.unlink()
        
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(str(self.socket_path))
        sock.listen(5)
        
        self.running = True
        print(f"[OK] SUT Verifier Server listening on {self.socket_path}")
        
        try:
            while self.running:
                conn, _ = sock.accept()
                self._handle_client(conn)
        except KeyboardInterrupt:
            print("\n[INFO] Shutting down...")
        finally:
            sock.close()
            if self.socket_path.exists():
                self.socket_path.unlink()
    
    def _handle_client(self, conn: socket.socket):
        """处理客户端请求"""
        try:
            # 协议: <length:4bytes><data> 使用网络字节序
            length_bytes = conn.recv(4)
            if len(length_bytes) != 4:
                return
            
            # 使用网络字节序（大端）解析，与C代码中的htonl()匹配
            length = int.from_bytes(length_bytes, 'big')
            data = conn.recv(length)
            
            # 验证
            result = self.tester.verify_layer3_layer4(data)
            
            # 返回结果（JSON）使用网络字节序
            response = json.dumps(result).encode('utf-8')
            conn.sendall(len(response).to_bytes(4, 'big'))  # 网络字节序
            conn.sendall(response)
            
        except Exception as e:
            print(f"[ERROR] Client handling error: {e}")
        finally:
            conn.close()


def main():
    parser = argparse.ArgumentParser(
        description="Layer 3-4 Real SUT Verifier for ChatAFL-Enhanced"
    )
    
    parser.add_argument('--protocol', type=str, required=True,
                       help='Protocol (FTP/SMTP/HTTP/RTSP/SIP)')
    parser.add_argument('--sampling-rate', type=float, default=0.15,
                       help='Sampling rate (default 0.15 = 15%%)')
    parser.add_argument('--server', action='store_true',
                       help='Run as Unix socket server')
    parser.add_argument('--socket-path', type=Path, default=Path("/tmp/sut-verifier.sock"),
                       help='Unix socket path (server mode)')
    parser.add_argument('--test-file', type=Path,
                       help='Test a single file (non-server mode)')
    
    args = parser.parse_args()
    
    if args.server:
        server = SUTVerifierServer(args.socket_path, args.protocol, args.sampling_rate)
        server.start()
    elif args.test_file:
        tester = SUTTester(args.protocol, args.sampling_rate)
        data = args.test_file.read_bytes()
        result = tester.verify_layer3_layer4(data)
        print(json.dumps(result, indent=2))
        print(f"\nStats: {tester.get_stats()}")
    else:
        parser.error("Either --server or --test-file is required")


if __name__ == "__main__":
    main()
