#!/usr/bin/env python3
"""
RFC → Grammar 离线转换器
支持FTP/SMTP/HTTP/RTSP/SIP/DAAP协议

用法：
  python3 rfc-grammar-converter.py --protocol FTP --rfc-file rfc959.txt --output ftp_grammar.json
  python3 rfc-grammar-converter.py --auto-generate --protocol SMTP

功能：
  1. 解析RFC文档中的ABNF语法
  2. 提取协议状态机
  3. 生成JSON格式的grammar + constraints
  4. 集成到chat-llm.c的template generation
"""

import re
import json
import argparse
import sys
from typing import Dict, List, Tuple, Optional
from pathlib import Path

class RFCGrammarConverter:
    """RFC文档→形式化Grammar转换器"""
    
    # 预定义协议RFC映射
    RFC_SPEC = {
        "FTP": {
            "rfc_number": "RFC 959",
            "commands": ["USER", "PASS", "CWD", "QUIT", "PORT", "PASV", "LIST", "RETR", "STOR", "DELE"],
            "responses": ["220", "331", "230", "221", "200", "227", "150", "226", "550"],
            "state_machine": {
                "INIT": ["USER"],
                "USER_OK": ["PASS"],
                "LOGGED_IN": ["CWD", "PORT", "PASV", "LIST", "RETR", "STOR", "DELE", "QUIT"],
                "DATA_CONN": ["LIST", "RETR", "STOR"]
            }
        },
        "SMTP": {
            "rfc_number": "RFC 5321",
            "commands": ["EHLO", "HELO", "MAIL", "RCPT", "DATA", "QUIT", "RSET", "VRFY", "EXPN"],
            "responses": ["220", "250", "354", "221", "550", "551", "552", "553", "554"],
            "state_machine": {
                "INIT": ["EHLO", "HELO"],
                "GREETED": ["MAIL", "QUIT", "RSET"],
                "MAIL_OK": ["RCPT"],
                "RCPT_OK": ["DATA", "RCPT"],
                "DATA_MODE": [".", "QUIT"]
            }
        },
        "HTTP": {
            "rfc_number": "RFC 2616",
            "commands": ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"],
            "responses": ["200", "201", "204", "301", "302", "400", "401", "403", "404", "500"],
            "state_machine": {
                "INIT": ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"],
                "REQUEST_SENT": ["response"],
                "RESPONSE_RECEIVED": ["GET", "POST"]
            }
        },
        "RTSP": {
            "rfc_number": "RFC 2326",
            "commands": ["DESCRIBE", "SETUP", "PLAY", "PAUSE", "TEARDOWN", "OPTIONS", "ANNOUNCE"],
            "responses": ["200", "404", "454", "455", "456", "457", "458", "459"],
            "state_machine": {
                "INIT": ["DESCRIBE", "OPTIONS"],
                "DESCRIBED": ["SETUP"],
                "READY": ["PLAY", "SETUP", "TEARDOWN"],
                "PLAYING": ["PAUSE", "TEARDOWN"],
                "PAUSED": ["PLAY", "TEARDOWN"]
            }
        },
        "SIP": {
            "rfc_number": "RFC 3261",
            "commands": ["INVITE", "ACK", "BYE", "CANCEL", "REGISTER", "OPTIONS"],
            "responses": ["100", "180", "200", "400", "404", "487"],
            "state_machine": {
                "INIT": ["REGISTER", "INVITE", "OPTIONS"],
                "REGISTERED": ["INVITE"],
                "CALLING": ["CANCEL", "ACK"],
                "ESTABLISHED": ["BYE"]
            }
        },
        "DAAP": {
            "rfc_number": "DAAP Spec",
            "commands": ["login", "update", "databases", "containers", "items"],
            "responses": ["200", "204", "400", "401", "403", "404"],
            "state_machine": {
                "INIT": ["login"],
                "AUTHENTICATED": ["databases", "update"],
                "BROWSING": ["containers", "items"]
            }
        }
    }
    
    def __init__(self, protocol: str):
        self.protocol = protocol.upper()
        if self.protocol not in self.RFC_SPEC:
            raise ValueError(f"Unsupported protocol: {protocol}. Supported: {list(self.RFC_SPEC.keys())}")
        
        self.spec = self.RFC_SPEC[self.protocol]
        
    def parse_abnf_from_file(self, rfc_file: Path) -> Dict:
        """解析RFC文件中的ABNF语法（真实RFC解析）"""
        if not rfc_file.exists():
            print(f"[WARN] RFC file {rfc_file} not found, using predefined templates", file=sys.stderr)
            return self._generate_from_predefined()
        
        content = rfc_file.read_text(errors='ignore')
        
        # 正则提取ABNF规则（RFC标准格式）
        # 示例: command = "USER" SP username CRLF
        abnf_pattern = r'^([a-zA-Z][\w-]*)\s*=\s*(.+)$'
        abnf_rules = {}
        
        for line in content.split('\n'):
            match = re.match(abnf_pattern, line.strip())
            if match:
                rule_name, rule_def = match.groups()
                abnf_rules[rule_name] = rule_def.strip()
        
        if abnf_rules:
            print(f"[OK] Extracted {len(abnf_rules)} ABNF rules from {rfc_file}", file=sys.stderr)
            return self._abnf_to_json(abnf_rules)
        else:
            print(f"[WARN] No ABNF rules found, using predefined templates", file=sys.stderr)
            return self._generate_from_predefined()
    
    def _abnf_to_json(self, abnf_rules: Dict) -> Dict:
        """将ABNF规则转换为JSON Grammar"""
        grammar = {
            "protocol": self.protocol,
            "rfc": self.spec["rfc_number"],
            "format": "JSON-Template-with-ABNF-Constraints",
            "commands": {},
            "responses": {},
            "state_machine": self.spec["state_machine"],
            "constraints": {}
        }
        
        # 转换命令
        for cmd in self.spec["commands"]:
            cmd_lower = cmd.lower()
            if cmd_lower in abnf_rules:
                grammar["commands"][cmd] = self._parse_abnf_rule(abnf_rules[cmd_lower])
            else:
                grammar["commands"][cmd] = self._default_command_template(cmd)
        
        return grammar
    
    def _parse_abnf_rule(self, rule: str) -> Dict:
        """解析单条ABNF规则"""
        # 简化版解析器：提取关键token
        tokens = []
        
        # 提取字符串字面量
        for match in re.finditer(r'"([^"]+)"', rule):
            tokens.append({"type": "literal", "value": match.group(1)})
        
        # 提取变量引用
        for match in re.finditer(r'\b([a-zA-Z][\w-]+)\b', rule):
            var = match.group(1)
            if var.upper() not in ["SP", "CRLF", "HTAB", "LF"]:  # 排除常见终结符
                tokens.append({"type": "variable", "name": var})
        
        return {
            "abnf": rule,
            "tokens": tokens,
            "template": self._tokens_to_template(tokens)
        }
    
    def _tokens_to_template(self, tokens: List[Dict]) -> List[str]:
        """将token转为ChatAFL模板格式"""
        template = []
        for token in tokens:
            if token["type"] == "literal":
                template.append(token["value"])
            elif token["type"] == "variable":
                template.append(f"<<{token['name'].upper()}>>")
        
        return template
    
    def _default_command_template(self, cmd: str) -> Dict:
        """为未在RFC中找到的命令生成默认模板"""
        # 基于协议特性生成
        if self.protocol == "FTP":
            return {
                "template": [f"{cmd} <<VALUE>>\\r\\n"],
                "constraints": {
                    "VALUE": {"type": "string", "max_length": 256}
                }
            }
        elif self.protocol == "SMTP":
            return {
                "template": [f"{cmd} <<VALUE>>\\r\\n"],
                "constraints": {
                    "VALUE": {"type": "email_or_domain", "max_length": 256}
                }
            }
        elif self.protocol == "HTTP":
            return {
                "template": [f"{cmd} <<URI>> HTTP/1.1\\r\\nHost: <<HOST>>\\r\\n\\r\\n"],
                "constraints": {
                    "URI": {"type": "uri_path", "max_length": 2048},
                    "HOST": {"type": "hostname", "max_length": 256}
                }
            }
        elif self.protocol == "RTSP":
            return {
                "template": [f"{cmd} <<URL>> RTSP/1.0\\r\\nCSeq: <<CSEQ>>\\r\\n\\r\\n"],
                "constraints": {
                    "URL": {"type": "rtsp_url", "max_length": 512},
                    "CSEQ": {"type": "integer", "min": 1, "max": 999999}
                }
            }
        else:
            return {
                "template": [f"{cmd} <<VALUE>>"],
                "constraints": {
                    "VALUE": {"type": "string", "max_length": 512}
                }
            }
    
    def _generate_from_predefined(self) -> Dict:
        """使用预定义模板生成Grammar"""
        grammar = {
            "protocol": self.protocol,
            "rfc": self.spec["rfc_number"],
            "format": "JSON-Template-with-Constraints",
            "generated_method": "predefined",
            "commands": {},
            "responses": self.spec["responses"],
            "state_machine": self.spec["state_machine"],
            "constraints": {}
        }
        
        for cmd in self.spec["commands"]:
            grammar["commands"][cmd] = self._default_command_template(cmd)
        
        return grammar
    
    def generate_grammar(self, rfc_file: Optional[Path] = None) -> Dict:
        """主入口：生成完整Grammar"""
        if rfc_file:
            return self.parse_abnf_from_file(rfc_file)
        else:
            return self._generate_from_predefined()
    
    def save_grammar(self, grammar: Dict, output_path: Path):
        """保存到JSON文件"""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(grammar, f, indent=2, ensure_ascii=False)
        print(f"[OK] Grammar saved to {output_path}")
    
    def generate_c_header(self, grammar: Dict, output_path: Path):
        """生成C头文件（供chat-llm.c使用）"""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            f.write(f"""/* Auto-generated from RFC Grammar Converter */
/* Protocol: {self.protocol} ({self.spec['rfc_number']}) */
#ifndef RFC_GRAMMAR_{self.protocol}_H
#define RFC_GRAMMAR_{self.protocol}_H

#define {self.protocol}_GRAMMAR_JSON \\
""")
            # 转义JSON为C字符串
            json_str = json.dumps(grammar, indent=2).replace('"', '\\"').replace('\n', ' \\\n')
            f.write(f'"{json_str}"\n\n')
            f.write(f"#endif /* RFC_GRAMMAR_{self.protocol}_H */\n")
        
        print(f"[OK] C header saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="RFC → Grammar Offline Converter for ChatAFL-Enhanced",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # 从RFC文件生成
  python3 rfc-grammar-converter.py --protocol FTP --rfc-file rfc959.txt --output ftp_grammar.json
  
  # 使用预定义模板生成所有协议
  python3 rfc-grammar-converter.py --auto-generate-all
  
  # 生成C头文件（集成到chat-llm.c）
  python3 rfc-grammar-converter.py --protocol SMTP --c-header grammar-smtp.h
        """
    )
    
    parser.add_argument('--protocol', type=str, 
                       help='Protocol name (FTP/SMTP/HTTP/RTSP/SIP/DAAP)')
    parser.add_argument('--rfc-file', type=Path,
                       help='Path to RFC document (optional, will use predefined if not provided)')
    parser.add_argument('--output', type=Path,
                       help='Output JSON file path')
    parser.add_argument('--c-header', type=Path,
                       help='Generate C header file')
    parser.add_argument('--auto-generate-all', action='store_true',
                       help='Generate grammars for all supported protocols')
    
    args = parser.parse_args()
    
    if args.auto_generate_all:
        output_dir = Path("rfc-grammars")
        c_header_dir = Path("rfc-grammars-c")
        
        for proto in RFCGrammarConverter.RFC_SPEC.keys():
            converter = RFCGrammarConverter(proto)
            grammar = converter.generate_grammar()
            
            json_path = output_dir / f"{proto.lower()}_grammar.json"
            converter.save_grammar(grammar, json_path)
            
            c_path = c_header_dir / f"grammar-{proto.lower()}.h"
            converter.generate_c_header(grammar, c_path)
        
        print(f"\n[OK] Generated grammars for all protocols in {output_dir}/ and {c_header_dir}/")
        return
    
    if not args.protocol:
        parser.error("--protocol is required (or use --auto-generate-all)")
    
    converter = RFCGrammarConverter(args.protocol)
    grammar = converter.generate_grammar(args.rfc_file)
    
    if args.output:
        converter.save_grammar(grammar, args.output)
    
    if args.c_header:
        converter.generate_c_header(grammar, args.c_header)
    
    if not args.output and not args.c_header:
        # 默认输出到stdout
        print(json.dumps(grammar, indent=2))


if __name__ == "__main__":
    main()
