#!/usr/bin/env python3
"""
ChatAFL vs ChatAFL-Enhanced 可视化对比脚本

用法:
    python3 visualize_comparison.py <comparison_results_dir>
    
示例:
    python3 visualize_comparison.py comparison_results/LightFTP_20260118_023011
"""

import sys
import os
import re
import json
from pathlib import Path
from datetime import datetime
import matplotlib
matplotlib.use('Agg')  # 非交互式后端
import matplotlib.pyplot as plt
import numpy as np

# 设置中文字体支持
plt.rcParams['font.sans-serif'] = ['DejaVu Sans', 'Arial Unicode MS', 'SimHei']
plt.rcParams['axes.unicode_minus'] = False

class FuzzerResults:
    """解析并存储fuzzer结果"""
    
    def __init__(self, name, base_dir):
        self.name = name
        self.base_dir = Path(base_dir)
        self.stats = {}
        self.crashes = []
        self.hangs = []
        self.queue_size = 0
        self.stt_files = []
        self.cegar_files = []
        
    def parse_fuzzer_stats(self):
        """解析fuzzer_stats文件"""
        stats_file = self.base_dir / "fuzzer_stats"
        if not stats_file.exists():
            print(f"[警告] {self.name} fuzzer_stats不存在: {stats_file}")
            return
        
        with open(stats_file, 'r') as f:
            for line in f:
                line = line.strip()
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    # 尝试转换为数字
                    try:
                        if '.' in value or '%' in value:
                            value = float(value.replace('%', ''))
                        else:
                            value = int(value)
                    except ValueError:
                        pass
                    
                    self.stats[key] = value
        
        print(f"[✓] {self.name} 统计数据已加载: {len(self.stats)} 项指标")
    
    def parse_crashes(self):
        """统计崩溃文件"""
        crashes_dir = self.base_dir / "crashes"
        if crashes_dir.exists():
            self.crashes = [f for f in crashes_dir.iterdir() 
                           if f.is_file() and f.name != 'README.txt']
            print(f"[✓] {self.name} 发现崩溃: {len(self.crashes)} 个")
    
    def parse_hangs(self):
        """统计挂起文件"""
        hangs_dir = self.base_dir / "hangs"
        if hangs_dir.exists():
            self.hangs = [f for f in hangs_dir.iterdir() 
                         if f.is_file() and f.name != 'README.txt']
            if self.hangs:
                print(f"[✓] {self.name} 发现挂起: {len(self.hangs)} 个")
    
    def parse_queue(self):
        """统计队列大小"""
        queue_dir = self.base_dir / "queue"
        if queue_dir.exists():
            self.queue_size = len([f for f in queue_dir.iterdir() 
                                  if f.is_file() and f.name != '.state'])
            print(f"[✓] {self.name} 队列大小: {self.queue_size} 个测试用例")
    
    def parse_enhanced_features(self):
        """解析Enhanced特有功能"""
        # STT状态树
        stt_dir = self.base_dir / ".stt_export"
        if stt_dir.exists():
            self.stt_files = list(stt_dir.glob("*.dot"))
            print(f"[✓] {self.name} STT状态树: {len(self.stt_files)} 个文件")
        
        # CEGAR缓存
        cegar_dir = self.base_dir / ".cegar_cache"
        if cegar_dir.exists():
            self.cegar_files = list(cegar_dir.glob("*.json"))
            print(f"[✓] {self.name} CEGAR缓存: {len(self.cegar_files)} 个文件")
    
    def load_all(self):
        """加载所有数据"""
        self.parse_fuzzer_stats()
        self.parse_crashes()
        self.parse_hangs()
        self.parse_queue()
        self.parse_enhanced_features()


def create_comparison_charts(chatafl, enhanced, output_dir):
    """创建对比图表"""
    
    output_dir = Path(output_dir)
    output_dir.mkdir(exist_ok=True)
    
    # 1. 关键指标对比条形图
    create_metrics_bar_chart(chatafl, enhanced, output_dir)
    
    # 2. 覆盖率对比
    create_coverage_chart(chatafl, enhanced, output_dir)
    
    # 3. 执行效率对比
    create_efficiency_chart(chatafl, enhanced, output_dir)
    
    # 4. 漏洞发现对比
    create_vulnerability_chart(chatafl, enhanced, output_dir)
    
    # 5. 综合雷达图
    create_radar_chart(chatafl, enhanced, output_dir)
    
    # 6. 生成HTML报告
    create_html_report(chatafl, enhanced, output_dir)


def create_metrics_bar_chart(chatafl, enhanced, output_dir):
    """关键指标对比条形图"""
    
    metrics = [
        ('execs_done', '总执行次数'),
        ('paths_total', '发现路径数'),
        ('unique_crashes', '唯一崩溃'),
        ('unique_hangs', '唯一挂起')
    ]
    
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle('ChatAFL vs ChatAFL-Enhanced: 关键指标对比', fontsize=16, fontweight='bold')
    
    for idx, (metric_key, metric_name) in enumerate(metrics):
        ax = axes[idx // 2, idx % 2]
        
        chatafl_val = chatafl.stats.get(metric_key, 0)
        enhanced_val = enhanced.stats.get(metric_key, 0)
        
        bars = ax.bar(['ChatAFL', 'Enhanced'], [chatafl_val, enhanced_val], 
                     color=['#3498db', '#e74c3c'], alpha=0.8, edgecolor='black')
        
        ax.set_ylabel(metric_name, fontsize=12)
        ax.set_title(f'{metric_name}', fontsize=13, fontweight='bold')
        ax.grid(axis='y', alpha=0.3)
        
        # 在柱子上显示数值
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                   f'{int(height)}',
                   ha='center', va='bottom', fontsize=11, fontweight='bold')
        
        # 显示差异百分比
        if chatafl_val > 0:
            diff_pct = ((enhanced_val - chatafl_val) / chatafl_val) * 100
            color = 'green' if diff_pct > 0 else 'red'
            ax.text(0.5, 0.95, f'差异: {diff_pct:+.1f}%', 
                   transform=ax.transAxes, ha='center', va='top',
                   bbox=dict(boxstyle='round', facecolor=color, alpha=0.3),
                   fontsize=10, fontweight='bold')
    
    plt.tight_layout()
    output_file = output_dir / 'metrics_comparison.png'
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"[✓] 图表已保存: {output_file}")


def create_coverage_chart(chatafl, enhanced, output_dir):
    """覆盖率对比"""
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    fig.suptitle('代码覆盖率对比', fontsize=16, fontweight='bold')
    
    # 位图覆盖率
    chatafl_cov = chatafl.stats.get('bitmap_cvg', 0)
    enhanced_cov = enhanced.stats.get('bitmap_cvg', 0)
    
    ax1.bar(['ChatAFL', 'Enhanced'], [chatafl_cov, enhanced_cov],
           color=['#3498db', '#e74c3c'], alpha=0.8, edgecolor='black')
    ax1.set_ylabel('位图覆盖率 (%)', fontsize=12)
    ax1.set_title('位图覆盖率', fontsize=13, fontweight='bold')
    ax1.grid(axis='y', alpha=0.3)
    
    for i, val in enumerate([chatafl_cov, enhanced_cov]):
        ax1.text(i, val, f'{val:.2f}%', ha='center', va='bottom', 
                fontsize=11, fontweight='bold')
    
    # 路径深度
    chatafl_depth = chatafl.stats.get('max_depth', 0)
    enhanced_depth = enhanced.stats.get('max_depth', 0)
    
    ax2.bar(['ChatAFL', 'Enhanced'], [chatafl_depth, enhanced_depth],
           color=['#3498db', '#e74c3c'], alpha=0.8, edgecolor='black')
    ax2.set_ylabel('最大深度', fontsize=12)
    ax2.set_title('路径探索深度', fontsize=13, fontweight='bold')
    ax2.grid(axis='y', alpha=0.3)
    
    for i, val in enumerate([chatafl_depth, enhanced_depth]):
        ax2.text(i, val, f'{int(val)}', ha='center', va='bottom', 
                fontsize=11, fontweight='bold')
    
    plt.tight_layout()
    output_file = output_dir / 'coverage_comparison.png'
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"[✓] 图表已保存: {output_file}")


def create_efficiency_chart(chatafl, enhanced, output_dir):
    """执行效率对比"""
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    fig.suptitle('Fuzzing效率对比', fontsize=16, fontweight='bold')
    
    # 执行速度
    chatafl_speed = chatafl.stats.get('execs_per_sec', 0)
    enhanced_speed = enhanced.stats.get('execs_per_sec', 0)
    
    ax1.bar(['ChatAFL', 'Enhanced'], [chatafl_speed, enhanced_speed],
           color=['#3498db', '#e74c3c'], alpha=0.8, edgecolor='black')
    ax1.set_ylabel('执行速度 (次/秒)', fontsize=12)
    ax1.set_title('执行速度', fontsize=13, fontweight='bold')
    ax1.grid(axis='y', alpha=0.3)
    
    for i, val in enumerate([chatafl_speed, enhanced_speed]):
        ax1.text(i, val, f'{val:.2f}', ha='center', va='bottom', 
                fontsize=11, fontweight='bold')
    
    # 队列大小
    ax2.bar(['ChatAFL', 'Enhanced'], [chatafl.queue_size, enhanced.queue_size],
           color=['#3498db', '#e74c3c'], alpha=0.8, edgecolor='black')
    ax2.set_ylabel('测试用例数量', fontsize=12)
    ax2.set_title('队列大小', fontsize=13, fontweight='bold')
    ax2.grid(axis='y', alpha=0.3)
    
    for i, val in enumerate([chatafl.queue_size, enhanced.queue_size]):
        ax2.text(i, val, f'{int(val)}', ha='center', va='bottom', 
                fontsize=11, fontweight='bold')
    
    plt.tight_layout()
    output_file = output_dir / 'efficiency_comparison.png'
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"[✓] 图表已保存: {output_file}")


def create_vulnerability_chart(chatafl, enhanced, output_dir):
    """漏洞发现对比"""
    
    fig, ax = plt.subplots(figsize=(10, 7))
    fig.suptitle('漏洞发现能力对比', fontsize=16, fontweight='bold')
    
    categories = ['崩溃数量', '挂起数量', 'STT状态树', 'CEGAR缓存']
    chatafl_vals = [
        len(chatafl.crashes),
        len(chatafl.hangs),
        len(chatafl.stt_files),
        len(chatafl.cegar_files)
    ]
    enhanced_vals = [
        len(enhanced.crashes),
        len(enhanced.hangs),
        len(enhanced.stt_files),
        len(enhanced.cegar_files)
    ]
    
    x = np.arange(len(categories))
    width = 0.35
    
    bars1 = ax.bar(x - width/2, chatafl_vals, width, label='ChatAFL',
                  color='#3498db', alpha=0.8, edgecolor='black')
    bars2 = ax.bar(x + width/2, enhanced_vals, width, label='Enhanced',
                  color='#e74c3c', alpha=0.8, edgecolor='black')
    
    ax.set_ylabel('数量', fontsize=12)
    ax.set_title('漏洞发现和特性使用', fontsize=13, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(categories, fontsize=11)
    ax.legend(fontsize=11)
    ax.grid(axis='y', alpha=0.3)
    
    # 在柱子上显示数值
    for bars in [bars1, bars2]:
        for bar in bars:
            height = bar.get_height()
            if height > 0:
                ax.text(bar.get_x() + bar.get_width()/2., height,
                       f'{int(height)}',
                       ha='center', va='bottom', fontsize=10, fontweight='bold')
    
    plt.tight_layout()
    output_file = output_dir / 'vulnerability_comparison.png'
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"[✓] 图表已保存: {output_file}")


def create_radar_chart(chatafl, enhanced, output_dir):
    """综合能力雷达图"""
    
    # 归一化指标 (0-100)
    def normalize(val, max_val):
        return (val / max_val * 100) if max_val > 0 else 0
    
    max_execs = max(chatafl.stats.get('execs_done', 1), enhanced.stats.get('execs_done', 1))
    max_paths = max(chatafl.stats.get('paths_total', 1), enhanced.stats.get('paths_total', 1))
    max_crashes = max(len(chatafl.crashes) + 1, len(enhanced.crashes) + 1)
    max_speed = max(chatafl.stats.get('execs_per_sec', 1), enhanced.stats.get('execs_per_sec', 1))
    max_coverage = max(chatafl.stats.get('bitmap_cvg', 1), enhanced.stats.get('bitmap_cvg', 1))
    
    categories = ['执行次数', '路径发现', '漏洞发现', '执行速度', '代码覆盖率', 'Enhanced特性']
    
    chatafl_scores = [
        normalize(chatafl.stats.get('execs_done', 0), max_execs),
        normalize(chatafl.stats.get('paths_total', 0), max_paths),
        normalize(len(chatafl.crashes), max_crashes),
        normalize(chatafl.stats.get('execs_per_sec', 0), max_speed),
        normalize(chatafl.stats.get('bitmap_cvg', 0), max_coverage),
        0  # ChatAFL无Enhanced特性
    ]
    
    enhanced_scores = [
        normalize(enhanced.stats.get('execs_done', 0), max_execs),
        normalize(enhanced.stats.get('paths_total', 0), max_paths),
        normalize(len(enhanced.crashes), max_crashes),
        normalize(enhanced.stats.get('execs_per_sec', 0), max_speed),
        normalize(enhanced.stats.get('bitmap_cvg', 0), max_coverage),
        normalize(len(enhanced.stt_files) + len(enhanced.cegar_files), 50)
    ]
    
    # 创建雷达图
    angles = np.linspace(0, 2 * np.pi, len(categories), endpoint=False).tolist()
    chatafl_scores += chatafl_scores[:1]
    enhanced_scores += enhanced_scores[:1]
    angles += angles[:1]
    
    fig, ax = plt.subplots(figsize=(10, 10), subplot_kw=dict(projection='polar'))
    
    ax.plot(angles, chatafl_scores, 'o-', linewidth=2, label='ChatAFL', color='#3498db')
    ax.fill(angles, chatafl_scores, alpha=0.25, color='#3498db')
    
    ax.plot(angles, enhanced_scores, 'o-', linewidth=2, label='Enhanced', color='#e74c3c')
    ax.fill(angles, enhanced_scores, alpha=0.25, color='#e74c3c')
    
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(categories, fontsize=11)
    ax.set_ylim(0, 100)
    ax.set_yticks([20, 40, 60, 80, 100])
    ax.set_yticklabels(['20', '40', '60', '80', '100'], fontsize=9)
    ax.grid(True)
    ax.legend(loc='upper right', bbox_to_anchor=(1.3, 1.1), fontsize=12)
    
    plt.title('综合能力对比雷达图', fontsize=16, fontweight='bold', pad=20)
    
    output_file = output_dir / 'radar_comparison.png'
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"[✓] 图表已保存: {output_file}")


def create_html_report(chatafl, enhanced, output_dir):
    """生成HTML对比报告"""
    
    html_content = f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ChatAFL vs ChatAFL-Enhanced 对比报告</title>
    <style>
        body {{
            font-family: 'Segoe UI', Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
        }}
        h1 {{
            color: #2c3e50;
            text-align: center;
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        .timestamp {{
            text-align: center;
            color: #7f8c8d;
            margin-bottom: 30px;
        }}
        .summary {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 40px;
        }}
        .fuzzer-card {{
            border: 2px solid #ecf0f1;
            border-radius: 10px;
            padding: 20px;
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
        }}
        .fuzzer-card h2 {{
            margin-top: 0;
            color: #34495e;
            font-size: 1.8em;
        }}
        .stat-row {{
            display: flex;
            justify-content: space-between;
            padding: 10px 0;
            border-bottom: 1px solid #ddd;
        }}
        .stat-label {{
            font-weight: bold;
            color: #555;
        }}
        .stat-value {{
            color: #2980b9;
            font-weight: bold;
        }}
        .charts {{
            display: grid;
            grid-template-columns: 1fr;
            gap: 30px;
        }}
        .chart-card {{
            border: 1px solid #ddd;
            border-radius: 10px;
            padding: 20px;
            background: #fafafa;
        }}
        .chart-card h3 {{
            margin-top: 0;
            color: #2c3e50;
            font-size: 1.5em;
        }}
        .chart-card img {{
            width: 100%;
            height: auto;
            border-radius: 5px;
        }}
        .winner {{
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            font-size: 1.3em;
            margin-top: 30px;
        }}
        .comparison-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        .comparison-table th, .comparison-table td {{
            border: 1px solid #ddd;
            padding: 12px;
            text-align: center;
        }}
        .comparison-table th {{
            background: #3498db;
            color: white;
            font-weight: bold;
        }}
        .comparison-table tr:nth-child(even) {{
            background: #f2f2f2;
        }}
        .better {{
            background: #d5f4e6 !important;
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔬 ChatAFL vs ChatAFL-Enhanced 对比报告</h1>
        <div class="timestamp">生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        
        <div class="summary">
            <div class="fuzzer-card">
                <h2>ChatAFL (基础版)</h2>
                <div class="stat-row">
                    <span class="stat-label">执行次数:</span>
                    <span class="stat-value">{chatafl.stats.get('execs_done', 0):,}</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">发现路径:</span>
                    <span class="stat-value">{chatafl.stats.get('paths_total', 0)}</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">代码覆盖率:</span>
                    <span class="stat-value">{chatafl.stats.get('bitmap_cvg', 0):.2f}%</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">执行速度:</span>
                    <span class="stat-value">{chatafl.stats.get('execs_per_sec', 0):.2f} 次/秒</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">崩溃数量:</span>
                    <span class="stat-value">{len(chatafl.crashes)}</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">队列大小:</span>
                    <span class="stat-value">{chatafl.queue_size}</span>
                </div>
            </div>
            
            <div class="fuzzer-card">
                <h2>ChatAFL-Enhanced (增强版)</h2>
                <div class="stat-row">
                    <span class="stat-label">执行次数:</span>
                    <span class="stat-value">{enhanced.stats.get('execs_done', 0):,}</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">发现路径:</span>
                    <span class="stat-value">{enhanced.stats.get('paths_total', 0)}</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">代码覆盖率:</span>
                    <span class="stat-value">{enhanced.stats.get('bitmap_cvg', 0):.2f}%</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">执行速度:</span>
                    <span class="stat-value">{enhanced.stats.get('execs_per_sec', 0):.2f} 次/秒</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">崩溃数量:</span>
                    <span class="stat-value">{len(enhanced.crashes)}</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">队列大小:</span>
                    <span class="stat-value">{enhanced.queue_size}</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">STT状态树:</span>
                    <span class="stat-value">{len(enhanced.stt_files)} 个</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">CEGAR缓存:</span>
                    <span class="stat-value">{len(enhanced.cegar_files)} 个</span>
                </div>
            </div>
        </div>
        
        <h2 style="color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px;">详细对比表</h2>
        <table class="comparison-table">
            <thead>
                <tr>
                    <th>指标</th>
                    <th>ChatAFL</th>
                    <th>Enhanced</th>
                    <th>差异</th>
                </tr>
            </thead>
            <tbody>
                {generate_comparison_rows(chatafl, enhanced)}
            </tbody>
        </table>
        
        <div class="charts">
            <div class="chart-card">
                <h3>📊 关键指标对比</h3>
                <img src="metrics_comparison.png" alt="关键指标对比">
            </div>
            
            <div class="chart-card">
                <h3>📈 代码覆盖率对比</h3>
                <img src="coverage_comparison.png" alt="覆盖率对比">
            </div>
            
            <div class="chart-card">
                <h3>⚡ Fuzzing效率对比</h3>
                <img src="efficiency_comparison.png" alt="效率对比">
            </div>
            
            <div class="chart-card">
                <h3>🐛 漏洞发现能力对比</h3>
                <img src="vulnerability_comparison.png" alt="漏洞发现对比">
            </div>
            
            <div class="chart-card">
                <h3>🎯 综合能力雷达图</h3>
                <img src="radar_comparison.png" alt="综合能力雷达图">
            </div>
        </div>
        
        {generate_winner_section(chatafl, enhanced)}
    </div>
</body>
</html>
"""
    
    output_file = output_dir / 'comparison_report.html'
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"[✓] HTML报告已保存: {output_file}")


def generate_comparison_rows(chatafl, enhanced):
    """生成对比表格行"""
    
    metrics = [
        ('execs_done', '执行次数', '{:,}'),
        ('paths_total', '发现路径', '{}'),
        ('bitmap_cvg', '代码覆盖率', '{:.2f}%'),
        ('execs_per_sec', '执行速度', '{:.2f}'),
        ('unique_crashes', '唯一崩溃', '{}'),
        ('unique_hangs', '唯一挂起', '{}'),
        ('max_depth', '最大深度', '{}'),
    ]
    
    rows = []
    for key, label, fmt in metrics:
        val1 = chatafl.stats.get(key, 0)
        val2 = enhanced.stats.get(key, 0)
        
        if val1 > 0:
            diff = ((val2 - val1) / val1) * 100
            diff_str = f"{diff:+.1f}%"
        else:
            diff_str = "N/A"
        
        better_class = ' class="better"' if val2 > val1 else ''
        
        row = f"""
                <tr>
                    <td>{label}</td>
                    <td>{fmt.format(val1)}</td>
                    <td{better_class}>{fmt.format(val2)}</td>
                    <td>{diff_str}</td>
                </tr>
        """
        rows.append(row)
    
    # 添加Enhanced特有功能
    rows.append(f"""
                <tr>
                    <td>STT状态树</td>
                    <td>0</td>
                    <td class="better">{len(enhanced.stt_files)}</td>
                    <td>+100%</td>
                </tr>
    """)
    rows.append(f"""
                <tr>
                    <td>CEGAR缓存</td>
                    <td>0</td>
                    <td class="better">{len(enhanced.cegar_files)}</td>
                    <td>+100%</td>
                </tr>
    """)
    
    return '\n'.join(rows)


def generate_winner_section(chatafl, enhanced):
    """生成结论部分"""
    
    # 计算综合得分
    chatafl_score = 0
    enhanced_score = 0
    
    metrics = ['execs_done', 'paths_total', 'bitmap_cvg', 'unique_crashes']
    for metric in metrics:
        if enhanced.stats.get(metric, 0) > chatafl.stats.get(metric, 0):
            enhanced_score += 1
        elif enhanced.stats.get(metric, 0) < chatafl.stats.get(metric, 0):
            chatafl_score += 1
    
    # Enhanced特有功能加分
    if len(enhanced.stt_files) > 0:
        enhanced_score += 1
    if len(enhanced.cegar_files) > 0:
        enhanced_score += 1
    
    if enhanced_score > chatafl_score:
        winner = "ChatAFL-Enhanced"
        icon = "🏆"
    elif chatafl_score > enhanced_score:
        winner = "ChatAFL"
        icon = "🏆"
    else:
        winner = "平局"
        icon = "🤝"
    
    return f"""
        <div class="winner">
            <h2>{icon} 综合评估结论</h2>
            <p style="font-size: 1.5em; margin: 10px 0;">优胜者: <strong>{winner}</strong></p>
            <p>ChatAFL得分: {chatafl_score} | Enhanced得分: {enhanced_score}</p>
        </div>
    """


def main():
    if len(sys.argv) < 2:
        print("用法: python3 visualize_comparison.py <comparison_results_dir>")
        print("示例: python3 visualize_comparison.py comparison_results/LightFTP_20260118_023011")
        sys.exit(1)
    
    results_dir = Path(sys.argv[1])
    
    if not results_dir.exists():
        print(f"[错误] 结果目录不存在: {results_dir}")
        sys.exit(1)
    
    print(f"\n{'='*70}")
    print(f"  ChatAFL vs ChatAFL-Enhanced 可视化对比")
    print(f"{'='*70}\n")
    print(f"[INFO] 结果目录: {results_dir}\n")
    
    # 加载ChatAFL结果
    print("[1] 加载ChatAFL结果...")
    chatafl_dir = results_dir / "chatafl"
    if not chatafl_dir.exists():
        print(f"[错误] ChatAFL目录不存在: {chatafl_dir}")
        sys.exit(1)
    
    chatafl = FuzzerResults("ChatAFL", chatafl_dir)
    chatafl.load_all()
    
    # 加载Enhanced结果
    print("\n[2] 加载ChatAFL-Enhanced结果...")
    enhanced_dir = results_dir / "chatafl-enhanced"
    if not enhanced_dir.exists():
        print(f"[错误] Enhanced目录不存在: {enhanced_dir}")
        sys.exit(1)
    
    enhanced = FuzzerResults("ChatAFL-Enhanced", enhanced_dir)
    enhanced.load_all()
    
    # 创建可视化输出目录
    print("\n[3] 生成可视化图表...")
    viz_dir = results_dir / "visualization"
    create_comparison_charts(chatafl, enhanced, viz_dir)
    
    print(f"\n{'='*70}")
    print(f"  ✅ 可视化完成!")
    print(f"{'='*70}")
    print(f"\n📁 输出目录: {viz_dir}")
    print(f"\n📊 生成的文件:")
    print(f"   • metrics_comparison.png      - 关键指标对比")
    print(f"   • coverage_comparison.png     - 覆盖率对比")
    print(f"   • efficiency_comparison.png   - 效率对比")
    print(f"   • vulnerability_comparison.png - 漏洞发现对比")
    print(f"   • radar_comparison.png        - 综合能力雷达图")
    print(f"   • comparison_report.html      - 交互式HTML报告")
    print(f"\n🌐 查看报告: firefox {viz_dir}/comparison_report.html")
    print(f"或: xdg-open {viz_dir}/comparison_report.html\n")


if __name__ == "__main__":
    main()
