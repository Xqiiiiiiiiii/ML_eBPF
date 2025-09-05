# data_preprocessing_clean.py

import pandas as pd
import numpy as np
import os

# 数据目录
ebpf_dir = '../ebpf'
output_dir = '../data'
os.makedirs(ebpf_dir, exist_ok=True)
os.makedirs(output_dir, exist_ok=True)

# ---------- 1. 读取 execve 日志 ----------
execve_file = os.path.join(ebpf_dir, 'execve_events.log')
if os.path.exists(execve_file):
    execve_df = pd.read_csv(execve_file, header=None,
                            names=['timestamp', 'pid', 'uid', 'comm', 'filename'])
    execve_df['event'] = 'execve'
else:
    execve_df = pd.DataFrame(columns=['timestamp', 'pid', 'uid', 'comm', 'filename', 'event'])

# ---------- 2. 读取 openat 日志 ----------
openat_file = os.path.join(ebpf_dir, 'openat_events.log')
if os.path.exists(openat_file):
    openat_df = pd.read_csv(openat_file, header=None,
                            names=['timestamp', 'pid', 'uid', 'comm', 'filename', 'flags'])
    openat_df['event'] = 'openat'
else:
    openat_df = pd.DataFrame(columns=['timestamp', 'pid', 'uid', 'comm', 'filename', 'flags', 'event'])

# ---------- 3. 合并事件 ----------
data = pd.concat([execve_df, openat_df], ignore_index=True, sort=False)

# ---------- 4. 时间戳处理 ----------
if not data.empty:
    data['timestamp'] = pd.to_datetime(data['timestamp'], unit='s')

# ---------- 5. 特征工程 ----------
# 按进程统计每种事件数量
event_counts = data.groupby(['pid', 'event']).size().unstack(fill_value=0).reset_index()

# ---------- 6. 添加标签 ----------
# 示例：随机生成标签 0=Normal, 1=Malicious
np.random.seed(42)
event_counts['label'] = np.random.choice([0, 1], size=len(event_counts))

# ---------- 7. 保存预处理数据 ----------
output_file = os.path.join(output_dir, 'preprocessed_data.csv')
event_counts.to_csv(output_file, index=False)

print(f"[INFO] Preprocessed data saved to {output_file}")
