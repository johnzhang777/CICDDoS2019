import numpy as np
import math
import os
import csv
from itertools import combinations
from collections import Counter, defaultdict
import pandas as pd
from typing import Dict, List

MAX_ELEMENTS = 3
CSV_PATH = "./Syn_benign.csv"
# RESULT_PATH = "./result_cicddos.csv"
# CSV_PATH = "./Syn_syn.csv"
WINDOW_SIZE = 400
ALPHA = 0.1
K = 5
TIME_BIN_SIZE = 1
ATTACK_RATIO_THRESHOLD = 0.5

# 全局变量
ema = None          # 熵值的指数加权均值
ema_squared = None # 熵值平方的指数加权均值
entropy_buffer = []  # 冷启动阶段的熵值缓存
prev_threshold = None
current_threshold = 0.5952
attack_count = 0



def calculate_entropy(packet_info, column_pair):
    try:
        total = len(packet_info)

        pair_counter = Counter()
        pair_to_indexes = defaultdict(list)

        if total == 0:
            return 0.0, [], ()

        # 单次遍历构建 pair_counter 和 pair_to_indexes
        for idx, data_item in enumerate(packet_info):
            if not isinstance(data_item, list):
                data_item = [data_item]

            pair = tuple(data_item[0][col] for col in column_pair)
            pair_counter[pair] += 1
            pair_to_indexes[pair].append(idx)
        
        if len(pair_counter) == 1:
            return 0.0, [], ()

        # 计算概率分布 + 熵
        entropy = 0.0
        for count in pair_counter.values():
            p = count / total
            entropy -= p * math.log2(p) if p > 0 else 0

        # if len(pair_counter) == 1:
        #     return 0.0, [packet_info[i] for i in pair_to_indexes[next(iter(pair_counter))][:MAX_ELEMENTS]], next(iter(pair_counter))

        # # 找出频率最高的 pair
        # most_common_pair, _ = pair_counter.most_common(1)[0]
        # impact_indexes = pair_to_indexes[most_common_pair]
        # impact_packets = [packet_info[i] for i in impact_indexes[:MAX_ELEMENTS]]

        normalized_entropy = entropy / math.log2(total)
        # return normalized_entropy, impact_packets, most_common_pair
        return normalized_entropy, [], ()

    except Exception as e:
        print(f"An error occurred in entropy calculation: {e}")
        return 0.0, [], ()

def calculate_entropies_for_all_pairs(packet_info, columns = ['packet_length', 'ttl', 'source_ip', 'destination_ip', 
               'protocol', 'source_port', 'destination_port', 'tcp_flags']):
    result = {}
    for column_pair in combinations(columns, 2):  # 遍历所有可能的列对组合
        entropy_values, _, _ = calculate_entropy(packet_info, column_pair)
        result[column_pair] = entropy_values
    return result

def cal_time_entropy(window, time_bin_size):
    """
    计算窗口内数据包到达时间间隔的熵值。
    
    参数：
      - window: 数据包列表，每个包包含 'Timestamp' 字段
      - time_bin_size: 时间间隔离散化的bin大小(秒), 用于减少浮点误差
      
    返回：
      - 时间间隔熵
    """
    if len(window) < 2:
        print("Insufficient data for calculating time entropy.")
        return 0.0
    # 计算连续包的时间差
    time_differences = [window[i]['Timestamp'] - window[i-1]['Timestamp'] for i in range(1, len(window))]
    # 离散化时间差（例如四舍五入到time_bin_size的倍数）
    binned_diffs = [round(td / time_bin_size) * time_bin_size for td in time_differences]
    binned_diffs = time_differences

    counts = Counter(binned_diffs)
    if len(counts) == 1:
        return 0.0
    total = len(binned_diffs)
    entropy = 0.0
    probabilities = [count / total for count in counts.values()]
    entropy = -sum(p * math.log2(p) for p in probabilities)
    normalized_entropy = entropy / math.log2(len(counts))
    
    return normalized_entropy

def update(entropy, pkts_per_sec=900):
    """
    输入当前窗口的熵值，返回动态阈值
    - entropy: 数值类型，表示最新窗口的熵值
    - 返回值: 当前阈值
    """
    # # 冷启动阶段：缓存数据，使用简单平均初始化EMA
    # if len(self.entropy_buffer) < self.warmup_steps:
    #     self.entropy_buffer.append(entropy)
        
    #     if len(self.entropy_buffer) == self.warmup_steps:
    #         # 计算初始均值和平方均值
    #         ema = np.mean(self.entropy_buffer)
    #         ema_squared = np.mean([x**2 for x in self.entropy_buffer])
    #     else:
    #         return None  # 冷启动期不返回阈值
    
    # 更新EMA和EMA²
    ema = ALPHA * entropy + (1 - ALPHA) * ema
    ema_squared = ALPHA * (entropy**2) + (1 - ALPHA) * ema_squared
    
    # 计算动态阈值
    variance = ema_squared - (ema ** 2)
    variance = max(variance, 0)  # 防止负方差
    std = np.sqrt(variance)
    threshold = max(ema - K * std, 0)
    if prev_threshold and (prev_threshold-threshold)/prev_threshold > 0.1:
        threshold = prev_threshold*0.9
    # if prev_threshold:
    #     if pkts_per_sec > 800:
    #         return prev_threshold if threshold < prev_threshold else threshold
    #     else:
    #         if (prev_threshold-threshold)/prev_threshold > 0.1:
    #             threshold = prev_threshold*0.9
            
    prev_threshold = threshold
    return threshold

def sliding_window_entropy(csv_path: str, column_pair, window_size: int =400):
    """
    流式处理CSV数据并计算滑动窗口熵值
    
    Args:
        csv_path: CSV文件路径
        window_size: 窗口大小（数据条数）
    """
    # 初始化滑动窗口
    window: List[Dict[str, any]] = []
    spatial_entropies = []
    temporal_entropies = []
    spatiotemporal_entropies = []

    global ema 
    global ema_squared
    global entropy_buffer
    global prev_threshold
    global current_threshold
    global attack_count
    
    # 逐行读取CSV（避免内存爆炸）
    for chunk in pd.read_csv(csv_path, chunksize=1):
        # 当前行转为字典并加入窗口
        row_dict = chunk.iloc[0].to_dict()
        window.append(row_dict)

        attack_count = attack_count + 1 if row_dict['Label'] == 1 else attack_count
        
        # 窗口满时计算熵值
        if len(window) == window_size:
            attack_ratio = attack_count / window_size
            true_label = 1 if attack_ratio >= ATTACK_RATIO_THRESHOLD else 0

            spatial_entropy, _, _ = calculate_entropy(window, column_pair)
            temporal_entropy = cal_time_entropy(window, TIME_BIN_SIZE)
            spatiotemporal_entropy = 0.5*spatial_entropy + 0.5*temporal_entropy

            spatial_entropy = round(spatial_entropy, 4)
            temporal_entropy = round(temporal_entropy, 4)
            spatiotemporal_entropy = round(spatiotemporal_entropy, 4)

            spatial_entropies.append(spatial_entropy)
            spatial_entropies.append(spatial_entropy)
            temporal_entropies.append(temporal_entropy)
            spatiotemporal_entropies.append(spatiotemporal_entropy)
            # print(spatial_entropy, temporal_entropy, spatiotemporal_entropy)
            
            
            # 清空窗口
            window.clear()
            attack_count = 0
    
    avg_spatial = np.mean(spatial_entropies) if spatial_entropies else 0
    avg_temporal = np.mean(temporal_entropies) if temporal_entropies else 0
    avg_spatiotemporal = np.mean(spatiotemporal_entropy) if spatiotemporal_entropy else 0

    return round(avg_spatial, 4), round(avg_temporal, 4), round(avg_spatiotemporal, 4)

# 使用示例
if __name__ == "__main__":
    df = pd.read_csv(CSV_PATH, nrows=0)
    print(CSV_PATH)
    columns = [
        'Source IP', 'Source Port', 'Destination IP', 'Destination Port',
        'Protocol', 'Flags', 'Length'
    ]
    for column_pair in combinations(columns, 2):  # 遍历所有可能的列对组合
        print(column_pair)
        avg_spatial, avg_temporal, avg_spatiotemporal = sliding_window_entropy(CSV_PATH, column_pair, WINDOW_SIZE)
        print(avg_spatial, avg_temporal, avg_spatiotemporal)
        # print("=================================")
    
    # column_pair = ('Source Port', 'Timestamp')
    # print(column_pair)
    # avg_spatial, avg_temporal, avg_spatiotemporal = sliding_window_entropy(CSV_PATH, column_pair, WINDOW_SIZE)
    # print("Average Entropy:")
    # print(avg_spatial, avg_temporal, avg_spatiotemporal)
    # print("=================================")
