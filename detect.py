import numpy as np
import math
import os
import csv
import secrets
from itertools import combinations
from collections import Counter, defaultdict
import pandas as pd
from typing import Dict, List

MAX_ELEMENTS = 3
CSV_PATH = "./Syn_extract.csv"
RESULT_PATH = "./result_cicddos.csv"
KEYPAIR = ('Protocol', 'Flags')
WINDOW_SIZE = 400
ALPHA = 0.1
BETA = 0.7
K = 5
TIME_BIN_SIZE = 1
ATTACK_RATIO_THRESHOLD = 0.25

# 全局变量
# ema = 0.631          # 熵值的指数加权均值
ema = 0.2896
ema_squared = ema**2 # 熵值平方的指数加权均值
entropy_buffer = []  # 冷启动阶段的熵值缓存
prev_threshold = None
current_threshold = ema*0.8
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

        # normalized_entropy = entropy / math.log2(len(pair_counter))
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
    global ema
    global ema_squared
    global prev_threshold
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

def sliding_window_entropy(csv_path: str, column_pair, window_size: int = 400):
    """
    优化版：无重叠窗口处理CSV数据并计算熵值
    Args:
        csv_path: CSV文件路径
        column_pair: 用于空间熵计算的字段组合
        window_size: 窗口大小（数据条数）
    Returns:
        三个熵的平均值（空间、时间、时空）
    """
    df = pd.read_csv(csv_path)
    num_rows = len(df)

    spatial_entropies = []
    temporal_entropies = []
    spatiotemporal_entropies = []

    results = []

    global ema 
    global ema_squared
    global entropy_buffer
    global current_threshold
    global attack_count


    for i in range(0, num_rows - window_size + 1, window_size):
        window_df = df.iloc[i:i+window_size]
        window_records = window_df.to_dict(orient='records')

        attack_count = (window_df['Label'] == 1).sum()
        attack_ratio = attack_count / window_size

        # 攻击比例过高，跳过98%的窗口
        if attack_ratio > ATTACK_RATIO_THRESHOLD and secrets.randbelow(100) < 98:
            continue

        true_label = 1 if attack_ratio >= ATTACK_RATIO_THRESHOLD else 0

        spatial_entropy, _, _ = calculate_entropy(window_records, column_pair)
        temporal_entropy = cal_time_entropy(window_records, TIME_BIN_SIZE)
        spatiotemporal_entropy = BETA * spatial_entropy + (1-BETA) * temporal_entropy

        spatial_entropy = round(spatial_entropy, 4)
        temporal_entropy = round(temporal_entropy, 4)
        spatiotemporal_entropy = round(spatiotemporal_entropy, 4)

        spatial_entropies.append(spatial_entropy)
        temporal_entropies.append(temporal_entropy)
        spatiotemporal_entropies.append(spatiotemporal_entropy)

        # 动态阈值更新与分类
        if spatiotemporal_entropy > current_threshold:
            current_threshold = update(spatiotemporal_entropy)
            predicted_label = 0  # 正常
        else:
            predicted_label = 1  # 攻击

        results.append([
            spatial_entropy, temporal_entropy, spatiotemporal_entropy,
            current_threshold, attack_ratio, predicted_label, true_label
        ])

        # print(f"{spatial_entropy}, {temporal_entropy}, {spatiotemporal_entropy}, {current_threshold}, {attack_ratio}, {predicted_label}, {true_label}")

    # 写入结果一次完成
    with open(RESULT_PATH, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['spatial_entropy', 'temporal_entropy', 'spatiotemporal_entropy',
                    'current_threshold', 'attack_ratio', 'predicted_label', 'true_label'])
        writer.writerows(results)

    # 平均值统计
    avg_spatial = np.mean(spatial_entropies) if spatial_entropies else 0
    avg_temporal = np.mean(temporal_entropies) if temporal_entropies else 0
    avg_spatiotemporal = np.mean(spatiotemporal_entropies) if spatiotemporal_entropies else 0

    return round(avg_spatial, 4), round(avg_temporal, 4), round(avg_spatiotemporal, 4)

# 使用示例
if __name__ == "__main__":
    
    if os.path.exists(RESULT_PATH):
        os.remove(RESULT_PATH)
    # 新增：写入CSV表头
    with open(RESULT_PATH, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            "Spatial_Entropy", "Temporal_Entropy", "Spatiotemporal_Entropy",
            "Current_Threshold", "Attack_Ratio", "Predicted_Label", "True_Label"
        ])

    df = pd.read_csv(CSV_PATH, nrows=0)
    print(CSV_PATH)
    columns = [col.strip() for col in df.columns.tolist()]
    # print(columns)
    for column_pair in combinations(columns, 2):  # 遍历所有可能的列对组合
        # print(column_pair)
        if column_pair != KEYPAIR:
            continue
        print(column_pair)
        avg_spatial, avg_temporal, avg_spatiotemporal = sliding_window_entropy(CSV_PATH, column_pair, WINDOW_SIZE)
        # print(avg_spatial, avg_temporal, avg_spatiotemporal)
        # print("=================================")
    
    # column_pair = ('Source Port', 'Timestamp')
    # print(column_pair)
    # avg_spatial, avg_temporal, avg_spatiotemporal = sliding_window_entropy(CSV_PATH, column_pair, WINDOW_SIZE)
    # print("Average Entropy:")
    # print(avg_spatial, avg_temporal, avg_spatiotemporal)
    # print("=================================")
