import pandas as pd
import numpy as np

def balanced_sample_csv(input_file, output_file, label_1_samples=100000, random_seed=42):
    """
    对CSV文件进行平衡采样（下采样Label=1，保留全部Label=0）
    
    Args:
        input_file (str): 输入CSV文件路径
        output_file (str): 输出CSV文件路径
        label_1_samples (int): 要采样的Label=1数量（默认10万）
        random_seed (int): 随机种子（确保可复现）
    """
    # 1. 读取数据
    df = pd.read_csv(input_file)
    
    # 2. 分离两类数据
    label_0 = df[df['Label'] == 0]
    label_1 = df[df['Label'] == 1]
    
    # 3. 采样Label=1（如果数据量不足则取全部）
    n_samples = min(len(label_1), label_1_samples)
    label_1_sampled = label_1.sample(n=n_samples, random_state=random_seed)
    
    # 4. 合并结果
    result = pd.concat([label_0, label_1_sampled])
    
    # 5. 保存采样后数据
    result.to_csv(output_file, index=False)
    
    # 6. 打印统计信息
    print(f"采样完成！结果分布：")
    print(f"- Label=0: {len(label_0)} (全部保留)")
    print(f"- Label=1: {n_samples}/{len(label_1)} (采样后/原数据)")
    
    return result

# 使用示例
if __name__ == "__main__":
    balanced_sample_csv(
        input_file="Syn_extract.csv",
        output_file="Syn_sampled.csv",
        label_1_samples=100000
    )