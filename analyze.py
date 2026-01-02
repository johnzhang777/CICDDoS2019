import pandas as pd
import matplotlib.pyplot as plt

def analyze_label_distribution(csv_path):
    # 读取数据
    df = pd.read_csv(csv_path)
    
    # 标记变化点
    df['Label_change'] = df['Label'].diff().ne(0).cumsum()
    
    # 提取Label=0的连续区间
    label_0_blocks = df[df['Label'] == 0].groupby('Label_change').agg(
        start_index=('Label_change', 'first'),
        end_index=('Label_change', 'last'),
        length=('Label_change', 'count')
    ).reset_index(drop=True)
    
    # 可视化
    plt.figure(figsize=(12, 3))
    plt.scatter(df.index, df['Label'], s=1, c=df['Label'], cmap='bwr')
    plt.title("Label Distribution(RED=0, BLUE=1)")
    plt.savefig("./label_distribution.png")
    
    # 打印统计结果
    print("Label=0连续区间:")
    print(label_0_blocks)
    print("\n统计指标:")
    print(f"总出现次数: {len(label_0_blocks)}")
    print(f"最大连续长度: {label_0_blocks['length'].max()}")
    print(f"平均连续长度: {label_0_blocks['length'].mean():.1f}")

# 使用示例
analyze_label_distribution('Syn_extract.csv')