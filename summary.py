import pandas as pd

def analyze_csv(file_path):
    # 读取 CSV 文件
    try:
        df = pd.read_csv(file_path)
    except Exception as e:
        print(f"读取文件失败: {e}")
        return

    # 基本信息
    print("\n=== CSV 文件基本信息 ===")
    print(f"文件路径: {file_path}")
    print(f"总行数: {len(df)}")
    print(f"总列数: {len(df.columns)}")
    print(f"缺失值总数: {df.isnull().sum().sum()}")

    # 统计 Label 列的各类型数量
    label_counts = df[' Label'].value_counts()

    print("=== Label 类别分布 ===")
    print(label_counts)

    # 列名及数据类型
    print("\n=== 列名及数据类型 ===")
    for col in df.columns:
        dtype = str(df[col].dtype)
        unique_count = df[col].nunique()
        null_count = df[col].isnull().sum()
        print(f"列名: {col:<30} | 类型: {dtype:<10} | 唯一值数量: {unique_count:<5} | 缺失值数量: {null_count}")

    # 前 5 行数据预览
    preview_full_csv(df)

    # 保存列名和类型到字典（可选）
    column_info = {
        "columns": list(df.columns),
        "dtypes": {col: str(df[col].dtype) for col in df.columns}
    }
    return column_info

def preview_full_csv(df: pd.DataFrame):

    pd.set_option('display.max_columns', None)  # 显示所有列
    pd.set_option('display.width', 1000)        # 显示宽度
    pd.set_option('display.max_colwidth', 50)   # 单列最大宽度

    # 转置数据：列名变为行，前N行数据变为列
    transposed = df.head().T  # 转置操作
    transposed.columns = [f"Row_{i+1}" for i in range(len(transposed.columns))]  # 重命名列
    
    # 优化显示设置
    pd.set_option('display.max_rows', None)  # 显示所有行（无截断）
    pd.set_option('display.max_colwidth', 30)  # 控制值显示长度
    
    print("\n=== 转置视图（列名作为行）===")
    print(transposed)

# 使用示例
if __name__ == "__main__":
    file_path = "./Portmap.csv"  # 例如: "data.csv"
    analyze_csv(file_path)