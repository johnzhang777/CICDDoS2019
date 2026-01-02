import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

# 读取CSV文件
csv_path = "./result_cicddos.csv"
df = pd.read_csv(csv_path)

# 提取预测标签和真实标签
y_true = df['true_label']
y_pred = df['predicted_label']

# 计算基本指标
accuracy = accuracy_score(y_true, y_pred)
precision = precision_score(y_true, y_pred)
recall = recall_score(y_true, y_pred)
f1 = f1_score(y_true, y_pred)

# 计算混淆矩阵
cm = confusion_matrix(y_true, y_pred)
tn, fp, fn, tp = cm.ravel()

# 计算FPR (False Positive Rate)
fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

# 打印结果
print("=== Evaluation Metrics ===")
print(f"Accuracy:  {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall:    {recall:.4f}")
print(f"F1 Score:  {f1:.4f}")
print(f"FPR:       {fpr:.4f}")

# 打印混淆矩阵
print("\n=== Confusion Matrix ===")
print(cm)
print("\n[[TN  FP]")
print(" [FN  TP]]")