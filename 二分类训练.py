import numpy as np
import pandas as pd
import re
import ast
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, classification_report
import xgboost as xgb
import matplotlib.pyplot as plt
import seaborn as sns

# -------------------- 数据预处理（保持原逻辑） --------------------
def parse_array(cell):
    """解析单元格内容为数组（保持原逻辑）"""
    try:
        if isinstance(cell, str):
            cleaned_cell = re.sub(r"Decimal$'([^']+)'$", r"\1", cell)
            parsed = ast.literal_eval(cleaned_cell)
            return [float(x) for x in parsed]
        elif isinstance(cell, (int, float)):
            return [float(cell)]
        elif isinstance(cell, (list, np.ndarray)):
            return [float(x) for x in cell]
        else:
            raise ValueError(f"无法解析的单元格类型: {type(cell)}, 内容: {cell}")
    except Exception as e:
        raise ValueError(f"解析失败: 单元格内容 = {cell}, 错误 = {e}")

# 读取训练数据
df = pd.read_csv('train_tor-2.csv', header=None)
df = df.drop(columns=0)
df.columns = range(df.shape[1])

# 特征处理
features = np.array([[parse_array(row[col]) for col in range(4)] for _, row in df.iterrows()])
n_samples, n_timesteps, n_features = features.shape
features_flatten = features.reshape(n_samples, -1)  # 展平为 (样本数, 4 * 9=36)

# 归一化
scaler = MinMaxScaler()
features_norm = scaler.fit_transform(features_flatten)

# 标签处理（XGBoost不需要one-hot编码）
targets = df[4].values
le = LabelEncoder()
y = le.fit_transform(targets)  # 直接使用整数编码标签

# 数据划分（XGBoost使用原始标签格式）
X_train, X_val, y_train, y_val = train_test_split(
    features_norm, y, 
    test_size=0.2, 
    stratify=y, 
    random_state=42
)
# -------------------- 模型构建 --------------------
# 计算类别权重
positive_count = np.sum(y == 1)
negative_count = np.sum(y == 0)
class_weights = negative_count / positive_count  # 平衡正负样本

model = xgb.XGBClassifier(
    objective='binary:logistic',  # 二分类目标函数
    learning_rate=0.1,
    max_depth=12,
    n_estimators=200,
    subsample=0.8,
    colsample_bytree=0.8,
    scale_pos_weight=class_weights,  # 正类权重
    eval_metric='logloss',           # 评估指标
    early_stopping_rounds=50,
    random_state=42
)
# 训练模型（使用验证集监控）
model.fit(
    X_train, y_train,
    eval_set=[(X_val, y_val)],
    verbose=True
)

model.save_model('new_model.model')

# -------------------- 模型评估 --------------------
# 验证集预测
y_pred = model.predict(X_val)

# 混淆矩阵
cm = confusion_matrix(y_val, y_pred)

print(cm)
# 分类报告
print("\nClassification Report:")
print(classification_report(
    y_val, y_pred,
    target_names=le.classes_.astype(str),
    digits=4
))

# # -------------------- 测试集预测 --------------------
# # 读取测试数据
# df_test = pd.read_csv('F:\\0研究生\\研究生\\课题\\数据包处理\\online.csv', header=None)

# # 特征处理（与训练集相同流程）
# test_features = np.array([[parse_array(row[col]) for col in range(4)] for _, row in df_test.iterrows()])
# test_features_flatten = test_features.reshape(test_features.shape[0], -1)
# test_features_norm = scaler.transform(test_features_flatten)

# # 预测
# test_pred = model.predict(test_features_norm)
# test_pred_labels = le.inverse_transform(test_pred)

# # 保存结果
# df_test['Predicted_Label'] = test_pred_labels
# df_test.to_csv('pre_xgboost.csv', index=False)