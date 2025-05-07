

# import numpy as np
# import pandas as pd
# import tensorflow as tf
# from tensorflow.keras.models import Sequential
# from tensorflow.keras.layers import Dense, Dropout, BatchNormalization, LeakyReLU
# from tensorflow.keras.optimizers import Adam
# from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
# from sklearn.preprocessing import LabelEncoder
# from sklearn.model_selection import train_test_split
# import re
# import ast
# # -------------------- 数据预处理（保持原逻辑） --------------------
# df = pd.read_csv('F:\\0研究生\\研究生\\课题\\数据包处理\\test.csv', header=None)
# df = df.drop(columns=0)
# df.columns = range(df.shape[1])
# def parse_array(cell):
#     """解析单元格内容为数组（保持原逻辑）"""
#     try:
#         if isinstance(cell, str):
#             cleaned_cell = re.sub(r"Decimal$'([^']+)'$", r"\1", cell)
#             parsed = ast.literal_eval(cleaned_cell)
#             return [float(x) for x in parsed]
#         elif isinstance(cell, (int, float)):
#             return [float(cell)]
#         elif isinstance(cell, (list, np.ndarray)):
#             return [float(x) for x in cell]
#         else:
#             raise ValueError(f"无法解析的单元格类型: {type(cell)}, 内容: {cell}")
#     except Exception as e:
#         raise ValueError(f"解析失败: 单元格内容 = {cell}, 错误 = {e}")


# # 提取特征数据并展平
# features = np.array([[parse_array(row[col]) for col in range(4)] for _, row in df.iterrows()])
# n_samples, n_timesteps, n_features = features.shape
# features_flatten = features.reshape(n_samples, -1)  # 展平为 (样本数, 4 * 9=36)


# from sklearn.preprocessing import MinMaxScaler
# scaler = MinMaxScaler()
# features_norm = scaler.fit_transform(features_flatten)


# for i in range(5):
#     fn=features_flatten[df[4]==i]
#     fn=np.array(fn)
#     center=np.mean(fn,axis=0)
#     print(center)

        

# print(fn)


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
df = pd.read_csv('train-video.csv', header=None)
df = df.drop(columns=0)
df = df.sample(frac=1, random_state=42).reset_index(drop=True)  # frac=1表示全部采样（即打乱）
df.columns = range(df.shape[1])

# 特征处理
features = np.array([[parse_array(row[col]) for col in range(4)] for _, row in df.iterrows()])
n_samples, n_timesteps, n_features = features.shape
features_flatten = features.reshape(n_samples, -1)  

# 归一化
scaler = MinMaxScaler()
features_norm = scaler.fit_transform(features_flatten)

# 标签处理（XGBoost不需要one-hot编码）
targets = df[4].values
le = LabelEncoder()
y = le.fit_transform(targets)  # 直接使用整数编码标签

# 数据划分（XGBoost使用原始标签格式）
X_train, X_val, y_train, y_val = train_test_split(
    features_flatten, y, 
    test_size=0.15, 
    stratify=y, 
    random_state=42
)

# -------------------- XGBoost模型构建 --------------------
# 计算类别权重（处理不平衡数据）
class_weights = len(y) / (len(le.classes_) * np.bincount(y))  # 自动计算权重

model = xgb.XGBClassifier(
    objective='multi:softprob',  # 多分类问题
    num_class=len(le.classes_),   # 类别数
    learning_rate=0.1,
    max_depth=10,
    n_estimators=500,
    subsample=0.8,
    colsample_bytree=0.8,
    scale_pos_weight=class_weights,  # 类别权重
    eval_metric='mlogloss',          # 多分类对数损失
    early_stopping_rounds=20,        # 早停轮数
    random_state=42
)

# 训练模型（使用验证集监控）
model.fit(
    X_train, y_train,
    eval_set=[(X_val, y_val)],
    verbose=True
)

# model.save_model('new_model.model')

# -------------------- 模型评估 --------------------
# 验证集预测
y_pred = model.predict(X_val)
importance_type = 'weight'  # 或 'gain'（分裂时的平均增益）、'cover'（样本覆盖量）
importance = model.get_booster().get_score(importance_type=importance_type)

# 按重要性排序并可视化
sorted_idx = model.feature_importances_.argsort()[::-1]
print(sorted_idx)
plt.barh(range(X_train.shape[1]), model.feature_importances_[sorted_idx])
plt.yticks(ticks=range(X_train.shape[1]),labels=sorted_idx)
plt.xlabel("Feature Importance")
plt.show()


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


# print(model.predict([[0.6100217864923747, 1.434782608695652, 0.007106057142857143, 1406.982608695652, -1104.1939393939394, 0.23093681917211328, 0.27233115468409586,0.8236151603498543, 1.4458874458874458, 0.007053111504424779, 605.9004329004329, -1329.9820359281437, 0.13411078717201166, 0.44314868804664725,0.8696969696969697, 1.4741379310344827, 0.00926835075493612, 249.18103448275863, -1509.7524366471735, 0.045454545454545456, 0.5222222222222223,0.8539576365663322, 1.528052805280528, 0.020856920365535245, 217.72607260726073, -1458.049676025918, 0.03567447045707915, 0.5128205128205128]]))

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