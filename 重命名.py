import os

def rename_files_in_folder(folder_path):
    # 获取文件夹中的所有文件
    files = os.listdir(folder_path)
    # 过滤出文件而非文件夹
    files = [f for f in files if os.path.isfile(os.path.join(folder_path, f))]
    
    # 遍历所有文件，按顺序重命名
    for i, file in enumerate(files, start=1):
        # 获取文件扩展名
        file_extension = os.path.splitext(file)[1]
        # 创建新文件名
        new_name = f"{i}{file_extension}"
        # 获取完整的文件路径
        old_file_path = os.path.join(folder_path, file)
        new_file_path = os.path.join(folder_path, new_name)
        # 重命名文件
        os.rename(old_file_path, new_file_path)
        print(f"Renamed: {file} -> {new_name}")

# 输入你需要重命名的文件夹路径
folder_path = r"F:\\0研究生\\研究生\\课题\\数据包处理\\构图\\graphs-1"
rename_files_in_folder(folder_path)
