import json
import re
from pymongo import MongoClient

# 邮箱的正则表达式
email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')

# 用于存储找到的邮箱地址
emails = []

# 从文件中读取JSON数据
def load_json_from_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:  # 指定文件编码为utf-8
            return json.load(file)
    except FileNotFoundError:
        print("文件未找到，请检查文件路径。")
        return None
    except json.JSONDecodeError:
        print("文件不是有效的JSON格式。")
        return None
    except OSError as e:
        print(f"打开文件时发生错误：{e}")
        return None
    except UnicodeDecodeError:
        print("文件编码错误，请确保文件是utf-8编码。")
        return None

# 递归函数，用于查找和提取邮箱地址
def find_emails(data):
    if isinstance(data, dict):
        for key, value in data.items():
            find_emails(value)  # 递归查找字典中的值
    elif isinstance(data, list):
        for item in data:
            find_emails(item)  # 递归查找列表中的项
    elif isinstance(data, str):
        matches = email_pattern.findall(data)  # 正确使用data变量
        emails.extend(matches)

# 将邮箱地址存储到MongoDB
def store_emails_to_mongodb(emails):
    client = MongoClient('localhost', 27017)  # 连接到MongoDB，假设它运行在默认端口27017
    db = client['email_db']  # 选择数据库，如果不存在则自动创建
    collection = db['emails']  # 选择集合，如果不存在则自动创建
    collection.insert_many([{'email': email} for email in emails])  # 插入文档
    print(f"Stored {len(emails)} emails to MongoDB.")

# 主函数
def main():
    # 假设JSON文件名为data.json
    file_path = r"C:\Users\caoji\Desktop\edb.new.json"  # 使用原始字符串来避免转义字符的问题

    # 加载JSON数据
    data = load_json_from_file(file_path)

    if data is not None:
        # 查找邮箱地址
        find_emails(data)

        # 打印找到的邮箱地址
        print("Found emails:", emails)
        print(f"Total emails found: {len(emails)}")

        # 存储到MongoDB
        store_emails_to_mongodb(emails)

if __name__ == "__main__":
    main()