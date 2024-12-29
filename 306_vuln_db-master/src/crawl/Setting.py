import os
import sys
from datetime import datetime

# 获取当前脚本的目录
current_path = os.path.dirname(sys.argv[0])
src_index = current_path.find("src") + 3  # 获取/src的位置并加上/src的长度4
PRO_PATH = current_path[:src_index]

now = datetime.now()
CURRENT_TIME = now.strftime("%Y%m")
# print(CURRENT_TIME)
CURRENT_TIME = '202407'

DATA_PATH = f'{PRO_PATH}/data'
LOG_PATH = f'{PRO_PATH}/log'




