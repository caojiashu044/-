import os
import time
import requests
from lxml import etree
from lxml import html
import pymongo

from Setting import DATA_PATH, CURRENT_TIME
from dataProce import init_item, getDeepin, queryrepeat
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class exploit_flies(object):
    def __init__(self, vulnName, collection, key, system):
        self.vulnName = vulnName
        self.collection = collection
        self.system = system
        self.key = key
        self.path = f'{DATA_PATH}/{CURRENT_TIME}/{vulnName}'
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        self.urls = []
        self.hrefs = []

    # 找到目标url和目录下需要爬取的路径
    def get_urls(self):
        url = 'https://packetstormsecurity.com/files/tags/exploit/page'
        for page in range(1, 2182):  # 页码从1到2181，所以循环从1到2182
            # 构造每一页的URL
            self.urls.append(url + str(page))
        # print(self.urls)
        print(f'-----------------成功读取{len(self.urls)}个url-----------------')

    def get_content(self):
        temp_dic = {
            'id': None,
            'author': None,
            'address': None,
            'email': None,
        }
        index1 = 0
        index2 = 0
        index3 = 0
        max_retries = 5
        retries = 0
        cur_url = 'https://packetstormsecurity.com'
        for temp_url in self.urls:
            print(f'-----------------开始爬取第{index1 + 1}个url的person元素-----------------')
            while retries < max_retries:
                try:
                    responses = requests.get(url=temp_url, headers=self.headers, timeout=10, verify=False)
                    # 假设content是你从响应中获取的HTML内容
                    content1 = responses.text
                    # 使用etree解析HTML内容
                    a_etree = etree.HTML(content1)
                    # 获取所有的person元素的href属性
                    xpath_address = f'//*[contains(@class, "person")]/@href'
                    hrefs_address = a_etree.xpath(xpath_address)
                    # 获取所有的person元素的文本内容
                    xpath_name = f'//*[contains(@class, "person")]/text()'
                    hrefs_name = a_etree.xpath(xpath_name)
                    # 将href和名称组合成一个二维数组
                    combined = list(zip(hrefs_address, hrefs_name))
                    count_new_hrefs = 0
                    for data in combined:
                        # 检查href是否已经存在于self.hrefs中
                        if data not in self.hrefs:
                            self.hrefs.append(data)
                            count_new_hrefs += 1  # 增加计数器
                        # print(combined)
                    print(
                        f'-----------------成功插入第{index1 + 1}个url的{count_new_hrefs}个person元素-----------------')
                    break  # 如果请求成功，跳出循环
                except requests.exceptions.ConnectTimeout:
                    retries += 1
                    if retries < max_retries:
                        time.sleep(2 ** retries)  # 指数退避策略
                    else:
                        print("达到最大重试次数，放弃请求")
            index1 += 1
        for temp_href in self.hrefs:
            href = temp_href[0]
            url = cur_url + href
            while retries < max_retries:
                try:
                    responses = requests.get(url=url, headers=self.headers, verify=False)
                    if responses.status_code == 200:
                        # 假设content是你从响应中获取的HTML内容
                        content2 = responses.text
                        # 使用etree解析HTML内容
                        b_etree = etree.HTML(content2)
                        # 获取作者对应的地址
                        xpath1 = '//tr[1]/td//a/@href'
                        xpath2 = '//tr[1]/td//a/text()'
                        author_email = b_etree.xpath(xpath1)
                        author_address = b_etree.xpath(xpath2)
                        # 加入dic
                        temp_dic['email'] = author_email
                        temp_dic['author'] = temp_href[1]
                        temp_dic['address'] = author_address
                        temp_dic['id'] = index2 + 1
                        print(temp_dic)
                        index2 += 1
                        query = {'id': temp_dic['id']}
                        self.collection.update_one(query, {'$set': temp_dic}, upsert=True)
                        print(f'存储成功第{index2}条数据')
                        print(f'-----------------共计存储{index2}条数据-----------------')
                        break  # 如果请求成功，跳出循环
                except requests.exceptions.ConnectTimeout:
                    retries += 1
                    if retries < max_retries:
                        time.sleep(2 ** retries)  # 指数退避策略
                    else:
                        print("达到最大重试次数，放弃请求")
    print(f'-----------------成功插入所有url的person元素-----------------')

    def crawl(self):
        self.get_urls()
        self.get_content()

    def run(self):
        self.crawl()


if __name__ == '__main__':
    # 获取当前时间
    start_time = time.time()

    # 连接数据库，运行程序
    client = pymongo.MongoClient('localhost', port=27017)
    db = client['306Project']
    collection = db['exploit_flies']
    # 每个源数据预处理后存入总数据表，总数据表名称
    system = db['system']

    obj = exploit_flies('exploit_flies', collection, 'url', system)
    obj.run()
    client.close()

    # 获取程序结束时间
    end_time = time.time()
    # 计算程序耗时
    duration = end_time - start_time
    # 打印程序耗时
    print(f"程序耗时：{duration} 秒")
