import fnmatch
import os
import random
import re
import time

import pymongo
import requests
from fake_headers import Headers

from bs4 import BeautifulSoup as bs

from crawl.Setting import DATA_PATH, CURRENT_TIME
from src.crawl.dataProce import insert_mongo, jsonToList, queryrepeat, init_item


class openEuler(object):
    def __init__(self, vulnName, collection, key, system):
        self.vulnName = vulnName
        self.collection = collection
        self.system = system
        self.key = key
        self.path = f'{DATA_PATH}/{CURRENT_TIME}/{vulnName}'
        if not os.path.exists(self.path):
            os.makedirs(self.path)

        self.url = 'https://www.openkylin.top/patch'

        header = Headers(browser='chrome',
                         os='win',
                         headers=True).generate()
        self.headers = {
            'User-Agent': header['User-Agent']
        }

    def crawl(self):
        print(f'----------{self.vulnName} 开始爬取----------')
        for i in range(24, 81):
            url = self.url + f'/{i}-cn.html'
            self.getDetail(url)
        print(f'----------{self.vulnName} 爬取完成----------')

    def getDetail(self,url):
        r = requests.get(url, headers=self.headers)
        # print(r.status_code)
        if r.status_code == 200:
            soup = bs(r.content, 'lxml')
            span_text1 = '未找到描述'
            span_text2 = '未找到安全级别'
            span_text3 = '未找到影响版本'
            span_text4 = '未找到影响组件'
            span_text5 = '未找到状态'
            text1 = '未找到详细介绍'
            section1 = soup.find('section', class_='details-title')
            if section1 is not None:
                h1 = section1.find('h1', class_='m-t-10 m-b-5')
                h1 = h1.text.strip()
                print(h1)
                # title = h1
                if h1 == '123':
                    return 0
                else:
                    if h1.startswith('OKSA'):
                        title = h1
                    else:
                        title = re.compile(r'公告ID：（(.*?)）').search(h1)
                        if not title:
                            title = re.compile(r'公告ID（(.*?)）').search(h1)
                            if not title:
                                title = re.compile(r'Bulletin ID \(\s*(.*?)\s*\)').search(h1)
                        title = title.group(1)
                print("公告名称:", title)
                div_element1 = section1.find('div', class_='info')
                date = div_element1.text.strip()
                # print("公布时间:", date)
            section2 = soup.find('section', class_='download-paralist')
            if section2 is not None:
                dl_element1 = section2.find_all('dl', class_='dl-horizontal clearfix font-size-16')
                if dl_element1 is not None:
                    span_element1 = dl_element1[0].find('span', class_='p-x-10')
                    if span_element1 is not None:
                        span_text1 = span_element1.text
                        # print("描述:", span_text1)
                    span_element2 = dl_element1[1].find('span', class_='p-x-10')
                    if span_element2 is not None:
                        span_text2 = span_element2.text
                        # print("安全级别:", span_text2)
                    span_element3 = dl_element1[2].find('span', class_='p-x-10')
                    if span_element3 is not None:
                        span_text3 = span_element3.text
                        # print("影响版本:", span_text3)
                    span_element4 = dl_element1[3].find('span', class_='p-x-10')
                    if span_element4 is not None:
                        span_text4 = span_element4.text
                        # print("影响组件:", span_text4)
                    span_element5 = dl_element1[4].find('span', class_='p-x-10')
                    if span_element5 is not None:
                        span_text5 = span_element5.text
                        # print("状态:", span_text5)
            section3 = soup.find('section', class_='met-editor clearfix')
            if section3 is not None:
                text1 = section3.text
                # print("详细介绍:", text1)

            delay = random.uniform(0.25, 2.5)  # 生成一个介于0.25和2.5之间的随机小数
            time.sleep(delay)

            # 将漏洞信息插入MongoDB数据库
            vulnerability = {
                "Title": title,
                "Date": date,
                "Description": span_text1,
                "Severity": span_text2,
                "Affected Versions": span_text3,
                "Affected Plugins": span_text4,
                "Verified": span_text5,
                "Details": text1
            }
            print(vulnerability)
            insert_data = [vulnerability]
            insert_mongo(self.collection,insert_data,self.key)

    def dataPreProc(self):
        print(f'----------{self.vulnName} 开始数据预处理----------')
        collection = self.collection
        system = self.system
        # 先把总数据表中对应数据源所有数据删除
        query = {'source': self.vulnName}
        result = system.delete_many(query)
        count = 1
        for doc in collection.find():
            item = init_item(self.vulnName)
            item['source_id'] = doc.get('Title', 'null')
            item['date'] = doc.get('Date', 'null')
            item['details'] = doc.get('Details', 'null')
            item['title'] = doc.get('Description', 'null')
            item['vul_id'] = f"021_{str(count).zfill(6)}"
            count += 1
            item['cve_id'] = 'null'

            # 其他字段丢进related
            related_data = {key: doc[key] for key in doc if
                            key not in ['_id', "Title", "Date", "Details", "Description"]}
            # 将所有字段转换为字符串类型
            related_data = {key: str(val) for key, val in related_data.items()}
            item['related'] = related_data
            # 数据预处理前存入的数据库以及做过去重，这里可以直接存进
            system.insert_one(item)
        print(f'----------{self.vulnName} 数据预处理完成----------')

    def run(self):
        self.crawl()
        self.dataPreProc()


if __name__ == '__main__':


    # 获取当前时间
    start_time = time.time()

    # 连接数据库，运行程序
    client = pymongo.MongoClient('localhost', port=27017)
    db = client['306Project']
    collection = db['openKylin']
    # 每个源数据预处理后存入总数据表，总数据表名称
    system = db['system']

    obj = openEuler('openKylin', collection, 'Title',system)
    obj.run()
    client.close()

    # 获取程序结束时间
    end_time = time.time()
    # 计算程序耗时
    duration = end_time - start_time
    # 打印程序耗时
    print(f"程序耗时：{duration} 秒")
