import json
import os
import random
import time

import requests
from bs4 import BeautifulSoup
from lxml import etree
from pymongo import MongoClient

from crawl.Setting import DATA_PATH, CURRENT_TIME
from crawl.dataProce import insert_mongo, init_item


class FFmpeg(object):
    def __init__(self, vulnName, collection, key, system):
        self.vulnName = vulnName
        self.collection = collection
        self.system = system
        self.key = key
        self.path = f'{DATA_PATH}/{CURRENT_TIME}/{vulnName}'
        print(self.path)
        if not os.path.exists(self.path):
            os.makedirs(self.path)

        self.start_url = 'https://trac.ffmpeg.org/'
        self.page = 31


    def crawlAndStorage(self):
        print(f'----------{self.vulnName} 开始爬取----------')
        url = self.start_url+'query?page={}'
        for i in range(1, self.page):
            print(f'---------第{i}页---------')
            res = requests.get(url=url.format(i))
            # print(res.text)
            if res.status_code == 200:
                soup = BeautifulSoup(res.text, 'html.parser')
                tree = etree.HTML(str(soup))
                process_list = tree.xpath("//td[@class='summary']/a")
                for process in process_list:
                    p = process.xpath("./@href")
                    detail_url = 'https://trac.ffmpeg.org' + p[0]
                    print(detail_url)
                    self.getDetail(detail_url)
                    random_time = random.uniform(0.2, 2)
                    time.sleep(random_time)

    def getValue(self,response,key):
        try:
            res = response.xpath(key)
            if not res:
                return ['null']
            return res
        except Exception as e:
            return ['null']

    def getDetail(self, detail_url):
        res = requests.get(url=detail_url)
        # print(res.text)
        if res.status_code == 200:
            soup = BeautifulSoup(res.text, 'html.parser')
            response = etree.HTML(str(soup))
            try:
                detail_summary = self.getValue(response,"//span[@class='summary']/text()")[0]

                detail_status = self.getValue(response,"//span[@class='trac-status']/a/text()")[0]
                detail_type = self.getValue(response,"//span[@class='trac-type']/a/text()")[0]

                h_reporter = self.getValue(response,"//a[@class='trac-author']/text()")[0]
                h_owner = self.getValue(response,"//td[@headers='h_owner']/a/text()")[0]
                h_priority = self.getValue(response,"//td[@headers='h_priority']/a/text()")[0]
                h_component = self.getValue(response,"//td[@headers='h_component']/a/text()")[0]
                h_vesion = self.getValue(response,"//td[@headers='h_version']/a/text()")[0]


                h_keywords = ''
                keywords_list = self.getValue(response,"//td[@headers='h_keywords']/a")
                if keywords_list != ['null']:
                    for list in keywords_list:
                        t = self.getValue(list,"./text()")[0]
                        h_keywords = h_keywords + str(t) + ' '


                h_reproduced = self.getValue(response,"//td[@headers='h_reproduced']/a/text()")[0]
                h_analyzed = self.getValue(response,"//td[@headers='h_analyzed']/a/text()")[0]


                h_cc = ''
                cc_list = self.getValue(response,"//td[@headers='h_cc']/a")
                if cc_list != ['null']:
                    for list in cc_list:
                        t = list.xpath("./text()")[0]
                        h_cc = h_cc + str(t) + ' '

                h_blockedby = self.getValue(response,"//td[@headers='h_blockedby']/a/text()")[0]
                h_blocking = self.getValue(response,"//td[@headers='h_blocking']/a/text()")[0]

                description_list = self.getValue(response,"//div[@class='searchable']//text()")
                detail_description = ''
                if description_list != ['null']:
                    for list in description_list:
                        if list.strip() == "":
                            pass
                        else:
                            detail_description = detail_description + str(list) + " "

                changelog_list = self.getValue(response,"//div[@id='changelog']//text()")
                detail_changelog = ''
                if changelog_list != ['null']:
                    for list in changelog_list:
                        if list.strip() == "":
                            pass
                        else:
                            detail_changelog = detail_changelog + str(list) + " "
            except Exception as e:
                print(e)

            item = {}
            item['title'] = str(detail_summary)
            item['status'] = str(detail_status)
            item['type'] = str(detail_type)
            item['reporter'] = str(h_reporter)
            item['owner'] = str(h_owner)
            item['priority'] = str(h_priority)
            item['component'] = str(h_component)
            item['vesion'] = str(h_vesion)
            item['keywords'] = str(h_keywords)
            item['missing'] = str(h_cc)
            item['blockedby'] = str(h_blockedby)
            item['blocking'] = str(h_blocking)
            item['Isreproduced'] = str(h_reproduced)
            item['Isanalyzed'] = str(h_analyzed)
            item['description'] = str(detail_description)
            item['changelog'] = str(detail_changelog)
            # print(item)

            insert_data = [item]
            insert_mongo(self.collection, insert_data, self.key)
            with open(os.path.join(self.path,"data.json"), 'a', encoding='utf=8') as f:
                f.write(str(item))
                f.write(',\n')
                f.close()

    def dataPreProc(self):
        print('----------ffmpeg 开始数据预处理----------')
        collection = self.collection
        system = self.system
        count = 1
        query = {'source': self.vulnName}
        result = system.delete_many(query)
        for doc in collection.find():
            item = init_item(self.vulnName)
            item['author'] = doc['reporter'] if doc['reporter'] is not None else 'null'
            item['details'] = doc['description'] if doc['description'] is not None else 'null'
            item['title'] = doc['title'] if doc['title'] is not None else 'null'
            item['type'] = doc['type'] if doc['type'] is not None else 'null'
            item['vul_id'] = f"014_{str(count).zfill(6)}"
            item['cve_id'] = 'null'
            item['software_version'] ='null'
            count += 1
            related_data = {key: doc[key] for key in doc if
                            key not in ['_id', "reporter", "description", "title", "type"]}
            related_data = {key: str(val) for key, val in related_data.items()}
            item['related'] = related_data
            system.insert_one(item)
        print('----------ffmpeg 数据预处理完成----------')

    def run(self):
        self.crawlAndStorage()
        self.dataPreProc()


if __name__ == '__main__':
    # 获取当前时间
    start_time = time.time()
    # 连接 MongoDB 数据库
    client = MongoClient('localhost', 27017)
    # 获取指定数据库和集合
    db = client['306Project']
    collection = db['ffmpeg']

    system = db['system']
    agent = FFmpeg('ffmpeg', collection, 'title', system)

    agent.run()

    client.close()
    # 获取程序结束时间
    end_time = time.time()
    # 计算程序耗时
    duration = end_time - start_time
    # 打印程序耗时
    print(f"程序耗时：{duration} 秒")
