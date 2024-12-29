import fnmatch
import json
import os
import time

import pymongo
import requests
from fake_headers import Headers

from crawl.Setting import DATA_PATH, CURRENT_TIME
from src.crawl.dataProce import insert_mongo, jsonToList, queryrepeat, init_item, getDeepin, isInDeepin


class openEuler(object):
    def __init__(self, vulnName, collection, key, system):
        self.vulnName = vulnName
        self.collection = collection
        self.system = system
        self.key = key
        self.path = f'{DATA_PATH}/{CURRENT_TIME}/{vulnName}'
        if not os.path.exists(self.path):
            os.makedirs(self.path)

        self.url = 'https://www.openeuler.org/api-euler/api-cve/cve-security-notice-server/securitynotice/findAll'
        self.detail_url = "https://www.openeuler.org/api-euler/api-cve/cve-security-notice-server/securitynotice/getBySecurityNoticeNo?securityNoticeNo="

        header = Headers(browser='chrome',
                         os='win',
                         headers=True).generate()
        self.headers = {
            'User-Agent': header['User-Agent']
        }

        self.totalCount = self.getTotal()
        self.idLists = []
        self.detailaList = []
        self.deepin2309, self.deepin2404 = getDeepin()

    def getTotal(self):
        data = {"pages": {"page": 1, "size": 100}, "keyword": "", "type": [], "date": [],
                "affectedProduct": [], "affectedComponent": "", "noticeType": "cve"}
        # 发送 POST 请求，并获取响应
        response = requests.post(url=self.url, json=data, headers=self.headers)
        res = json.loads(response.text)
        totalCount = res['result']['totalCount']
        return totalCount

    def getIDS(self):
        print('----------openEuler 开始爬取----------')
        for i in range(1, int(self.totalCount / 100) + 2):
            data = {"pages": {"page": i, "size": 100}, "keyword": "", "type": [], "date": [],
                    "affectedProduct": [], "affectedComponent": "", "noticeType": "cve"}
            # 发送 POST 请求，并获取响应
            response = requests.post(url=self.url, json=data, headers=self.headers)
            res = json.loads(response.text)
            securityNos = res['result']['securityNoticeList']
            for sn in securityNos:
                self.idLists.append(sn['securityNoticeNo'])
            time.sleep(0.25)

    def getDetail(self):
        i = 0
        for id in self.idLists:
            i += 1
            print(id)
            response = requests.get(url=f"{self.detail_url}{id}", headers=self.headers)
            res = json.loads(response.text)
            # print(res)
            self.detailaList.append(res['result'])
            if i % 10 == 0 or i == self.totalCount:
                with open(f"{self.path}/data{int(i / 10)}.json", 'w') as f:
                    json.dump(self.detailaList, f, indent=4)
                    f.close()
                self.detailaList = []
            time.sleep(0.1)

    def SaveFile(self, data):
        with open(f"{self.path}/data{self.i}.json", 'w') as f:
            f.write(data)
            f.close()
        print('----------openEuler 爬取完成，存入文件----------')

    def insertToMongo(self):
        print('----------openEuler 开始存入数据库----------')
        for root, dirnames, filenames in os.walk(self.path):
            for filename in fnmatch.filter(filenames, '*.json'):
                filepath = os.path.join(root, filename)  # 获取文件的完整路径
                print(filepath)
                data = jsonToList(filepath)
                insert_mongo(self.collection, data, self.key)
        # 查重
        queryrepeat(self.vulnName, self.collection, self.key)
        print('----------openEuler 存入数据库完成----------')

    def dataPreProc(self):
        print('----------openEuler 开始数据预处理----------')
        collection = self.collection
        system = self.system
        # 先把总数据表中对应数据源所有数据删除
        query = {'source': self.vulnName}
        result = system.delete_many(query)
        count = 1
        for doc in collection.find():
            item = init_item(self.vulnName)
            item['source_id'] = doc.get('securityNoticeNo', 'null')
            item['date'] = doc.get('announcementTime', 'null')
            item['details'] = doc.get('description', 'null')
            item['title'] = doc.get('summary', 'null')
            item['vul_id'] = f"012_{str(count).zfill(6)}"
            count += 1
            #处理多个cveid字符串，取第一个
            cve_list = doc.get('cveId', 'null')
            if cve_list != 'null':
                item['cve_id'] = cve_list.split(';')[0]

            if item['cve_id'] != 'null':
                item['software_version'] = isInDeepin(item['cve_id'], self.deepin2309, self.deepin2404)

            # 其他字段丢进related
            related_data = {key: doc[key] for key in doc if
                            key not in ['_id', "securityNoticeNo", "announcementTime", "description", "summary",
                                        "cveId"]}
            # 将所有字段转换为字符串类型
            related_data = {key: str(val) for key, val in related_data.items()}
            item['related'] = related_data
            # 数据预处理前存入的数据库以及做过去重，这里可以直接存进
            system.insert_one(item)
        print(f'----------{self.vulnName} 数据预处理完成----------')

    def run(self):
        self.getIDS()
        print(len(self.idLists))
        self.getDetail()
        self.insertToMongo()
        self.dataPreProc()


if __name__ == '__main__':


    # 获取当前时间
    start_time = time.time()

    # 连接数据库，运行程序
    client = pymongo.MongoClient('localhost', port=27017)
    db = client['306Project']
    collection = db['openEuler']
    # 每个源数据预处理后存入总数据表，总数据表名称
    system = db['system']

    obj = openEuler('openEuler', collection, 'securityNoticeNo',system)
    obj.run()
    client.close()

    # 获取程序结束时间
    end_time = time.time()
    # 计算程序耗时
    duration = end_time - start_time
    # 打印程序耗时
    print(f"程序耗时：{duration} 秒")
