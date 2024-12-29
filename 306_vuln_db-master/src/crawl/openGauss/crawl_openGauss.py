import json
import os
import random
import time
import pymongo
import requests
from fake_headers import Headers
from src.crawl.Setting import DATA_PATH, CURRENT_TIME
from src.crawl.dataProce import insert_mongo, init_item, getDeepin, isInDeepin


class openGauss(object):
    def __init__(self, vulnName, collection, key,system):
        self.vulnName = vulnName
        self.collection = collection
        self.system = system
        self.key = key
        self.path = f'{DATA_PATH}/{CURRENT_TIME}/{vulnName}'
        if not os.path.exists(self.path):
            os.makedirs(self.path)

        self.url = "https://opengauss.org/api-cve/v1/gauss/sa"
        header = Headers(browser='chrome',
                         os='win',
                         headers=True).generate()
        self.headers = {
            'User-Agent': header['User-Agent'],
            'Host': 'opengauss.org',
            'cookie': "HWWAFSESID=4eecb763af3286c2d6; HWWAFSESTIME=1713232623934; sensorsdata2015jssdkcross=%7B%22distinct_id%22%3A%2218ee49f44ebc37-0299ab94671a326-4c657b58-3686400-18ee49f44ec1243%22%2C%22first_id%22%3A%22%22%2C%22props%22%3A%7B%22%24latest_traffic_source_type%22%3A%22%E7%9B%B4%E6%8E%A5%E6%B5%81%E9%87%8F%22%2C%22%24latest_search_keyword%22%3A%22%E6%9C%AA%E5%8F%96%E5%88%B0%E5%80%BC_%E7%9B%B4%E6%8E%A5%E6%89%93%E5%BC%80%22%2C%22%24latest_referrer%22%3A%22%22%7D%2C%22identities%22%3A%22eyIkaWRlbnRpdHlfY29va2llX2lkIjoiMThlZTQ5ZjQ0ZWJjMzctMDI5OWFiOTQ2NzFhMzI2LTRjNjU3YjU4LTM2ODY0MDAtMThlZTQ5ZjQ0ZWMxMjQzIn0%3D%22%2C%22history_login_id%22%3A%7B%22name%22%3A%22%22%2C%22value%22%3A%22%22%7D%2C%22%24device_id%22%3A%2218ee49f44ebc37-0299ab94671a326-4c657b58-3686400-18ee49f44ec1243%22%7D; agreed-cookiepolicy=120240314; Hm_lvt_ace49cc6c2f3d0542e97ce86732094dc=1713232696; Hm_lpvt_ace49cc6c2f3d0542e97ce86732094dc=1713426198"
        }
        self.ids = []
        self.page = 3

        self.deepin2309, self.deepin2404 = getDeepin()


    def crawl(self):

        for i in range(1, self.page+1):
            url = self.url + f"?pageNum={i}&pageSize=10&searchName=&years=0&cveLevel=0&releaseFlag=2"
            response = requests.get(url=url, headers=self.headers)
            res = json.loads(response.text)
            datas = res['body']
            self.page = res['totalPage']
            for data in datas:
                detail_url = self.url + f"/detail?gaussSaNum={data['gaussSaNum']}"
                # detail_url = "https://opengauss.org/api-cve/v1/gauss/sa/detail?gaussSaNum=openGauss-SA-2024-1011"
                print(detail_url)
                isConnect = False
                while not isConnect:
                    result = requests.get(url=detail_url, headers=self.headers)
                    if result.status_code == 200:
                        isConnect = True
                print(f'result.text:{type(result.text)}')
                res = json.loads(result.text)
                insert = [res['body']]
                insert_mongo(self.collection,insert,self.key)

                da = str(res['body'])
                print(f'da:{type(da)}')
                # print(da)
                with open(f'{self.path}/data.json','a') as f:
                    f.write(da+'\n')
                    f.close()
                random_time = random.uniform(0.2, 2)
                time.sleep(random_time)
    def dataPreProc(self):
        print('----------openGauss 开始数据预处理----------')
        collection = self.collection
        system = self.system
        query = {'source': self.vulnName}
        result = system.delete_many(query)
        # print(f"删除了 {result.deleted_count} 条数据。")
        count = 1
        for doc in collection.find():
            item = init_item(self.vulnName)
            item['cve_id'] = doc['cveNumbers'] if doc['cveNumbers'] is not None else 'null'
            if item['cve_id'] != 'null':
                item['software_version'] = isInDeepin(item['cve_id'], self.deepin2309, self.deepin2404)

            item['date'] = doc['releaseDate'] if doc['releaseDate'] is not None else 'null'
            item['details'] = doc['description'] if doc['description'] is not None else 'null'
            item['title'] = doc['gaussSaNum'] if doc['gaussSaNum'] is not None else 'null'
            item['vul_id'] = f"013_{str(count).zfill(6)}"
            count += 1
            related_data = {key: doc[key] for key in doc if
                            key not in ['_id',"cveNumbers", "releaseDate", "description", "gaussSaNum"]}
            # 将所有字段转换为字符串类型
            related_data = {key: str(val) for key, val in related_data.items()}
            item['related'] = related_data
            # 数据预处理前存入的数据库以及做过去重，这里可以直接存进
            system.insert_one(item)
        print('----------openGauss 数据预处理完成----------')

    def run(self):
        self.crawl()
        self.dataPreProc()

if __name__ == '__main__':
    start_time = time.time()
    myclient = pymongo.MongoClient('localhost', port=27017)
    db = myclient['306Project']
    collection = db['openGauss']
    system = db['system']
    obj = openGauss('openGauss', collection, 'gaussSaNum',system)
    obj.run()
    end_time = time.time()
    # 计算程序耗时
    duration = end_time - start_time
    # 打印程序耗时
    print(f"程序耗时：{duration} 秒")
