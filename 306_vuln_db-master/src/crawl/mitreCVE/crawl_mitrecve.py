import fnmatch
import os
import subprocess
import time

import pymongo
from pymongo import MongoClient

from src.crawl.dataProce import jsonToList, queryrepeat, fieldToValue, init_item, getDeepin, isInDeepin
from src.crawl.Setting import *
class MITRECVE(object):
    def __init__(self, vulnName, collection, key, system):
        self.vulnName = vulnName
        self.collection = collection
        self.system = system
        self.key = key
        self.path = f'{DATA_PATH}/{CURRENT_TIME}/{vulnName}'
        if not os.path.exists(self.path):
            os.makedirs(self.path)
        self.deepin2309, self.deepin2404 = getDeepin()
    def clone(self):
        url1 = 'https://foo:bar@hub.yzuu.cf/CVEProject/cvelistV5.git'
        url2 = 'https://foo:bar@github.com/CVEProject/cvelistV5.git'
        url3 = 'https://hub.yzuu.cf/github/CVEProject/cvelistV5.git'
        url4 = 'https://github.com/github/CVEProject/cvelistV5.git'
        e_count = 0
        for url in [url1, url2, url3, url4]:
            try:
                cmd = f"cd {self.path}" + f"&&git clone {url}"
                subprocess.check_output(cmd, shell=True, cwd=self.path)
                print(f'----------{self.vulnName} 下载完成----------')
                return 1
            except Exception as e:
                print(f"发生了异常：{e}")
                return 0


    def mitrecveToMongo(self):
        path = f'{self.path}/cvelistV5/cves'
        for root, dirnames, filenames in os.walk(path):
            for filename in fnmatch.filter(filenames, 'CVE*.json'):  # 判断文件是否是以CVE开头的 json 类型文件
                file_path = os.path.join(root, filename)  # 获取文件的完整路径
                # print(file_path)
                data = jsonToList(file_path)
                print(data)
                # 插入数据
                key1,key2 = self.key.split('.')
                # 查询是否有重复的 id
                query = {self.key: data[key1][key2]}
                existing_data = self.collection.find_one(query)

                if existing_data:
                    # 如果存在重复的 id，则更新该数据
                    self.collection.update_one(query, {'$set': data})
                    # print('Data updated:', insert_data_dict)
                    print("duplicate！")
                else:
                    # 如果不存在重复的 id，则插入新数据
                    self.collection.insert_one(data)
                    print('Data inserted:', data)
        # 查重
        queryrepeat(self.vulnName, self.collection, self.key)

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
            # print(doc)
            if 'cveMetadata' in doc.keys():
                data = doc['cveMetadata'] if doc['cveMetadata'] is not None else 'null'
                if data != 'null':
                    if 'cveId' in data.keys():
                        item['source_id'] = doc['cveMetadata']['cveId'] if doc['cveMetadata']['cveId'] is not None else 'null'
                    else:
                        item['source_id'] = 'null'
                    if 'datePublished' in data.keys():
                        item['date'] = doc['cveMetadata']['datePublished'] if doc['cveMetadata']['datePublished'] is not None else 'null'
                    else:
                        item['date'] = 'null'

                else:
                    item['date'] = 'null'
                    item['source_id'] = 'null'


            item['title'] = item['source_id']
            item['cve_id'] = item['source_id']
            if item['cve_id'] != 'null':
                item['software_version'] = isInDeepin(item['cve_id'], self.deepin2309, self.deepin2404)

            item['vul_id'] = f"010_{str(count).zfill(6)}"
            count += 1
            if 'containers' in doc.keys() and 'containers.cna' in doc.keys():
                items=fieldToValue(doc['containers']['cna'],'descriptions')
                description = fieldToValue(items[0],'value')
                item['details'] = description if description is not None else 'null'

                # 其他字段丢进related
            related_data = {key: doc[key] for key in doc if
                            key not in ['_id', "cveMetadata.cveId", "cveMetadata.dateUpdated", "cveMetadata.cveId", "cveMetadata.cveId",
                                        "containers.cna.descriptions"]}
            # 将所有字段转换为字符串类型
            related_data = {key: str(val) for key, val in related_data.items()}
            item['related'] = related_data
            # 数据预处理前存入的数据库以及做过去重，这里可以直接存进
            system.insert_one(item)
        print(f'----------{self.vulnName} 数据预处理完成----------')


    def run(self):
        # self.dataPreProc()

        notDownload = True
        while notDownload:
            isExist = self.clone()
            if isExist:
                notDownload = False
                self.mitrecveToMongo()
                self.dataPreProc()


if __name__ == '__main__':


    # 获取当前时间
    start_time = time.time()

    # 连接数据库，运行程序
    client = pymongo.MongoClient('localhost', port=27017)
    db = client['306Project']
    collection = db['mitrecve']
    # 每个源数据预处理后存入总数据表，总数据表名称
    system = db['system']

    obj = MITRECVE('mitrecve', collection, 'cveMetadata.cveId', system)
    obj.run()
    client.close()

    # 获取程序结束时间
    end_time = time.time()
    # 计算程序耗时
    duration = end_time - start_time
    # 打印程序耗时
    print(f"程序耗时：{duration} 秒")