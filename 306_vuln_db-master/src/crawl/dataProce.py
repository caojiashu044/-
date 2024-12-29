import json
import re
import pymongo
from pymongo import MongoClient
import xmltodict
import fnmatch
from Setting import *

CNNVD_data = []
def saveFile(filepath,data):
    with open(filepath, 'w', encoding='utf=8') as f:
        f.write(data)
        f.close()
def jsonToList(jsonPath):
    # 读取 JSON 文件
    with open(jsonPath, 'r',encoding='utf-8') as f:
        data = json.load(f)
    return data

def find(key,line):
    match = re.search(f'<{key}>(.*?)</{key}>', line)
    if match:
        res = match.group(1)
    else:
        res = ''
    return res
def CNNVD_xmlTojson(path):
    # 遍历指定目录
    for root, dirnames, filenames in os.walk(path):
        for filename in fnmatch.filter(filenames, '*.xml'):  # 判断文件是否是 xml 类型文件
            file_path = os.path.join(root, filename)  # 获取文件的完整路径
            count1 = 0
            count2 = 0
            with open(file_path, 'r', encoding='utf-8') as f:
                line = f.readline()
                while line:
                    if '<entry>' in line:
                        vuln_dict = {}
                        count1 += 1
                        line = f.readline()
                        while '</entry>' not in line:
                            if '<name>' in line:
                                vuln_dict['vuln_name'] = find('name', line)
                            elif '<vuln-id>' in line:
                                vuln_dict['vuln_id'] = find('vuln-id', line)
                            elif '<published>' in line:
                                vuln_dict['published'] = find('published', line)
                            elif '<modified>' in line:
                                vuln_dict['modified'] = find('modified', line)
                            elif '<source>' in line:
                                vuln_dict['source'] = find('source', line)
                            elif '<severity>' in line:
                                vuln_dict['severity'] = find('severity', line)
                            elif '<vuln-type>' in line:
                                vuln_dict['vuln_type'] = find('vuln-type', line)
                            elif '<vuln-descript>' in line:
                                vuln_dict['vuln_descript'] = find('vuln-descript', line)
                            elif '<bugtraq-id>' in line:
                                vuln_dict['bugtraq_id'] = find('bugtraq-id', line)
                            elif '<cve-id>' in line:
                                vuln_dict['cve_id'] = find('cve-id', line)
                            elif '<vuln-solution>' in line:
                                vuln_dict['vuln_solution'] = find('vuln-solution', line)
                            line = f.readline()
                    elif '</entry>' in line:
                        count2 += 1
                        CNNVD_data.append(vuln_dict)
                        line = f.readline()
                        # break
                    else:
                        line = f.readline()
            print(f'{file_path}The number of <entry> tags is {count1} {count2}')
    print(f'data有{len(CNNVD_data)}')
    with open(f'{path}/data.json', 'w') as f:
        json.dump(CNNVD_data, f, indent=4)

'''
不能用xmlToList中的xmltodict（第三方包）解析cnnvd，cnnvd的数据存在格式错误，使用CNNVD_xmlTojson暴力解决
'''
def cnvd_xmlToList(path):
    Data = []

    # 遍历指定目录
    for root, dirnames, filenames in os.walk(path):
        # print(len(filenames))
        for filename in fnmatch.filter(filenames, '*.xml'):  # 判断文件是否是 xml 类型文件
            print(filename)
            file_path = os.path.join(root, filename)  # 获取文件的完整路径
            print(file_path)
            with open(file_path,'r',encoding='utf-8') as f:
                datas = xmltodict.parse(f.read())
                # print(data)
                if datas is not None and "vulnerabilitys" in datas:
                    data = datas['vulnerabilitys']
                    if data is not None and'vulnerability' in data:
                        print(len(data['vulnerability']))
                        for da in data['vulnerability']:
                            Data.append(da)
                    else:
                        continue
                else:
                    continue
    print(len(Data))
    return Data
def insert_mongo(collection,insert_data: list,key):

    collection.create_index(key, unique=True)
    for item in insert_data:
        try:
            collection.insert_one(item)
        except pymongo.errors.DuplicateKeyError as e:
            # 删除 _id 字段,insert_one会增加这个字段
            del item["_id"]
            collection.update_one({key: item[key]}, {'$set': item})
            # print(e)

def insert_mongo_many(colletion,insert_data: list,key):
    for data in insert_data:
        insert_mongo_one(colletion,data,key)
def insert_mongo_one(collection, insert_data_dict: dict,key):  # 这个性能更好
    """
    往mongodb中插入数据, _id为自增, 注意_id为数值类型
    :param table: 表名
    :param insert_data_dict: 插入的数据,例如{"name": "zhang"}
    """

    # 查询是否有重复的 id
    query = {key: insert_data_dict[key]}
    existing_data = collection.find_one(query)

    if existing_data:
        # 如果存在重复的 id，则更新该数据
        collection.update_one(query, {'$set': insert_data_dict})
        # print('Data updated:', insert_data_dict)
        # print("duplicate！")
    else:
        # 如果不存在重复的 id，则插入新数据
        collection.insert_one(insert_data_dict)
        # print('Data inserted:', insert_data_dict)

def queryrepeat(vulnName,col,key):
    '''
    通过漏洞id验证漏洞数据库中是否有重复数据
    :param vulnName:
    :param db:
    :param key:
    :return:
    '''

    # 查询某个字段重复
    pipeline = [
        # 将指定字段作为分组依据进行分组
        {"$group": {"_id": f"${key}", "count": {"$sum": 1}}},
        # 匹配重复次数大于1的分组结果
        {"$match": {"count": {"$gt": 1}}}
    ]
    # 执行查询操作并打印结果
    result = col.aggregate(pipeline)
    result_list = list(result)
    if not result_list:
        print(f"{vulnName}中无重复漏洞！")
        return True
    else:
        print(f"{vulnName}中有重复漏洞，如下：")
        for doc in result_list:
            print(doc)
        return False


def distinct(vulnName,col,key):
    # 查询重复文档的_id值，并去重
    result = col.aggregate([
        {"$group": {"_id": f"${key}", "ids": {"$addToSet": "$_id"}, "count": {"$sum": 1}}},
        {"$match": {"count": {"$gt": 1}}}
    ])
    ids_to_delete = []
    for doc in result:
        ids_to_delete.extend(doc['ids'][1:])

    # 删除重复文档
    if ids_to_delete:
        col.delete_many({"_id": {"$in": ids_to_delete}})

def getDeepin():
    # 连接 MongoDB 数据库
    client = MongoClient('localhost', 27017)
    # 获取指定数据库和集合
    db = client['306Project']
    col1 = db['deepin202309']
    col2 = db['deepin202404']

    deepin2309 = []
    for doc in col1.find():
        deepin2309.append(doc['cve_id'])
    deepin2404 = []
    for doc in col2.find():
        deepin2404.append(doc['cve_id'])
    return deepin2309,deepin2404

def isInDeepin(value,deepin2309,deepin2404):
    # value = ['CVE-2013-1739','CVE-2014-9497']
    res1 = False
    res2 = False
    if type(value) == list:
        for va in value:
            if va in deepin2309:
                res1 = True
            elif va in deepin2404:
                res2 = True
    elif type(value) == str:
        if value in deepin2309:
            res1 = True
        elif value in deepin2404:
            res2 = True
    if res1 and res2:
        return 'deepin_202309 and deepin_202404'
    elif res1:
        return 'deepin_202309'
    elif res2:
        return 'deepin_202404'
    else:
        return 'null'


def init_item(vul_name):
    item = {
        'vul_id': '',
        "author": '未知',
        "cve_id":'',
        "details": '',
        "date":'',
        "platform": '未知',
        "title":'',
        "source": vul_name,
        "source_id":'',
        "type":'未知',
        "related":'',
        "software_version":'null'
    }
    return item



def fieldToValue(doc,key):

    try:
        res = doc[key] if doc[key] is not None else 'null'
        # print(res)
    except Exception as e:
        res = 'null'
    return res
def getVulid():
    # 连接到MongoDB
    client = MongoClient('localhost', 27017)  # 请用实际的MongoDB连接信息替换

    # 选择数据库
    db = client['306Database']  # 请用实际的数据库名称替换

    # 获取数据库中的所有集合（数据表）
    collections = db.list_collection_names()
    total = 0
    # 遍历每个集合，并获取其中的文档数量
    for collection_name in collections:
        collection = db[collection_name]
        count = collection.count_documents({})
        # print(f"集合 {collection_name} 中的文档数量为: {count}")
        total += count
    # 关闭连接
    client.close()
    return total

def newDir():
    dir = f'{DATA_PATH}/{CURRENT_TIME}'
    if not os.path.exists(dir):
        os.makedirs(dir)
    vulnList = ['cnnvd','cnvd','nvd','mitrecve','redhat','debian','GHSA','osv','exploitDB']
    for vuln in vulnList:
        path = f'{dir}/{vuln}'
        if not os.path.exists(path):
            os.makedirs(path)

def savaToMongoDB():
    # newDir()
    # 连接 MongoDB 数据库
    client = MongoClient('localhost', 27017)
    # 获取指定数据库和集合
    db = client['306Project']

    # osvToMongo('osv',db)

    # 关闭 MongoDB 连接
    client.close()

if __name__ == '__main__':
    savaToMongoDB()
