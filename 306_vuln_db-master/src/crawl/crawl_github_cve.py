import json
import random
import time
from multiprocessing.dummy import Pool
from random import uniform

import openpyxl
import requests
from bs4 import BeautifulSoup
from pymongo import MongoClient
import urllib.request

from dataProce import init_item


class github_cve(object):
    def __init__(self,vulnName,collection,system):
        # 创建一个空列表来存储URL
        self.url_list = []
        self.count = 0
        self.dic_list = []
        self.vulnName = vulnName
        self.collection = collection
        self.system = system
        return

    def get_url(self):
        # 指定Excel文件路径
        file_path = r"C:\Users\陈毅杰\Desktop\新建 Microsoft Excel 工作表.xlsx"
        # 打开Excel文件
        workbook = openpyxl.load_workbook(file_path)

        # 选择活动的工作表或者指定名称的工作表
        sheet = workbook.active

        row_count = 0
        # 遍历工作表中的每一行
        for row in sheet.iter_rows(min_row=2, values_only=True):  # 假设第一行是标题行，从第二行开始读取
            # 将第一列的值添加到列表中
            self.url_list.append(row[0])
            row_count += 1  # 增加行计数器

        # 关闭工作簿
        workbook.close()

    def getheaders(self):
        my_headers = [
            "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.153 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:30.0) Gecko/20100101 Firefox/30.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/537.75.14",
            "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Win64; x64; Trident/6.0)",
            'Mozilla/5.0 (Windows; U; Windows NT 5.1; it; rv:1.8.1.11) Gecko/20071127 Firefox/2.0.0.11',
            'Opera/9.25 (Windows NT 5.1; U; en)',
            'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)',
            'Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.5 (like Gecko) (Kubuntu)',
            'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.0.12) Gecko/20070731 Ubuntu/dapper-security Firefox/1.5.0.12',
            'Lynx/2.8.5rel.1 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/1.2.9',
            "Mozilla/5.0 (X11; Linux i686) AppleWebKit/535.7 (KHTML, like Gecko) Ubuntu/11.04 Chromium/16.0.912.77 Chrome/16.0.912.77 Safari/535.7",
            "Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:10.0) Gecko/20100101 Firefox/10.0 "

        ]
        headers = {
            'User-Agent': random.choice(my_headers),
            'Cookie': 'gitee-session-n=bEFPMkJ5cHhXNjl6cGhtbUZ3bmlZaGVnYS9jUlRKc0tKVVhWai84SUh4emdwRXk3SnlUZHE2VEtGS0lwcUlpRHo2anI3QnZUVzk3clU0dldmcEdvYXVZOExiYUU2dDRjMnEyYjdIQVJCbXQ0ckd5YWFwT3l1MExGNEFvVXhCc1F4NW9kczYreVNaVUVUZWtnaldYaVg2TjR4bWZSMkZLY28wa2FkeGJOMGk4SnNsQXlqZ25KRU5YWU9TUXl5NzRtQnhaZWNlV0FxcG10cUFMWGZYbFIzc2h1Y3FteFQvUmVaRjltdDgzMGdtY0F5ZVQzWkZIOUhERzFjNkN2bTdiUWQ2dk80WTQ0RnNtYWZYV2QrWGVtOU0xN1JVK3lzaVZ0WExuR1V2RXVPZ0N0Q1NraW92M3BZMjFrQjd3MXBuSGg3Tm1MN1hhNkhWbDZoSGlZc3JvTFZPVEo5M3U3NmZSaU0rMTZPZUQrcVppTjF5a3JzVEhRZEk3aXpmcnJvQXJZY3JaOTFOOTVjZ3J2YWs1ZVgxNHU2M2R1WStVTXNYMHNCRnRibWJjSnRCWkFUSFd0cXo1ZWZvTFNzaW5NUU5aNWNGeU41cW5BUUV3dXVFVzR3YmZMejNVb3VWbFA4a2Z0TFNOZlhEcWdxZzZiS0FxMjRzcWdBMFpaZkJEZ3VxN1hrclVPTGZTUDZCUzArOTdKNWduWm1VaFNmV2c3MVIzVGF3T3ZiOGIxRXhjMldXZENHTFlyT3FWdGw1bHFJUTBJTkdDRnBTZ1hrTVRMaUxYZ0d2WWlHNzNqNkpQNVpSYnBvVUN5QlpmeDAzc2xxUjgxbUFuN1MrQW9PeDRUNDBlSUtSRU5LdHBWTU1BZ01WR09lcy83WjZwam5qQlFkN2xHaDltNTFjRVJCOUNtcG1TRFBuWmFUR1hKRlg0Yzh2UThOdDUyQUJQT3JkT2l3QUVSb2oydjNCTnN6V2lOdXFNMXQwRUZySk9nRXBCbmZYNkNDaVYwYTNEYTlLeEZ1QjFYVEU0MUNwTFFQUTVjejExM3RCTXRvbUg0ZEVwb0JiNDFlaDJFdFFMYWRzTXpWV0FtSzR3UFExaFhVRnJxK0pjYS0tWWljMXdLbWcvUmhhSmVzRU0vc0Jwdz09--996a8472a80dd31eecc8a8566f2f4b3096859b76; domain=.gitee.com; path=/; HttpOnly'
        }

        return headers

    def get_page(self,url):


        time.sleep(random.uniform(1, 1.3))

        print(f'----------正在爬取第{self.count}/{len(self.url_list)}个url----------')
        self.count += 1

        start_time = time.time()
        while True:
            end_time = time.time()
            if end_time - start_time > 10:
                return
            try:
                dic = {
                    'url':'null',
                    'data': 'null',
                    'status':'null'
                }
                req = urllib.request.Request(url)

                dic['url'] = url

                # 发送请求并获取响应
                with urllib.request.urlopen(req) as response:
                    html = response.read()
                status_code = response.getcode()


                dic['status'] = status_code

                if status_code == 200:

                    soup = BeautifulSoup(html, 'html.parser')

                    data_list = soup.find_all("article",class_="markdown-body entry-content container-lg")
                    if len(data_list) > 0:

                        text = data_list[0].text

                        dic['data'] = text

                    else:
                        data_list = soup.find_all("textarea",id="read-only-cursor-text-area")
                        if len(data_list) > 0:
                            text = data_list[0].text

                            dic['data'] = text
                    # print(dic)
                    self.dic_list.append(dic)

                    break

            except requests.exceptions.RequestException as e:
                print(e)
                time.sleep(random.uniform(5, 10))
            except urllib.error.HTTPError as e:
                # print(f"HTTP Error for URL {url}: {e.code} - {e.reason}")
                break
            except urllib.error.URLError as e:
                # print(f"URL Error for URL {url}: {e.reason}")
                break
            except Exception as e:
                # print(f"General Error for URL {url}: {e}")
                break
            finally:
                time.sleep(random.uniform(1, 1.3))
                return


    def crawl(self):
        pool = Pool(16)
        pool.map(self.get_page, self.url_list)
        with open('data.json', 'w', encoding='utf-8') as f:
            json.dump(self.dic_list, f, ensure_ascii=False, indent=4)
        print('爬取结束')

    def githubCveToMongo(self, collection):
        # 读取JSON文件并插入到MongoDB
        print(f'----------{self.vulnName} 开始存储----------')
        with open('data.json', 'r', encoding='utf-8') as f:
            data_list = json.load(f)
            collection.insert_many(data_list)


    def dataPreProc(self):
        print(f'----------{self.vulnName}开始数据预处理----------')
        collection = self.collection
        system = self.system
        count = 1
        for doc in collection.find():
            item = init_item(self.vulnName)
            item['url'] = doc['url']
            item['vul_id'] = f"044_{str(count).zfill(6)}"
            item['status'] = doc['status']
            item['text'] = doc['data']

            item['source_id'] = 'null'
            item['date'] = 'null'
            item['details'] = 'null'
            item['title'] = 'null'
            item['type'] = 'null'
            item['platform'] = 'null'
            item['author'] = 'null'
            item['cve_id'] = 'null'

            item['source'] = self.vulnName
            item['software_version'] = 'null'
            # 其他字段丢进related
            related_data = {key: doc[key] for key in doc if
                            key not in ['_id', "id", "detail", "type_id", "platform_id"
                                , 'author_id', 'code', 'type', 'platform', 'author']}

            related_data = {key: str(val) for key, val in related_data.items()}
            item['related'] = related_data

            count += 1
            # 数据预处理前存入的数据库以及做过去重，这里可以直接存进
            system.insert_one(item)
        print(f'----------{self.vulnName} 数据预处理完成----------')

    def run(self):
        self.get_url()
        print("----------开始爬取----------")
        self.crawl()
        self.githubCveToMongo(self.collection)
        self.dataPreProc()


if __name__ == '__main__':
    start_time = time.time()
    client = MongoClient('localhost', 27017)
    db = client['306Project']
    # 选择集合，如果不存在则MongoDB会自动创建
    collection = db['github_cve']
    system = db['system']

    agen = github_cve('github_cve',collection=collection,system=system)
    agen.run()

    client.close()
    # 获取程序结束时间
    end_time = time.time()
    # 计算程序耗时
    duration = end_time - start_time
    # 打印程序耗时
    print(f"程序耗时：{duration} 秒")