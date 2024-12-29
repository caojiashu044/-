import os
import random
import time

import pymongo
import requests

from src.crawl.Setting import DATA_PATH, CURRENT_TIME
from src.crawl.dataProce import insert_mongo, init_item, getDeepin, isInDeepin
from bs4 import BeautifulSoup as bs

class MyCase(object):
    def __init__(self, vulnName, collection, key,system):
        self.vulnName = vulnName
        self.collection = collection
        self.key = key
        self.system=system
        self.path = f'{DATA_PATH}/{CURRENT_TIME}/{vulnName}'
        if not os.path.exists(self.path):
            os.makedirs(self.path)
        self.deepin2309, self.deepin2404 = getDeepin()
        self.headers = {
        'Host': 'www.seebug.org',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
        'Accept-Encoding': 'gzip, deflate, br',
        'Referer': 'https://www.seebug.org/vuldb/ssvid-97587',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Te': 'trailers',
        'Connection': 'keep-alive',
    }

    def crawl(self,url):
        r = requests.get(url, headers=self.headers)
        # print(r.status_code)
        # 用bs解析该页面，soup是一个参数可以用其他参数a、b、c代替按自己喜好，soup用lxml格式解析得到了整个页面的内容
        soup = bs(r.content, 'lxml')
        # vulas也是一个参数可以按自己喜好更改，vulas是获取整个页面中所有元素为a，class=vul-title的值，得到一个列表
        vulas = soup.find_all(name='a', attrs={'class': 'vul-title'})
        # 对vulas这个列表开始做循环，vula是循环中每个元素为a，class=vul-title的值
        for vula in vulas:
            # 获取元素a中href值的标识符
            ssvid = vula['href'].split('-')[-1]
            # print("ssvid", ssvid)
            # 获取元素a中title值
            vulname = vula['title']
            # print("PoC名称:", vulname)
            # 该网站详情页面的地址
            download_url = f"https://www.seebug.org/vuldb/ssvid-{ssvid}"
            download_res = requests.get(download_url, headers=self.headers)
            # 该网站poc下载的链接
            reference = f"https://www.seebug.org/vuldb/downloadPoc/{ssvid}"
            # print("下载链接:", reference)
            # 同上面一样 用bs4通过lxml类型去解析详情页面的内容
            soup1 = bs(download_res.content, 'lxml')
            # 从解析后详情页面的内容中通过find函数去寻找元素为section、class=vul-basic-info，id=j-vul-basic-info的属性
            section_element = soup1.find('section', class_='vul-basic-info', id='j-vul-basic-info')
            # 定义一些参数的初始值，是为了如果该页面的该属性是空，在存入数据库时有一个默认值能够存进去
            dd_text1 = '未找到PoC源编号'
            dd_text2 = '未找到PoC发布时间'
            cleaned_text1 = '未找到漏洞编号CVE_id'
            cleaned_text2 = '未找到漏洞编号CNNVD_id'
            cleaned_text3 = '未找到漏洞编号CNVD_id'
            # 在section_element不为空时进行下一步，为空值时返回“未找到PoC基本信息”
            if section_element is not None:
                # 通过find_all函数找到section_element下所有元素为div，class_='col-md-4'的属性，因为对页面进行观察 发现section_element下有好几个div，class_='col-md-4'的属性，所以通过find_all返回一个div列表
                div_element = section_element.find_all('div', class_='col-md-4')
                # 在div_element不为空时进行下一步，为空值时返回“未找到PoC基本信息”   这里div_element都是可以用其他顺手的参数替换
                if div_element is not None:
                    # 通过find_all函数找到div_element[0]下元素为dd的所有属性，因为对页面进行观察 发现div_element下有好几个dd，所以通过find_all返回一个dd列表
                    dd_element = div_element[0].find_all('dd')
                    # 在dd_element不为空时进行下一步，为空值时返回“未找到PoC基本信息”
                    if dd_element[0] is not None:
                        # 返回dd_element列表第一个 dd的值 对比页面发现是 漏洞编码这个字段
                        dd_text1 = dd_element[0].text
                        # print("PoC源编号:", dd_text1)
                    else:
                        print("未找到PoC源编号")
                    if dd_element[0] is not None:
                        # 返回dd_element列表第二个 dd的值 对比页面发现是 发现时间这个字段
                        dd_text2 = dd_element[1].text
                        # print("发布时间:", dd_text2)
                    else:
                        print("未找到PoC发布时间")
                    # 通过find_all函数找到div_element[2]下元素为dd的所有属性
                    cve_element = div_element[2].find_all('dd')
                    if cve_element[0] is not None:
                        # 这里的代码是因为返回出来会跳行 所有去除空余的空格符号 和上面的含义是一样的
                        cve_id = cve_element[0].text.strip()
                        lines = cve_id.split('\n')
                        cleaned_text1 = '\n'.join(line.strip() for line in lines if line.strip())
                        # print("漏洞编号CVE_id:", cleaned_text1)
                    else:
                        print("未找到漏洞CVE_id")
                    cnnvd_element = div_element[2].find_all('dd')
                    if cnnvd_element[1] is not None:
                        # 同上 获取页面中cnnvd_id的属性
                        cnnvd_id = cnnvd_element[1].text.strip()
                        lines = cnnvd_id.split('\n')
                        cleaned_text2 = '\n'.join(line.strip() for line in lines if line.strip())
                        # print("CNNVD_id:", cleaned_text2)
                    else:
                        print("未找到漏洞CNNVD_id")
                    cnvd_element = div_element[2].find_all('dd')
                    if cnvd_element[2] is not None:
                        # 同上 获取页面中cnnvd_id的属性
                        cnvd_id = cnnvd_element[2].text.strip()
                        lines = cnvd_id.split('\n')
                        cleaned_text2 = '\n'.join(line.strip() for line in lines if line.strip())
                        # print("CNVD_id:", cleaned_text2)
                    else:
                        print("未找到漏洞CNVD_id")
                else:
                    print("未找到PoC基本信息")

            else:
                print("未找到PoC基本信息")

            div_padding_md = soup1.find('div', class_='padding-md')
            link_text = '未找到来源'
            if div_padding_md is not None:
                div_md_source = div_padding_md.find('div', id='j-md-source')
                if div_md_source is not None:
                    a_tag = div_md_source.find('a')
                    if a_tag is not None:
                        link_text = a_tag.text
                        # print("来源:", link_text)
                    else:
                        print("未找到来源")
                else:
                    print("未找到来源")
            else:
                print("未找到来源")
            div_content_holder = soup1.find('div', class_='content-holder padding-md')
            description_text = '未找到Poc描述'
            if div_content_holder is not None:
                div_md_detail = div_content_holder.find('div', id='j-md-detail')
                if div_md_detail is not None:
                    description_text = div_md_detail.text.strip()
                    # print("Poc描述:", description_text)
                else:
                    print("未找到Poc描述")
            else:
                print("未找到Poc描述")
            time.sleep(random.uniform(0.2, 2))

            # 将漏洞信息插入MongoDB数据库
            vulnerability = {
                "Patch_ID": cleaned_text1,
                "Patch_Name": vulname,
                "Source": "Seebug",
                "Source_ID": dd_text1,
                "Published-Date": dd_text2,
                "Description": description_text if description_text else "未找到Poc描述",
                "Reference": reference,
                "Visit_url": download_url,
                "Source_url": link_text if link_text else "未找到来源",
                "ssvid": ssvid,
                "CNNVD_id": cleaned_text2,
                "CNVD_id": cleaned_text3
            }
            # print(vulnerability)
            with open(os.path.join(self.path, "data.json"), 'a', encoding='UTF-8') as f:
                f.write(str(vulnerability) + '\n')
                f.close()
            insert_data = [vulnerability]
            insert_mongo(self.collection, insert_data, self.key)

    def dataPreProc(self):
        print('----------seebug 开始数据预处理----------')
        collection = self.collection
        system = self.system
        count = 1
        query = {'source': self.vulnName}
        result = system.delete_many(query)
        # print(f"删除了 {result.deleted_count} 条数据。")
        for doc in collection.find():
            item = init_item(self.vulnName)
            item['cve_id'] = doc['Patch_ID'] if doc['Patch_ID'] is not None else 'null'
            if item['cve_id'] != 'null':
                item['software_version'] = isInDeepin(item['cve_id'], self.deepin2309, self.deepin2404)

            item['date'] = doc['Published-Date'] if doc['Published-Date'] is not None else 'null'
            item['title'] = doc['Patch_Name'] if doc['Patch_Name'] is not None else 'null'
            item['source_id'] = doc['Source_ID'] if doc['Source_ID'] is not None else 'null'
            item['source'] = doc['Source'] if doc['Source'] is not None else 'null'
            item['details'] = doc['Description'] if doc['Description'] is not None else 'null'
            item['vul_id'] = f"016_{str(count).zfill(6)}"
            count += 1
            related_data = {key: doc[key] for key in doc if
                            key not in ['_id', "Patch_ID", "Published-Date", "Patch_Name","Source_ID","Source","Description"]}
            related_data = {key: str(val) for key, val in related_data.items()}
            item['related'] = related_data
            system.insert_one(item)
        print('----------seebug 数据预处理完成----------')

    def run(self):
        for i in range(1,2215):#2215
            print(f"-----------第{i}页---------")
            self.crawl(f"https://www.seebug.org/vuldb/vulnerabilities?has_poc=true&page={str(i)}")
        self.dataPreProc()


if __name__ == '__main__':
    start_time = time.time()
    myclient = pymongo.MongoClient('localhost', port=27017)
    db = myclient['306Project']
    collection = db['seebug']
    system = db['system']
    obj = MyCase('seebug', collection, 'Patch_ID',system)
    obj.run()
    # 获取程序结束时间
    end_time = time.time()
    # 计算程序耗时
    duration = end_time - start_time
    # 打印程序耗时
    print(f"程序耗时：{duration} 秒")
