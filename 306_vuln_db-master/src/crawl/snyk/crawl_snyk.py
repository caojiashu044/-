import json
import os
import time

import pymongo
import requests
from requests.adapters import HTTPAdapter
import bs4 as soup
import logging

from crawl.Setting import DATA_PATH, CURRENT_TIME
from src.crawl.dataProce import insert_mongo, getVulid, init_item, getDeepin, isInDeepin


class SNYK(object):
    def __init__(self, vulnName, collection, key, system):
        self.vulnName = vulnName
        self.collection = collection
        self.system = system
        self.key = key
        self.path = f'{DATA_PATH}/{CURRENT_TIME}/{vulnName}'
        if not os.path.exists(self.path):
            os.makedirs(self.path)
        self.deepin2309, self.deepin2404 = getDeepin()

    def initialize(self):
        return {
            "name": "",
            "type": "",
            "package": "",
            "range": [],
            "fix": "",
            "overview": "",
            "references": [],
            "introduced_time": "",
            "cve_id": "",
            "cwe_id": "",
            "cvss_score": "",
            "severity_badge": "",
            "epss": "",
            "snyk_id": ""
        }

    def typeGetpageUrl(self):
        typeList = ['cargo', 'cocoapods', 'composer', 'golang', 'hex', 'maven', 'npm', 'nuget', 'pip',
                    'rubygems', 'swift', 'unmanaged', 'alpine', 'amzn', 'centos', 'debian', 'oracle',
                    'rhel', 'rocky', 'sles', 'ubuntu', 'wolfi', 'chainguard']
        # typeList = ['cargo']

        for type in typeList:
            print(f"----------------------{type}----------------------")
            count = 1
            isExist = True
            while True:
                if isExist == False:
                    break
                print("{}类型，第{}页".format(type, count))
                url = 'https://security.snyk.io/vuln/' + type + "/" + str(count)
                isExist = self.listGetVulnURL(url)
                count += 1

    def listGetVulnURL(self, page_url):
        print(page_url)
        o = requests.Session()
        o.mount('http://', HTTPAdapter(max_retries=3))
        count = 1
        isExist = False
        try:
            res = o.get(page_url, timeout=5)
            res.raise_for_status()
            html = res.content.decode()
            s = soup.BeautifulSoup(html, "html.parser")
            # 先判断该类型漏洞这页是否存在
            # if isPageExist(s):
            tbody = s.find_all(attrs={'class': 'vue--table__tbody'})
            # 获取该页的漏洞列表
            vul_list = tbody[0].find_all(attrs={'class': 'vue--table__row'})
            isExist = True
            for t in vul_list:

                # print(count)
                count = count + 1
                vul_name = t.find_all(attrs={'class': 'vue--anchor'})
                name = vul_name[0].text.strip()
                url = "https://security.snyk.io/" + vul_name[0].attrs['href']
                # print(name, url)
                try:
                    self.getVulnInformation(url)

                except Exception as e1:
                    print(e1, e1.__traceback__.tb_lineno)

        except Exception as e:
            print(e, e.__traceback__.tb_lineno)
        return isExist

    def isPageExist(self, html):
        return False

    def getVulnInformation(self, url):
        print(url)
        vuln_detail = self.initialize()
        o = requests.Session()
        o.mount('http://', HTTPAdapter(max_retries=3))
        res = o.get(url, timeout=5)
        res.raise_for_status()
        html = res.content.decode()
        s = soup.BeautifulSoup(html, "html.parser")

        '''
        第一部分，title_info，包含漏洞名称、受影响的包、受影响的包版本范围、漏洞类型
        '''
        # print("-----第一部分，title_info------")
        title = s.find_all(attrs={'class': 'vue--heading title'})
        info = title[0].text.split('\n')
        title_info = []
        for i in info:
            if i.strip() == '' or i.strip() == 'Affecting' or i.strip() == 'package, versions':
                continue
            title_info.append(i.strip())
        vuln_detail["name"] = title_info[0]  # 漏洞名称
        vuln_detail["package"] = title_info[1]  # 受影响的包
        vuln_detail["range"] = title_info[2:]  # 受影响包的范围
        # print(vuln_detail.range)
        vuln_detail["type"] = s.find_all(attrs={'class': 'vue--breadcrumbs__list-item'})[1].text  # 漏洞类型
        # print(vuln_detail["name"] + "\n" + vuln_detail["package"] + "\n" + vuln_detail["type"])

        '''
        第二部分，fix_info,包含修复建议、概述、参考链接
        '''
        # print("-----第二部分，fix_info------")
        fix_info = s.find_all(attrs={'class': "markdown-section"})

        for fi in fix_info:
            title = fi.find("h2").text.strip()
            if title == "How to fix?":
                vuln_detail["fix"] = fi.find(attrs={'class': 'vue--prose'}).text.strip()

            if title == "Overview":
                vuln_detail["overview"] = fi.find(attrs={'class': 'vue--prose'}).text.strip()

            if title == "References":
                references = fi.find(attrs={'class': 'vue--prose'}).find_all("a")
                for refer in references:
                    references_href = refer.attrs['href']
                    references_name = refer.text
                    dict = {"references_name": references_name, "references_href": references_href}
                    vuln_detail["references"].append(dict)

        # print(vuln_detail.fix + "\n" + vuln_detail.overview)
        # print(vuln_detail.references)

        '''
        第三部分，cve_info，包含CVE_id、CWE_id、引入时间
        '''
        # print("-----第三部分，cve_info-------")
        cve_info = s.find_all(attrs={"class": "vuln-info-block"})
        introduced_time = cve_info[0].find_all(attrs={"class": "vue--heading date"})[0].text
        vuln_detail["introduced_time"] = introduced_time.split(':')[1].strip()
        cveAndcwe = cve_info[0].find_all(attrs={"class": "vue--anchor"})
        '''synk给出了cve_id的链接，这里并没有爬取链接，cve和cwe的链接都是url+cve_id形式，如：https://www.cve.org/CVERecord?id=CVE-2023-26987
            之后需要链接地址，只需一行代码url+cve_id，就不需要数据库存储链接，只需获取cve_id即可。
        '''

        for b in cveAndcwe:
            temp = b.text.strip().split("\n")[0]
            if temp.startswith('CVE'):
                vuln_detail["cve_id"] = temp
                continue
            if temp.startswith('CWE'):
                vuln_detail["cwe_id"] = temp
                continue
        # print(vuln_detail.introduced_time + "\n" + vuln_detail.cve_id + "\n" + vuln_detail.cwe_id)

        '''第四部分，synk_cvss_info,包含cvss_score,severity_badge

            Attack Complexity,Confidentiality,Integrity,Availability,
            Attack Vector,Privileges Required,User Interaction,scope(这八个没有爬取)
        '''
        # print("-----第四部分，synk_cvss_info-------")
        severity = s.find(attrs={"class": "severity-widget__badge big"})

        for se in severity.text.split("\n"):
            if se.strip() == '':
                continue

            if se.strip().__contains__("."):
                vuln_detail["cvss_score"] = severity.find("div").attrs['data-snyk-test-score']
                continue
            vuln_detail["severity_badge"] = se.strip()
        # print(vuln_detail.cvss_score + "\n" + vuln_detail.severity_badge)

        # details = s.find_all(attrs={"class":"details-box__body"})[0].find_all(attrs={"class":"cvss-details-item"})
        # attack_complexity = details[0].find('strong').text.strip()
        # confidentiality = details[1].find(attrs={"class":"vue--badge__text"}).text.strip()
        # integrity = details[2].find(attrs={"class":"vue--badge__text"}).text.strip()
        # availability = details[3].find(attrs={"class":"vue--badge__text"}).text.strip()
        # print(attack_complexity+"\n"+confidentiality+"\n"+integrity+"\n"+availability)

        '''
        第五部分，other_info,包括，EPSS,Snyk ID
        '''
        # print("-----第五部分，other_info-------")

        try:
            threat_intelligence = s.find(attrs={"class": "threat-intelligence-detail"})
            epss_list = threat_intelligence.find_all('strong')[0].text.split("\n")
            for epss in epss_list:
                vuln_detail["epss"] += epss.strip()
        except Exception as epssE:
            print(epssE, epssE.__traceback__.tb_lineno)
            logging.error("{} in line{},url is {}".format(str(epssE), str(epssE.__traceback__.tb_lineno), url))

        snyk_info = \
        s.find_all(attrs={"class": "vue--block vue--card vuln-credit vue--card--white vue--card--no-padding"})[
            0].find_all("li")
        vuln_detail["snyk_id"] = snyk_info[0].find_all("strong")[0].text.strip()
        # print(vuln_detail.epss + "\n" + vuln_detail.snyk_id)

        '''
        转为json格式，存入mongoDB
        '''

        insert_content = {'name': vuln_detail["name"], "url": url, 'details': vuln_detail}
        # print(insert_content)
        insert = [insert_content]
        insert_mongo(self.collection, insert, 'url')
        with open(os.path.join(self.path, 'snyk_data.json'), 'a') as f:
            json_str = json.dumps(vuln_detail)
            f.write(json_str)
            f.close()

        time.sleep(0.2)

    def dataPreProc(self):
        print('----------synk 开始数据预处理----------')
        collection = self.collection
        system = self.system
        count = 1
        # 先把总数据表中对应数据源所有数据删除
        query = {'source': self.vulnName}
        result = system.delete_many(query)
        # print(f"删除了 {result.deleted_count} 条数据。")
        for doc in collection.find():
            item = init_item(self.vulnName)
            item['source_id'] = doc['details']['snyk_id'] if doc['details']['snyk_id'] is not None else 'null'
            item['date'] = doc['details']['introduced_time'] if doc['details'][
                                                                    'introduced_time'] is not None else 'null'
            item['details'] = doc['details']['overview'] if doc['details']['overview'] is not None else 'null'
            item['title'] = doc['name'] if doc['name'] is not None else 'null'
            item['cve_id'] = doc['details']['cve_id'] if doc['details']['cve_id'] is not None else 'null'
            if item['cve_id'] != 'null':
                item['software_version'] = isInDeepin(item['cve_id'], self.deepin2309, self.deepin2404)

            item['type'] = doc['details']['type'] if doc['details']['type'] is not None else 'null'

            item['vul_id'] = f"020_{str(count).zfill(6)}"
            count += 1
            # 其他字段丢进related
            related_data = {key: doc[key] for key in doc if key not in ['_id', "name"]}

            related_data = {key: doc[key] for key in doc if key not in ['_id', "name", "details"]}
            related_data1 = {key: doc['details'][key] for key in doc['details'] if
                             key not in ['snyk_id', 'overview', 'type', 'cve_id', 'introduced_time']}
            related_data.update(related_data1)
            # 将所有字段转换为字符串类型
            related_data = {key: str(val) for key, val in related_data.items()}
            item['related'] = related_data

            # 数据预处理前存入的数据库以及做过去重，这里可以直接存进
            system.insert_one(item)

        print('----------synk 数据预处理完成----------')

    def run(self):
        self.typeGetpageUrl()
        self.dataPreProc()


if __name__ == '__main__':
    # 获取当前时间
    start_time = time.time()

    # 连接数据库，运行程序
    client = pymongo.MongoClient("localhost", port=27017)
    local_vulnerability = client['306Project']
    collection = local_vulnerability['snyk']

    # 每个源数据预处理后存入总数据表，总数据表名称
    system = local_vulnerability['system']

    obj = SNYK('snyk', collection, 'url', system)
    obj.run()
    client.close()

    # 获取程序结束时间
    end_time = time.time()
    # 计算程序耗时
    duration = end_time - start_time
    # 打印程序耗时
    print(f"程序耗时：{duration} 秒")