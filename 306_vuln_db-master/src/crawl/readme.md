
### pip下载第三方包
“ pip install -i https://pypi.tuna.tsinghua.edu.cn/simple xxx”

# 已爬取数据源
## 1、CNNVD
可以直接下载 "https://www.cnnvd.org.cn/home/dataDownLoad", 每月执行任务当天手动下载至相应文件夹

(已经解决)写了自动化脚本获取漏洞数据，步骤：获取图形验证码、登录获取token、利用token去上面网址下载
(数据不全)(运行36670s)

## 2、debian
git clone 或者直接下载' https://salsa.debian.org/security-tracker-team/security-tracker.git '
已自动化git clone脚本

1、DLA（Debian Linux Advisory）：Debian Linux安全公告，是Debian发行版的安全公告，用于发布有关已知漏洞和安全问题的信息，以及可能的解决方案。

2、DSA（Debian Security Advisory）：Debian安全公告，是Debian发行版的另一种安全公告形式，用于发布有关Debian软件包中存在的安全问题的信息，通常会提供修复建议和更新指南。
（目前获取的DSA）
(一对多)(数据不全)(运行1478s)

3、DTSA（Debian Testing Security Advisory）：Debian测试版安全公告，与DSA类似，但专门针对Debian测试版（即Debian的下一个稳定版本）发布的安全公告。 DTSA通常包含有关测试版中安全问题的信息以及修复方案
   
4、CVE涵盖了mitrecve中的cve包括mitrecve关闭(可能修复了或者未公开)了的cve

## 3、GHSA
git clone 或者直接下载" https://github.com/github/advisory-database.git "
(运行1149s)

已自动化git clone脚本

## 4、mitrecve
直接下载" https://www.cve.org/Downloads "或者git clone 
已自动化git clone脚本
(运行大约4小时)

## 5、redhat
爬取脚本已完成，每次运行前需检查一下page有多少页，如有x页，则修改run()函数中第39行" for i in range(1, x+1): "
(运行96s)

## 6、nvd
爬取时间长，大约17个小时，设置了sleep时间防止被区域性封IP
运行64770s

## 7、exploitDB
爬取时间长，设置了sleep时间防止被区域性封IP
（解决方案）使用try except编写错误块处理脚本,断掉就接着跑
(运行6小时)

## 8、osvDB
需要通过谷歌云服务下载，国内无法访问，找寻国外同学帮忙下载
(运行240s)

## 9、CNVD：反爬虫机制
（解决部分）现在通过api下载，但是数据不全; cookie有时效性
(一对多)(数据不全)(运行1010s)

## 10、snyk
只能获取前30页，因此分类型获取各类型前30页，这样能尽可能多获取（有的类型没有30页）
(运行25030s)

## 11、curl
curl.py通过分析原网页获取数据。在原网页中发现提供了直接下载的链接，该方法写在crawl_curl.py
(运行40s)

## 12、exploitAlert
爬取时间长,需要10多个小时,每次执行前浏览器查看x页,更改for i in range(1,x)

## 13、seebug
爬取时间长, 需要10多个小时,每次执行前浏览器查看x页,更改for i in range(1,x),经常跑一半断掉,cooike有时效性,断了就改range从断掉地方开始并更改cooike
(运行63391s)

## 14、openEuler
获取totalcount,根据totalcount翻页
(运行971s)

## 15、kylinos
每次执行前浏览器查看x页,更改for i in range(1,x)

## 16、openGuass
(运行11s)

## 17、talos
运行1579s

## 18、vapidlabs
运行96s

## 19、ffmpeg
运行三小时左右

## 20、vulnera
现在用scrapy框架爬取，后期改为requests（便于项目协作并统一调用形式）
数据量不大，大约几分钟跑完

## 21、zeroscience
运行3498s

## 22、seclist
需要对爬取内容再做细分

## 23.360CERT
运行1576s，内容部分还可以细分

## 24.sec_consult
运行411s


