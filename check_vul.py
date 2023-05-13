import requests
import re

from variables import *
from retrying import retry
from bs4 import BeautifulSoup

'''
漏洞检测模块
'''


# 比较版本号version1大于version2返回1
def compare_versions(version1, version2):
    # 将版本号字符串转换成列表
    v1 = version1.split('.')
    v2 = version2.split('.')

    # 将版本号列表转换成整数列表
    v1 = [int(x) for x in v1]
    v2 = [int(x) for x in v2]

    # 补齐版本号列表长度
    while len(v1) < len(v2):
        v1.append(0)
    while len(v2) < len(v1):
        v2.append(0)

    # 逐位比较版本号大小
    for i in range(len(v1)):
        if v1[i] > v2[i]:
            return 1
        elif v1[i] < v2[i]:
            return -1

    # 版本号相等
    return 0


# 漏洞类
class vul_details:
    def __init__(self):
        self.min_version = "*"  # 漏洞影响版本范围的最小值(包括)
        self.max_version = "*"  # 漏洞影响版本范围的最大值(不包括)
        self.name = "*"  # 漏洞名称
        self.level = "*"  # 漏洞等级
        self.cve = "*"  # CVE编号
        self.cwe = "*"  # CWE编号
        self.overview = "*"  # 漏洞概述
        self.href = "*"  # 漏洞信息来源的网站

    def version_is_affected(self, version):
        if "*" in version:
            return False
        version = version.replace("-SNAPSHOT", "").replace("-LATEST", "").replace("-RELEASE", "").strip()
        try:
            if self.min_version != "*" and compare_versions(self.min_version, version) == 1:
                return False
            if self.max_version != "*" and compare_versions(self.max_version, version) == -1:
                return False
            if self.max_version != "*" and compare_versions(self.max_version, version) == 0:
                return False
        except:
            return False
        return True


# 根据给定的 groupId:artifactId和version 在snyk中查找漏洞，存储到vul_details_dict
@retry(stop_max_attempt_number=3)
def req_snyk(ga, version):
    res = []
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:48.0) Gecko/20100101 Firefox/48.0',
        'Content-Type': 'text/xml;charset=UTF-8'
    }
    # 在snyk搜索该组件
    r = requests.get(f"https://security.snyk.io/vuln?search={ga}", headers=headers, timeout=8)
    r.encoding = 'utf-8'
    # 该组件没有任何漏洞，返回None
    if "No results found" in r.text:
        return None
    soup = BeautifulSoup(r.text, "html.parser")
    # print(r.text)
    tr_list = soup.select("#sortable-table > tbody > tr")
    # print(tr_list)
    for tr in tr_list:
        # 创建一个vul_details对象，记录搜索出来的每一个漏洞
        vul = vul_details()
        # 开始提取漏洞等级和影响版本
        vul.level = tr.select("ul > li > abbr > span")[0].text.strip()
        v = tr.select("td:nth-child(2) > span")[0].text.strip()
        vul.min_version = v.split(",")[0].replace("[", "").strip() if v.split(",")[0].replace("[",
                                                                                              "").strip() != "" else "*"
        vul.max_version = v.split(",")[1].replace(")", "").strip() if v.split(",")[1].replace(")",
                                                                                              "").strip() != "" else "*"
        # 如果组件版本在漏洞影响版本范围内，继续处理
        if not vul.version_is_affected(version):
            continue
        # 漏洞名字
        vul.name = tr.select("td:nth-child(1) > a")[0].text.strip()
        # 详情页链接
        href = tr.select("td:nth-child(1) > a")[0]["href"]
        vul.href = "https://security.snyk.io/" + href
        # 访问漏洞详情页
        try:
            r1 = requests.get(vul.href, headers=headers, timeout=8)
            r1.encoding = 'utf-8'
            soup = BeautifulSoup(r1.text, "html.parser")
            vul.cve = soup.select(
                "#__layout > div > main > div > div.vue--layout-container.vuln-page__body-wrapper.grid-wrapper > div.left > div.vuln-page__info-block__container > div.vuln-info-block > span.cve > span > a")[
                0].text if soup.select(
                "#__layout > div > main > div > div.vue--layout-container.vuln-page__body-wrapper.grid-wrapper > div.left > div.vuln-page__info-block__container > div.vuln-info-block > span.cve > span > a")[
                0].text else "*"
            if vul.cve!="*":
                vul.cve = re.search(r'CVE-\d{4}-\d{4,7}', vul.cve).group(0)
            vul.cwe = soup.select(
                "#__layout > div > main > div > div.vue--layout-container.vuln-page__body-wrapper.grid-wrapper > div.left > div.vuln-page__info-block__container > div.vuln-info-block > span:nth-child(3) > span > a")[
                0].text if soup.select(
                "#__layout > div > main > div > div.vue--layout-container.vuln-page__body-wrapper.grid-wrapper > div.left > div.vuln-page__info-block__container > div.vuln-info-block > span:nth-child(3) > span > a")[
                0].text else "*"
            if vul.cwe != "*":
                vul.cwe = re.search(r'CWE-\d{1,4}', vul.cwe).group(0)
            vul.overview = soup.select(
                "#__layout > div > main > div > div.vue--layout-container.vuln-page__body-wrapper.grid-wrapper > div.left > div:nth-child(3) > div > div > div")[
                0].text if soup.select(
                "#__layout > div > main > div > div.vue--layout-container.vuln-page__body-wrapper.grid-wrapper > div.left > div:nth-child(3) > div > div > div")[
                0].text else "*"
            if vul.overview!="*":
                vul.overview = BeautifulSoup(vul.overview, 'html.parser').get_text()
        except:
            pass
        res.append(vul)
    vul_details_dict[(ga, version)] = res


# 漏洞检测,更新xml_res中的漏洞等级
def check_vul(progressbarOne, root, progressbar_tips):
    # 进度值最大值
    progressbarOne['maximum'] = len(xml_res)
    # 进度值初始值
    progressbarOne['value'] = 0

    for i in range(len(xml_res)):
        info = xml_res[i]
        ga = f"{info[0]}:{info[1]}"

        progressbar_tips.set("正在检测组件 " + ga)
        # 刷新进度条
        progressbarOne['value'] += 1
        root.update()

        version = info[2]
        req_snyk(ga, version)
        level = "*"
        if vul_details_dict.get((ga, version)) != None:
            levels = [l.level for l in vul_details_dict[(ga, version)]]
            if "C" in levels:
                 level = "严重"
            elif "H" in levels:
                level = "高危"
            elif "M" in levels:
                level = "中危"
            elif "L" in levels:
                level = "低危"
            else:
                level = "*"
            # level = vul_details_dict[(ga, version)][0].level
        xml_res[i] = [info[0], info[1], info[2], level, info[4]]


# 返回该组件在给定的版本中所有的漏洞详情(显示在文本框中的)
def get_details_by_version(ga, version):
    if vul_details_dict.get((ga, version)) != None:
        return vul_details_dict.get((ga, version))
    return []
