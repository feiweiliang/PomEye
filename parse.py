import os

from bs4 import BeautifulSoup
from variables import *
from check_vul import check_vul

'''
解析pom文件模块
'''


# 构建父子依赖关系树
def construct_pom_tree():
    for file, ga_pga in ga_record.items():
        ga = ga_pga[0]
        parent_ga = ga_pga[1]
        # 再次遍历ga_record寻找该文件的父项目的pom文件
        for n_file, n_ga_pga in ga_record.items():
            if parent_ga == n_ga_pga[0]:
                pom_tree[file] = n_file


# 当pom文件中组件的version为空时，会继承父项目中该组件的版本
def dependence_inherit():
    for i in range(len(xml_res)):
        info = xml_res[i]
        if info[2] == "*":
            version = find_parent_version(info[-1], f"{info[0]}.{info[1]}")
            if version == None:
                version = "*"
            xml_res[i] = [info[0], info[1], version, info[3], info[4]]
            # print(xml_res[i])


# 查找pom文件x的父项目中y组件的依赖的版本
def find_parent_version(x, y):
    if pom_tree.get(x) == None:
        return "*"
    parent = pom_tree.get(x)
    for r in xml_res:
        if r[-1] == parent and y == f"{r[0]}.{r[1]}":
            if r[2] == "*":
                return find_parent_version(r[-1], y)
            return r[2]


# 从文件夹中寻找所有的pom文件
file_list = []
def find_pom(filename):
    file = os.listdir(filename)
    for f in file:
        real_filename = os.path.join(filename, f)
        if os.path.isfile(real_filename):
            if (real_filename.split(os.sep)[-1] == "pom.xml" or real_filename.split("/")[-1] == "pom.xml"):
                file_list.append(os.path.abspath(real_filename))
        elif os.path.isdir(real_filename):
            find_pom(real_filename)
        else:
            pass


# 解析pom文件，返回版本信息和漏洞信息
def parse(files, progressbarOne, root, progressbar_tips):
    pom_files = []

    # 如果传入的是多个文件
    if os.path.isfile(files[0]):
        for file in files:
            if (file.split(os.sep)[-1] == "pom.xml" or file.split("/")[-1] == "pom.xml"):
                pom_files.append(file)
    # 如果传入的是文件夹
    else:
        find_pom(files)
        for file in file_list:
            pom_files.append(file)

    # 开始解析每一个文件
    for pom_file in pom_files:
        progressbar_tips.set("正在解析文件 " + pom_file)
        # 使用bs4开始解析
        pom = BeautifulSoup(open(pom_file, 'r', encoding='utf-8').read(), "xml")
        dependencies = pom.find_all("dependency")
        # 进度值最大值
        progressbarOne['maximum'] = len(dependencies)
        # 进度值初始值
        progressbarOne['value'] = 0
        for d in dependencies:
            # 刷新进度条
            progressbarOne['value'] += 1
            root.update()
            # 解析
            groupId = d.find("groupId").text
            artifactId = d.find("artifactId").text
            try:
                # 直接给出  <version>4.7.1</version>
                version = d.find("version").text
                # 先<fastjson.version>1.2.78</fastjson.version>，然后<version>${fastjson.version}</version>
                if (version.startswith('${')):
                    version = pom.find_all(version.lstrip('${').rstrip('}'))[0].text
            except:
                version = "*"
            xml_res.append([groupId, artifactId, version, "*", pom_file])

        # 提取父子项目依赖关系
        # 先找到父项目的groupId和artifactId
        if (pom.find_all("parent") == []):
            parent_ga = "*"
        else:
            parent_ga = pom.select("parent > groupId")[0].text + "." + pom.select("parent > artifactId")[0].text
        # 找到本项目的artifactId
        ad = pom.select("project > artifactId")[0].text
        # 如果本项目没提供groupId，则和父项目一样
        if pom.select("project > groupId") == []:
            gd = pom.select("parent > groupId")[0].text
        else:
            gd = pom.select("project > groupId")[0].text
        ga = gd + "." + ad
        ga_record[pom_file] = [ga, parent_ga]

    # 构建父子依赖关系树
    construct_pom_tree()
    # 子项目继承父项目的依赖
    dependence_inherit()
    # 开始漏洞检测
    check_vul(progressbarOne, root, progressbar_tips)
