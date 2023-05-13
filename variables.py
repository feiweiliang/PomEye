# -*- coding: utf-8 -*-
'''
所有需要用到的全局变量
'''


#从pom文件中解析出的组件信息,(artifactId, groupId, 版本, 漏洞等级, 来源文件)
global xml_res
xml_res = []
#记录每个项目的父项目是谁，{a:b}表示b是a的父项目
global pom_tree
pom_tree = {}
#记录每个项目的groupId.artifactId，以及其父项目的groupId.artifactId, {a:[a.groupId.artifactId,a.parent.groupId.artifactId]}
global ga_record
ga_record = {}
#记录查找出来的漏洞信息，例如{("org.apache.shiro:shiro-core","2.0.1"),["漏洞1","漏洞2","漏洞3"]}
global vul_details_dict
vul_details_dict = {}