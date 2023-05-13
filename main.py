from pom_parse_client import upload_gui

'''
author: s8ark
+ 精致、优美、易使用的图形化用户界面
+ 使用BeautifulSoup解析xml文件，速度快、不出错
+ 根据pom.xml文件中的<parent>标签构建父子关系树，当子项目的组件版本未知时递归的查找其父项目的该组件的版本号
+ 利用第三方漏洞库snyk检测组件漏洞，显示漏洞名称、危险等级、影响版本、漏洞详情及snyk参考链接
'''


if __name__ == "__main__":
    upload_gui()