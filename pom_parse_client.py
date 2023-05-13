import ttkbootstrap as ttk
import tkinter.filedialog

from variables import *
from ttkbootstrap.constants import *
from parse import parse
from check_vul import get_details_by_version
from tkinter import Canvas

'''
可视化界面模块：上传界面，详细信息界面，跳转
'''


# 上传文件的界面，也就是主界面
def upload_gui():
    root = ttk.Window("pom文件提取组件版本及漏洞检测", themename="flatly")
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    root.geometry(f'{int(1 * (screen_width / 3))}x{int(2 * (screen_height / 3))}')

    global progressbar_tips
    progressbar_tips = tkinter.StringVar(root)
    progressbar_tips.set("还未上传文件！！！")

    # 说明文件
    t1 = ttk.Label(root, text="上传你需要检测的pom文件：\n    1.上传所有需要检测的pom文件\n    2.上传文件夹，程序会自动查找pom文件\n注：程序会解析父子项目依赖关系",
                   bootstyle="danger")
    t1.pack(anchor="center", expand=True)

    # 进度条
    p1 = ttk.Progressbar(root, bootstyle="info-striped", length=int(1 * (screen_width / 5)))

    upload_frame = ttk.Frame(root)
    upload_frame.pack(anchor="center", expand=True)
    # 上传按钮
    b1 = ttk.Button(upload_frame, text="上传文件", bootstyle=(INFO, OUTLINE),
                    command=lambda: upload_to_info_gui(root, p1, "openFiles"))
    b1.pack(side='left', padx=20)
    b2 = ttk.Button(upload_frame, text="上传文件夹", bootstyle=(SUCCESS, OUTLINE),
                    command=lambda: upload_to_info_gui(root, p1, "openDir"))
    b2.pack(side='left', padx=20)

    # 进度条文字
    t2 = ttk.Label(root, textvariable=progressbar_tips, bootstyle="info")
    t2.pack()
    p1.pack(anchor="center", side=BOTTOM, pady=40)

    root.mainloop()


# 文件上传后跳转到组件详细信息界面
def upload_to_info_gui(root, p1, type):
    if type == "openFiles":
        files = tkinter.filedialog.askopenfilenames()
    else:
        files = tkinter.filedialog.askdirectory()
    parse(files, p1, root,progressbar_tips)
    info_gui(root)


# 组件详细信息界面
def info_gui(root):
    # 主窗口
    root2 = ttk.Toplevel(root)
    root2.title("pom文件提取组件版本及漏洞检测")
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    # root2.geometry(f'{int(1 * (screen_width / 2))}x{int(1 * (screen_height / 2))}')
    root2.geometry(f'{int(screen_width)}x{int(screen_height)}')

    # 顶栏提示信息
    lbl = ttk.Label(master=root2, text="点击组件查看漏洞详情", bootstyle=(LIGHT, INVERSE))
    lbl.pack(side=TOP, fill=X)
    # 信息表格
    table_frame = ttk.Frame(root2)
    table_frame.pack(fill=X)
    columns = ["groupId", "artifactId", "version", "level", "fold"]
    table = ttk.Treeview(
        master=table_frame,  # 父容器
        height=20,  # 高度,可显示height行
        columns=columns,  # 显示的列
        show='headings',
        bootstyle='info',
    )
    #滚动条
    scrollbar_y = ttk.Scrollbar(table_frame, orient=VERTICAL, bootstyle="info")
    scrollbar_y.config(command=table.yview)
    table.configure(yscrollcommand=scrollbar_y.set)
    scrollbar_y.pack(side=RIGHT,fill=ttk.Y)

    for c in columns:
        table.heading(c, text=c)
        table.column(c, anchor='center', width=int(screen_width / 10), stretch=True)
    # 给表格添加元素，根据漏洞危险程度标记上颜色
    kkj = 0
    for info in xml_res:
        if info[3] == "严重":
            table.insert("", END, values=info, tags=('critical',))
            table.tag_configure('critical', background='tomato')
        elif info[3] == "高危":
            table.insert("", END, values=info, tags=('high',))
            table.tag_configure('high', background='orange')
        else:
            table.insert("", END, values=info)
        # if kkj%4 == 1:
        #     table.insert("",END,values=info, tags = ('high',))
        #     table.tag_configure('high', background='orange')
        # if kkj%4 == 2:
        #     table.insert("",END,values=info, tags = ('middle',))
        #     table.tag_configure('middle', background='yellow')
        # if kkj%4 == 3:
        #     table.insert("",END,values=info, tags = ('low',))
        #     table.tag_configure('low', background='slategray')
        kkj = kkj + 1

    def treeviewClick(event):  # 单击
        item_text = table.item(table.selection()[0], "values")
        print(item_text)
        try:
            text.delete("1.0", END)
            text.delete("1.0", "1.end")
        except:
            pass
        #在下方的文本框显示漏洞详情
        vul_details = get_details_by_version(item_text[0]+":"+item_text[1],item_text[2])
        # text_content = ""
        # for d in vul_details:
        #     text_content = text_content +f"{d.name}\n{d.cve}\n"+"="*10+"\n"
        # text.insert(INSERT, text_content)
        # 因为设置文本框很繁琐，我就放到另一个方法里了
        info_text_gui(text,vul_details,item_text[0]+":"+item_text[1],screen_width)

    # 给表格绑定点击事件
    table.bind('<ButtonRelease-1>', treeviewClick)
    table.pack(fill=X)

    # 详情栏
    text = ttk.Text(root2, undo=True, autoseparators=False)

    text.pack(side=BOTTOM, fill=X)

    root2.mainloop()

def info_text_gui(text,vul_details,ga,screen_width):
    class TextSeparat(Canvas):  # working
        '''
        用于在tkinter文本框插入不同颜色、样式的分割线
        '''

        def __init__(self, text, width, bg='white', color='#66CCCC', line='common'):
            super().__init__(text, width=width, height=8, background=bg, highlightthickness=0, relief='flat', bd=0)
            if line == 'common':  # ---
                self.create_line(0, 4, width, 4, fill=color, width=2)
            elif line == 'dash':  # - -
                self.create_line(0, 4, width, 4, fill=color, dash=(10, 3), width=2)
            elif line == 'dash_point':  # -··
                self.create_line(0, 4, width, 4, fill=color, dash=(5, 2, 3), width=2)
            elif line == 'point':  # ···
                self.create_line(0, 4, width, 4, fill=color, dash=(2, 2), width=2)
            elif line == 'double_line':  # ===
                self.create_line(0, 3, width, 3, fill=color, width=1)
                self.create_line(0, 6, width, 6, fill=color, width=1)
            elif line == 'double_dash':  # = =
                self.create_line(0, 3, width, 3, fill=color, dash=(10, 3), width=1)
                self.create_line(0, 6, width, 6, fill=color, dash=(10, 3), width=1)

    font1 = ('Arial', 16, 'bold')
    text.tag_configure('bold_style', font=font1)
    font2 = ('Arial', 13)
    text.tag_configure('not_bold_style', font=font2)
    text.tag_configure('red_style', font=font2, foreground='#FF4500')
    text.tag_configure('blue_style', font=font2, foreground='#6495ED')
    text.tag_configure('deep_blue_style', font=font2, foreground='#7B68EE')
    text.tag_configure('gray_style', font=font2, foreground='#696969')

    text.window_create('end', window=TextSeparat(text, screen_width, bg=text['background'], line='double_line'))
    text.insert(END, "\n\n")
    for v in vul_details:
        text.insert(INSERT, f"{v.name}", 'bold_style')
        if "C" in v.level:
            level = "严重"
        elif "H" in v.level:
            level = "高危"
        elif "M" in v.level:
            level = "中危"
        elif "L" in v.level:
            level = "低危"
        else:
            level = "*"
        text.insert(INSERT, f"      {level}", 'red_style')
        text.insert(INSERT, "\nAffecting ", 'not_bold_style')
        text.insert(INSERT, f"{ga}", 'red_style')
        text.insert(INSERT, " package, versions ", 'not_bold_style')
        text.insert(INSERT, f"[{v.min_version}, {v.max_version})", 'red_style')
        text.insert(INSERT, f"\n{v.cve}      {v.cwe}", 'deep_blue_style')
        text.insert(INSERT,
                f"\n{v.overview}",
                'gray_style')
        text.insert(INSERT, f"\n{v.href}", 'blue_style')

        text.insert(END, "\n\n")
        text.window_create('end', window=TextSeparat(text, screen_width, bg=text['background'], line='double_line'))
        text.insert(END, "\n\n")
    # 将文字设置为居中
    text.tag_add("center", "1.0", "end")
    text.tag_configure("center", justify="center")
