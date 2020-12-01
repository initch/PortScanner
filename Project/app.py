from tkinter import *
from scanner import Single_host_scanner, Hosts_scanner
import multiprocessing
import multiprocessing_win
import scapy

class App(Tk):

    def __init__(self):
        super().__init__()
        self.title("PortScanner")
        self.widgets = []  #控件列表
        self.target = StringVar()
        self.port_low = IntVar()
        self.port_high = IntVar()
        self.layout()
        self.set_menu()
        self.init_ui()
        
    def layout(self):
        """
        窗口整体布局
        """
        self.menubar = Menu(self)
        self.config(menu=self.menubar)

        self.frm_1 = Frame(self)
        self.frm_2 = Frame(self)
        self.frm_1.pack()
        self.frm_2.pack()
        self.output = Text(self.frm_2, padx=60,pady=30)
        self.output.pack()
        
        
    def set_menu(self):
        menu1 = Menu(self.menubar, tearoff=False)
        menu1.add_command(label='扫描主机', command=self.icmp_ui)
        menu1.add_command(label='扫描网段', command=self.segment_ui)
        
        self.menubar.add_cascade(label="ICMP扫描",menu=menu1)
        self.menubar.add_command(label="TCP扫描", command=self.tcp_ui)
        self.menubar.add_command(label="UDP扫描", command=self.udp_ui)
    
    def clear(self):
        """
        清空布局控件和output文本框的内容
        """
        for w in self.widgets:
            w.grid_forget()
        self.widgets = []
        self.output.delete(1.0, END)
    
    
    def tip(self, event):
        """
        用于绑定事件，当点击按钮时，提示正在扫描
        """
        self.output.insert(END, "\n正在扫描......")

    def init_ui(self):
        self.clear()
        l = Label(self.frm_1, text="请点击上方菜单选择扫描模式")
        self.widgets.append(l)
        l.grid(row=0, column=0)
    
    def add_basic_widgets(self):
        #对于单个主机的TCP UDP端口扫描，基本控件布局都是一致的
        target_label = Label(self.frm_1, text="目的主机: ")
        target_label.grid(row=0, column=0)
        port_label = Label(self.frm_1, text="指定端口范围：")
        port_label.grid(row=1, column=0)
        l = Label(self.frm_1, text="to")
        l.grid(row=1, column=2)

        e_1 = Entry(self.frm_1, textvariable=self.target)
        e_1.grid(row=0, column=1)

        e_2 = Entry(self.frm_1, textvariable=self.port_low, width=5)
        e_3 = Entry(self.frm_1, textvariable=self.port_high, width=5)
        e_2.grid(row=1, column=1)
        e_3.grid(row=1, column=3)

        self.widgets.append(target_label)
        self.widgets.append(port_label)
        self.widgets.append(l)
        self.widgets.append(e_1)
        self.widgets.append(e_2)
        self.widgets.append(e_3)

    def segment_ui(self):
        self.clear()
        target_label = Label(self.frm_1, text="目的网段: ")
        target_label.grid(row=0, column=0)

        entry = Entry(self.frm_1, textvariable=self.target)
        entry.grid(row=0, column=1)

        btn_start = Button(self.frm_1, text="扫描", command=self.segmant_scan)
        btn_start.bind('<Button-1>', self.tip)
        #btn_stop = Button(self.frm_1, text="停止")
        btn_start.grid(row=0, column=2)
        #btn_stop.grid(row=1, column=1)

        self.widgets.append(target_label)
        self.widgets.append(entry)
        self.widgets.append(btn_start)
        #self.widgets.append(btn_stop)
    
    def segmant_scan(self):
        """
        网段主机开机状态扫描
        """
        try:
            segment = Hosts_scanner(self.target.get())
            segment.icmp_scan()
            self.output.insert(END, segment.info)
        except:
            self.output.insert(END, "扫描失败，请检查输入格式及网络连接")


    def icmp_ui(self):
        self.clear()  #首先清空布局

        target_label = Label(self.frm_1, text="目的主机: ")
        target_label.grid(row=0, column=0)

        entry = Entry(self.frm_1, textvariable=self.target)
        entry.grid(row=0, column=1)

        #扫描按钮
        btn_start = Button(self.frm_1, text="扫描", command=self.icmp_scan)
        btn_start.bind('<Button-1>', self.tip)
        btn_start.grid(row=0,column=2)

        self.widgets.append(target_label)
        self.widgets.append(entry)
        self.widgets.append(btn_start)
    
    def icmp_scan(self):
        """
        单个主机开机状态扫描
        """
        try:
            ip = Single_host_scanner(self.target.get())
            ip.icmp_scan()
            self.output.insert(END, ip.info)
        except:
            self.output.insert(END, "扫描失败，请检查输入格式及网络连接")

    def tcp_ui(self):
        self.clear()  #清空布局
        self.add_basic_widgets() #基本控件

        #用户选择扫描模式
        pattern = IntVar()
        pattern.set(1)
        l = Label(self.frm_1, text="选择扫描模式：")
        l.grid(row=2,column=0)
        r_1 = Radiobutton(self.frm_1, text="TCP Connect扫描", value=1, variable=pattern)
        r_2 = Radiobutton(self.frm_1, text="TCP SYN扫描", value=2, variable=pattern)
        r_3 = Radiobutton(self.frm_1, text="TCP FIN扫描", value=3, variable=pattern)
        r_1.grid(row=3,column=0)
        r_2.grid(row=4,column=0)
        r_3.grid(row=5,column=0)

        btn = Button(self.frm_1, text="扫描", command=lambda: self.tcp_scan(pattern.get()))
        btn.bind('<Button-1>', self.tip)
        btn.grid(row=6,column=0)

        self.widgets.append(l)
        self.widgets.append(r_1)
        self.widgets.append(r_2)
        self.widgets.append(r_3)
        self.widgets.append(btn)
    
    def tcp_scan(self, pattern):

        ip = Single_host_scanner(self.target.get())
        dports = range(self.port_low.get(), self.port_high.get()+1)

        try:
            if pattern == 1: #TCP Connect扫描
                ip.tcp_connect(dports)
            elif pattern == 2: #TCP SYN扫描
                ip.syn_scan(dports)
            elif pattern == 3: #TCP FIN扫描
                ip.fin_scan(dports)
            self.output.insert(END, ip.info)
        except:
            self.output.insert(END, "扫描失败，请检查输入格式及网络连接")


    def udp_ui(self):
        self.clear() 
        self.add_basic_widgets()

        btn = Button(self.frm_1, text="扫描", command=self.udp_scan)
        btn.bind('<Button-1>', self.tip)
        btn.grid(row=2,column=0)

        self.widgets.append(btn)

    def udp_scan(self):
        dports = range(self.port_low.get(), self.port_high.get()+1)
        try:
            ip = Single_host_scanner(self.target.get())
            ip.udp_scan(dports)
            self.output.insert(END, ip.info)
        except:
            self.output.insert(END, "扫描失败，请检查输入格式及网络连接")

    
if __name__ == "__main__":
    multiprocessing.freeze_support()
    app = App()
    app.mainloop()
