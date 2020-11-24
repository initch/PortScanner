from scapy.all import *
import sys
from random import randint
from multiprocessing import Process, Queue, Manager
import ipaddress
from scapy.layers.inet import IP,ICMP,TCP,UDP


class Single_host_scanner():
    """
    单个主机扫描：ICMP TCP UDP
    """

    def __init__(self, host):
        self.host = host
        self.state = False  # 开机状态
        self.portstatus = {} # 端口状态字典
        self.info = ""  #要打印到GUI界面的信息

    def insert_info(self, line):
        """
        添加要打印到GUI界面的信息，同时在终端也打印出来
        """
        print(line)
        self.info = self.info + '\n' + line + '\n'
    
    def clear_info(self):
        """
        每次开始新的扫描前清除扫描器的信息
        """
        self.info = ""
    
    def insert_result(self):
        """
        将端口状态扫描结果加入要打印的信息
        """
        for port,s in self.portstatus.items():
            self.insert_info("port %d | %s" %(port, s))

    def icmp_scan(self):
        """
        使用 ICMP Request 数据包判断主机是否开机
        """
        self.clear_info()
        seq_send = randint(0,100) # 设置随机序列号

        try:
            ans = sr1(IP(dst=self.host)/ICMP(seq=seq_send),timeout=1,verbose=0)
            
            self.insert_info("\n--------------------------------")

            if ans is None:
                raise TimeoutError

            seq_recieve = ans[1].fields["seq"]
            self.insert_info("本次发送随机序列号为 %d" %seq_send)
            self.insert_info("主机返回数据包的序列号为 %d \n" % seq_recieve)

            if ans[1].fields["seq"] == seq_send:  # 若返回数据包的序列号与发送的序列号相同，则对应本进程
                self.insert_info("主机 %s | 开启" %self.host)
                self.state = True
            else:
                self.insert_info("序列号匹配失败,无法判断主机开启状态\n")

        except:
            self.insert_info("主机 %s | 关闭" %self.host)

        return self.state


    def tcp_connect(self, dports):
        """
        TCP Connect扫描

        Params: 
            dports(list) : 用户定义需要扫描的端口

        Return:
            端口状态字典
        """
        if not self.icmp_scan():
            self.insert_info("目的主机处于关机状态，无法进行端口扫描")
            return

        for dport in dports:
            ans= sr1(IP(dst=self.host)/TCP(dport=dport,flags="S"),timeout=1,verbose=0)

            if ans is None:
        	    self.portstatus[dport] = "closed"
        
            elif ans.haslayer(TCP):
                if 'SA' in str(ans[TCP].flags): #若端口处于侦听状态，主机返回SYN/ACK数据包

                    # 向主机发送带有ACK和RST标识的数据包，连接成功
                    send = sr1(IP(dst=self.host) / TCP(dport=dport, flags="AR", seq=ans.ack, ack=ans.seq+1), timeout=1, verbose=0)
                    self.portstatus[dport] = "open"

                elif 'R' in str(ans[TCP].flags): #若端口关闭，主机返回RST
                    self.portstatus[dport] = "closed"
            
            else:
                self.portstatus[dport] = "closed"
            
        self.clear_info()
        self.insert_info("\n--------------------------------\n")
        self.insert_info("%s TCP Connect端口扫描 :\n " %str(self.host))
        self.insert_result()
        self.insert_info("扫描完成")

        return self.portstatus

    def syn_scan(self, dports):
        """
        TCP SYN 扫描
        """

        if not self.icmp_scan():
            self.insert_info("目的主机处于关机状态，无法进行端口扫描")
            return

        for dport in dports:
            ans = sr1(IP(dst=self.host)/TCP(dport=dport,flags="S"), timeout=1, verbose=0)

            if ans is None:
                self.portstatus[dport] = "closed"

            elif ans.haslayer(TCP):
                print(ans[TCP].flags)
                if 'SA' in str(ans[TCP].flags): #若端口处于侦听状态，主机返回SYN/ACK数据包
                    # 向主机发送RST结束连接
                    send_1 = sr1(IP(dst=self.host) / TCP(dport=dport, flags="R"), timeout=1, verbose=0)
                    self.portstatus[dport] = "open"

                elif 'R' in str(ans[TCP].flags): #若端口关闭，主机返回RST
                    self.portstatus[dport] = "closed"
            
            else:
                self.portstatus[dport] = "closed"

        self.clear_info()
        self.insert_info("\n--------------------------------\n")
        self.insert_info("%s TCP SYN 端口扫描 :\n " %str(self.host))
        self.insert_result()
        self.insert_info("扫描完成")

        return self.portstatus
    

    def fin_scan(self, dports):
        """
        TCP FIN 扫描
        """

        if not self.icmp_scan():
            self.insert_info("目的主机处于关机状态，无法进行端口扫描")
            return

        for dport in dports:
            ans = sr1(IP(dst=self.host)/TCP(dport=dport,flags="F"),timeout=2,verbose=0)

            if ans is None: # 若端口打开，且无连接，主机直接丢弃数据包，无回应;若端口被过滤，也会没有回包
    	        self.portstatus[dport] = "no response: open or filtered" 
        
            elif ans.haslayer(TCP):
                if 'A' in str(ans[TCP].flags): #若端口打开，且存在连接，主机返回ACK数据包
                    self.portstatus[dport] = "open, a link existed"

                elif 'R' in str(ans[TCP].flags): #若端口关闭，主机返回RST
                    self.portstatus[dport] = "closed"

                elif ans.haslayer(ICMP) and int(ans.getlayer(ICMP).type)==3: #如果目的端返回一个 ICMP 目的不可达（dest-unreach，类型3）报文，说明端口被过滤
                    self.portstatus[dport] = "filtered"
            
            else:
                self.portstatus[dport] = "unkowned, errors occured"
                ans.show()
        
        self.clear_info()
        self.insert_info("\n--------------------------------\n")
        self.insert_info("%s TCP FIN 端口扫描 :\n " %str(self.host))
        self.insert_result()
        self.insert_info("扫描完成")

        return self.portstatus

    def udp_scan(self, dports):
        """
        UDP 端口扫描：向目的端发送一个带有端口号的 UDP 数据包，如果目的端回复一个 UDP 数据包，则目标端口是开放的；
        如果目的端返回一个 ICMP 目的不可达（dest-unreach，类型3）报文，说明端口是关闭的；如果未收到回复数据包，则
        端口可能是开放的或被目的端过滤。
        """

        if not self.icmp_scan():
            self.insert_info("目的主机处于关机状态，无法进行端口扫描")
            return
            
        for dport in dports:
            ans = sr1(IP(dst=self.host)/UDP(dport=dport),timeout=1,verbose=0)
            if ans is None:
                self.portstatus[dport] = "no response: open or filtered"
            elif ans.haslayer(UDP):
                if ans[UDP].flags == "SA":
                    self.portstatus[dport] = "open"
            elif ans.haslayer(ICMP):
                if int(ans.getlayer(ICMP).type)==3:
                    self.portstatus[dport] = "closed"
        
        self.clear_info()
        self.insert_info("\n--------------------------------\n")
        self.insert_info("%s UDP 端口扫描 :\n " %str(self.host))
        self.insert_result()
        self.insert_info("扫描完成")

        return self.portstatus    

class Hosts_scanner():

    def __init__(self, segment):
        self.segment = segment
        self.ip_list = []
        self.active_ip = Manager().list()  #多进程间共享数据
        self.info = ""  #要打印到GUI的信息
        self.parse_ip()

    def parse_ip(self):
        net = ipaddress.ip_network(self.segment)
        
        for ip in net:
            ip = str(ip)
            self.ip_list.append(ip)
        
        return self.ip_list
    
    def insert_info(self, line):
        """
        添加要打印到GUI界面的信息，同时在终端也打印出来
        """
        print(line)
        self.info = self.info + '\n' + line + '\n'
    
    def run_process(self, i, q):
        print("start process %s" %i)
        while not q.empty():
            ip = q.get(timeout=1)
            scanner = Single_host_scanner(ip)
            if scanner.icmp_scan():
                self.active_ip.append(ip)
        print("exit process %s" %i)
    
    def icmp_scan(self):
        """
        开启多进程，使用 ICMP Request 数据包判断网段内主机是否开机
        """
        
        workQueue = Queue(len(self.ip_list))
        for ip in self.ip_list:
            workQueue.put(ip)
        
        process_list = []

        start = time.time()
        for i in range(0,4):
            p = Process(target=self.run_process,args=(i, workQueue))
            p.start()
            #time.sleep(2)
            process_list.append(p)
        
        for p in process_list:
            p.join()
        end = time.time()
        
        self.insert_info("\n-----8<-----8<-----8<-----8<-----")
        self.insert_info("网段扫描完成，总计扫描 %d 个IP,其中 %d 个处于开机状态，用时 %f s" %(len(self.ip_list),len(self.active_ip), end-start))

        if len(self.active_ip) != 0:
            self.insert_info("\n网段内处于开机状态的主机：")
            for ip in self.active_ip:
                self.insert_info(ip)

        return
    


if __name__ == "__main__":
    my = "192.168.17.130"
    sjtu = "202.112.26.54"  
    ftp = "202.120.58.157"
    ports = [21,80]
    scan = Single_host_scanner(sjtu)
    #scan.icmp_scan()
    #scan.tcp_connect(ports)
    #scan.syn_scan(ports)
    scan.fin_scan(ports)
    #scan.udp_scan(ports)
    