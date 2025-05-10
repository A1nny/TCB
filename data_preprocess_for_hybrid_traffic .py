from scapy.all import rdpcap
import numpy as np
import csv
import struct
import os

label=0

for root, dirs, files in os.walk("E:\\研究生\\课题\\流量pcap\\点播"):
    for file in files:
        # 筛选 pcap/pcapng 文件（不区分大小写）
        if file.lower().endswith(('.pcap', '.pcapng')):
            file_path = os.path.join(root, file)
            print(f"Reading: {file_path}")
            packets = rdpcap(file_path)
            token=0
            time=packets[0].time
            pkts=[]
            pktSum=[]
            time0=packets[0].time #第一个包到达时间
            for index, packet in enumerate(packets):
                if packet.time-time >= 15 :
                    token+= 1
                    pktSum.append(pkts)
                    pkts=[]
                    time0=packet.time
                pkts.append(packet)
                time=time0
            pktSum.append(pkts)

            
            for Pkt in pktSum:
                No=1
                
                burstBuf=[]
                # 遍历并打印每个数据包的time字段
                sessions = {}        # peer_ip -> session_id
                session_counter = 0  # 会话ID计数器
                session_bytes = {}   # session_id -> 字节数
                session_percent = []
                total_bytes = 0      # 总字节数
                for index, packet in enumerate(Pkt):
                    time=Pkt[0].time       #第一个包到达时间
                    #print(packet.time-time)    #当前包到达时间
                    if packet.haslayer("IPv6"):  # 检查数据包是否有 IP 层
                        src_ip = packet["IPv6"].src  # 源 IP
                        dst_ip = packet["IPv6"].dst  # 目标 IP
                        length = len(packet)
                    elif packet.haslayer("IP"):  # 检查数据包是否有 IP 层
                        src_ip = packet["IP"].src  # 源 IP
                        dst_ip = packet["IP"].dst  # 目标 IP
                        length = packet["IP"].len + 14
                    else:
                        continue

                    subnet="192.168.1.5" 
                    if src_ip in subnet and dst_ip not in subnet:
                        peer_ip = str(dst_ip)
                    elif dst_ip in subnet and src_ip not in subnet:
                        peer_ip = str(src_ip)
                    elif src_ip in subnet and dst_ip in subnet:
                        peer_ip = str(subnet)  # 自通信
                    else:
                        # output += f"Not involving {subnet}"
                        # print(output)
                        continue
                    # 分配会话ID（你的原有逻辑）
                    if peer_ip not in sessions:
                        sessions[peer_ip] = session_counter
                        session_counter += 1
                    session_id = sessions[peer_ip]
                    # 统计字节数（新增部分）
                    packet_size = length
                    session_bytes[session_id] = session_bytes.get(session_id, 0) + packet_size
                    total_bytes += packet_size
                    percentages = [0.0] * session_counter  # 创建空数组
                    for session_id in range(session_counter):
                        bytes_count = session_bytes.get(session_id, 0)
                        percentages[session_id] = round(bytes_count / total_bytes , 4) if total_bytes else 0
                    # print(percentages)
                    array_with_ip_time=[]
                    relativeTime=packet.time-time
                    
                    # print(src_ip.startswith(subnet))
                    if src_ip.startswith(subnet):
                        array_with_ip_time.append(1)
                        array_with_ip_time.append(relativeTime)
                        array_with_ip_time.append(length)
                    elif dst_ip.startswith(subnet):
                        array_with_ip_time.append(-1)
                        array_with_ip_time.append(relativeTime)
                        array_with_ip_time.append(length)
                    else:
                        # array_with_ip_time.append(0)
                        continue
                    # ----------------30s
                    # if relativeTime<2:
                    #     array_with_ip_time.append(0)
                    # elif relativeTime>=2 and relativeTime<6:
                    #     array_with_ip_time.append(1)
                    # elif relativeTime>=6 and relativeTime<14:
                    #     array_with_ip_time.append(2)
                    # elif relativeTime>=14 and relativeTime<=30:
                    #     array_with_ip_time.append(3)
                    # else :
                    #     array_with_ip_time.append(-1)
                    # ---------------------------15s
                    # if relativeTime<1:
                    #     array_with_ip_time.append(0)
                    # elif relativeTime>=1 and relativeTime<3:
                    #     array_with_ip_time.append(1)
                    # elif relativeTime>=3 and relativeTime<7:
                    #     array_with_ip_time.append(2)
                    # elif relativeTime>=7 and relativeTime<=15:
                    #     array_with_ip_time.append(3)
                    # else :
                    #     array_with_ip_time.append(-1)
                    
                    # print(burstBuf[i])
                #-----------------------------获取会话号---------------------------------------
                    
                    # if src_ip == subnet and dst_ip != subnet:
                    #     peer_ip = dst_ip
                    # elif dst_ip == subnet and src_ip != subnet:
                    #     peer_ip = src_ip
                    # elif src_ip == subnet and dst_ip == subnet:
                    #     peer_ip = subnet  # 自通信情况
                    # else:
                    #     output += f"Not involving {subnet}"
                    #     print(output)
                    #     continue
                    # # 分配会话号
                    # if peer_ip not in sessions:
                    #     sessions[peer_ip] = session_counter
                    #     session_counter += 1
                    # # output += f"Session {sessions[peer_ip]} (with {peer_ip})"
                    # # print(output)

                    array_with_ip_time.append(session_id)
                    array_with_ip_time.append(percentages[session_id])
                #---------------------------------------------------------------
                    burstBuf.append(array_with_ip_time)
                # burstSplit=[[],[],[],[]]

                # for i in range(1,len(burstBuf)) :
                #     if len(burstBuf)<4:
                #         continue
                #     if burstBuf[i-1][3]==0:
                #         burstSplit[0].append(burstBuf[i-1])
                #     elif burstBuf[i-1][3]==1:
                #         burstSplit[1].append(burstBuf[i-1])
                #     elif burstBuf[i-1][3]==2:
                #         burstSplit[2].append(burstBuf[i-1])
                #     elif burstBuf[i-1][3]==3:
                #         burstSplit[3].append(burstBuf[i-1])
                #     else:
                #         break
                    
                
                print("------------------------------\n")

                
                
                
                def featureCal(burstBuf,tdl):
                    if len(burstBuf)==0:
                        return 0,0,0,0,0,0,0
                    else:
                        burst = 0
                        
                        time = 0
                        posi_Num = 0
                        nega_Num = 0
                        posiLen = 0
                        negaLen = 0
                        sumLen = 0
                        posi_High_Num = 0
                        posi_Low_Num = 0
                        nega_High_Num = 0
                        nega_Low_Num = 0
                        # 遍历整个pcap文件并求各个特征
                        for i in range(1, len(burstBuf)):
                            if burstBuf[i - 1][2] >= 500 and burstBuf[i - 1][0] == 1:
                                posi_High_Num += 1*burstBuf[i-1][4]
                            elif burstBuf[i - 1][2] < 500 and burstBuf[i - 1][0] == 1:
                                posi_Low_Num += 1*burstBuf[i-1][4]
                            elif burstBuf[i - 1][2] >= 500 and burstBuf[i - 1][0] == -1:
                                nega_High_Num += 1*burstBuf[i-1][4]
                            elif burstBuf[i - 1][2] < 500 and burstBuf[i - 1][0] == -1:
                                nega_Low_Num += 1*burstBuf[i-1][4]
                            if burstBuf[i][0] == burstBuf[i - 1][0] and burstBuf[i][0] != 0 and burstBuf[i][1] - burstBuf[i - 1][1] < 0.001 and burstBuf[i][3]==burstBuf[i-1][3]: #同向、同会话、间隔小于阈值
                                
                                sumLen += burstBuf[i - 1][2]*burstBuf[i-1][4]
                                continue
                            elif burstBuf[i][0] != burstBuf[i - 1][0] :  #不同方向
                                if burstBuf[i - 1][0] == -1:
                                    burst += 1 * burstBuf[i - 1][4]
                                    nega_Num += 1 * burstBuf[i - 1][4]
                                    sumLen += burstBuf[i - 1][2]*burstBuf[i-1][4]
                                    negaLen += (-1) * sumLen
                                elif burstBuf[i - 1][0] == 1:
                                    burst+= 1* burstBuf[i - 1][4]
                                    posi_Num += 1* burstBuf[i - 1][4]
                                    sumLen += burstBuf[i - 1][2]*burstBuf[i-1][4]
                                    posiLen += sumLen
                                
                                sumLen = 0
                                time += (burstBuf[i][1] - burstBuf[i - 1][1])* burstBuf[i - 1][4]
                            elif burstBuf[i][3] != burstBuf[i-1][3] :  #不同会话
                                if burstBuf[i - 1][0] == -1:
                                    burst += 1 * burstBuf[i - 1][4]
                                    nega_Num += 1* burstBuf[i - 1][4]
                                    sumLen += burstBuf[i - 1][2]
                                    negaLen += (-1) * sumLen
                                elif burstBuf[i - 1][0] == 1:
                                    burst+= 1* burstBuf[i - 1][4]
                                    posi_Num += 1* burstBuf[i - 1][4]
                                    sumLen += burstBuf[i - 1][2]
                                    posiLen += sumLen
                                
                                sumLen = 0
                                time += (burstBuf[i][1] - burstBuf[i - 1][1])* burstBuf[i - 1][4]
                            elif burstBuf[i][0] == burstBuf[i - 1][0] and burstBuf[i][0] != 0 and burstBuf[i][1] - burstBuf[i - 1][1] >= 0.001 and burstBuf[i][3]==burstBuf[i-1][3]:#同向、同会话、间隔大于阈值
                                if burstBuf[i - 1][0] == -1:
                                    burst += 1 * burstBuf[i - 1][4]
                                    nega_Num += 1* burstBuf[i - 1][4]
                                    sumLen += burstBuf[i - 1][2]
                                    negaLen += (-1) * sumLen
                                elif burstBuf[i - 1][0] == 1:
                                    burst+= 1* burstBuf[i - 1][4]
                                    posi_Num += 1* burstBuf[i - 1][4]
                                    sumLen += burstBuf[i - 1][2]
                                    posiLen += sumLen
                                
                                sumLen = 0
                                time += burstBuf[i][1] - burstBuf[i - 1][1]
                        if posi_Num==0:
                            posi_Num=1
                        if nega_Num==0:
                            nega_Num=1
                        time+=tdl-burstBuf[len(burstBuf)-1][1]* burstBuf[len(burstBuf) - 1][4]
                        lenBBf=0
                        for row in burstBuf:
                            lenBBf += row[4]
                        print(lenBBf,len(burstBuf))
                        RltvBurst= lenBBf/burst  #相对突发次数
                        NaP=nega_Num / posi_Num  #正负向包之比
                        if burst==0:
                            RltvTime=0
                            pHP=0
                            nHP=0
                        else:
                            RltvTime=float(time) / burst #平均突发间隔时间
                            pHP=posi_High_Num/lenBBf  #正向高频比例
                            nHP=nega_High_Num/lenBBf  #负向高频比例
                        avePlen=posiLen / posi_Num  #正向平均突发长度
                        aveNlen=negaLen / nega_Num  #负向平均突发长度
                        return RltvBurst,NaP,RltvTime,avePlen,aveNlen,pHP,nHP
                data=[]
                data.append(No)
                #遍历整个pcap文件并求各个特征
                # print(len(burstSplit))
                result=featureCal(burstBuf,15)
                data.append(result)
                data.append(label)
                print(data)
                # 追加数据到现有的CSV文件
                # with open('./train.csv', mode='a', newline='') as file:
                #     writer = csv.writer(file)
                #     writer.writerow(data)
                with open('train1.csv', mode='a', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(data)
        # label+=1
