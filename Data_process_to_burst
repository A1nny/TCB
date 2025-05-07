from scapy.all import rdpcap
import numpy as np
import csv
import struct
import os

label=44

for root, dirs, files in os.walk("F:\\0研究生\\研究生\\课题\\抓包\\数据流量获取\\tor\\Pcaps\\tor"):
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
                i=0
                burstBuf=[]
                # 遍历并打印每个数据包的time字段
                
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
                    array_with_ip_time=[]
                    relativeTime=packet.time-time
                    # print(packet.payload.len)#！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！
                    
                    subnet="10.0.2.15" 
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
                    if relativeTime<1:
                        array_with_ip_time.append(0)
                    elif relativeTime>=1 and relativeTime<3:
                        array_with_ip_time.append(1)
                    elif relativeTime>=3 and relativeTime<7:
                        array_with_ip_time.append(2)
                    elif relativeTime>=7 and relativeTime<=15:
                        array_with_ip_time.append(3)
                    else :
                        array_with_ip_time.append(-1)
                    burstBuf.append(array_with_ip_time)
                    # print(burstBuf[i])
                    
                    
                    i+=1
                burstSplit=[[],[],[],[]]

                for i in range(1,len(burstBuf)) :
                    if len(burstBuf)<4:
                        continue
                    if burstBuf[i-1][3]==0:
                        burstSplit[0].append(burstBuf[i-1])
                    elif burstBuf[i-1][3]==1:
                        burstSplit[1].append(burstBuf[i-1])
                    elif burstBuf[i-1][3]==2:
                        burstSplit[2].append(burstBuf[i-1])
                    elif burstBuf[i-1][3]==3:
                        burstSplit[3].append(burstBuf[i-1])
                    else:
                        break
                    
                
                print("------------------------------\n")

                
                
                
                def featureCal(burstBuf,tdl):
                    if len(burstBuf)==0:
                        return 0,0,0,0
                    else:
                        burst = []
                        take = 1
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
                                posi_High_Num += 1
                            elif burstBuf[i - 1][2] < 500 and burstBuf[i - 1][0] == 1:
                                posi_Low_Num += 1
                            elif burstBuf[i - 1][2] >= 500 and burstBuf[i - 1][0] == -1:
                                nega_High_Num += 1
                            elif burstBuf[i - 1][2] < 500 and burstBuf[i - 1][0] == -1:
                                nega_Low_Num += 1
                            if burstBuf[i][0] == burstBuf[i - 1][0] and burstBuf[i][0] != 0 and burstBuf[i][1] - burstBuf[i - 1][1] < 0.001:
                                take = take + 1
                                sumLen += burstBuf[i - 1][2]
                                continue
                            elif burstBuf[i][0] != burstBuf[i - 1][0] and burstBuf[i][0] != 0 and burstBuf[i - 1][0] != 0:
                                if burstBuf[i - 1][0] == -1:
                                    burst.append((-1) * take)
                                    nega_Num += 1
                                    sumLen += burstBuf[i - 1][2]
                                    negaLen += (-1) * sumLen
                                elif burstBuf[i - 1][0] == 1:
                                    burst.append(take)
                                    posi_Num += 1
                                    sumLen += burstBuf[i - 1][2]
                                    posiLen += sumLen
                                take = 1
                                sumLen = 0
                                time += burstBuf[i][1] - burstBuf[i - 1][1]
                            elif burstBuf[i][0] == burstBuf[i - 1][0] and burstBuf[i][0] != 0 and burstBuf[i][1] - burstBuf[i - 1][
                                1] >= 0.001:
                                if burstBuf[i - 1][0] == -1:
                                    burst.append((-1) * take)
                                    nega_Num += 1
                                    sumLen += burstBuf[i - 1][2]
                                    negaLen += (-1) * sumLen
                                elif burstBuf[i - 1][0] == 1:
                                    burst.append(take)
                                    posi_Num += 1
                                    sumLen += burstBuf[i - 1][2]
                                    posiLen += sumLen
                                take = 1
                                sumLen = 0
                                time += burstBuf[i][1] - burstBuf[i - 1][1]
                        if posi_Num==0:
                            posi_Num=1
                        if nega_Num==0:
                            nega_Num=1
                        time+=tdl-burstBuf[len(burstBuf)-1][1]
                        RltvBurst=len(burst) / len(burstBuf)  #相对突发次数
                        NaP=nega_Num / posi_Num  #正负向包之比
                        if len(burst)==0:
                            RltvTime=0
                            pHP=0
                            nHP=0
                        else:
                            RltvTime=float(time) / len(burst) #平均突发间隔时间
                            pHP=posi_High_Num/len(burstBuf)  #正向高频比例
                            nHP=nega_High_Num/len(burstBuf)  #负向高频比例
                        avePlen=posiLen / posi_Num  #正向平均突发长度
                        aveNlen=negaLen / nega_Num  #负向平均突发长度
                        # return RltvBurst,nega_Num,posi_Num,RltvTime
                        return RltvBurst,NaP,RltvTime,avePlen,aveNlen,pHP,nHP
                data=[]
                data.append(No)
                #遍历整个pcap文件并求各个特征
                # print(len(burstSplit))
                for i in range (0,len(burstSplit)):
                    result=featureCal(burstSplit[i],2**(i+2)-2)
                    if result==(0,0,0,0):
                        break
                    data.append(result)
                    # print(data)
                if len(data)<5:
                    continue
                print(data)
                data.append(label)
                # 追加数据到现有的CSV文件
                # with open('./train.csv', mode='a', newline='') as file:
                #     writer = csv.writer(file)
                #     writer.writerow(data)
                with open('train_tor.csv', mode='a', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(data)
        label+=1
