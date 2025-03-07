# 流量包说明

> 大部分流量包不上传了,省空间，可以去开源网站下载测试。
> 脚本从一些仓库找到并修改,后续还会修正和更新

Zeek 脚本用于检测各种类型的攻击，包括密码猜测、HTTP Dos、DNS DDos 和 SYN 洪水攻击


1.暴力破解
暴力攻击，也称为密码猜测攻击，是一种通过猜测所有可能的字符组合直到找到正确的字符组合来尝试破解密码的方法。黑客经常使用它来访问安全系统，并且可以通过使用强密码、不同帐户的不同密码并定期更改它们来防止。系统还可以具有内置的安全措施来防止暴力攻击。


2.HTTP DoS 攻击
HTTP DoS 是一种网络攻击，可在短时间内向 Web 服务器或 Web 应用程序发送大量请求，使其不堪重负且不可用。这可以通过速率限制和入侵检测系统等安全措施来防止。


3.SYN 洪水攻击
SYN 泛洪攻击是一种网络攻击，它利用 TCP 协议中的弱点，向服务器发送大量未完成的 TCP 连接请求，使其不堪重负且不可用。


4.DNS DDoS
DNS DDoS 是一种以域名系统 （DNS） 基础设施为目标的网络攻击，它通过向 DNS 服务器发送大量流量，导致它们不堪重负且不可用。这可以通过速率限制、流量过滤和 DNS 缓存等安全措施以及使用最新的安全补丁使 DNS 服务器软件保持最新状态来防止。

5.rfc_scp
检测未经认证的scp行为


安装 zeek 才能运行和执行 pcap 文件和 zeek 脚本。

用法
您可以使用以下命令运行脚本：
zeek -C -r xxx.pcap xxx.zeek

例:
zeek -Cr pcaps/sshguess.pcap scripts/brtforce.zeek

https://www.malware-traffic-analysis.net/index.html 
：我们衷心感谢本网站为我们提供必要的 pcap 和知识来检测这些攻击。

注意：
用于测试 SYN FLOOD 和 HTTP DoS 脚本的 Pcaps 
可以在这里找到：https://ordo.open.ac.uk/articles/dataset/HTTPDoSDatasetinPCAPformatfor_Wireshark/17206289