# threat-detection
## 环境要求
本程序需在Linux环境下运行，基于python 2.7语法规范编写，主要的相关依赖包如下：
json、logging、datetime、time、elasticsearch、ConfigParser、socket、struct、re、requests、bs4、lxml、cloghandler

请将 python 二进制文件与 /opt/python 进行软连接，或者修改 threat-detection.sh 的python路径。

## 运行方法
threat-detection.sh [ACTION]  
>ACTION:  start  stop  status  restart  



