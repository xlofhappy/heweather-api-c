# How to get Heweather's data
# 获取和风天气的天气数据

### 和风天气官网

https://www.heweather.com

### 和风天气接口文档
（实况数据）https://www.heweather.com/documents/api/s6/weather-now

### 和风天气城市搜索文档
https://www.heweather.com/documents/search/find

## 编译

在代码目录中执行

``` shell
make
```

## 运行

编译成功后，可执行文件名称为`ssl_client`

注意：若当前系统没有openssl动态库，需要先在`代码顶级目录`中执行如下命令，将lib目录添加到程序动态库的查找路径中

``` shell
export LD_LIBRARY_PATH=./lib:$LD_LIBRARY_PATH
```

## 举例

下面命令向`https://www.openssl.org`发送HTTP请求，内容为`example/http_req`文件

``` shell
./ssl_client www.openssl.org 443 example/http_req

```
