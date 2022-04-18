# 获取和风天气的天气数据（失效）
## 该文档已经不再适用和风天气新版本接口（源码仅供参考）
```
# linux 命令获取数据
curl -XGET --compressed "https://api.qweather.com/v7/weather/now?location=101010300&key=Your-Private-Key"
```

#### 和风天气官网
https://www.heweather.com

#### 和风天气接口文档
（实况数据）https://www.heweather.com/documents/api/s6/weather-now

#### 和风天气城市搜索文档
https://www.heweather.com/documents/search/find

#### 密钥
1. 请不要使用示例中的密钥，密钥是个人所有，和风官网可以注册免费账户（https://console.heweather.com/register）, 在应用管理里面新建一个应用，应用下新建一个密钥即可使用，免费数据足够测试了，需要更多数据就去购买吧
2. 密钥存放在 example/http_req 中，可根据自己的密钥进行替换 key=xxxxxxxxxxxxxx
3. 如果是按量计费或者付费用户，host 使用 api.heweather.net


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

下面命令向`free-api.heweather.net`发送HTTP请求，内容为`example/http_req`文件

``` shell
./ssl_client free-api.heweather.net 443 example/http_req

```
