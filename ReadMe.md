## PaoPao GateWay
![PaoPaoDNS](https://th.bing.com/th/id/OIG.0FtL40H4krRLeooEGFpu?w=220&h=220&c=6&r=0&o=5&pid=ImgGn)    

PaoPao GateWay是一个体积小巧、稳定强大的FakeIP网关，核心由clash驱动，支持`Full Cone NAT` ，支持多种方式下发配置，支持多种出站方式，包括自定义socks5、自定义openvpn、自定义yaml节点、订阅模式和自由出站，支持节点测速自动选择、节点排除等功能，并附带web面板可供查看日志连接信息等。PaoPao GateWay可以和其他DNS服务器一起结合使用，比如配合[PaoPaoDNS](https://github.com/kkkgo/PaoPaoDNS)的`CUSTOM_FORWARD`功能就可以完成简单精巧的分流。   

你可以从Github Release下载到最新的镜像：[https://github.com/kkkgo/PaoPaoGateWay/releases](https://github.com/kkkgo/PaoPaoGateWay/releases)   
##### 如果对你有帮助，欢迎点`Star`，如果需要关注更新，可以点`Watch`。
## [→详细说明《FakeIP网关的工作原理》](https://blog.03k.org/post/paopaogateway.html)

### 运行要求和配置下发
类型|要求
-|-
虚拟机CPU|x86-64
内存|最低128MB，推荐256MB
硬盘|不需要
网卡|1
光驱|1  

*注意：如果节点数量很多或者连接数很多或者你的配置文件比较复杂的话，建议适当增加内存和CPU核心数*
  
#### 方式一：使用docker内嵌配置
你可以使用Docker一键定制ISO镜像，其中包括为ISO**配置静态IP**、替换Clash核心、替换Country.mmdb、内嵌ppgw.ini等功能，**详情见使用Docker定制ISO镜像一节**。   

#### 方式二：使用DHCP下发配置
PaoPao GateWay是一个iso镜像，为虚拟机运行优化设计，你只需要添加一个网络接口和一个虚拟光驱塞iso即可。虚拟机启动之后，会自动使用DHCP初始化eth0接口，因此你需要在路由器里为这个虚拟机**绑定静态的IP地址**，如果你在路由器里面找不到哪个是PaoPao GateWay的话，他的主机名是PaoPaoGW，虚拟机也会滚动显示获取到的eth0接口的IP地址和MAC信息。  
为了实现配置和虚拟机分离，达到类似docker的效果，PaoPaoGateWay采用了配置下发的方式进行配置，你需要把配置文件放在对应位置，假设系统启动后通过DHCP获取到以下信息：  
```shell
IP: 10.10.10.3
DNS1: 10.10.10.8
DNS2: 10.10.10.9
网关： 10.10.10.1
```
系统会依次尝试以下方式获取配置，并记忆最后一次成功的连接，下次循环优先使用：  
- 1 从`http://paopao.dns:7889/ppgw.ini`下载配置。使用此方式，你需要配合你的DNS服务，把`paopao.dns`这个域名解析到你的静态文件服务IP，服务端口是7889。如果配合[PaoPaoDNS](https://github.com/kkkgo/PaoPaoDNS)使用，你只需要设置`SERVER_IP`参数和设置`HTTP_FILE=yes`，映射7889端口即可，你可以直接把配置文件`ppgw.ini`放在`PaoPaoDNS`的`/data`目录。  
- 2 从`http://10.10.10.1:7889/ppgw.ini`下载配置。使用此方式，你可以在主路由上映射7889端口到你的静态文件服务。
- 3 从`http://10.10.10.8:7889/ppgw.ini`下载配置。如果你直接使用PaoPaoDNS作为你的DNS服务IP，那么你只需要设置PaoPaoDNS的`HTTP_FILE=yes`，映射7889端口即可。
- 4 从`http://10.10.10.9:7889/ppgw.ini`下载配置。同上。  

系统会不停尝试直到成功获取到配置文件为止，并在后续定期获取新配置（默认值是30秒），当配置的值发生变化的时候将会重新加载网关。你也可以手动进入虚拟机本地终端输入`reload`回车强制马上重载所有配置。
### ppgw.ini配置说明
ppgw.ini的所有配置项如下：  
```ini
#paopao-gateway

# mode=socks5|ovpn|yaml|suburl|free
# default: free
mode=free

# Set fakeip's CIDR here
# default: fake_cidr=7.0.0.0/8
fake_cidr=7.0.0.0/8

# Set your trusted DNS here
# default: dns_ip=1.0.0.1
dns_ip=10.10.10.8
# default: dns_port=53
# If used with PaoPaoDNS, you can set the 5304 port
dns_port=5304

# Clash's web dashboard
clash_web_port="80"
clash_web_password="clashpass"

# default：openport=no
# socks+http mixed 1080
openport=no

# default: udp_enable=no
udp_enable=no

# default:30
sleeptime=30

# socks5 mode settting
# default: socks5_ip=gatewayIP
socks5_ip="10.10.10.5"
# default: socks5_port="7890"
socks5_port="7890"

# ovpn mode settting
# The ovpn file in the same directory as the ppgw.ini.
# default: ovpnfile=custom.ovpn
ovpnfile="custom.ovpn"
ovpn_username=""
ovpn_password=""

# yaml mode settting
# The yaml file in the same directory as the ppgw.ini.
# default: yamlfile=custom.yaml
yamlfile="custom.yaml"

# suburl mode settting
suburl="https://..."
subtime=1d

# fast_node=check/yes/no
fast_node=yes
test_node_url="https://www.youtube.com/generate_204"
ext_node="Traffic|Expire| GB|Days|Date"
cpudelay="3000"
```
下面逐项来解释选项的用法：
- 1 配置文件第一行必须以`#paopao-gateway`开头。配置格式为`选项="值"`。
- 2 `mode`是网关的运行模式，也就是当静态路由的流量到达网关之后，怎么出去。一共有五种模式可以选择（`socks5`,`ovpn`,`yaml`,`suburl`,`free`）:
    - `socks5`:配置为socks5代理出站，这是最简单也是最通用的配置方式，如果其他模式不能满足你的需求，你可以把能满足你需求的服务程序开一个`socks5`代理给网关使用。
    - `ovpn`:配置为openvpn出站，适用于一些专线场景。
    - `yaml`：自定义clash的yaml配置文件出站。你可以自己写一个clash格式的yaml配置文件，clash支持多种出站协议，具体写法请看官方wiki。只写`proxies:`字段即可，也可以包含`rules:`字段。如果只有`proxies:`字段，在网关启动后你可以在web端选择节点；如果有`rules:`字段，则会按照你写的规则来执行。注意，网关使用开源的官方clash核心，如果你的`rules:`包含闭源Premium core的规则，则无法加载并报错，导致clash无法启动。使用开源的Clash核心是因为功能已经可以满足需求，网关本身也不适合加载过于复杂的规则，Premium core的功能会降低稳定性、增加崩溃的几率，比如`RULE-SET`功能在启动的时候下载远程url文件失败的话可能会导致clash无法正常启动，而clash无法启动的时候文件可能不能被正常下载，进入了死循环。此外，由于网关也不适用GEOIP规则，请勿写入任何GEOIP规则，因为GEOIP规则依赖GEOIP库更新，而稳定的网关不适合依赖更新运行([参见](https://github.com/Dreamacro/clash/issues/2674#issuecomment-1507868338))，此外碰到GEOIP规则会触发DNS解析，降低了处理效率。如果有更复杂的规则需求，建议单独跑一个docker配置你所需的规则，开放socks5端口，让网关使用`socks5`模式，或者参考**使用docker定制ISO镜像**一节更换定制的clash核心。选择该模式，你需要把配置文件放在和`ppgw.ini`同一目录，系统将会在指定的`sleeptime`内循环检测配置值的变化并重载网关。
   - `suburl`：自定义远程订阅clash配置，不过是从给定的url下载配置。注意事项与`yaml`模式基本一样，不能使用包含开源clash功能之外的规则的订阅，或者参考**使用docker定制ISO镜像**一节更换定制的clash核心。推荐nodelist类型订阅，或者使用subconverter等程序转换订阅。
    - `free`: 自由出站模式，选择此模式的场景是，假定你在IP层面把虚拟机IP出口走了专线，流量直接出站处理。
- 3 `fake_cidr`是指定你的FakeIP地址池范围。比如默认值是`7.0.0.0/8`，你需要在主路由上设置一条静态路由`7.0.0.0/8`到PaoPaoGateWay。你应该使用一些看起来是公网但实际上不是（或者不会被实际使用）的地址段，比如实验用地址段、DoD网络地址段。如果你有其他真实的公网IP段需要被网关处理，直接写对应的静态路由即可（比如某些聊天软件走的是IP直连而不是域名），除了指定的`fake_cidr`段会被建立域名映射，其他公网IP地址段都会被网关按普通流量处理分流。
- 4 `dns_ip`和`dns_port`用于设置可信任的DNS服务器，“可信任”意味着真实无污染的原始解析结果。如果你配合PaoPaoDNS使用，可以把`dns_ip`设置成PaoPaoDNS的IP，把`dns_port`设置成映射的5304端口，详情可参见PaoPaoDNS的可映射端口说明。该DNS服务在代理出站的时候实际上不会被用到，流量还是会以域名发送到远端，更多的是用于其他模式的节点解析、规则匹配。
- 5 `clash_web_port`和`clash_web_password`是clash web仪表板的设置，分别设置web的端口和访问密码，默认值为`80`和`clashpass`。网页登录地址为`http://网关IP:端口/ui`。你可以在web端查看流量和日志，以及选择节点等。不要忘了登录地址是`/ui`。
- 6 `openport`设置是否向局域网开启一个1080端口的socks5+http代理，默认值为`no`，需要开启可以设置为`yes`。
- 7 `udp_enable`: 是否允许UDP流量通过网关，默认值为no，设置为no则禁止UDP流量进入网关。（此选项只影响路由，不影响`openport`选项）注意：如果你的节点不支持UDP或者不稳定不建议开启，开启UDP将会导致QUIC失败导致网站有时候上不去的现象。   
- 8 `sleeptime`是拉取配置检测更新的时间间隔，默认值是30，单位是秒。`sleeptime`在第一次成功获取到配置后生效，如果配置的值发生变化，将会重载网关配置。
- 9 `socks5_ip`和`socks5_port`: socks5运行模式的专用设置，指定socks5的服务器IP和端口。
- 10 `ovpnfile`，`ovpn_username`和`ovpn_password`: ovpn运行模式的专用设置，`ovpnfile`指定ovpn的文件名，系统将会从`ppgw.ini`的同一目录下载该文件。如果你的ovpn需要用户名和密码认证，可以指定`ovpn_username`和`ovpn_password`。
- 11 `yamlfile`: yaml运行模式的专用设置，指定yaml的文件名，系统将会从`ppgw.ini`的同一目录下载该文件，并使用`sleeptime`的值循环刷新检测配置文件变化，值发生变化则重载网关。
- 12 `suburl`和`subtime`: suburl运行模式的专用配置，`suburl`指定订阅的地址（记得加英文半角双引号），而`subtime`则指定刷新订阅的时间间隔，单位可以是m（分钟），h（小时）或者d（天），默认值为1d。与yaml模式不同，suburl模式使用单独的刷新间隔而不是`sleeptime`，因为订阅一般都是动态生成，每次刷新都不一样，会导致刷新网关必定重载。需要注意的是`subtime`仅配置订阅的时间间隔，检测配置变化仍然是由`sleeptime`进行。注意如果开了`fast_node`功能，检测不通的时候会主动拉新订阅。  
- 13 `fast_node`、`test_node_url`和`ext_node`：测试最快的节点并自动选择该节点的功能。`fast_node`默认值为no。如果`fast_node`值为空，并且yaml模式或者suburl的配置文件中不包含rules，则会被设置为yes。`test_node_url`是用于测速的网址，将会使用clash的api测试延迟，默认值是`http://https://www.youtube.com/generate_204`。`ext_node`是排除测速的节点，多个关键字用竖线隔开，默认值是`ext_node="Traffic|Expire| GB|Days|Date"`。`fast_node`的行为如下：
  - 当`fast_node=yes`或者`fast_node=check`，系统将会在`sleeptime`间隔检测`test_node_url`是否可达，若可达，则不进行任何操作；若不可达，则立即停止clash并秒重载网关配置，如果是suburl模式，还会在重载前拉新订阅配置。
  - 仅当`fast_node=yes`，在网关重载后对所有节点（不包括`ext_node`）进行测速，并自动选择延迟最低的节点。`fast_node=yes`会忽略加载`rules：`规则并开启`global`模式。
  - 当`fast_node=yes`仅会在`test_node_url`不可达的时候主动切换节点，不会影响你在Web手动选择节点使用。因此强烈建议习惯单节点使用的开启该项功能。或者可以使用`fast_node=check`来实现当`test_node_url`不可达的时候主动拉新订阅而不主动选择节点。
  - 注意，设置为`check`不会测速，设置为`yes`测速失败到阈值会杀死进程并终止应用网关并重载，而`check`不会杀死进程，仅重载所有配置并关闭所有现有的旧连接。  
  - 如果你的所有的节点都延迟过高不稳定，建议设置为`no`避免增加意外的断流的情况，同时你需要手动切换节点。
  - `cpudelay`选项是设定如果CPU处理延迟大于指定值则放弃本次测速。该选项是防止低性能设备负载过高导致死机，默认值为3000。设置更小的值可能会放弃更多测速，设置更高的值可能会让低性能设备负载过高。  

## 使用docker定制ISO镜像:ppwgiso
![pull](https://img.shields.io/docker/pulls/sliamb/ppgwiso.svg) ![size](https://img.shields.io/docker/image-size/sliamb/ppgwiso)   

默认的ISO是通过DHCP下发配置的，这个通常能满足大部分场景需求，然而一些企业内部的服务器网段也许只能设置静态IP，或者通过公开的http端口拉取配置觉得不够安全，或者自带的标准开源clash核心支持的功能和协议不够多等等，现在你可以通过docker镜像`sliamb/ppgwiso`，来定制你的专属ISO镜像。  
### 使用方法
现在，你可以准备一个文件夹，根据需求，选择性放入以下文件，或者不放：
#### 配置网络：`network.ini`
如果你要配置静态IP等信息，可以新建一个`network.ini`如下：
```ini
ip=10.10.10.3
mask=255.255.255.0
gw=10.10.10.1
dns1=10.10.10.8
dns2=10.10.10.9
```
#### 指定`ppgw.ini`的下载地址：`ppgwurl.ini`
如果你要指定ppgw.ini的下载地址而不是按上面的规则来寻找，比如你弄了一个带鉴权的http服务器提高安全性，防止配置泄露，你可以新建一个`ppgwurl.ini`如下：
```ini
ppgwurl="http://...."
```
#### 内嵌`ppgw.ini`
如果你想固定`ppgw.ini`的配置而不是通过http远程拉取，你可以直接在当前目录放入`ppgw.ini`。   
注意：内嵌`ppgw.ini`优先级比`ppgwurl.ini`高，同时内嵌`ppgwurl.ini`不生效。

#### 内嵌`custom.ovpn`
你可以把节点信息`custom.ovpn`放入当前目录，当`mode=ovpn`的时候将会强制使用该文件。    
注意：你仍然需要在`ppgw.ini`中指定`mode=ovpn`才会使用到该文件。

#### 内嵌`custom.yaml`
你可以把节点信息`custom.yaml`放入当前目录，当`mode=yaml`的时候将会强制使用该文件。    
注意：你仍然需要在`ppgw.ini`中指定`mode=yaml`才会使用到该文件。

#### 替换clash核心
你可以把你的amd64的clash二进制文件重命名为clash放到当前目录即可。通过替换clash核心，你可以支持更多的协议和规则功能，比如`Premium Core`支持Wireguard出站，Meta核心支持VLESS等等。   
注意：使用Wireguard出站建议设置`remote-dns-resolve: false`。  

#### 替换Country.mmdb
默认的GEOIP数据`Country.mmdb`仅包含`CN`和`PRIVATE`地址，你可以在当前目录放入你自己的Country.mmdb。  
默认的数据来源：https://github.com/kkkgo/Country-only-cn-private.mmdb  

#### 最后一步：一键生成ISO
你只需要在放好文件的当前目录执行以下命令即可一键生成镜像。  
确保在每次进行操作之前，使用`docker pull`拉取最新的镜像（不同于release版本，docker版本会每天同步最新所有上游代码）。    
在Linux上或者Windows上操作均可：
```shell
docker pull sliamb/ppgwiso
docker run --rm -v .:/data sliamb/ppgwiso
```
*如果你的网络环境访问Dokcer镜像有困难，可以尝试使用[上海交大](https://mirror.sjtu.edu.cn/docs/docker-registry)的镜像。*   

只需等待十几秒，你就可以在当前目录看到你定制的`paopao-gateway-x86-64-custom-[hash].iso`。

#### 可选：生成前置嗅探的ISO
生成前置嗅探的ISO，流量到达网关后先尝试嗅探出域名再使用FAKEIP，更适合企业环境使用：  

优点：
- 即使FAKE DNS缓存出错也能正确连接常见协议（http/tls），可以避免因网站使用了QUIC不稳定导致网页断流；   
- 重启虚拟机也不会因FAKE IP映射不正确而引起无法访问的短暂故障、对DNS TTL处理不正常的客户端兼容更好；   
- 嗅探禁止BT流量；   

缺点： 
- Web面板看不到请求的IP来源
- 需要占用更多内存
- 有可能导致UDP Type降级
- 可能会略微增加延迟

使用该功能，只需要在生成的时候加入环境变量参数`SNIFF=yes`即可：
```shell
docker pull sliamb/ppgwiso
docker run --rm -e SNIFF=yes -v .:/data sliamb/ppgwiso
```
此外，有时候节点远程解析的DNS存在问题或者存在审计，而又没有节点服务器的控制权，出于避免DNS请求泄漏到节点或者节点服务器DNS不正常等场景，如果你想在嗅探的基础上，使用本地可信任DNS（ppgw.ini中所配置的）来解析所有请求来代替远程解析，可以使用`SNIFF=dns`：
```shell
docker pull sliamb/ppgwiso
docker run --rm -e SNIFF=dns -v .:/data sliamb/ppgwiso
```
## 与DNS服务器配合完成分流
PaoPao GateWay启动后会监听53端口作为FAKEIP的DNS服务器，所有域名的查询到达的话这里都会解析成`fake_cidr`内的IP。当你在主路由添加`fake_cidr`段到PaoPao GateWay的静态路由后，你只需要把需要走网关的域名解析转发到PaoPao GateWay的53端口即可，能实现这个功能的DNS软件很多，比如有些系统自带的dnsmasq就可以指定某个域名使用某个DNS服务器。   
配合[PaoPaoDNS](https://github.com/kkkgo/PaoPaoDNS)的`CUSTOM_FORWARD`功能就可以完成简单精巧的分流，以下是一个简单的非CN IP的域名转发到PaoPao GateWay的docker compose配置：  
假设PaoPaoDNS容器IP是10.10.10.8。PaoPao GateWay的IP是10.10.10.3，还开启了`openport`功能：
```yaml
version: "3"

services:
  paopaodns:
    image: sliamb/paopaodns:latest
    container_name: PaoPaoDNS
    restart: always
    volumes:
      - /home/paopaodns:/data
    environment:
      - TZ=Asia/Shanghai
      - UPDATE=weekly
      - DNS_SERVERNAME=PaoPaoDNS,blog.03k.org
      - DNSPORT=53
      - CNAUTO=yes
      - CNFALL=yes
      - CN_TRACKER=yes
      - USE_HOSTS=no
      - IPV6=no
      - SOCKS5=10.10.10.3:1080
      - SERVER_IP=10.10.10.8
      - CUSTOM_FORWARD=10.10.10.3:53
      - AUTO_FORWARD=yes
      - AUTO_FORWARD_CHECK=yes
      - USE_MARK_DATA=yes
      - HTTP_FILE=yes
    ports:
      - "53:53/udp"
      - "53:53/tcp"
      - "5304:5304/udp"
      - "5304:5304/tcp"
      - "7889:7889/tcp"
```
需要注意的是，一小部分应用不走域名而是IP直连，比如某些聊天软件应用（比如[tg](https://core.telegram.org/resources/cidr.txt)），你只需要网上搜索一下对应的IP段，添加少量对应的的静态路由即可。  
***如果配合`PaoPaoDNS`使用，强烈建议开启`PaoPaoDNS`的`USE_MARK_DATA`功能，提升分流精准度。***     

## 构建说明
`PaoPao GateWay`iso镜像由Github Actions自动构建仓库代码构建推送，你可以在[Actions](https://github.com/kkkgo/PaoPaoGateWay/actions)查看构建日志并对比下载的镜像sha256值。

## 附录
PaoPaoDNS： https://github.com/kkkgo/PaoPaoDNS   
Clash WiKi： https://dreamacro.github.io/clash/   
Yacd： https://github.com/haishanh/yacd  
