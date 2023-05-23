## PaoPao GateWay
![PaoPaoDNS](https://th.bing.com/th/id/OIG.0FtL40H4krRLeooEGFpu?w=220&h=220&c=6&r=0&o=5&pid=ImgGn)    

PaoPao GateWay是一个体积小巧、稳定强大的FakeIP网关，系统由openwrt定制构建，核心由clash驱动，支持`Full Cone NAT` ，支持多种方式下发配置，支持多种出站方式，包括自定义socks5、自定义yaml节点、订阅模式和自由出站，支持节点测速自动选择、节点排除等功能，并附带web面板可供查看日志连接信息等。PaoPao GateWay可以和其他DNS服务器一起结合使用，比如配合[PaoPaoDNS](https://github.com/kkkgo/PaoPaoDNS)的`CUSTOM_FORWARD`功能就可以完成简单精巧的分流。   

你可以从Github Release下载到最新的镜像：[https://github.com/kkkgo/PaoPaoGateWay/releases](https://github.com/kkkgo/PaoPaoGateWay/releases)   
## [→详细说明《FakeIP网关的工作原理》](https://blog.03k.org/post/paopaogateway.html)

### 运行要求和配置下发
类型|要求
-|-
虚拟机CPU|x86-64
内存|最低128MB，推荐512MB
硬盘|不需要
网卡|1
光驱|1

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

# Set fakeip's CIDR here
# default: fake_cidr=7.0.0.0/8
fake_cidr=7.0.0.0/8

# Set your trusted DNS here
# default: dns_ip=1.0.0.1
dns_ip=10.10.10.8
# default: dns_port=53
# If used with PaoPaoDNS, you can set the 5304 port
dns_port=5304

#openport=no
# socks+http mixed 1080
openport=no

# sleeptime
sleeptime=30

# Clash's web dashboard
# default: clash_web_port="80"
clash_web_port="80"
# default: clash_web_password="clashpass"
clash_web_password="clashpass"

# mode=socks5|yaml|suburl|free
# default: socks5
mode=socks5
# default: udp_enable=yes
udp_enable=yes

# socks5 mode settting
# default: socks5_ip=gatewayIP
socks5_ip="10.10.10.5"
# default: socks5_port="7890"
socks5_port="7890"

# yaml mode settting
# The yaml file in the same directory as the ppgw.ini.
# default: yamlfile=custom.yaml
yamlfile="custom.yaml"

# suburl mode settting
suburl="https://..."
subtime=1d

# yaml and subrul mode setting
# when no rules (Global) and fast_node empty, default yes.
fast_node=yes
test_node_url="https://www.google.com/"
ext_node="Traffic|Expire| GB|Days|Date"
```
下面逐项来解释选项的用法：
- 1 配置文件第一行必须以`#paopao-gateway`开头。配置格式为`选项="值"`。
- 2 `fake_cidr`是指定你的FakeIP地址池范围。比如默认值是`7.0.0.0/8`，你需要在主路由上设置一条静态路由`7.0.0.0/8`到PaoPaoGateWay。你应该使用一些看起来是公网但实际上不是（或者不会被实际使用）的地址段，比如实验用地址段、DoD网络地址段。如果你有其他真实的公网IP段需要被网关处理，直接写对应的静态路由即可，除了指定的`fake_cidr`段会被建立域名映射，其他公网IP地址段都会被网关按普通流量处理分流。
- 3 `dns_ip`和`dns_port`用于设置可信任的DNS服务器，“可信任”意味着真实无污染的原始解析结果。如果你配合PaoPaoDNS使用，可以把`dns_ip`设置成PaoPaoDNS的IP，把`dns_port`设置成映射的5304端口，详情可参见PaoPaoDNS的可映射端口说明。该DNS服务在代理出站的时候实际上不会被用到，流量还是会以域名发送到远端，更多的是用于其他模式的节点解析、规则匹配。
- 4 `openport`设置是否向局域网开启一个1080端口的socks5+http代理，默认值为`no`，需要开启可以设置为`yes`。
- 5 `sleeptime`是拉取配置检测更新的时间间隔，默认值是30，单位是秒。`sleeptime`在第一次成功获取到配置后生效，如果配置的值发生变化，将会重载网关配置。
- 6 `clash_web_port`和`clash_web_password`是clash web仪表板的设置，分别设置web的端口和访问密码，默认值为`80`和`clashpass`。网页登录地址为`http://网关IP:端口/ui`。你可以在web端查看流量和日志，以及选择节点等。
- 7 `mode`是网关的运行模式。一共有四种模式可以选择（`socks5`,`yaml`,`subrul`,`free`）:
    - `socks5`:配置为socks5代理出站，这是最简单也是最通用的配置方式，如果其他模式不能满足你的需求，你可以把能满足你需求的服务程序开一个`socks5`代理给网关使用。
    - `yaml`：自定义clash的yaml配置文件出站。你可以自己写一个clash格式的yaml配置文件，clash支持多种出站协议，具体写法请看官方wiki。只写`proxies:`字段即可，也可以包含`rules:`字段。如果只有`proxies:`字段，在网关启动后你可以在web端选择节点；如果有`rules:`字段，则会按照你写的规则来执行。注意，网关使用开源的官方clash核心，如果你的`rules:`包含闭源Premium core的规则，则无法加载并报错，导致clash无法启动。使用开源的Clash核心是因为功能已经可以满足需求，网关本身也不适合加载过于复杂的规则，Premium core的功能会降低稳定性、增加崩溃的几率，比如`RULE-SET`功能在启动的时候下载远程url文件失败的话可能会导致clash无法正常启动，而clash无法启动的时候文件可能不能被正常下载，进入了死循环。此外，由于网关也不适用GEOIP规则，请勿写入任何GEOIP规则，因为GEOIP规则依赖GEOIP库更新，而稳定的网关不适合依赖更新运行，此外碰到GEOIP规则会触发DNS解析，降低了处理效率。如果有更复杂的规则需求，建议单独跑一个docker配置你所需的规则，开放socks5端口，让网关使用`socks5`模式。选择该模式，你需要把配置文件放在和`ppgw.ini`同一目录，系统将会在指定的`sleeptime`内循环检测配置值的变化并重载网关。
    - `suburl`：自定义远程订阅clash配置，不过是从给定的url下载配置。注意事项与`yaml`模式基本一样，不能使用包含开源clash功能之外的规则的订阅，推荐nodelist类型订阅，或者使用subconverter等程序转换订阅。需要注意的是，如果在`yaml`和`suburl`之间切换模式，你需要手动在虚拟机本地终端输入`reload`回车或者重启虚拟机。
    - `free`: 自由出站模式，选择此模式的场景是，假定你在IP层面把虚拟机IP出口走了专线，流量直接出站处理。
- 8 `udp_enable`: 是否允许UDP流量通过网关，默认值为yes，设置为no则禁止UDP流量进入网关。（此选项只影响路由，不影响`openport`选项）
- 9 `socks5_ip`和`socks5_port`: socks5运行模式的专用设置，指定socks5的服务器IP和端口。
- 10 `yamlfile`: yaml运行模式的专用设置，指定yaml的文件名，系统将会从`ppgw.ini`的同一目录下载该文件，并使用`sleeptime`的值循环刷新检测配置文件变化，值发生变化则重载网关。
- 11 `suburl`和`subtime`: subrul运行模式的专用配置，`suburl`指定订阅的地址（记得加双引号），而`subtime`则指定刷新订阅的时间间隔，单位可以是m（分钟），h（小时）或者d（天），默认值为1d。与yaml模式不同，suburl模式使用单独的刷新间隔而不是`sleeptime`，因为订阅一般都是动态生成，每次刷新都不一样，会导致刷新网关必定重载。需要注意的是`subtime`仅配置订阅的时间间隔，检测配置变化仍然是由`sleeptime`进行。
- 12 `fast_node`、`test_node_url`和`ext_node`：测试最快的节点并自动选择该节点的功能，适用于yaml和suburl运行模式。`fast_node`默认值为no，当`fast_node`设置为yes的时候有效。如果`fast_node`值为空，并且yaml模式或者suburl的配置文件中不包含rules，则会被设置为yes。`test_node_url`是用于测速的网址，将会使用clash的api测试延迟，默认值是`http://www.google.com`。`ext_node`是排除测速的节点，多个关键字用竖线隔开，默认值是`ext_node="Traffic|Expire| GB|Days|Date"`。当开启`fast_node`功能后，系统将会在`sleeptime`间隔检测`test_node_url`是否可达，若可达，则不进行任何操作；若不可达，则对所有节点（不包括`ext_node`）进行测速，并自动选择延迟最低的节点。开启该功能会忽略`rules：`规则。   

## 构建说明
`PaoPao GateWay`iso镜像由Github Actions自动构建仓库代码构建推送，你可以在[Actions](https://github.com/kkkgo/PaoPaoGateWay/actions)查看构建日志并对比下载的镜像sha256值。

## 附录
PaoPaoDNS： https://github.com/kkkgo/PaoPaoDNS   
Clash WiKi： https://dreamacro.github.io/clash/   
Yacd： https://github.com/haishanh/yacd  
