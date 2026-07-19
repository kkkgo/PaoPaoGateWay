## PaoPao GateWay
<img src="https://raw.githubusercontent.com/kkkgo/PaoPaoGateWay/main/paopaogateway.png" width="200">


PaoPao GateWay是一个体积小巧、稳定强大的FakeIP网关，核心由Rust实现的sniffbox驱动，内含智能嗅探和高效rapidhash的FakeIP算法，支持`Full Cone NAT` ，支持多种方式下发配置，支持多种出站方式，包括自定义socks5、自定义openvpn、自定义yaml节点、订阅模式和自由出站，支持节点测速自动选择、节点排除等功能，并附带web面板可供查看日志连接信息等。PaoPao GateWay可以和其他DNS服务器一起结合使用，比如配合[PaoPaoDNS](https://github.com/kkkgo/PaoPaoDNS)的`CUSTOM_FORWARD`功能就可以完成简单精巧的分流。   

你可以从Github Release下载到最新的镜像：[https://github.com/kkkgo/PaoPaoGateWay/releases](https://github.com/kkkgo/PaoPaoGateWay/releases)   
##### 如果对你有帮助，欢迎点`Star`，如果需要关注更新，可以点`Watch`。
## [→详细说明《FakeIP网关的工作原理》](https://blog.03k.org/post/paopaogateway.html)

### 运行要求和配置下发
类型|要求
-|-
虚拟机CPU|x86-64，推荐3核心或更多
内存|最低512MB，推荐1024MB或更多
硬盘|不需要
网卡|1
光驱|1  

*注意：如果节点数量很多或者连接数很多或者你的配置文件比较复杂的话，建议适当增加内存和CPU核心数*
  
#### 方式一：使用docker内嵌配置
你可以使用Docker一键定制ISO镜像，其中包括为ISO**配置静态IP**、替换Clash/mihomo核心、替换Geo数据文件、内嵌ppgw.ini等功能，**详情见使用Docker定制ISO镜像一节**。   

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
- 1 从`http://paopao.dns:7889/ppgw.ini`下载配置。使用此方式，你需要配合你的DNS服务，把`paopao.dns`这个域名解析到你的静态文件服务IP，服务端口是7889。如果配合[PaoPaoDNS](https://github.com/kkkgo/PaoPaoDNS)使用，你只需要设置`SERVER_IP`参数和设置`HTTP_FILE=yes`，映射7889端口即可，你可以直接把配置文件`ppgw.ini`放在`PaoPaoDNS`的`/data`目录。`paopao.dns`会从网卡DNS解析获取解析结果，如果结果不可用并且之前有ppgw.ini指定的dns会再尝试获取。      
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
# default: dns_ip=223.5.5.5
dns_ip=10.10.10.8
# default: dns_port=53
# If used with PaoPaoDNS, you can set the 5304 port
dns_port=5304

# Web dashboard password
clash_web_password="clashpass"

# default：openport=no
# socks+http mixed 1080
openport=no
#openport_auth="username:password"

# default: udp_enable=no
udp_enable=no

# access control (optional)
#admin_cidr="192.168.0.0/16,10.0.0.0/8"
#proxy_cidr="192.168.0.0/16,10.0.0.0/8"

# socks5 mode settting
# default: socks5_ip=gatewayIP
socks5_ip="10.10.10.5"
# default: socks5_port="7890"
socks5_port="7890"
#socks5_username="username"
#socks5_password="password"

# ovpn mode settting
# ovpnfile can be:
#   - a filename in the same directory as ppgw.ini (downloaded via the local :7889 path), or
#   - a full remote URL, e.g. ovpnfile="http://example.com/example.ovpn"
# An embedded /www/custom.ovpn (baked into the ISO/Docker image) takes priority when present.
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
#subcron=5

# fast_node=check/yes/no
fast_node=yes
test_node_url="http://cp.cloudflare.com/generate_204"
ext_node="Traffic|Expire| GB|Days|Date"
fall_direct="no"
# dns burn setting
# depend on ppsub OR fast_node=yes & mode=suburl/yaml
dns_burn=yes
ex_dns="223.5.5.5:53,1.0.0.1:53"

# Network traffic records
net_rec=no
max_rec=5000
#net_cleanday=15

# box adv tune
#box=
```
下面逐项来解释选项的用法：
- 1 配置文件第一行必须以`#paopao-gateway`开头。配置格式为`选项="值"`。
- 2 `mode`是网关的运行模式，也就是当静态路由的流量到达网关之后，怎么出去。一共有五种模式可以选择（`socks5`,`ovpn`,`yaml`,`suburl`,`free`）:
    - `socks5`:配置为socks5代理出站，这是最简单也是最通用的配置方式，如果其他模式不能满足你的需求，你可以把能满足你需求的服务程序开一个`socks5`代理给网关使用。
    - `ovpn`:配置为openvpn出站，适用于一些专线场景。
    - `yaml`：自定义clash的yaml配置文件出站。你可以自己写一个clash格式的yaml配置文件，clash支持多种出站协议，具体写法请看官方wiki。只写`proxies:`字段即可，也可以包含`rules:`字段。如果只有`proxies:`字段，在网关启动后你可以在web端选择节点；如果有`rules:`字段，则会按照你写的规则来执行。注意，网关默认内置mihomo内核并附带Geo数据（GeoSite.dat/GeoIP.dat/ASN.mmdb），`GEOSITE`/`GEOIP`规则可以直接使用，无需再替换核心；但仍建议尽量使用域名规则，IP类规则会触发额外的DNS解析，降低处理效率。网关本身不适合加载过于复杂的规则，比如启动时下载远程`RULE-SET`文件失败可能会导致核心无法正常启动，而核心无法启动的时候文件可能不能被正常下载，进入了死循环。
   - `suburl`：自定义远程订阅clash配置，不过是从给定的url下载配置。注意事项与`yaml`模式基本一样，不能使用包含开源clash功能之外的规则的订阅，或者参考**使用docker定制ISO镜像**一节更换定制的clash核心。推荐nodelist类型订阅，或者使用subconverter等程序转换订阅。
    - `free`: 自由出站模式，选择此模式的场景是，假定你在IP层面把虚拟机IP出口走了专线，流量直接出站处理。
- 3 `fake_cidr`是指定你的FakeIP地址池范围。比如默认值是`7.0.0.0/8`，你需要在主路由上设置一条静态路由`7.0.0.0/8`到PaoPaoGateWay。你应该使用一些看起来是公网但实际上不是（或者不会被实际使用）的地址段，比如实验用地址段、DoD网络地址段。如果你有其他真实的公网IP段需要被网关处理，直接写对应的静态路由即可（比如某些聊天软件走的是IP直连而不是域名），除了指定的`fake_cidr`段会被建立域名映射，其他公网IP地址段都会被网关按普通流量处理分流。[【ROS用户看这里】](https://github.com/kkkgo/PaoPaoGateWay/discussions/48#discussioncomment-7978269)  [【爱快用户看这里】](https://github.com/kkkgo/PaoPaoGateWay/discussions/26) 除了静态路由，[或者你可以顺便添加DHCP option 121优化](https://github.com/kkkgo/PaoPaoGateWay/discussions/25#discussioncomment-7221895)。
不建议使用`198.18.0.0/15`作为`fake_cidr`段，Chrome会认为这个是局域网段并警告，请参考：
  - https://developer.chrome.google.cn/blog/local-network-access?hl=zh-cn 
  - https://wicg.github.io/local-network-access/
- 4 `dns_ip`和`dns_port`用于设置可信任的DNS服务器，“可信任”意味着真实无污染的原始解析结果。如果你配合PaoPaoDNS使用，可以把`dns_ip`设置成PaoPaoDNS的IP，把`dns_port`设置成映射的5304端口，详情可参见PaoPaoDNS的可映射端口说明。该DNS服务在代理出站的时候实际上不会被用到，流量还是会以域名发送到远端，更多的是用于其他模式的节点解析、规则匹配。
- 5 `clash_web_password`是web面板的访问密码设置，默认值为`clashpass`。网页登录地址固定为`http://网关IP:80`。你可以在web端查看流量和日志，以及选择节点等。`clash_web_password`选项兼容除特殊字符外所有字符串（比如可以设置clash_web_password="一去二三里烟村四五家"）。  
- 6 `openport`设置是否向局域网开启代理端口（socks5 http 1080代理），默认值为`no`，需要开启可以设置为`yes`。
    - 当`openport=yes`且**没有**配置`openport_auth`时，外部可以直接通过`1080`端口免认证访问。
    - 可配置`openport_auth="username:password"`添加认证，格式为`"用户名:密码"`。
- 6a `admin_cidr` / `proxy_cidr`（可选）：网关访问控制。`admin_cidr`限定可访问`:80`Web控制面板的源网段，空则全放行；`proxy_cidr`限定可走TPROXY/入站代理的源网段，空则全放行。多个网段用逗号分隔。
- 7 `udp_enable`: 是否允许UDP流量通过网关，默认值为no，设置为no则禁止UDP流量进入网关。注意：如果你的节点不支持UDP或者不稳定不建议开启，开启UDP将会导致QUIC失败导致网站有时候上不去的现象。   
- 8 `socks5_ip`和`socks5_port`: socks5运行模式的专用设置，指定socks5的服务器IP和端口。如果socks5有用户验证，可以指定`socks5_username`和`socks5_password`。
- 9 `ovpnfile`，`ovpn_username`和`ovpn_password`: ovpn运行模式的专用设置。`ovpnfile`支持两种写法：①**文件名**（如`ovpnfile="custom.ovpn"`），系统将从`ppgw.ini`的同一目录（本地`:7889`路径）下载该文件；②**完整远程URL**（如`ovpnfile="http://example.com/example.ovpn"`），系统将直接从该URL下载。若镜像内已内嵌`custom.ovpn`（见下文「内嵌`custom.ovpn`」），则优先使用内嵌文件。如果你的ovpn需要用户名和密码认证，可以指定`ovpn_username`和`ovpn_password`。openvpn进程的拉起、结束与健康看护统一由常驻的sniffbox负责：`mode=ovpn`下sniffbox每30秒检查`tun114`接口与openvpn进程，发现缺失则自动冷重启openvpn（单周期最多重试5次，超阈值等下个周期再试），并在配置变化时自动加载新的ovpn配置。
- 10 `yamlfile`: yaml运行模式的专用设置，指定yaml的文件名，系统将会从`ppgw.ini`的同一目录下载该文件，并循环刷新检测配置文件变化，值发生变化则重载网关。
- 11 `suburl`和`subtime`和`subcron`: suburl运行模式的专用配置，`suburl`指定订阅的地址（记得加英文半角双引号），而`subtime`则指定刷新订阅的时间间隔，单位可以是m（分钟），h（小时）或者d（天），默认值为1d。与yaml模式不同，suburl模式使用单独的刷新间隔，因为订阅一般都是动态生成，每次刷新都不一样，会导致刷新网关必定重载。需要注意的是`subtime`仅配置订阅的时间间隔。注意如果开了`fast_node`功能，检测不通的时候会主动拉新订阅。`subcron`参数支持指定每天0-23时刷新订阅，比如`subcron=5`每天凌晨5点内刷新订阅。该参数启用的时候`subtime`参数会失效。    
- 12 `fast_node`、`test_node_url`和`ext_node`：测试最快的节点并自动选择该节点的功能。`fast_node`默认值为no。如果`fast_node`值为空，并且yaml模式或者suburl的配置文件中不包含rules，则会被设置为yes。`test_node_url`是用于测速的网址，将会使用clash的api测试延迟，默认值是`http://cp.cloudflare.com/generate_204`。`ext_node`是排除测速的节点，多个关键字用竖线隔开，默认值是`ext_node="Traffic|Expire| GB|Days|Date"`。`fast_node`的行为如下：
  - 当`fast_node=yes`或者`fast_node=check`，系统将会定时检测`test_node_url`是否可达，若可达，则不进行任何操作；若不可达，则立即停止clash并秒重载网关配置，如果是suburl模式，还会在重载前拉新订阅配置。**在 PPSUB 模式下（`suburl` 以 `ppsub@` 开头），`fast_node=check` 的代理连通性检测不会执行，因为 PPSUB 有独立的全局健康监测。**
  - 仅当`fast_node=yes`，在网关重载后对所有节点（不包括`ext_node`）进行测速，并自动选择延迟最低的节点。***`fast_node=yes`会忽略加载`rules：`规则并开启`global`模式***。  
  - 当`fast_node=yes`仅会在`test_node_url`不可达的时候主动切换节点，不会影响你在Web手动选择节点使用。因此强烈建议习惯单节点使用的开启该项功能。或者可以使用`fast_node=check`来实现当`test_node_url`不可达的时候主动拉新订阅而不主动选择节点（PPSUB 模式除外）。
  - 注意，设置为`check`不会测速，设置为`yes`测速失败到阈值会杀死进程并终止应用网关并重载，而`check`不会杀死进程，仅重载所有配置并关闭所有现有的旧连接。  
  - 如果你的所有的节点都延迟过高不稳定，建议设置为`no`避免增加意外的断流的情况，同时你需要手动切换节点。  
  - `fall_direct`选项设置为`yes`在`fast_node`测试全部节点失败的时候，若互联网路由可达，则尝试切换到`DIRECT`直连。（仅在开启`fast_node=yes`的时候生效）        
- 14 `dns_burn`选项和`ex_dns`选项：`dns_burn`功能可以把所有节点的域名解析成所有可能的IP结果，把server字段替换为解析的IP结果，以`节点名@IP最后一位`的名称作为新节点加入，临时硬编码到配置文件中。上面设置的`dns_ip`和`dns_port`，和`ex_dns`选项会被用于`dns_burn`功能，`ex_dns`选项用于指定额外的DNS用于解析节点，建议设置为境内DNS以获得不同的结果，如果为空默认值为`223.5.5.5:53`，如果配合PaoPaoDNS使用，则可以设置为PaoPaoDNSIP:53。你也可以设置多个`ex_dns`，格式为逗号分隔，比如`ex_dns=223.5.5.5:53,1.0.0.1:53`。适用于`suburl`模式和`yaml`模式，依赖于`fast_node=yes`。该功能的优点和应用场景如下：
    - 1、节点使用了分区域解析，只有使用了境内DNS才能连接，参见[issue](https://github.com/kkkgo/PaoPaoGateWay/issues/20)，`dns_burn`功能可以额外对节点进行解析。
    - 2、节点DNS解析存在多个解析入口，`dns_burn`功能会把所有可能的入口都作为新节点加入到配置文件中，在测速的时候就可以选择到速度最好的入口，而不是随机选择。
    - 3、节点的所有可能的解析结果都会被临时硬编码到配置文件中，除非所有节点都测速失败或者订阅更新，该配置文件不会变化，可以减少节点的DNS查询，使用IP直连，并有效避免节点临时出现可能的DNS污染或者DNS故障的情况，比如节点域名忘记续费导致解析失败。
- 15 `net_rec`选项：网络流量记录功能，可以记录网关连接了哪些域名、上传下载消耗了多少流量、客户端IP，并默认按照消耗流量的大小排序，该功能可以根据实际情况方便地调整分析自己的域名规则列表。设置为`yes`开启该功能后可以在web界面查看、统计分析和下载记录。其中`max_rec`选项指定最大记录数，默认为5000。注意事项：  
    - 1、重启或者修改ppgw的密码、`max_rec`选项、调整任何和`net_rec`相关选项会导致sniffbox重启并清空历史记录。
    - 2、如果流量太小连接持续时间过短，有可能在记录之前连接已经关闭，流量有可能会显示为0B。
    - 3、理论上会略微增加资源占用，取决于你的并发连接数量以及`max_rec`，可适当增加运行资源。
`net_cleanday=1-31`选项，指定每个月某一天清空网络流量数据记录，比如`net_cleanday=15`每月15日清空网络流量数据记录。如果指定值大于当月有效天数，比如2月份指定31，将会取该月最大值执行，该值为空的时候只有达到了max_rec限制才会清理。    
- 16 `box`: 高级转发核心项目调整，以逗号分隔，一般不需要调整。可调整项目示例`route.block_bittorrent=true,route.block_quic=true,route.block_unknown=false`。 block_bittorrent：禁止bt下载（默认true）；block_quic：禁止quic流量(默认true)，block_unknown：禁止非http/tls的未识别流量（默认false）。   

## PPSUB 组合订阅使用指南

#### 基本使用流程

1. 从左侧菜单 PPsub 编辑器开始，编辑你的订阅提供商、节点组、规则组后，导出 json 文件。也可以下载离线编辑器：https://github.com/kkkgo/PaoPaoGateWay/blob/main/ppsub_offline.html
2. 导出了 json 配置后，设置 `ppgw.ini` 的 `mode=suburl`， 设置 `suburl="ppsub@http://.../ppsub.json"`（suburl 前面加 `ppsub@`）

#### 全局健康监测
开启全局健康监测，可以在指定url监测失败的时候，重新处理和拉取所有PaoPaoGateway配置。

#### 订阅提供商

提供订阅的 url，相当于 suburl。假设你有多个订阅，你可以添加多个订阅提供商。

- 勾选强制依赖的属性会要求必须下载到该订阅，否则当处理失败，全部重来
- 当没有订阅提供商被勾选强制依赖，则至少需要一个订阅提供商被下载成功
- 如果节点组依赖的订阅提供商没有下载成功，则跳过生成节点组。

> **注意**：请不要把这个区域和第三方的 `proxy-providers` 功能混淆，PPsub 不使用这个功能，PPSub有专用的处理过程。

#### 节点组

根据关键字、排除关键字、订阅提供商的组合，组合出你的节点组，用于规则分流。  
节点组可以嵌套其他节点组，但关键字筛选仅对来自订阅提供商的节点生效。
**示例**：你想筛选了某些节点用于访问 openai 网站，命名为"AI 专用"，则后续在规则中可以使用 `geosite,openai,AI专用` 这样的规则。

**模式说明**：
- **手动选择模式**：需要在配置加载后你自己选择一个节点组里的节点
- **测速模式**：这个节点组会根据提供的测速 url 来自动选择节点，例如填写 `https://openai.com/`

#### 规则组

在规则组可以编写你的分流规则，也可以选择从指定url下载规则（要求正常yaml格式，会提取下载yaml文件的`rules`字段），或者下载`RULE-SET`订阅。

**格式**：规则类型,匹配内容,节点组名称（或者内置策略：`REJECT`、`DIRECT`）

**示例**：`GEOSITE,openai,ai专用`

**参考资料**：
- 规则语法参考：https://wiki.metacubex.one/config/rules/
- geosite 参考：https://github.com/v2fly/domain-list-community/tree/master/data

**提示**：
- 如果规则引用的节点组不存在或者没有处理成功，则跳过该条规则。
- 请尽量使用域名规则，使用 IP 相关规则会触发额外的 DNS 解析动作
- **重要**：请不要忘记最后使用 match 规则兜底，比如 `match,all`（假设你有一个节点组叫 all）


#### PPSUB 模式下的配置项说明

**被禁用的选项**：
- fast_node 相关选项（fast_node/test_node_url/ext_node/fall_direct）
- 相关功能请在节点组中定义；其中 `fast_node=check` 在 PPSUB 模式下不会执行代理连通性检测，由 PPSUB 自身的全局健康监测负责

**参考使用的选项**：
- `dns_burn=yes`：当节点是域名，会把节点再次额外解析成 IP 节点，以节点名@+IP最后一位增加到节点组
- `ex_dns`：当 `dns_burn=yes`，此处的 DNS 服务器会被再次使用解析，如有额外结果会增加到节点组。此外会主动尝试读取订阅提供的DNS配置用于解析节点，如果有额外可用的解析结果，将会为节点添加@subdns后缀
**生效的选项**：
- `subtime`、`subcron` 和 `suburl` 一样定时刷新订阅

## 使用docker定制ISO镜像:ppgwiso  
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
如果`ip`值为空或者无有效值，则忽略以上设置，IPv4将使用dhcp进行分配。  
如果要开启IPv6特性，请加入以下配置：
```ini
ip6=auto
```
该配置将会使用`DHCPv6 + SLAAC`获取IPv6地址。  
如果需要配置静态IPv6地址，配置示例如下：  
```ini
ip6=240e:3b6:2333:4444:215:5dff:fe0a:e200/64
gw6=fe80::2a3c:8ff:fe47:28e7
```
如果需要额外配置一个静态ULA地址，可以使用`ula`选项：  
```ini
ula=fd10:10:10::3/64
```
IPv4配置和IPv6配置可以同时写入。当缺少IPv4配置的时候默认使用dhcpv4，当缺少IPv6配置的时候默认删除IPv6功能。  
IPv6支持静态路由到网关。详情参考文档：https://github.com/kkkgo/PaoPaoGateWay/discussions/209   
**虚拟机网卡分配的dns仅用于拉取`ppgw.ini`无其他作用。只有一个dns就只填dns1。*    
###### 特殊场景高级配置：自定义局域网属性地址
*如果你看不懂下面这段文字，说明你没有这个场景需求，请不要配置它。*
如果你的局域网CIDR是由非标准局域网地址组成的，或者代理目标含有局域网地址，那么你可以增加以下配置到`network.ini`来重定义局域网属性地址，可以增删示例配置中的CIDR段，以逗号分隔：
```ini
localnet="10.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.168.0.0/16"
```
同理，如果存在非标准的IPv6局域网段，可以定义localnet6。
#### 指定`ppgw.ini`的下载地址：`ppgwurl.ini`
如果你要指定ppgw.ini的下载地址而不是按上面的规则来寻找，比如你弄了一个带鉴权的http服务器提高安全性，防止配置泄露，你可以新建一个`ppgwurl.ini`如下：
```ini
ppgwurl="http://...."
```
#### 内嵌`ppgw.ini`
如果你想固定`ppgw.ini`的配置而不是通过http远程拉取，你可以直接在当前目录放入`ppgw.ini`。   
注意：内嵌`ppgw.ini`优先级比`ppgwurl.ini`高，同时内嵌`ppgwurl.ini`不生效。

#### 内嵌`custom.ovpn`
你可以把节点信息`custom.ovpn`放入当前目录（或制作ISO/Docker镜像时放入`/data/custom.ovpn`，`remakeiso.sh`会自动内嵌），当`mode=ovpn`的时候将会强制使用该文件，其优先级高于`ovpnfile`指定的文件名/远程URL。内嵌时会自动归一化CRLF换行（兼容Windows导出的`.ovpn`）。    
注意：你仍然需要在`ppgw.ini`中指定`mode=ovpn`才会使用到该文件。

#### 内嵌`custom.yaml`
你可以把节点信息`custom.yaml`放入当前目录，当`mode=yaml`的时候将会强制使用该文件。    
注意：你仍然需要在`ppgw.ini`中指定`mode=yaml`才会使用到该文件。

#### 内嵌`ppsub.json`
你可以把`ppsub.json`放入当前目录，当`mode=suburl`的时候将会强制使用该文件。    
注意：你仍然需要在`ppgw.ini`中指定`mode=suburl`才会使用到该文件。

#### 替换clash/mihomo核心
你可以把你的amd64的clash/mihomo二进制文件重命名为clash放到当前目录即可。通过替换clash核心，你可以支持更多的协议和规则功能，比如替换为[mihomo](https://github.com/MetaCubeX/mihomo/releases)。   
常见问题： [我应该下载哪一个文件？](https://github.com/MetaCubeX/mihomo/wiki/FAQ)   
你应该下载类似mihomo-linux-amd64-v3-xxx.gz的文件并解压重命名为clash   
如果你的虚拟机平台不支持v3 CPU（比如PVE，默认类型不支持，你需要把CPU类别设置为host）或者不确定你应该下载什么，那么你应该下载类似mihomo-linux-amd64-compatible-xxx.gz的文件并解压重命名为clash   

*内置核心*：如果当前目录没有放入自定义核心，将默认使用镜像内置的mihomo内核（compatible版本，不一定是最新版本）。如果你的CPU和虚拟机平台支持v3（比如PVE需要把CPU类别设置为host），可以使用`-e MI=3`使用内置的mihomo v3版本。
#### 替换Geo数据文件
默认情况下镜像会附带完整的Geo数据文件（GeoSite.dat/GeoIP.dat/ASN.mmdb，并附`update.log`记录上游数据的更新日期），`GEOSITE`/`GEOIP`规则开箱可用。    
如果规则不含或者不需要Geo数据，可以设置`-e GEO=no`以减小镜像体积。默认为yes。      
支持引入自定义Geo数据文件，当目录下存在`mmdb`或`dat`格式文件的时候会自动复制进镜像。当复制了任意Geo数据文件时，将会删除所有自带的数据文件。  

#### 最后一步：一键生成ISO
你只需要在放好文件的当前目录执行以下命令即可一键生成镜像。  
确保在每次进行操作之前，使用`docker pull`拉取最新的镜像（不同于release版本，docker版本会每天同步最新所有上游代码）。    
在Linux上或者Windows上操作均可(在Linux路径错误的话，`.:/data`可以换成`$(pwd):/data`)：
```shell
docker pull sliamb/ppgwiso
docker run --rm -v .:/data sliamb/ppgwiso
```
如果你的网络环境访问Docker Hub镜像有困难，***可以尝试使用public.ecr.aws镜像:***    
- 示例： `docker pull public.ecr.aws/sliamb/ppgwiso`  
- 示例： `docker run -d public.ecr.aws/sliamb/ppgwiso`  

只需等待十几秒，你就可以在当前目录看到你定制的`ppgw-version-[hash].iso`。  

#### 可选：物理网卡直通
镜像因为是虚拟机专用默认仅包含虚拟网卡驱动，如果有物理网卡直通需求，你可以把定制的docker镜像切换成`fullmod`版本，增加驱动(还包含qemu-ga/open-vm-tools)：  
```shell
docker pull sliamb/ppgwiso:fullmod
docker run --rm -v .:/data sliamb/ppgwiso:fullmod
```
*注：`fullmod`附带了所有可能支持的网卡驱动和相关模块，生成的镜像会大20M左右，可适当增加运行内存。*

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
需要注意的是，一小部分应用不走域名而是IP直连，比如某些聊天软件应用（比如telegram，Netflix），你只需要网上搜索一下对应的IP段(可以使用https://geo.03k.org/  点`IP matches`)，添加少量对应的的静态路由即可。  
***如果配合`PaoPaoDNS`使用，强烈建议开启`PaoPaoDNS`的`USE_MARK_DATA`功能，提升分流精准度。***     
注：[抓取跳过域名参考](https://github.com/kkkgo/PaoPaoDNS/discussions/47#discussioncomment-7217219)

## 更多教程
由于每个人的网络拓扑平台和路由系统不一样，可能没有通用的详细教程，你可以在论坛查看其他人的[配置分享](https://github.com/kkkgo/PaoPaoGateWay/discussions/categories/%E9%85%8D%E7%BD%AE%E5%88%86%E4%BA%AB)，如果你成功部署了网关，欢迎在论坛分享你的相关过程或者解决方案给其他人参考。  

## 构建说明
`PaoPao GateWay`iso镜像由Github Actions自动构建仓库代码构建推送，你可以在[Actions](https://github.com/kkkgo/PaoPaoGateWay/actions)查看构建日志并对比下载的镜像sha256值。

## 附录
PaoPaoDNS： https://github.com/kkkgo/PaoPaoDNS   
mihomo releases: https://github.com/MetaCubeX/mihomo/releases  
mihomo config: https://github.com/MetaCubeX/mihomo/blob/Alpha/docs/config.yaml    
mihomo wiki: https://wiki.metacubex.one/config/proxies/    
Geo数据工具： https://github.com/kkkgo/PaoPaoGateWay/discussions/188