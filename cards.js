// 牌组数据：全部来自 网络安全教学/learning-records/ 的检查点与已纠正表述
// 规则：一卡一检查点；正面问"是什么/为什么/如何判断"；背面：结论 + 成立条件 + 最小例子 + 修复/失败信号
// id 是稳定标识符（进度存在手机 localStorage 里靠它对应），以后加卡可以追加，但不要改已有 id

const DECKS = [
  { id: "all", name: "全部" },
  { id: "source-sink", name: "Source / Sink 模型" },
  { id: "cmd", name: "命令注入" },
  { id: "owasp", name: "OWASP Top 10" },
  { id: "owasp-hook", name: "编号挂钩" },
  { id: "owasp-boundary", name: "易混边界" },
];

const CARDS = [
  // ===== Source / Sink 模型 =====
  {
    id: "ss-source", deck: "source-sink",
    q: "代码：name = request.args.get(\"name\")，sql = \"SELECT * FROM users WHERE name = '\" + name + \"'\"，cursor.execute(sql)。source 是哪个表达式？",
    a: "source = request.args.get(\"name\") —— 从 HTTP 查询参数取得不可信输入。规则：回答 source/sink 必须落到具体变量、函数或语句，不能背通用定义。",
  },
  {
    id: "ss-sink", deck: "source-sink",
    q: "上面三行代码里，sink 是哪个调用？只写方法名算不算完整？",
    a: "sink = cursor.execute(sql)。执行 SQL 的危险接口。只写 cursor.execute 不完整，必须带参数；且'接收数据的地方'不等于危险 sink，sink 定义要窄。",
  },
  {
    id: "ss-interp", deck: "source-sink",
    q: "上面三行代码里，SQL 解释器是什么？是 cursor 吗？",
    a: "解释器 = 数据库 SQL 解析/执行引擎。cursor.execute(sql) 只是应用侧把 SQL 发给数据库驱动的调用（sink）；真正把语法解析出来的是数据库端，不是 cursor 对象。",
  },
  {
    id: "ss-params", deck: "source-sink",
    q: "参数绑定之后，用户输入被数据库当成什么？这如何让 ' OR 1=1 -- 失效？",
    a: "输入被当成参数值（value），不是 SQL 语法。数据库按固定模板解析，payload 整段作为 username 的值参与比较，条件不成立，返回空结果。核心句：参数绑定把输入当值、不当语法。",
  },
  {
    id: "ss-payload", deck: "source-sink",
    q: "输入 ' OR 1=1 -- 在字符串拼接版本里逐段起什么作用？",
    a: "' 提前结束 username 的字符串字面量 → 后面内容变成 SQL 语法；OR 1=1 使条件恒真，返回所有行；-- 注释掉剩余的密码条件。三段各做一件事，少说了任何一段都不完整。",
  },
  {
    id: "xss-trio", deck: "source-sink",
    q: "代码：const q = new URLSearchParams(location.search).get(\"q\")；document.querySelector(\"#output\").innerHTML = q。source / sink / 解释器各是什么？",
    a: "source = URLSearchParams(...).get(\"q\")；sink = innerHTML = q 赋值语句；解释器 = 浏览器 HTML 解析器（不是 SQL 引擎——换上下文换解释器，模型不变）。",
  },
  {
    id: "xss-chain", deck: "source-sink",
    q: "上面代码里输入 <img src=x onerror=alert(1)>，完整触发链是什么？",
    a: "URL 参数 q → innerHTML → HTML 解析器把字符串解析成 DOM，创建 img 元素节点（不是一段字符串文本）→ src=x 加载失败触发 error 事件 → 浏览器调用 onerror 处理器 → JavaScript 引擎执行 alert(1)。",
  },
  {
    id: "xss-fix", deck: "source-sink",
    q: "修 DOM XSS 最该改 source 还是 sink？改用 textContent 后页面显示什么？",
    a: "改 sink。用 textContent 或按上下文编码；source 端校验只是补充。textContent 把 payload 当文本节点显示（页面显示字面量 <img…>），不创建元素、不触发 onerror。source 不可控，控制解释行为在 sink。",
  },
  {
    id: "xss-richtext", deck: "source-sink",
    q: "业务必须支持用户提交 <b>hello</b> 且能真正加粗，但不能执行 onerror。怎么处理？",
    a: "textContent 会显示字面量 <b>，不行。正确链路：可信 HTML 净化器（DOMPurify 类）按标签/属性白名单净化 → 净化后的 HTML → innerHTML。白名单需移除事件属性、script、iframe、危险 URL；不是 innerHTML 自己执行白名单。普通文本仍用 textContent。",
  },

  // ===== 命令注入 =====
  {
    id: "cmd-trio", deck: "cmd",
    q: "代码：host = request.args.get(\"host\")，cmd = \"ping -c 1 \" + host，subprocess.run(cmd, shell=True)。source / sink / 解释器各是什么？",
    a: "source = request.args.get(\"host\")；sink = subprocess.run(cmd, shell=True)；解释器 = 系统 Shell（POSIX 的 /bin/sh 或 Windows 的 cmd.exe），由它解析 cmd 字符串。subprocess.run 不是解释器，它只是把字符串交给 Shell。",
  },
  {
    id: "cmd-argv", deck: "cmd",
    q: "shell=True 和 shell=False + 参数列表，本质区别是什么？最小修复怎么写？",
    a: "shell=True：整串命令交给 Shell，管道、分号、命令替换都被解释。shell=False + 列表：不启动 Shell，每个列表元素作为独立 argv 传给固定程序。修复：subprocess.run([\"ping\", \"-c\", \"1\", host], shell=False)，再对 host 做语义校验。",
  },
  {
    id: "cmd-semicolon", deck: "cmd",
    q: "shell=False 且参数列表时，host 输入为 \"1.1.1.1; whoami\"，whoami 会被执行吗？",
    a: "不会。没有 Shell 来解释分号，ping 收到包含 ; whoami 的完整字符串作为一个参数（可能因主机名非法报错），whoami 不会被当成第二条命令。",
  },
  {
    id: "cmd-option", deck: "cmd",
    q: "shell=False 时输入 host = \"-f\" 还有没有风险？为什么？",
    a: "有风险（选项注入）。shell=False 只阻止 Shell 解释特殊字符；目标程序自己仍会解析以 - 开头的参数。必要时用程序支持的参数终止符或严格白名单。",
  },
  {
    id: "cmd-list", deck: "cmd",
    q: "黑名单和白名单分别能不能可靠防住命令注入？",
    a: "黑名单不能：Shell 语法面大（分隔符/管道/重定向/命令替换/通配符），有编码绕过、平台差异，过滤时机不对时发生在解码/拼接之前。白名单在严格、语义化、正确阶段校验时可作防御层，但要拒绝而非删除危险字符，且不能替代安全执行。核心仍是固定程序 + argv + shell=False。",
  },

  // ===== OWASP 台词卡 =====
  {
    id: "owasp-a01-scene", deck: "owasp",
    q: "场景：用户 A 登录后把订单号 1001 改成 1002，看到用户 B 的订单。SQL 已参数化。三句话回答：",
    a: "① 不是 SQL 注入：参数绑定让输入只是订单编号的值，没变成 SQL 语法。② 这是 A01 访问控制失效（横向越权）：服务端没检查订单 1002 的归属。③ 修复：服务端在每次读取/修改/删除对象前检查 owner_id == 当前用户。",
  },
  {
    id: "owasp-a02", deck: "owasp",
    q: "A02 安全配置错误：它和业务代码写错有什么本质不同？给 3 个一眼识别场景 + 防御主线。",
    a: "本质：不是算法写错，是系统/框架/云服务的设置让它不安全工作。场景：admin/admin 默认凭据、生产开调试模式返回堆栈、云存储桶公开可下、多余示例页面。防御：安全默认值、最小化安装（删示例/测试/默认账户）、统一基线用配置扫描验证、不硬编码密钥。",
  },
  {
    id: "owasp-a02-scene", deck: "owasp",
    q: "场景：生产站保留安装示例后台，默认账号还是 admin/admin，调试模式开着返回完整堆栈。属于哪类？哪一点最直接导致未授权进入？说出三条修复。",
    a: "A02 安全配置错误。最直接的是默认凭据 admin/admin（调试堆栈主要帮攻击者侦察）。修复：删除示例页面和默认账户、关闭生产调试/用通用错误页+集中记录详细信息、建立可扫描的安全基线。",
  },
  {
    id: "owasp-a03-scene", deck: "owasp",
    q: "场景：项目引用第三方日志库，只知道直接依赖版本，不追踪间接依赖，不锁定来源，不校验构建产物。属于哪类？说出两个可能出问题的环节和三条防御。",
    a: "A03 软件供应链失效（2025 版已从'组件过旧'扩大到整条链）。危险环节：包管理器安装脚本执行恶意代码、更新服务器被攻破携带后门、CI/CD 凭据权限过大改产物。防御：SBOM 盘点含间接依赖、锁定可信来源和版本、签名/哈希校验制品、仓库与构建系统最小权限。",
  },
  {
    id: "owasp-a09", deck: "owasp",
    q: "日志、监控、告警、响应分别是什么？只有日志够不够？A09 失效的实际后果是什么？",
    a: "日志=记录发生了什么；监控=持续观察；告警=达到阈值通知负责人；响应=有人调查/隔离/修复/复盘。只有日志不够——没有告警和响应，攻击进行很久也发现不了。A09 的后果：无证据（无法还原）或留了日志却无人处置。还要保护日志本身：统一收集、防篡改删除、不记录密码和完整 token。",
  },
  {
    id: "owasp-a10-scene", deck: "owasp",
    q: "代码：try { allowed = check_permission(user) } catch { allowed = True }。这是什么问题？为什么危险？正确做法叫什么？",
    a: "A10 异常处理不当里的'失败放行'：权限检查出错后反而放行，异常绕过了安全控制。正确做法是失败关闭（失败时默认拒绝）。其他 A10 形态：多步交易中间失败不回滚、错误页泄露堆栈版本、资源未释放被耗尽。",
  },
  {
    id: "owasp-md5", deck: "owasp",
    q: "场景：数据库里存的是 md5(password)。属于哪类？为什么快哈希不行？说出两个可用替代和一组必考边界。",
    a: "A04 加密机制失效。MD5 是快速哈希，泄露后可被预计算表/高性能设备快速碰撞；密码哈希应设计为慢且不可逆。替代：Argon2id、scrypt、PBKDF2（兼容旧系统用 bcrypt），配随机盐+工作因子。边界：哈希≠加密（加密通常可解密）；Base64≠加密只是编码。",
  },
  {
    id: "owasp-a08-scene", deck: "owasp",
    q: "场景：设备从厂商服务器下载固件更新后直接安装，不校验签名。为什么'文件能下载成功'不等于可信？属于哪类？",
    a: "A08 完整性失效。能下载只证明网络可达，不证明内容来自可信来源且未被中间人替换。修复：更新包数字签名并在使用前验证；哈希值必须来自可信渠道（同一不可信页面拿哈希没意义）；不可信序列化数据要先校验，Cookie/令牌不能直接信客户端字段。",
  },

  // ===== 编号挂钩 =====
  {
    id: "hook-1-5", deck: "owasp-hook",
    q: "闭卷：说出 A01-A05 对应的挂钩词。",
    a: "A01 门卫，A02 开关，A03 链条，A04 锁，A05 注射器。",
  },
  {
    id: "hook-6-10", deck: "owasp-hook",
    q: "闭卷：说出 A06-A10 对应的挂钩词。",
    a: "A06 图纸，A07 身份证，A08 签名，A09 日志本，A10 保险丝。",
  },
  {
    id: "hook-a01", deck: "owasp-hook",
    q: "A01（门卫）：一眼识别场景 + 防御主线？",
    a: "场景：改订单号看别人的订单；普通用户直接访问管理员接口。防御主线：服务端检查对象归属、角色和功能权限；默认拒绝；权限检查在服务端。",
  },
  {
    id: "hook-a02", deck: "owasp-hook",
    q: "A02（开关）：一眼识别场景 + 防御主线？",
    a: "场景：debug 开启、默认密码、公开存储桶、多余端口和示例应用。防御主线：安全默认值、最小化安装、自动化配置基线检查。",
  },
  {
    id: "hook-a03", deck: "owasp-hook",
    q: "A03（链条）：一眼识别场景 + 防御主线？",
    a: "场景：依赖、构建、分发、更新渠道整条链被污染。防御主线：SBOM、可信来源并锁定版本、构建系统最小权限、签名与补丁管理。",
  },
  {
    id: "hook-a04", deck: "owasp-hook",
    q: "A04（锁）：一眼识别场景 + 防御主线？",
    a: "场景：MD5 保存密码、明文传输（HTTP）、密钥硬编码、可预测 token、证书不校验。防御主线：全站 TLS、专用密码慢哈希+盐、密钥管理系统、安全随机数。注意：哈希≠加密，Base64≠加密。",
  },
  {
    id: "hook-a05", deck: "owasp-hook",
    q: "A05（注射器）：一眼识别场景 + 防御主线？",
    a: "场景：输入进入 SQL、Shell、HTML、模板并变成语法（数据和指令没分开）。防御主线：参数绑定、上下文编码、固定程序+参数列表。根因同一：解释器把数据当成指令。",
  },
  {
    id: "hook-a06", deck: "owasp-hook",
    q: "A06（图纸）：一眼识别场景 + 防御主线？",
    a: "场景：优惠券无限使用、一次预订六百个座位、安全问题找回密码。本质：设计阶段就没定义防滥用约束，改代码写法修不了，要改业务规则。防御主线：威胁建模、业务限制、滥用用例。",
  },
  {
    id: "hook-a07", deck: "owasp-hook",
    q: "A07（身份证）：一眼识别场景 + 防御主线？",
    a: "场景：爆破、撞库、会话固定、退出后会话仍有效、登录错误提示能区分账号存在。防御主线：MFA、限速、登录后轮换会话 ID、服务端会话失效、统一错误提示防枚举。",
  },
  {
    id: "hook-a08", deck: "owasp-hook",
    q: "A08（签名）：一眼识别场景 + 防御主线？",
    a: "场景：更新包不验签直接安装、不可信反序列化、直接相信客户端传来的权限字段。防御主线：数字签名并使用前验证、哈希/来源证明来自可信渠道、安全反序列化。",
  },
  {
    id: "hook-a09", deck: "owasp-hook",
    q: "A09（日志本）：一眼识别场景 + 防御主线？",
    a: "场景：不记录失败登录、无告警、日志只在本机且攻击者拿到权限后能删除。防御主线：记录安全事件、集中保护防篡改、监控、告警和响应链路完整。",
  },
  {
    id: "hook-a10", deck: "owasp-hook",
    q: "A10（保险丝）：一眼识别场景 + 防御主线？",
    a: "场景：异常后放行（catch 里 allowed=True）、多步交易不回滚、错误页泄露内部信息、资源耗尽。防御主线：失败关闭、事务回滚、统一异常处理、资源限制。",
  },
  {
    id: "hook-a06-scene", deck: "owasp-hook",
    q: "场景：优惠券可以无限重复使用。属于哪类？为什么不主要归 A01 或 A02？",
    a: "A06 不安全设计：业务规则在设计时缺少单用户次数、叠加规则、库存和频率限制等防滥用控制。它不是权限检查缺失（A01）也不是配置错误（A02）——光换实现改不掉，必须在设计层面加约束。",
  },
  {
    id: "hook-a07-scene", deck: "owasp-hook",
    q: "场景：登录无限尝试 + 登录后沿用旧会话 ID + 退出只删浏览器 Cookie。属于哪类？为什么删 Cookie 不算会话失效？",
    a: "A07 身份认证失效。删 Cookie 只清了客户端一份副本，服务器端会话仍有效、可被复用（劫持/回放）。修复：登录限速、登录成功后轮换新的高熵会话 ID、退出/超时在服务端使会话失效。边界提醒：会说'A04 是密码失效'是错的——密码怎么保存属于 A04。",
  },

  // ===== 易混边界 =====
  {
    id: "bound-authn-authz", deck: "owasp-boundary",
    q: "认证和授权各回答什么问题？一句话区分，并说明参数绑定能否替代授权检查。",
    a: "认证：你是谁？授权：你能对哪个对象做哪个动作？登录成功不等于有权访问所有对象。参数绑定只解决 SQL 注入（语法边界），不能替代对象归属检查（权限边界）。",
  },
  {
    id: "bound-a01-a05", deck: "owasp-boundary",
    q: "A01 与 A05 的边界：改订单号看到别人数据 vs 输入改变 SQL 结构，各属于哪个？",
    a: "改对象编号后看到别人的数据 → A01 权限边界（输入还是值，只是归属检查缺失）。输入改变 SQL/HTML/命令的结构 → A05 语法边界（数据和指令没分开）。先问：输入有没有变成语法？",
  },
  {
    id: "bound-a03-a08", deck: "owasp-boundary",
    q: "A03 与 A08 的边界各盯什么？",
    a: "A03：依赖、构建、分发整条生态是否可信（链条视角）。A08：某个具体制品（更新包/反序列化数据/令牌）的完整性校验是否失败（单件视角）。从被攻破供应商下载更新两者重叠，说明主要失败点即可。",
  },
  {
    id: "bound-a04-a07", deck: "owasp-boundary",
    q: "A04 与 A07 的边界：密码保存、TLS、密钥、随机数归谁？登录限速、MFA、会话固定归谁？",
    a: "密码如何保存/保护（哈希、TLS、密钥、随机数、证书验证）→ A04 加密机制失效。登录、MFA、限速、会话轮换、退出失效、账号枚举 → A07 身份认证失效。一句话：A04 管密码学实现，A07 管登录与会话流程。",
  },
  {
    id: "bound-a02-a06-a09", deck: "owasp-boundary",
    q: "一句话区分 A02 / A06 / A09 的根因视角。",
    a: "A02 是'配置让它变得不安全'；A06 是'业务设计本身没有安全约束'；A09 是'没有日志、告警或处置'。配置错误可以进一步导致 A01、A05 等，分类看根因和主要失败点。",
  },
];