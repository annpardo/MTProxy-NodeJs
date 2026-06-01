'use strict'

const { MTProtoProxy } = (function()
{
	const module={exports:{}};
	const exports=module.exports;
'use strict'

const net = require('net');
const https =require('https');
const crypto = require('crypto');
const os = require('os');
const REQUEST_TIMEOUT_MS = 5000;
const REQUEST_MAX_BYTES = 1024 * 1024;

function rp(url)
{
	return new Promise(function(accept,reject)
	{
		let rawData=[];
		let rawLength=0;
		let settled=false;
		function finish(err,data)
		{
			if (settled)
				return;
			settled=true;
			if (err)
			{
				c.destroy();
				reject(err);
			}
			else
				accept(data);
		}
		let c=https.get(url,function(res)
		{
			if (res.statusCode!==200)
			{
				res.resume();
				return finish(new Error(`Status code is ${res.statusCode}`));
			}
			res.on('data',function(ret)
			{
				rawLength+=ret.length;
				if (rawLength>REQUEST_MAX_BYTES)
					return finish(new Error('Response is too large'));
				rawData.push(ret);
			})
			res.on('end',function()
			{
				finish(null,Buffer.concat(rawData,rawLength));
			})
		})
		c.setTimeout(REQUEST_TIMEOUT_MS,function(){finish(new Error('Request timed out'))});
		c.on('error',finish);
	})
}

let TABLE=new Uint32Array(256)
Buffer.from([
'AAAAAJYwB3csYQ7uulEJmRnEbQeP9GpwNaVj6aOVZJ4yiNsOpLjceR7p1eCI2dKXK0y2Cb18sX4HLbjn',
'kR2/kGQQtx3yILBqSHG5895BvoR91Noa6+TdbVG11PTHhdODVphsE8Coa2R6+WL97Mllik9cARTZbAZj',
'Yz0P+vUNCI3IIG47XhBpTORBYNVycWei0eQDPEfUBEv9hQ3Sa7UKpfqotTVsmLJC1sm720D5vKzjbNgy',
'dVzfRc8N1txZPdGrrDDZJjoA3lGAUdfIFmHQv7X0tCEjxLNWmZW6zw+lvbieuAIoCIgFX7LZDMYk6Qux',
'h3xvLxFMaFirHWHBPS1mtpBB3HYGcdsBvCDSmCoQ1e+JhbFxH7W2BqXkv58z1LjooskHeDT5AA+OqAmW',
'GJgO4bsNan8tPW0Il2xkkQFcY+b0UWtrYmFsHNgwZYVOAGLy7ZUGbHulARvB9AiCV8QP9cbZsGVQ6bcS',
'6ri+i3yIufzfHd1iSS3aFfN804xlTNT7WGGyTc5RtTp0ALyj4jC71EGl30rXldg9bcTRpPv01tNq6WlD',
'/NluNEaIZ63QuGDacy0EROUdAzNfTAqqyXwN3TxxBVCqQQInEBALvoYgDMkltWhXs4VvIAnUZrmf5GHO',
'DvneXpjJ2SkimNCwtKjXxxc9s1mBDbQuO1y9t61susAgg7jttrO/mgzitgOa0rF0OUfV6q930p0VJtsE',
'gxbccxILY+OEO2SUPmptDahaanoLzw7knf8JkyeuAAqxngd9RJMP8NKjCIdo8gEe/sIGaV1XYvfLZ2WA',
'cTZsGecGa252G9T+4CvTiVp62hDMSt1nb9+5+fnvvo5DvrcX1Y6wYOij1tZ+k9GhxMLYOFLy30/xZ7vR',
'Z1e8pt0GtT9LNrJI2isN2EwbCq/2SgM2YHoEQcPvYN9V32eo745uMXm+aUaMs2HLGoNmvKDSbyU24mhS',
'lXcMzANHC7u5FgIiLyYFVb47usUoC72yklq0KwRqs1yn/9fCMc/QtYue2Swdrt5bsMJkmybyY+yco2p1',
'CpNtAqkGCZw/Ng7rhWcHchNXAAWCSr+VFHq44q4rsXs4G7YMm47Skg2+1eW379x8Id/bC9TS04ZC4tTx',
'+LPdaG6D2h/NFr6BWya59uF3sG93R7cY5loIiHBqD//KOwZmXAsBEf+eZY9prmL40/9rYUXPbBZ44gqg',
'7tIN11SDBE7CswM5YSZnp/cWYNBNR2lJ23duPkpq0a7cWtbZZgvfQPA72DdTrrypxZ673n/Pskfp/7Uw',
'HPK9vYrCusowk7NTpqO0JAU20LqTBtfNKVfeVL9n2SMuemazuEphxAIbaF2UK28qN74LtKGODMMb3wVa',
'je8CLQ=='].join(),'base64').copy(Buffer.from(TABLE.buffer));

function crc32(buf, previous) {
  let crc = ~~previous ^ -1;
  for (let index = 0; index < buf.length; index++) {
    const byte = buf[index];
    crc = TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  }
  return crc ^ -1
}



const TLS_START_BYTES = Buffer.from('1603010200010001fc0303','hex');
const MAX_CHUNK_SIZE = 16384 + 24;
const FAKE_CERT_CACHE = crypto.randomBytes(4096);
const EMPTY_BUFFER = Buffer.alloc(0);
const ZERO8 = Buffer.from('0000000000000000','hex');
const PADDING_WORD = Buffer.from('04000000','hex');
const IPV4_MAPPED_PREFIX = Buffer.from('00000000000000000000ffff','hex');
const AD_TAG_ALIGN = Buffer.from('000000','hex');
const RPC_PROXY_REQ = Buffer.from('eef1ce36','hex');
const PROXY_REQ_EXTRA = Buffer.from('18000000ae261edb','hex');

const firstPart =Buffer.from('1603030000020000000303000000000000000000000000000000000000000000000000000000000000000000','hex');
const secondPart=Buffer.from('130100002e00330024001d00200000000000000000000000000000000000000000000000000000000000000000002b000203041403030001011703030000','hex')
const PROXY_SECRET_ADDR = 'https://core.telegram.org/getProxySecret';
const PUBLIC_IP_ADDRS_V4 = ['https://v4.ident.me/','https://ipv4.icanhazip.com/','https://api.ipify.org/'];
const PUBLIC_IP_ADDRS_V6 = ['https://v6.ident.me/','https://ipv6.icanhazip.com/','https://api6.ipify.org/'];
const TG_DATACENTERS_V4 = [
	'149.154.175.50',
	'149.154.167.51',
	'149.154.175.100',
	'149.154.167.91',
	'149.154.171.5',
];
const TG_DATACENTERS_V6 = [
	'2001:b28:f23d:f001::a',
	'2001:67c:04e8:f002::a',
	'2001:b28:f23d:f003::a',
	'2001:67c:04e8:f004::a',
	'2001:b28:f23f:f005::a',
];
const TG_MIDDLE_PROXIES_V4_DEFAULT = {
	1: [{host:'149.154.175.50',port:8888}], '-1': [{host:'149.154.175.50',port:8888}],
	2: [{host:'149.154.161.144',port:8888}], '-2': [{host:'149.154.161.144',port:8888}],
	3: [{host:'149.154.175.100',port:8888}], '-3': [{host:'149.154.175.100',port:8888}],
	4: [{host:'91.108.4.136',port:8888}], '-4': [{host:'149.154.165.109',port:8888}],
	5: [{host:'91.108.56.183',port:8888}], '-5': [{host:'91.108.56.183',port:8888}],
};
const TG_MIDDLE_PROXIES_V6_DEFAULT = {
	1: [{host:'2001:b28:f23d:f001::d',port:8888}], '-1': [{host:'2001:b28:f23d:f001::d',port:8888}],
	2: [{host:'2001:67c:04e8:f002::d',port:80}], '-2': [{host:'2001:67c:04e8:f002::d',port:80}],
	3: [{host:'2001:b28:f23d:f003::d',port:8888}], '-3': [{host:'2001:b28:f23d:f003::d',port:8888}],
	4: [{host:'2001:67c:04e8:f004::d',port:8888}], '-4': [{host:'2001:67c:04e8:f004::d',port:8888}],
	5: [{host:'2001:b28:f23f:f005::d',port:8888}], '-5': [{host:'2001:b28:f23f:f005::d',port:8888}],
};

let globaleIndex=0;
let classic_secrets, secured_secrets, tls_secrets;
let use_middle_proxy=true;
//let AD_TAG;
const CON_TIMEOUT= 5 * 60 * 1000;
const DIRECT_CONNECT_TIMEOUT = 10 * 1000;
const DIRECT_CHUNK_SIZE = 64 * 1024;
const FAST_MODE = true;
let PREFER_IPV6 = false;
const PROTO_ABRIDGED = Buffer.from('efefefef','hex');
const PROTO_INTERMEDIATE = Buffer.from('eeeeeeee','hex');
const PROTO_SECURE = Buffer.from('dddddddd','hex');

function isTLSClientHello(data)
{
	return data.length>=11 && data[0]===0x16 && data[1]===0x03 && data[5]===0x01 && data[9]===0x03;
}

function parseTLSClientHelloSNI(data)
{
	try
	{
		let pos=43;
		if (pos>=data.length)
			return '';
		let sessionIdLen=data[pos++];
		pos+=sessionIdLen;
		if (pos+2>data.length)
			return '';
		let cipherLen=data.readUInt16BE(pos);
		pos+=2+cipherLen;
		if (pos>=data.length)
			return '';
		let compressionLen=data[pos++];
		pos+=compressionLen;
		if (pos+2>data.length)
			return '';
		let extensionsLen=data.readUInt16BE(pos);
		pos+=2;
		let extensionsEnd=Math.min(pos+extensionsLen,data.length);
		while (pos+4<=extensionsEnd)
		{
			let type=data.readUInt16BE(pos);
			let len=data.readUInt16BE(pos+2);
			pos+=4;
			if (pos+len>extensionsEnd)
				return '';
			if (type===0)
			{
				let namePos=pos+2;
				if (namePos+3>pos+len)
					return '';
				let nameType=data[namePos++];
				let nameLen=data.readUInt16BE(namePos);
				namePos+=2;
				if (nameType!==0 || namePos+nameLen>pos+len)
					return '';
				return data.slice(namePos,namePos+nameLen).toString('ascii');
			}
			pos+=len;
		}
	}
	catch(e)
	{
		return '';
	}
	return '';
}

function getFakeCertData()
{
	let len=1024+Math.floor(3*1024*Math.random());
	return FAKE_CERT_CACHE.slice(0,len);
}

let PROXY_SECRET;
let PROXY_SECRET_HEADER;
let my_ip;
let my_ip_v4;
let my_ip_v6;
let my_ip_v4_text;
let my_ip_v6_text;
let dc;
let dc_v4=cloneProxyMap(TG_MIDDLE_PROXIES_V4_DEFAULT);
let dc_v6=cloneProxyMap(TG_MIDDLE_PROXIES_V6_DEFAULT);

function numberToBuffer(value,bytes)
{
	if (bytes===2)
	{
		let ret=Buffer.alloc(2);
		ret.writeUInt16LE(value)
		return ret;
	}
	else
	{
		let ret=Buffer.alloc(4);
		if (value<0)
			ret.writeInt32LE(value);
		else
			ret.writeUInt32LE(value);
		return ret;
	}
}

function chooseOne(array)
{
	if (array.length===0)
		return null;
	let i=Math.floor(array.length*Math.random());
	return array[i];
}

function assertit(check,msg)
{
	if (!msg)
		msg='';
	if (!check)
		throw new Error('Assertion failed: '+msg);
}

function sleep(ms)
{
	return new Promise(resolve=>setTimeout(resolve,ms));
}

function retryDelay(attempt)
{
	return Math.min(1000*Math.pow(2,attempt),10000);
}

function rpMaybe(url)
{
	return rp(url).catch(()=>EMPTY_BUFFER);
}

function cloneProxyMap(map)
{
	let ret=[];
	Object.keys(map).forEach(function(dcId)
	{
		ret[dcId]=map[dcId].map(item=>({host:item.host,port:item.port}));
	});
	return ret;
}

function updateSelectedProxyList()
{
	let useIPv6=my_ip_v6_text && (PREFER_IPV6 || !my_ip_v4_text) && Object.keys(dc_v6).length>0;
	dc=useIPv6?dc_v6:dc_v4;
}

function updatePublicIPs(v4Data,v6Data)
{
	let v4=normalizeIp(v4Data.toString());
	let v6=normalizeIp(v6Data.toString());
	my_ip_v4_text=net.isIP(v4)===4?v4:undefined;
	my_ip_v6_text=net.isIP(v6)===6?v6:undefined;
	my_ip_v4=my_ip_v4_text?ipv4ToBuffer(my_ip_v4_text):undefined;
	my_ip_v6=my_ip_v6_text?ipv6ToBuffer(my_ip_v6_text):undefined;
	my_ip=my_ip_v4;
}

function hasUsableInterface(family)
{
	return Object.values(os.networkInterfaces()).some(function(items)
	{
		return items.some(function(item)
		{
			if (item.internal)
				return false;
			if (family===4)
				return item.family==='IPv4' || item.family===4;
			if (!(item.family==='IPv6' || item.family===6))
				return false;
			let address=normalizeIp(item.address).toLowerCase();
			return address && !address.startsWith('fe80:') && address!=='::1';
		});
	});
}

function refreshPublicIPs()
{
	let hasIPv4=hasUsableInterface(4);
	let hasIPv6=hasUsableInterface(6);
	return Promise.all([
		hasIPv4?firstPublicIp(PUBLIC_IP_ADDRS_V4,4):EMPTY_BUFFER,
		hasIPv6?firstPublicIp(PUBLIC_IP_ADDRS_V6,6):EMPTY_BUFFER
	]).then(function(arr)
	{
		updatePublicIPs(arr[0],arr[1]);
		PREFER_IPV6=!my_ip_v4_text && !!my_ip_v6_text;
		updateSelectedProxyList();
	});
}

function getDetectedPublicHost()
{
	return my_ip_v4_text || my_ip_v6_text || 'YOUR_IP';
}

async function firstPublicIp(urls,family)
{
	for (let url of urls)
	{
		let data=await rpMaybe(url);
		let ip=normalizeIp(data.toString());
		if (net.isIP(ip)===family)
			return Buffer.from(ip);
	}
	return EMPTY_BUFFER;
}

function refreshProxyInfo(attempt=0)
{
	return Promise.all([
		rp(PROXY_SECRET_ADDR),
		refreshPublicIPs()
	]).then(function(arr)
	{
		PROXY_SECRET=arr[0];
		PROXY_SECRET_HEADER=PROXY_SECRET.slice(0,4);
		updateSelectedProxyList();
	}).catch(function()
	{
		return sleep(retryDelay(attempt)).then(()=>refreshProxyInfo(Math.min(attempt+1,4)));
	});
};

function getServer(dcId,attempt=0)
{ 
	return new Promise(function(accept,reject)
	{
		assertit(dc[dcId] && dc[dcId].length>0,'No proxy for DC');
		let server = net.createConnection(chooseOne(dc[dcId]));
		function cleanupConnectListeners()
		{
			server.removeListener('connect',onConnect);
			server.removeListener('error',onError);
		}
		async function onConnect()
		{
			cleanupConnectListeners();
			extendSocket(server,'server');
			server.setTimeout(CON_TIMEOUT);
			const RPC_NONCE = Buffer.from('aa87cb7a','hex');
			const RPC_HANDSHAKE = Buffer.from('f5ee8276','hex');
			const RPC_FLAGS = Buffer.from('00000000','hex'); //    # pass as consts to simplify code
		    const CRYPTO_AES = numberToBuffer(1);
		    const SENDER_PID = Buffer.from('IPIPPRPDTIME');
		    const PEER_PID = Buffer.from('IPIPPRPDTIME');

		    let my_port=server.localPort;
		    let remoteAddress=normalizeIp(server.remoteAddress);
		    let useIPv6=net.isIP(remoteAddress)===6;
		    let localAddress=useIPv6?(my_ip_v6_text || normalizeIp(server.localAddress)):(my_ip_v4_text || normalizeIp(server.localAddress));
		    let remoteIp4=useIPv6?Buffer.alloc(4):Buffer.from(ipv4ToBuffer(remoteAddress)).reverse();
		    let localIp4=useIPv6?Buffer.alloc(4):Buffer.from(ipv4ToBuffer(localAddress)).reverse();
		    let remoteIp6=useIPv6?ipv6ToBuffer(remoteAddress):undefined;
		    let localIp6=useIPv6?ipv6ToBuffer(localAddress):undefined;
		    server.proxyLocalIpBuffer=ipToBuffer(localAddress);
			let options=
			{
				client:
				{
					ip: localIp4,
					ipv6: localIp6,
					port: numberToBuffer(my_port,2), 
					ts: numberToBuffer(Math.floor(Date.now()/1000)),
					nonce: crypto.randomBytes(16)
				},
				server:
				{
					ip: remoteIp4,
					ipv6: remoteIp6,
					port: numberToBuffer(server.remotePort,2),
				},
				middleproxy_secret: PROXY_SECRET
			};

			server.beginWriteCRC();
			server.bufferedWrite(Buffer.concat([numberToBuffer(44),numberToBuffer(-2),RPC_NONCE,PROXY_SECRET_HEADER,CRYPTO_AES,options.client.ts,options.client.nonce]));
			server.endWriteCRC();
			server.bufferedWrite(numberToBuffer(4)); //->48 ->Multiplier of 16
			let msg_len;
			do
			{
				server.beginReadCRC();
				let  msg_len_bytes = await server.bufferedReadExactly(4);
				msg_len = msg_len_bytes.readInt32LE();
			} while (msg_len===4);
			assertit(msg_len===44);
			await server.bufferedReadAssert(-2);
			await server.bufferedReadAssert(RPC_NONCE);
			await server.bufferedReadAssert(PROXY_SECRET_HEADER);
			await server.bufferedReadAssert(CRYPTO_AES);
			options.server.ts = await server.bufferedReadExactly(4);
			options.server.nonce = await server.bufferedReadExactly(16);
			await server.endReadCRC();
			let [encryptkey,decryptkey]=get_middleproxy_aes_key_and_iv(options);
			let encoder=createAESCBCTransform(encryptkey,false);
			let decoder=createAESCBCTransform(decryptkey,true);
			server.addCryptoLayer({decoder,encoder})
			server.beginWriteCRC();
			server.bufferedWrite(Buffer.concat([numberToBuffer(44),numberToBuffer(-1),RPC_HANDSHAKE, RPC_FLAGS, SENDER_PID, PEER_PID]));
			server.endWriteCRC();
			server.bufferedWrite(numberToBuffer(4));
			do
			{
				server.beginReadCRC();
				let msg_len_bytes = await server.bufferedReadExactly(4);
				msg_len = msg_len_bytes.readInt32LE();
			} while (msg_len===4);
			assertit(msg_len===44);
			await server.bufferedReadAssert(-1)
			await server.bufferedReadAssert(Buffer.concat([RPC_HANDSHAKE, RPC_FLAGS]))
			let handshake_sender_pid = server.bufferedReadExactly(12);
			await server.bufferedReadAssert(SENDER_PID);
			await server.endReadCRC();
			await server.bufferedReadAssert(4);
			accept(server);
		}
		function onError(err)
		{
			cleanupConnectListeners();
			reject(err);
		}
		server.once('connect',onConnect);
		server.once('error',onError);
	}).catch(function()
	{
		return sleep(retryDelay(attempt)).then(()=>getServer(dcId,Math.min(attempt+1,4)));
	})
}

function get_middleproxy_aes_key_and_iv({client,server,middleproxy_secret})
{
    return ([Buffer.from('CLIENT'),Buffer.from('SERVER')].map(function(purpose)
    {
    	let parts=[server.nonce, client.nonce, client.ts, server.ip, client.port, purpose, client.ip, server.port, middleproxy_secret, server.nonce];
    	if (client.ipv6 && server.ipv6)
    		parts.push(client.ipv6,server.ipv6);
    	parts.push(client.nonce);
    	let s = Buffer.concat(parts);
		return {
		    key : Buffer.concat([crypto.createHash('md5').update(s.slice(1)).digest().slice(0,12), crypto.createHash('sha1').update(s).digest()]),
		    iv : crypto.createHash('md5').update(s.slice(2)).digest()
		}
    }))
}

function normalizeIp(ip)
{
	ip=String(ip || '').trim();
	if (ip.startsWith('[') && ip.endsWith(']'))
		ip=ip.slice(1,-1);
	if (ip.includes('%'))
		ip=ip.split('%')[0];
	if (ip.startsWith('::ffff:') && net.isIP(ip.slice(7))===4)
		return ip.slice(7);
	return ip;
}

function ipv4ToBuffer(ip)
{
	ip=normalizeIp(ip);
	let parts=ip.split('.').map(x=>Number(x));
	assertit(parts.length===4 && parts.every(x=>Number.isInteger(x) && x>=0 && x<=255),'Bad IPv4');
	return Buffer.from(parts);
}

function ipv6ToBuffer(ip)
{
	ip=normalizeIp(ip).toLowerCase();
	if (ip.includes('.'))
	{
		let lastColon=ip.lastIndexOf(':');
		let v4=ipv4ToBuffer(ip.slice(lastColon+1));
		let high=v4.readUInt16BE(0).toString(16);
		let low=v4.readUInt16BE(2).toString(16);
		ip=ip.slice(0,lastColon)+':'+high+':'+low;
	}
	let sides=ip.split('::');
	assertit(sides.length<=2,'Bad IPv6');
	let head=sides[0]?sides[0].split(':').filter(Boolean):[];
	let tail=sides.length===2 && sides[1]?sides[1].split(':').filter(Boolean):[];
	let fill=sides.length===2 ? 8-head.length-tail.length : 0;
	assertit(fill>=0,'Bad IPv6');
	let words=head.concat(Array(fill).fill('0'),tail);
	assertit(words.length===8,'Bad IPv6');
	let ret=Buffer.allocUnsafe(16);
	for (let i=0;i<8;i++)
	{
		let n=parseInt(words[i],16);
		assertit(Number.isInteger(n) && n>=0 && n<=0xffff,'Bad IPv6');
		ret.writeUInt16BE(n,i*2);
	}
	return ret;
}

function ipToBuffer(ip)
{
	ip=normalizeIp(ip);
	let family=net.isIP(ip);
	assertit(family!==0,'Bad IP');
	return family===6?ipv6ToBuffer(ip):ipv4ToBuffer(ip);
}

function makeIpPort(ip,port)
{
	let ipBuf=Buffer.isBuffer(ip)?ip:ipToBuffer(ip);
	let ret=Buffer.allocUnsafe(20);
	if (ipBuf.length===4)
	{
		IPV4_MAPPED_PREFIX.copy(ret,0);
		ipBuf.copy(ret,12);
	}
	else
		ipBuf.copy(ret,0);
	numberToBuffer(port).copy(ret,16);
	return ret;
}

function formatDcId(dcId)
{
	return dcId<0?`media DC ${-dcId}`:`DC ${dcId}`;
}

function isHttpRequestStart(data)
{
	return data.length>=5 &&
		((data[0]===0x47 && data[1]===0x45 && data[2]===0x54 && data[3]===0x20 && data[4]===0x2f) ||
		(data.length>=6 && data[0]===0x50 && data[1]===0x4f && data[2]===0x53 && data[3]===0x54 && data[4]===0x20 && data[5]===0x2f));
}

let extendedSocket=
{
	startBuffering(name)
	{
		let self=this;
		self.autoWrite=true;
		self.setOutputBufferLength=function(){};
		self.outputBuffers=[];
		self.localName=name;
		self.writeCRCval=0x00000000;
		self.readCRCval=0x00000000;
		self.writeCRCactive=false;
		self.readCRCactive=false;
		self.newDataCallback=function(){};
		self.errorCallback=function(){};
		self.inputBuffers=[];
		self.inputLength=0;
		self.cryptoLayers=[];
		self.on('data',function(data){try{self.ondata.call(self,data)}catch(e){self.emit('finished',e)}}); //why
		self.on('timeout',function(){self.emit('finished',new Error(`${self.localName} timedout`))})
		self.on('end'  ,function()		{self.emit('finished',new Error(`${self.localName} ended`))});
		self.on('error',function(err)	{self.emit('finished',err)});
		self.once('finished',function(err)
		{
			self.end();
			try { self.errorCallback(err); } catch(e) {}
			self.setErrorHandler=function(handler)
			{
				if (handler)
					handler(err);
			}
		})
	},
	addCryptoLayer(layer)
	{
		this.cryptoLayers.push(layer);
		let {decoder}=layer
		if (this.inputLength>0)
		{
			let data=this.consumeInput(this.inputLength);
			data=decoder(data);
			this.pushInput(data);
		}
	},
	pushInput(data)
	{
		if (data.length===0)
			return;
		this.inputBuffers.push(data);
		this.inputLength+=data.length;
	},
	consumeInput(len)
	{
		if (len===0)
			return EMPTY_BUFFER;
		if (len===this.inputLength)
		{
			let ret;
			if (this.inputBuffers.length===1)
				ret=this.inputBuffers[0];
			else
				ret=Buffer.concat(this.inputBuffers,this.inputLength);
			this.inputBuffers=[];
			this.inputLength=0;
			return ret;
		}

		let remaining=len;
		let chunks=[];
		while (remaining>0)
		{
			let chunk=this.inputBuffers[0];
			if (chunk.length<=remaining)
			{
				chunks.push(chunk);
				this.inputBuffers.shift();
				this.inputLength-=chunk.length;
				remaining-=chunk.length;
			}
			else
			{
				chunks.push(chunk.slice(0,remaining));
				this.inputBuffers[0]=chunk.slice(remaining);
				this.inputLength-=remaining;
				remaining=0;
			}
		}
		return chunks.length===1?chunks[0]:Buffer.concat(chunks,len);
	},
	setErrorHandler(handler)
	{
		if (handler)
			this.errorCallback=handler;
	},
	bufferedWrite(data)
	{
		return this.bufferedWriteWithLayers(data,this.cryptoLayers.length);
	},
	bufferedWriteWithLayers(data,layerCount)
	{
		if (data.length===0)
			return
		if (this.writeCRCactive)
			this.writeCRCval = crc32(data,this.writeCRCval);
		for (let i=layerCount-1;i>=0;i--)
			data=this.cryptoLayers[i].encoder(data);
		if (data.length!==0)
		{
			if (this.autoWrite)
				this.write(data)
			else
				this.outputBuffers.push(data);
		}
	},
	bufferedWriteWithLayersAndDrain(data,layerCount)
	{
		if (data.length===0)
			return Promise.resolve();
		if (this.writeCRCactive)
			this.writeCRCval = crc32(data,this.writeCRCval);
		for (let i=layerCount-1;i>=0;i--)
			data=this.cryptoLayers[i].encoder(data);
		if (data.length===0)
			return Promise.resolve();
		if (!this.autoWrite)
		{
			this.outputBuffers.push(data);
			return Promise.resolve();
		}
		if (this.write(data))
			return Promise.resolve();
		let self=this;
		return new Promise(function(resolve,reject)
		{
			function cleanup()
			{
				self.removeListener('drain',onDrain);
				self.removeListener('finished',onFinished);
			}
			function onDrain()
			{
				cleanup();
				resolve();
			}
			function onFinished(err)
			{
				cleanup();
				reject(err || new Error(`${self.localName} ended`));
			}
			self.once('drain',onDrain);
			self.once('finished',onFinished);
		});
	},
	flushBuffer()
	{
		if (this.outputBuffers.length===1)
			this.write(this.outputBuffers[0]);
		else if (this.outputBuffers.length>1)
			this.write(Buffer.concat(this.outputBuffers));
		this.outputBuffers=[];
	},
	beginWriteCRC()
	{
		this.writeCRCval=0x00000000;
		this.writeCRCactive=true;
	},
	endWriteCRC()
	{
		let ret=Buffer.alloc(4);
		ret.writeInt32LE(this.writeCRCval);
		this.writeCRCval=0x00000000;
		this.writeCRCactive=false;
		this.bufferedWrite(ret);
	},
	beginReadCRC()
	{
		this.readCRCval=0x00000000;
		this.readCRCactive=true;
	},
	async endReadCRC()
	{
		let ret=Buffer.alloc(4);
		ret.writeInt32LE(this.readCRCval);
		this.readCRCval=0x00000000;
		this.readCRCactive=false;
		return this.bufferedReadAssert(ret)
	},
	ondata(data)
	{
		for (let layer of this.cryptoLayers)
			data=layer.decoder(data);

		if (data.length===0)
			return
		this.pushInput(data);
		this.newDataCallback();
	},
	waitForNewData()
	{
		let self=this;
		if (self.idling)
			self.idling();
		return new Promise(function(accept,reject)
		{
			self.newDataCallback=accept;
			self.setErrorHandler(reject);
		});
	},
	async bufferedRead()
	{
		let data;
		if (this.inputLength===0)
		{
			await this.waitForNewData();
		}
		data=this.consumeInput(this.inputLength);
		if (this.readCRCactive)
			this.readCRCval=crc32(data,this.readCRCval)
		return data;
	},
	async bufferedReadExactly(len)
	{
		let data;
		while (this.inputLength<len)
		{
			await this.waitForNewData();
		}
		data=this.consumeInput(len);
		if (this.readCRCactive)
			this.readCRCval=crc32(data,this.readCRCval)
		return data;
	},
	async bufferedReadAtmost(len)
	{
		let data;
		if (this.inputLength===0)
		{
			await this.waitForNewData();
		}
		len=Math.min(len,this.inputLength);
		data=this.consumeInput(len);
		if (this.readCRCactive)
			this.readCRCval=crc32(data,this.readCRCval)
		return data;
	},
	async bufferedReadInt()
	{
		return (await this.bufferedReadExactly(4)).readInt32LE();
	},
	async bufferedReadAssert(data,msg)
	{
		if (!msg)
			msg='';
		if (Buffer.isBuffer(data))
		{
			if (Buffer.compare(data,await this.bufferedReadExactly(data.length))!==0)
				return Promise.reject(new Error('Assertion failed: '+msg));
		}
		else
		{
			if (data!==(await this.bufferedReadInt()))
				return Promise.reject(new Error('Assertion failed: '+msg));
		}
	}
}

function extendSocket(socket,name)
{
	Object.assign(socket,extendedSocket);
	socket.startBuffering(name);
}

function createAESCBCTransform({key,iv},mode)
{
	let cr;
	let bufferedData=EMPTY_BUFFER;
	if (!mode)
		cr = crypto.createCipheriv('aes-256-cbc', key, iv)
	else
		cr = crypto.createDecipheriv('aes-256-cbc', key, iv)
	cr.setAutoPadding(false);

	return (function(data)
		{
			if (bufferedData.length>0)
				data=Buffer.concat([bufferedData,data]); 
			let len=data.length;
			let pos=(len % 16)
			bufferedData=data.slice(len-pos);
			data=data.slice(0,len-pos); 
			return cr.update(data)
		});
}

function createAESCTRTransform({key,iv},mode)
{
	let cr;
	if (!mode)
		cr = crypto.createCipheriv('aes-256-ctr', key, iv);
	else
		cr = crypto.createDecipheriv('aes-256-ctr', key, iv);
	return ((data)=>cr.update(data));
}

function createDirectObfuscatedHandshake(protoTag,fastClientKeyIv)
{
	let rnd;
	while(true)
	{
		rnd=crypto.randomBytes(64);
		if (rnd[0]===0xef)
			continue;
		let val=rnd.readUInt32LE(0);
		let val2=rnd.readUInt32LE(4);
		if ([0x44414548,0x54534f50,0x20544547,0x4954504f,0xeeeeeeee,0xdddddddd].includes(val))
			continue;
		if (val2===0)
			continue;
		break;
	}
	if (fastClientKeyIv)
		Buffer.from(fastClientKeyIv).reverse().copy(rnd,8);
	protoTag.copy(rnd,56);
	let encKeyIv=rnd.slice(8,56);
	let enc={key:encKeyIv.slice(0,32),iv:encKeyIv.slice(32)};
	let decKeyIv=Buffer.from(encKeyIv).reverse();
	let dec={key:decKeyIv.slice(0,32),iv:decKeyIv.slice(32)};
	let encoder=createAESCTRTransform(enc,false);
	let decoder=createAESCTRTransform(dec,true);
	let packet=encoder(rnd);
	rnd.copy(packet,0,0,56);
	if (fastClientKeyIv)
		decoder=function(data){return data};
	return {packet,layer:{encoder,decoder}};
}

function connectDirectDC(dcId,protoTag,fastClientKeyIv)
{
	let index=Math.abs(dcId)-1;
	let useIPv6=my_ip_v6_text && (PREFER_IPV6 || !my_ip_v4_text);
	let servers=useIPv6?TG_DATACENTERS_V6:TG_DATACENTERS_V4;
	assertit(index>=0 && index<servers.length,'Bad direct DC');
	let host=servers[index];
	return new Promise(function(resolve,reject)
	{
		let server=net.createConnection({host,port:443});
		server.setNoDelay();
		server.setKeepAlive(true);
		server.setTimeout(DIRECT_CONNECT_TIMEOUT);
		function cleanup()
		{
			server.removeListener('connect',onConnect);
			server.removeListener('error',onError);
			server.removeListener('timeout',onTimeout);
		}
		function onError(err)
		{
			cleanup();
			reject(err);
		}
		function onTimeout()
		{
			cleanup();
			server.destroy();
			reject(new Error('server connect timedout'));
		}
		function onConnect()
		{
			cleanup();
			server.setTimeout(CON_TIMEOUT);
			extendSocket(server,'server');
			let hs=createDirectObfuscatedHandshake(protoTag,fastClientKeyIv);
			server.write(hs.packet);
			server.addCryptoLayer(hs.layer);
			resolve(server);
		}
		server.once('connect',onConnect);
		server.once('error',onError);
		server.once('timeout',onTimeout);
	});
}

async function pipeDirectSocket(from,to,setOutputLength,layerCount)
{
	while(true)
	{
		let data=await from.bufferedReadAtmost(DIRECT_CHUNK_SIZE);
		if (setOutputLength)
			to.setOutputBufferLength(data.length);
		await to.bufferedWriteWithLayersAndDrain(data,layerCount);
	}
}

function bridgeDirect(client,server,clientOutputLayerCount)
{
	client.once('finished',function(err){server.emit('finished',err)});
	server.once('finished',function(err){client.emit('finished',err)});
	return Promise.all([
		pipeDirectSocket(client,server,false,server.cryptoLayers.length),
		pipeDirectSocket(server,client,true,clientOutputLayerCount),
	]);
}


async function handleClient(client,filter,id)
{
	let currentSecret;
	let currentProtoTag;
	let isTLS=false;
	let AD_TAG
	let SNI;
	client.setKeepAlive(true);
	client.setNoDelay();
	client.setTimeout(5000);
	let cl_ip 	=ipToBuffer(client.remoteAddress);
	let cl_port =client.remotePort;
	extendSocket(client,'client');
	let h1=await client.bufferedReadExactly(64);
	if (isTLSClientHello(h1))
	{
		isTLS=true
		let tls_record_len=h1.readUInt16BE(3);
		let total_tls_len=5+tls_record_len;
		assertit(total_tls_len>=64,'Bad TLS record length');
		let h2=await client.bufferedReadExactly(total_tls_len-64);
		let handshake=Buffer.concat([h1,h2]);
		SNI=parseTLSClientHelloSNI(handshake);
		let d=handshake.slice(11, 11 + 32);
		let digest=Buffer.from(d);
		d.fill(0);
		let isOK=false;
		let mainPacket;
		for (let secret of tls_secrets)
		{
			let computed_digest=crypto.createHmac('sha256', secret.secret).update(handshake).digest();
			if (computed_digest.compare(digest,0,28,0,28)!==0)
				continue
			let timestamp=computed_digest.readUInt32LE(28)^digest.readUInt32LE(28);
			let lag=timestamp-Math.floor(Date.now()/1000);
			if (Math.abs(lag)>60*10)
				continue

			let sess_id_len = handshake[43];
	    	let sess_id = handshake.slice(44, 44 + sess_id_len);
			let http_data = getFakeCertData();
			let fake_cert_len=http_data.length;

	    	let p1=Buffer.from(firstPart);
	    	let p2=Buffer.from(secondPart);
	    	p1.writeUInt16BE(90+sess_id_len,3);
	    	p1.writeUInt32BE(86+sess_id_len,5);
	    	p1.writeUInt8(2,5);
	    	p1.writeUInt8(sess_id_len,43);
	    	crypto.randomBytes(32).copy(p2,13); //x25519_public_key
	    	p2.writeUInt16BE(fake_cert_len,60);
	    	let dd=Buffer.concat([digest,p1,sess_id,p2,http_data]);
	    	mainPacket=dd.slice(32);
	    	let digestPlaceHolder=mainPacket.slice(11);
	    	crypto.createHmac('sha256', secret.secret).update(dd).digest().copy(digestPlaceHolder)

	        isOK=true;
	        currentSecret=secret;
	        break;
		}
		

		assertit(isOK,'No matching secret found')
		client.bufferedWrite(mainPacket)
		client.addCryptoLayer(
			(function()
			{
				let cache=EMPTY_BUFFER;
				let remainingLen1=0;
				let remainingLen2=0;
				let remainingPacketLen=0;
				let readingHeader=true;
				let skip=false;
				client.setOutputBufferLength=function(bufferLen)
				{
					//len=remainingLen+remainingPacketLen
					assertit(remainingLen2===0);
					assertit(remainingPacketLen===0)
					remainingLen2=bufferLen;
					remainingPacketLen=0;
				}
				return {
					decoder(msg)
					{
						if (cache.length>0)
						{
							msg=Buffer.concat([cache,msg]);
							cache=EMPTY_BUFFER;
						}
						let chunks=[];
						while(true)
						{
							if (msg.length===0)
								return chunks.length===0?EMPTY_BUFFER:Buffer.concat(chunks);

							if (readingHeader)
							{
								if (msg.length<5)
								{
									cache=msg;
									return chunks.length===0?EMPTY_BUFFER:Buffer.concat(chunks);
								}
								assertit([0x14,0x17].includes(msg[0]));
								assertit(msg[1]===0x03);
								assertit(msg[2]===0x03);
								
								skip=(msg.readUInt8()===0x14);
								remainingLen1=msg.readUInt16BE(3);
								msg=msg.slice(5);
								readingHeader=false;
							}
							if (remainingLen1<=msg.length)
							{
								if (!skip)
									chunks.push(msg.slice(0,remainingLen1));
								msg=msg.slice(remainingLen1);
								readingHeader=true;
							}
							else
							{
								remainingLen1-=msg.length;
								if (!skip)
									chunks.push(msg);
								return chunks.length===0?EMPTY_BUFFER:Buffer.concat(chunks);
							}
						}
					},
					encoder(msg)
					{
						let chunks=[];
						while (msg.length>0)
						{
							if (remainingLen2+remainingPacketLen===0)
								throw new Error('No remaining Len');
							if (remainingPacketLen===0)
							{
								let p=Math.min(remainingLen2,MAX_CHUNK_SIZE);
								remainingLen2-=p;
								remainingPacketLen+=p;
								let header=Buffer.from('1703030000','hex');
								header.writeUInt16BE(p,3);
								chunks.push(header);
							}
							let q=Math.min(msg.length,remainingPacketLen);
							chunks.push(msg.slice(0,q));
							remainingPacketLen-=q;
							msg=msg.slice(q);
						}
						return chunks.length===0?EMPTY_BUFFER:Buffer.concat(chunks);
					}
				}
			})());
		h1=await client.bufferedReadExactly(64);
	}

	let skip = h1.slice(0,8);
	let dec_prekey_and_iv = h1.slice(8,56);
	let dec_proto_tag = h1.slice(56,60);
	let dec_dcId = h1.slice(60,62);
	let trailing = h1.slice(62,64);

	let enc_prekey_and_iv = Buffer.from(dec_prekey_and_iv).reverse();
	let dec = {prekey : dec_prekey_and_iv.slice(0,32),iv : dec_prekey_and_iv.slice(32)}
	let enc = {prekey : enc_prekey_and_iv.slice(0,32),iv : enc_prekey_and_iv.slice(32)}
	let decoder,encoder;
	let permission=false;
	let s=isTLS?[currentSecret]:secured_secrets.concat(classic_secrets);
	let triedProtoTags=[];
	for (let secret of s)
	{
		let candidateSecrets=(secret.mtprotoSecrets || [secret.secret]);
		for (let candidateIndex=0;candidateIndex<candidateSecrets.length;candidateIndex++)
		{
			let secretForMTProto=candidateSecrets[candidateIndex];
			dec.key = crypto.createHash('sha256').update(Buffer.concat([dec.prekey, secretForMTProto])).digest();
			enc.key = crypto.createHash('sha256').update(Buffer.concat([enc.prekey, secretForMTProto])).digest();
			decoder = createAESCTRTransform(dec,true);
			encoder = createAESCTRTransform(enc,false);
			decoder(skip);
			decoder(dec_prekey_and_iv);
			let proto_tag = decoder(dec_proto_tag);
			triedProtoTags.push(`${secret.index}:${candidateIndex}:${proto_tag.toString('hex')}`);
			let protoAllowed=false;
			if (secret.isTLS && ((proto_tag.compare(PROTO_SECURE)===0)||(proto_tag.compare(PROTO_ABRIDGED)===0)||(proto_tag.compare(PROTO_INTERMEDIATE)===0)))
				protoAllowed=true;
			if (secret.isSecured && proto_tag.compare(PROTO_SECURE)===0)
				protoAllowed=true;
			if (secret.isClassic && ((proto_tag.compare(PROTO_ABRIDGED)===0)||(proto_tag.compare(PROTO_INTERMEDIATE)===0)))
				protoAllowed=true;
			if (!protoAllowed)
				continue;
			permission=true;
			currentSecret=secret;
			currentProtoTag=proto_tag;
			break;
		}
		if (permission)
			break;
	}

	assertit(permission,`No matching secret; proto tags ${triedProtoTags.join(',')}`);
	let dcId = decoder(dec_dcId).readInt16LE();
	assertit(dcId>=-5);
	assertit(dcId<=5);
	assertit(dcId!==0);
	decoder(trailing);
	AD_TAG=await filter({id,address:client.remoteAddress,port:client.remotePort,secretIndex:currentSecret.index,dcId,dc:formatDcId(dcId),SNI});
	client.addCryptoLayer({decoder,encoder})
	client.setTimeout(CON_TIMEOUT);
	if (!use_middle_proxy)
	{
		let fastClientKeyIv=FAST_MODE?Buffer.concat([enc.key,enc.iv]):undefined;
		let clientOutputLayerCount=FAST_MODE?(isTLS?1:0):client.cryptoLayers.length;
		let server=await connectDirectDC(dcId,currentProtoTag,fastClientKeyIv);
		return bridgeDirect(client,server,clientOutputLayerCount);
	}
	let server=await getServer(dcId);
	server.setNoDelay();
	client.once('finished',function(err)
	{
		server.emit('finished',err);
	})
	server.once('finished',function(err)
	{
		client.emit('finished',err);
	})

	server.autoWrite=false;
	client.autoWrite=false;
	server.idling=function()
	{
		client.flushBuffer();
	}
	client.idling=function()
	{
		server.flushBuffer();
	}

	let out_conn_id = crypto.randomBytes(8); //CHeck
	AD_TAG=Buffer.from(AD_TAG,'hex')
	if (AD_TAG.length!==16)
		AD_TAG=Buffer.alloc(16);
	let adTagField=Buffer.allocUnsafe(20);
	adTagField[0]=16;
	AD_TAG.copy(adTagField,1);
	AD_TAG_ALIGN.copy(adTagField,17);
	async function serverToClient()
	{
		const RPC_PROXY_ANS = Buffer.from("0dda0344",'hex')
	    const RPC_CLOSE_EXT = Buffer.from("a234b65e",'hex')
	    const RPC_SIMPLE_ACK = Buffer.from("9b40ac3b",'hex')
		let remainingLen;
		let seq_no=0;
		let msg_len_bytes,msg_len,msg_seq_bytes,msg_seq,checksum_bytes,checksum,ans_type;
		function setClientOutputLength(len)
		{
			client.setOutputBufferLength(len);
		}
		function writeClientPacketHeader(dataLen)
		{
			if (currentProtoTag.compare(PROTO_ABRIDGED)===0)
			{
				let len4=dataLen/4;
				if (len4<0x7f)
				{
					setClientOutputLength(dataLen+1);
					client.bufferedWrite(Buffer.from([len4]));
				}
				else
				{
					let b=Buffer.alloc(4);
					b[0]=0x7f;
					b.writeUIntLE(len4,1,3);
					setClientOutputLength(dataLen+4);
					client.bufferedWrite(b);
				}
				return;
			}
			if (currentProtoTag.compare(PROTO_INTERMEDIATE)===0)
			{
				setClientOutputLength(dataLen+4);
				client.bufferedWrite(numberToBuffer(dataLen));
				return;
			}
			let padding_len = Math.floor(4*Math.random());
			setClientOutputLength(dataLen+padding_len+4);
			client.bufferedWrite(numberToBuffer(padding_len+dataLen));
			return padding_len;
		}
		function writeSimpleAck(confirm)
		{
			if (currentProtoTag.compare(PROTO_ABRIDGED)===0)
				confirm=Buffer.from(confirm).reverse();
			setClientOutputLength(confirm.length);
			client.bufferedWrite(confirm);
		}
		while(true)
		{
			server.beginReadCRC();
			msg_len = await server.bufferedReadInt();
			if (msg_len === 4)
				continue;
			assertit(msg_len%4===0);
			assertit(12<=msg_len);
			assertit(msg_len<=0x01000000);
	        msg_seq = await server.bufferedReadInt()
	        assertit(msg_seq===(seq_no++));
	        remainingLen=msg_len - 4 - 4 - 4;
	        if (remainingLen>=4)
	       	{
		        ans_type = await server.bufferedReadExactly(4);
		        remainingLen-=4;
		        if (ans_type.compare(RPC_CLOSE_EXT)===0)
		        {
		        }
		        else if (ans_type.compare(RPC_PROXY_ANS)===0)
		        {
		        	let ans_flags = await server.bufferedReadExactly(4);
		        	remainingLen-=4;
		        	let conn_id = await server.bufferedReadExactly(8);
		        	remainingLen-=8;
		        	let padding_len = writeClientPacketHeader(remainingLen) || 0;
		        	while(remainingLen>0)
			        {
			        	let data=await server.bufferedReadAtmost(remainingLen);
			        	remainingLen-=data.length;
						client.bufferedWrite(data);
			        }
			        if (padding_len)
			        	client.bufferedWrite(crypto.randomBytes(padding_len));
		        }
		        else if (ans_type.compare(RPC_SIMPLE_ACK)===0)
		        {
		        	let conn_id = await server.bufferedReadExactly(8);
		        	remainingLen-=8;
		        	let confirm = await server.bufferedReadExactly(4);
		        	writeSimpleAck(confirm);
		        	remainingLen-=4;
		        }
		        else
		        	throw(new Error('Invalid ans type'+ans_type.toString('hex')))
	    	}

	    	if (remainingLen>0)
	    		await server.bufferedReadExactly(remainingLen);
	        await server.endReadCRC();
		}
	};
	async function clientToServer()
	{
		let seq_no=0;
		let remote_ip_port=makeIpPort(cl_ip,cl_port);
		let our_ip_port=makeIpPort(server.proxyLocalIpBuffer || my_ip_v4 || my_ip,server.localPort);
		async function readClientPacket()
		{
			let quickAck=false;
			let msg_len;
			if (currentProtoTag.compare(PROTO_ABRIDGED)===0)
			{
				msg_len=(await client.bufferedReadExactly(1))[0];
				if (msg_len>=0x80)
				{
					quickAck=true;
					msg_len-=0x80;
				}
				if (msg_len===0x7f)
					msg_len=(await client.bufferedReadExactly(3)).readUIntLE(0,3);
				msg_len*=4;
				return {data:await client.bufferedReadExactly(msg_len),quickAck};
			}
			msg_len=(await client.bufferedReadExactly(4)).readUInt32LE();
			if (msg_len&0x80000000)
			{
				quickAck=true;
				msg_len=msg_len&0x7fffffff;
			}
			if (currentProtoTag.compare(PROTO_INTERMEDIATE)===0)
				return {data:await client.bufferedReadExactly(msg_len),quickAck};
			let trailing_len=msg_len%4;
			msg_len-=trailing_len;
			let data=await client.bufferedReadExactly(msg_len);
			if (trailing_len!==0)
				await client.bufferedReadExactly(trailing_len);
			return {data,quickAck};
		}
		function getProxyFlags(data,quickAck)
		{
			let flags=0x00021008;
			if (currentProtoTag.compare(PROTO_ABRIDGED)===0)
				flags|=0x40000000;
			else if (currentProtoTag.compare(PROTO_INTERMEDIATE)===0)
				flags|=0x20000000;
			else
				flags|=0x28000000;
			if (quickAck)
				flags|=0x80000000;
			if (data.slice(0,8).compare(ZERO8)===0)
				flags|=0x2;
			return flags;
		}

		while(true)
		{
			let {data,quickAck}=await readClientPacket();
			let msg_len=data.length;
		    let flags=getProxyFlags(data,quickAck);
		    assertit (msg_len>=8);
		    server.beginWriteCRC();
		    server.bufferedWrite(numberToBuffer(msg_len+96));
		    server.bufferedWrite(numberToBuffer(seq_no)); //check ++seq_no
		    seq_no++;
		    let proxyHeader=Buffer.allocUnsafe(64);
		    RPC_PROXY_REQ.copy(proxyHeader,0);
		    proxyHeader.writeUInt32LE(flags>>>0,4);
		    out_conn_id.copy(proxyHeader,8);
		    remote_ip_port.copy(proxyHeader,16);
		    our_ip_port.copy(proxyHeader,36);
		    PROXY_REQ_EXTRA.copy(proxyHeader,56);
		    server.bufferedWrite(proxyHeader);
		    server.bufferedWrite(adTagField);
			server.bufferedWrite(data)
		    server.endWriteCRC();
		    while((msg_len%16)!==0)
		    {
		    	msg_len+=4;
		    	server.bufferedWrite(PADDING_WORD);
		    }
		}
	};
	return Promise.all([clientToServer(),serverToClient()]);
}

class MTProtoProxy
{
	constructor(options)
	{
		let {httpServer,enter,leave,ready}=options;
		leave=leave || function(){};
		let secrets=options.secrets.map(function(secret,index)
		{
			secret=String(secret).toLowerCase();
			let raw=Buffer.from(secret,'hex');
			let isTLS=secret.startsWith('ee');
			let isSecured=secret.startsWith('dd');
			let isClassic=!isTLS&&!isSecured;
			let secretBytes=isClassic?raw.slice(0,16):raw.slice(1,17);
			let domain=isTLS?raw.slice(17).toString():undefined;
			return {secret:secretBytes,index,isTLS,isSecured,isClassic,domain,raw:secret};
		});
		tls_secrets=secrets.filter(function(secret){return secret.isTLS});
		secured_secrets=secrets.filter(function(secret){return secret.isSecured});
		classic_secrets=secrets.filter(function(secret){return secret.isClassic});
		use_middle_proxy=options.useMiddleProxy!==false;
		(use_middle_proxy?refreshProxyInfo():refreshPublicIPs()).then(function(){ready(getDetectedPublicHost())});
		this.proxy=function(client)
		{
			client.on('error',function(){})
			client.once('data',function(data)
			{
				if ((httpServer)&&isHttpRequestStart(data))
				{
					httpServer.emit('connection',client);
					client.emit('data',data);
					return false;
				}

				let index=globaleIndex;
				globaleIndex++;
				handleClient(client,enter,index).catch(function(err)
				{
					let error=err.stack;
					if (err.message==='client ended')
						error=undefined;
					leave({id:index,bytesWritten:client.bytesWritten,bytesRead:client.bytesRead,error})
					client.emit('finished',err)
				});
				client.emit('data',data);
			})
		};
	}
}

module.exports.MTProtoProxy=MTProtoProxy;


	return module.exports;
})();

const net = require('net');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const LISTEN_ADDR_IPV4 = '0.0.0.0';
const LISTEN_ADDR_IPV6 = '::';
const CONFIG_PATH = path.join(__dirname,'config.json');

const DEFAULT_SECRETS = new Set([
	'00000000000000000000000000000000',
	'0123456789abcdef0123456789abcdef',
	'00000000000000000000000000000001',
]);

function loadConfig()
{
	let cfg=JSON.parse(fs.readFileSync(CONFIG_PATH,'utf8'));
	cfg.PORT = Number(cfg.PORT || cfg.port || 5050);
	if (!Number.isInteger(cfg.PORT) || cfg.PORT<=0 || cfg.PORT>65535)
		cfg.PORT=5050;
	cfg.AD_TAG = normalizeAdTag(cfg.AD_TAG!==undefined?cfg.AD_TAG:cfg.adtag);
	cfg.AD_TAG_ENABLED = cfg.AD_TAG !== '';
	cfg.USE_MIDDLE_PROXY = cfg.AD_TAG_ENABLED;
	cfg.TLS_DOMAIN = cfg.TLS_DOMAIN || 'www.cloudflare.com';
	cfg.MODES = Object.assign({classic:false, secure:false, tls:true}, cfg.MODES || {});
	cfg.USERS = cfg.USERS || {};
	if (Object.keys(cfg.USERS).length===0)
		cfg.USERS={tg:'00000000000000000000000000000000'};
	return cfg;
}

function hasUsableIPv6()
{
	return Object.values(os.networkInterfaces()).some(function(items)
	{
		return items.some(function(item)
		{
			if (item.internal || !(item.family==='IPv6' || item.family===6))
				return false;
			let address=String(item.address || '').toLowerCase();
			return address && !address.startsWith('fe80:') && address!=='::1';
		});
	});
}

function normalizeAdTag(tag)
{
	tag=String(tag || '').trim().toLowerCase();
	return /^[0-9a-f]{32}$/.test(tag)?tag:'';
}

function hexDomain(domain)
{
	return Buffer.from(domain,'ascii').toString('hex');
}

function fixSecret(secret)
{
	secret=String(secret || '').replace(/[^0-9a-fA-F]/g,'').toLowerCase();
	return secret.padStart(32,'0').slice(0,32);
}

function getBaseSecret(secret)
{
	secret=String(secret || '').replace(/[^0-9a-fA-F]/g,'').toLowerCase();
	if (secret.startsWith('dd') || secret.startsWith('ee'))
		secret=secret.slice(2);
	return fixSecret(secret.slice(0,32));
}

function printSecretRecommendations(cfg)
{
	let items=[];
	Object.keys(cfg.USERS).sort().forEach(function(user)
	{
		items.push({user,secret:fixSecret(cfg.USERS[user])});
	});

	for (let item of items)
	{
		if (!DEFAULT_SECRETS.has(item.secret))
			continue;
		let randomSecret=crypto.randomBytes(16).toString('hex');
		console.log(`The default secret for ${item.user} is used, this is not recommended`);
		console.log(`You can change it to this random secret: ${randomSecret}`);
	}
}

function buildSecretsAndLinks(cfg, publicHost)
{
	let secrets=[];
	let links=[];
	let secretUsers=[];

	Object.keys(cfg.USERS).sort().forEach(function(user)
	{
		let secret=fixSecret(cfg.USERS[user]);
		if (cfg.MODES.classic)
		{
			secrets.push(secret);
			secretUsers.push({user,mode:'classic'});
			links.push({user,mode:'classic',link:makeLink(publicHost,cfg.PORT,secret)});
		}
		if (cfg.MODES.secure)
		{
			let s='dd'+secret;
			secrets.push(s);
			secretUsers.push({user,mode:'secure'});
			links.push({user,mode:'secure',link:makeLink(publicHost,cfg.PORT,s)});
		}
		if (cfg.MODES.tls)
		{
			let internalSecret='ee'+secret;
			let linkSecret=internalSecret+hexDomain(cfg.TLS_DOMAIN);
			secrets.push(internalSecret);
			secretUsers.push({user,mode:'tls'});
			links.push({user,mode:'tls',link:makeLink(publicHost,cfg.PORT,linkSecret)});
		}
	});
	return {secrets,links,secretUsers};
}

function makeLink(host,port,secret)
{
	let q=new URLSearchParams({server:host,port:String(port),secret});
	return 'tg://proxy?'+q.toString().replace(/%3A/g,':');
}

function printLinks(links)
{
	for (let item of links)
	{
		let mode=item.mode?`/${item.mode}`:'';
		console.log(`${item.user}${mode}: ${item.link}`);
	}
}

const config=loadConfig();

let initialSecrets=buildSecretsAndLinks(config,'YOUR_IP').secrets;
if (initialSecrets.length===0)
	throw new Error('No enabled proxy modes or users configured');

function isExpectedError(err)
{
	if (!err)
		return true;
	return err.code==='ECONNRESET' || ['client ended','server ended','client timedout','server timedout'].includes(err.message);
}

function handleFatal(kind,err)
{
	if (isExpectedError(err))
		return;
	console.log(kind,err && (err.stack || err));
	setTimeout(function(){process.exit(1)},100);
}

process.on('uncaughtException',function(err)
{
	handleFatal('Uncaught exception:',err);
});
process.on('unhandledRejection',function(err)
{
	handleFatal('Unhandled rejection:',err);
});

let telegram=new MTProtoProxy(
{
	secrets:initialSecrets,
	useMiddleProxy:config.USE_MIDDLE_PROXY,
	enter()
	{
		return config.AD_TAG || '00000000000000000000000000000000';
	},
	ready(publicHost)
	{
		let {links}=buildSecretsAndLinks(config,publicHost);
		let listenIPv6=hasUsableIPv6();
		let startupInfo={
			port:config.PORT,
			upstream:config.USE_MIDDLE_PROXY?'middle_proxy':'direct_dc',
			tls_domain:config.TLS_DOMAIN
		};
		if (config.AD_TAG_ENABLED)
			startupInfo.adtag=config.AD_TAG;
		console.log(startupInfo);
		printLinks(links);
		printSecretRecommendations(config);

		function listen(host,ipv6Only)
		{
			let proxy=net.createServer(telegram.proxy);
			proxy.on('error',function(err)
			{
				console.log(err);
			});
			proxy.listen({port:config.PORT,host,ipv6Only});
		}

		listen(LISTEN_ADDR_IPV4,false);
		if (listenIPv6)
			listen(LISTEN_ADDR_IPV6,true);
	}
});
