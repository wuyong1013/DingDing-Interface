# !/usr/bin/python
# -*- coding: utf-8 -*-

# 功能：接口数据预警，有问题发送钉钉通知
# 作者：吴勇
# 创建时间：2020/10/18
# 参数说明：
# 密钥（key）, 密斯偏移量（iv） CBC模式加密
import base64
from Crypto.Cipher import AES
import requests
import json
import Crypto
import logging

# 密钥（key）, 密斯偏移量（iv） CBC模式加密
def AES_Encrypt(key, data):
    # 填写aesIv:
    vi = ''
    pad = lambda s: s + (16 - len(s) % 16) * chr(16 - len(s) % 16)
    data = pad(data)
    # 字符串补位
    cipher = AES.new(key.encode('utf8'), AES.MODE_CBC, vi.encode('utf8'))
    encryptedbytes = cipher.encrypt(data.encode('utf8'))
    # 加密后得到的是bytes类型的数据
    encodestrs = base64.b64encode(encryptedbytes)
    # 使用Base64进行编码,返回byte字符串
    enctext = encodestrs.decode('utf8')
    # 对byte字符串按utf-8进行解码
    return enctext


def AES_Decrypt(key, data):
    #填写aesIv:
    vi = ''
    data = data.encode('utf8')
    encodebytes = base64.decodebytes(data)
    # 将加密数据转换位bytes类型数据
    cipher = AES.new(key.encode('utf8'), AES.MODE_CBC, vi.encode('utf8'))
    text_decrypted = cipher.decrypt(encodebytes)
    unpad = lambda s: s[0:-s[-1]]
    text_decrypted = unpad(text_decrypted)
    # 去补位
    text_decrypted = text_decrypted.decode('utf8')
    return text_decrypted

# 脚本自动向钉钉机器人发送信息
def post_to_dd(content):
    #填写钉钉机器人的发送码
    url = ''
    HEADERS = {
        "Content-Type": "application/json ;charset=utf-8"
    }
    String_textMsg = {"msgtype": "text", "text": {"content": content}}
    String_textMsg = json.dumps(String_textMsg)
    res = requests.post(url, data=String_textMsg, headers=HEADERS)
    logging.info(res.text)

#请求接口
gf_url = ""
#请求头
header = {'Content-Type': 'application/json;charset=UTF-8'}
#接口请求的json数据
payload ={
	"a001": {
		"uuid": "6A2FA853FA76044CC801942440095B2A",
		"uuid1": "6A2FA853FA76044CC801942440095B2A",
		"mac": "00-0C-29-D1-37-29",
		"cpuNo": "756E65476C65746E49656E69",
		"biosNo": "VMware-564d4639bc64f752-1076005d13d13729",
		"cpuNum": 4,
		"memSize": 3
	},
	"a002": {
		"osVer": "WIN10",
		"osVerNo": "10.0.18362",
		"bit": 1,
		"vm": 1,
		"ieVer": ""
	},
	"a003": {
		"aapp": [],
		"ssvc": []
	},
	"a004": {
		"product": "XXX",
		"proVer": "1.3.2.10817",

	},
	"data": {
		"type": 2
	}
}
#将请求头转换成json
data_1 = json.dumps(payload)
# 填写密钥
key = ''
datas=data_1
#将请求数据加密
AES_Encrypt(key, datas)
#加密数据
enctext = AES_Encrypt(key, datas)
#请求接口数据
r = requests.post(gf_url,headers=header,data=enctext,verify=False)
text=r.text
#解密数据
text_decrypted = AES_Decrypt(key, text)
# 将 JSON 对象类型转换为 Python 字典
user_dic = json.loads(text_decrypted)
print(text_decrypted)
if user_dic['code'] ==0:
    post_to_dd("结论："+ "\n"+r.url+"   接口请求成功"+ "\n"+"返回内容："+ "\n"+text_decrypted)
else:
    post_to_dd("结论："+ "\n"+r.url+"   接口请求失败"+ "\n"+"返回内容："+ "\n"+text_decrypted)
