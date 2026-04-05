# OCR + Detector 三档对比

## 总览

| 指标 | strong | balanced | weak |
|---|---:|---:|---:|
| 候选总数 | 102 | 25 | 7 |
| 首轮总耗时（s） | 0.229920 | 0.062564 | 0.063976 |
| 预热后总耗时均值（s） | 0.045850 | 0.042565 | 0.041296 |
| 预热后单图均值（ms） | 3.527 | 3.274 | 3.177 |
| 聚合类型分布 | {'address': 28, 'email': 3, 'name': 68, 'organization': 2, 'phone': 1} | {'address': 15, 'email': 3, 'name': 2, 'organization': 4, 'phone': 1} | {'address': 1, 'email': 3, 'name': 2, 'phone': 1} |

OCR 总耗时：`6.334255s`，共 `13 张` 图片。

## 逐图对比

| 图片 | OCR块数 | OCR耗时(s) | strong | balanced | weak |
|---|---:|---:|---|---|---|
| 072416f5dcba877aff78edb5440cd2aa.jpg | 119 | 1.107152 | 31 个 / 0.0305s<br>类型: {'address': 6, 'name': 25}<br>示例: name:全部；address:润国际社区；name:时效；name:成色 | 1 个 / 0.0110s<br>类型: {'address': 1}<br>示例: address:泰州 | 0 个 / 0.0097s<br>类型: {}<br>示例: 无 |
| 55b69a3f4e97be3ced0c0ff8ed2f82e8.jpg | 40 | 0.439670 | 15 个 / 0.0052s<br>类型: {'address': 6, 'name': 6, 'organization': 2, 'phone': 1}<br>示例: address:福满生活超市；name:文盛印刷；organization:材料有限公司；address:北京市昌平区百善镇下东廓村2号库 77 北京 | 10 个 / 0.0051s<br>类型: {'address': 5, 'name': 1, 'organization': 3, 'phone': 1}<br>示例: organization:文盛印刷 材料有限公司；address:北京市昌平区百善镇下东廓村2号库 77 北京；organization:丽图文化传播有限公司；address:北京市昌平区昌平区 | 3 个 / 0.0045s<br>类型: {'address': 1, 'name': 1, 'phone': 1}<br>示例: phone:+86 18244520251；address:福满生活超市；name:VVV |
| ac01bbac18d2aab9d85aa07ed4b8fac0.jpg | 85 | 0.568991 | 15 个 / 0.0062s<br>类型: {'address': 4, 'name': 11}<br>示例: name:荣耀；name:国家补贴；name:国补；name:国家补贴 | 1 个 / 0.0063s<br>类型: {'address': 1}<br>示例: address:泰州 | 0 个 / 0.0083s<br>类型: {}<br>示例: 无 |
| amazon_0.png | 26 | 0.413085 | 5 个 / 0.0034s<br>类型: {'address': 2, 'email': 1, 'name': 2}<br>示例: address:co；name:keVIN dANiEl；name:keVIN；address:in | 3 个 / 0.0034s<br>类型: {'address': 2, 'email': 1}<br>示例: address:co；address:in；email:santos4318@outlook.gov | 1 个 / 0.0034s<br>类型: {'email': 1}<br>示例: email:santos4318@outlook.gov |
| booking_50.png | 18 | 0.359945 | 2 个 / 0.0023s<br>类型: {'email': 1, 'name': 1}<br>示例: name:zHaNg；email:Address alicewilliams@yahoo.org | 1 个 / 0.0022s<br>类型: {'email': 1}<br>示例: email:Address alicewilliams@yahoo.org | 1 个 / 0.0021s<br>类型: {'email': 1}<br>示例: email:Address alicewilliams@yahoo.org |
| email_100.png | 34 | 0.398192 | 1 个 / 0.0015s<br>类型: {'email': 1}<br>示例: email:Message ramesh_petrov@msn.net | 1 个 / 0.0013s<br>类型: {'email': 1}<br>示例: email:Message ramesh_petrov@msn.net | 1 个 / 0.0015s<br>类型: {'email': 1}<br>示例: email:Message ramesh_petrov@msn.net |
| ins_200.png | 26 | 0.414396 | 3 个 / 0.0036s<br>类型: {'address': 2, 'name': 1}<br>示例: address:or；name:CaROlIne mCinTyRe；address:90989 | 2 个 / 0.0031s<br>类型: {'address': 1, 'name': 1}<br>示例: address:or；name:CaROlIne mCinTyRe | 1 个 / 0.0031s<br>类型: {'name': 1}<br>示例: name:CaROlIne mCinTyRe |
| meituan_waimai_300.png | 35 | 0.450696 | 14 个 / 0.0047s<br>类型: {'address': 4, 'name': 10}<br>示例: address:Lincoln Street；name:Bobby JacksOn Phone number；address:94215-7906；name:时间 | 1 个 / 0.0041s<br>类型: {'address': 1}<br>示例: address:北京善缘街 | 0 个 / 0.0041s<br>类型: {}<br>示例: 无 |
| rednote_450.png | 31 | 0.434072 | 2 个 / 0.0027s<br>类型: {'address': 2}<br>示例: address:ID；address:in | 2 个 / 0.0027s<br>类型: {'address': 2}<br>示例: address:ID；address:in | 0 个 / 0.0027s<br>类型: {}<br>示例: 无 |
| tiktok_500.png | 26 | 0.399108 | 1 个 / 0.0021s<br>类型: {'name': 1}<br>示例: name:bRENda | 0 个 / 0.0019s<br>类型: {}<br>示例: 无 | 0 个 / 0.0029s<br>类型: {}<br>示例: 无 |
| wechat_550.png | 29 | 0.400378 | 3 个 / 0.0023s<br>类型: {'address': 1, 'name': 2}<br>示例: address:ID；name:bRiAn；name:FoSTER | 1 个 / 0.0020s<br>类型: {'address': 1}<br>示例: address:ID | 0 个 / 0.0019s<br>类型: {}<br>示例: 无 |
| whatsapp_600.png | 46 | 0.459227 | 1 个 / 0.0032s<br>类型: {'address': 1}<br>示例: address:or | 1 个 / 0.0029s<br>类型: {'address': 1}<br>示例: address:or | 0 个 / 0.0026s<br>类型: {}<br>示例: 无 |
| xiecheng_650.png | 42 | 0.469254 | 9 个 / 0.0043s<br>类型: {'name': 9}<br>示例: name:连锁；name:房 大床；name:费接送机；name:房必读 | 1 个 / 0.0036s<br>类型: {'organization': 1}<br>示例: organization:轻奢连锁酒店 | 0 个 / 0.0039s<br>类型: {}<br>示例: 无 |

## 结论

- `strong` 召回最高，但误检最明显，尤其容易把商品词、页面文案、短 token 打成 `name` 或 `address`。
- `balanced` 整体最均衡，邮箱、电话、明确地址还能保留较多，同时大幅减少了 `strong` 的噪声。
- `weak` 最保守，速度略快，但会漏掉不少姓名和地址。
