# OCR 拼接逻辑与实际输出

输出目录：`D:\GitHub\PrivacyGuard\output\ocr_detector_render_20260405_235612`

## 当前代码逻辑

代码入口：
- `build_ocr_stream`：`privacyguard/infrastructure/pii/detector/preprocess.py`
- `analyze_ui_layout`：`privacyguard/infrastructure/pii/detector/ui_layout.py`
- 哨兵 token：`privacyguard/infrastructure/pii/rule_based_detector_shared.py`

处理顺序：
- crop_blocks: 先裁掉顶部 6% 与底部 8% 的 OCR block。
- group_into_lines: 按 Y-overlap > 0.45 聚成视觉行，行内按 X 排序。
- split_line_segments: 若行内 block 间距 > 平均字符宽度 * 3，则切成多个 segment。
- split_into_regions: 按垂直大间距、列数跳变、列对齐断裂切成多个区域。
- detect_layout: 区域内多段行占主导且列对齐时判为 table，否则为 flow。
- merge_table: 每行横向合并成一个语义组。
- merge_flow: 用缩进、左对齐续行、回到 anchor、冒号 label 等规则合并。
- prepare_ocr_block_text: 对每个 block 做 Unicode 归一、空白改写、边缘噪声裁剪、歧义字符修正。
- build_ocr_stream: 组间插 semantic break，组内跨视觉行插普通空格，同一视觉行内 block 之间插空格。

- `[INLINE_GAP]` 表示保留的大间距。
- `[SEMANTIC_BREAK]` 表示不同语义组之间的硬边界。

## 072416f5dcba877aff78edb5440cd2aa.jpg

- OCR blocks：`119`
- 裁剪后 blocks：`106`
- 视觉行数：`34`
- 区域数：`7`
- 语义组数：`45`

区域与分组：
- Region 1: lines 0..3, layout=table, groups=4
  raw: vivo xfold5手机 | X | AI | o0 | 00
  clean: vivo xfold5手机 | X | AI | o0 | 00
  raw: 全部 | 秒送 | 店铺 | 口碑
  clean: 全部 | 秒送 | 店铺 | 口碑
  raw: 华润国际社区. | 综合推荐 | 销量 | 筛选了
  clean: 华润国际社区. | 综合推荐 | 销量 | 筛选了
  raw: 黑色星期五 | 京东物流/时效 | 机身内存 | 成色 | <
  clean: 黑色星期五 | 京东物流/时效 | 机身内存 | 成色
- Region 2: lines 4..7, layout=table, groups=4
  raw: HOT | 国家补贴|vivo授权体验店 | 自营秒送 | vivoXFold5等效6000
  clean: HOT | 国家补贴|vivo授权体验店 | 自营秒送 | vivoXFold5等效6000
  raw: vivo X Fold5 | 100+人已买 | 1千+人加购
  clean: vivo X Fold5 | 100+人已买 | 1千+人加购
  raw: 联合研发
  clean: 联合研发
  raw: 6000mAh蓝海电池蔡司超级长 | 至高12期免息 | 第三代骁龙8 | NFC | 支持5G
  clean: 6000mAh蓝海电池蔡司超级长 | 至高12期免息 | 第三代骁龙8 | NFC | 支持5G
- Region 3: lines 8..8, layout=flow, groups=4
  raw: 30分钟送达 | 快至
  clean: 30分钟送达 | 快至
  raw: 购机送积分官网兑好礼 | 免费贴膜免费保养
  clean: 购机送积分官网兑好礼 | 免费贴膜免费保养
  raw: CPU型号
  clean: CPU型号
  raw: 特征特质 | 5G网络
  clean: 特征特质 | 5G网络
- Region 4: lines 9..9, layout=flow, groups=2
  raw: 晒单有礼联系门店领取 | ￥7999政府补贴价 | ￥8499
  clean: 晒单有礼联系门店领取 | ¥7999政府补贴价 | ¥8499
  raw: +
  clean: +
- Region 5: lines 10..13, layout=flow, groups=5
  raw: 补贴估到手价
  clean: 补贴估到手价
  raw: 20分钟达 | 政府补贴 | 3期免息
  clean: 20分钟达 | 政府补贴 | 3期免息
  raw: 9限部分地区部分机型与 | 国家补贴至 | 仅剩1件799弄 | 今10:15起送好评率99% | 本周上新vivo体验店-泰州万象..
  clean: 9限部分地区部分机型与 | 国家补贴至 | 仅剩1件799弄 | 今10:15起送好评率99% | 本周上新vivo体验店-泰州万象..
  raw: vivo
  clean: vivo
  raw: 出游季 | 自营 | vivoXFold5专业折叠旗舰
  clean: 出游季 | 自营 | vivoXFold5专业折叠旗舰
- Region 6: lines 14..28, layout=flow, groups=21
  raw: XFold5
  clean: XFold5
  raw: NFC功能|IPX8防护|轻薄机身
  clean: NFC功能|IPX8防护|轻薄机身
  raw: 票司联合研发
  clean: 票司联合研发
  raw: 到手价 | 6999 | 人
  clean: 到手价 | 6999 | 人
  raw: ￥6464.01政府补贴价 | ￥6999 | +
  clean: ¥6464.01政府补贴价 | ¥6999 | +
  raw: 等效6000mAh蓝海电池
  clean: 等效6000mAh蓝海电池
  raw: 明日达 | 政府补贴 | 京补合约 | 只换不修
  clean: 明日达 | 政府补贴 | 京补合约 | 只换不修
  raw: 超可靠三防折叠屏 | 蔡司超级长焦
  clean: 超可靠三防折叠屏 | 蔡司超级长焦
  raw: vivo京东自营旗舰店> | 155件同款在售 | 低至￥5965.44
  clean: vivo京东自营旗舰店 | 155件同款在售 | 低至¥5965.44
  raw: vivo
  clean: vivo
  raw: 出游季 | vivoXFold5新品5G手机折叠屏
  clean: 出游季 | vivoXFold5新品5G手机折叠屏
  raw: XFold5 | 更轻了更强了
  clean: XFold5 | 更轻了更强了
  raw: 频PWM|2K师彩|原作台
  clean: 频PWM|2K师彩|原作台
  raw: 12+256GB到手价
  clean: 12+256GB到手价
  raw: 6499 | 元
  clean: 6499 | 元
  raw: 12GB | 8.03英寸 | 5000万像素
  clean: 12GB | 8.03英寸 | 5000万像素
  raw: IOS生态破壁
  clean: IOS生态破壁
  raw: 运行内存 | 屏幕尺寸 | 后摄主像素
  clean: 运行内存 | 屏幕尺寸 | 后摄主像素
  raw: 2K蔡司大师色彩 | 现货速发快至次日达 | 专属原子工作台
  clean: 2K蔡司大师色彩 | 现货速发快至次日达 | 专属原子工作台
  raw: ￥6499.05到手价 | ￥6999
  clean: ¥6499.05到手价 | ¥6999
  raw: +
  clean: +
- Region 7: lines 29..33, layout=table, groups=5
  raw: 超可靠三防折叠屏 | 购礼150元 | 免费上门退换 | 7天价保
  clean: 超可靠三防折叠屏 | 购礼150元 | 免费上门退换 | 7天价保
  raw: 晒单享10元红包
  clean: 晒单享10元红包
  raw: 已售1000+2万+人种草
  clean: 已售1000+2万+人种草
  raw: 年度五星店铺炜东电商旗舰店 | □
  clean: 年度五星店铺炜东电商旗舰店 | □
  raw: 京东指数 | vivoXFold512+256G明
  clean: 京东指数 | vivoXFold512+256G明

block 级 clean 结果：

| block | raw_text | clean_text |
|---:|---|---|
| 0 | 01:19 | 01:19 |
| 1 | . | . |
| 2 | 89 | 89 |
| 3 | AI | AI |
| 4 | o0 | o0 |
| 5 | vivo xfold5手机 | vivo xfold5手机 |
| 6 | X | X |
| 7 | 00 | 00 |
| 8 | 全部 | 全部 |
| 9 | 秒送 | 秒送 |
| 10 | 店铺 | 店铺 |
| 11 | 口碑 | 口碑 |
| 12 | 华润国际社区. | 华润国际社区. |
| 13 | 综合推荐 | 综合推荐 |
| 14 | 销量 | 销量 |
| 15 | 筛选了 | 筛选了 |
| 16 | 黑色星期五 | 黑色星期五 |
| 17 | 京东物流/时效 | 京东物流/时效 |
| 18 | 机身内存 | 机身内存 |
| 19 | 成色 | 成色 |
| 20 | < |   |
| 21 | 国家补贴\|vivo授权体验店 | 国家补贴\|vivo授权体验店 |
| 22 | 自营秒送 | 自营秒送 |
| 23 | vivoXFold5等效6000 | vivoXFold5等效6000 |
| 24 | HOT | HOT |
| 25 | 100+人已买 | 100+人已买 |
| 26 | 1千+人加购 | 1千+人加购 |
| 27 | vivo X Fold5 | vivo X Fold5 |
| 28 | 联合研发 | 联合研发 |
| 29 | 6000mAh蓝海电池蔡司超级长 | 6000mAh蓝海电池蔡司超级长 |
| 30 | 第三代骁龙8 | 第三代骁龙8 |
| 31 | NFC | NFC |
| 32 | 支持5G | 支持5G |
| 33 | 至高12期免息 | 至高12期免息 |
| 34 | 免费贴膜免费保养 | 免费贴膜免费保养 |
| 35 | CPU型号 | CPU型号 |
| 36 | 特征特质 | 特征特质 |
| 37 | 5G网络 | 5G网络 |
| 38 | 快至 | 快至 |
| 39 | 30分钟送达 | 30分钟送达 |
| 40 | 购机送积分官网兑好礼 | 购机送积分官网兑好礼 |
| 41 | 晒单有礼联系门店领取 | 晒单有礼联系门店领取 |
| 42 | ￥7999政府补贴价 | ¥7999政府补贴价 |
| 43 | + | + |
| 44 | ￥8499 | ¥8499 |
| 45 | 20分钟达 | 20分钟达 |
| 46 | 政府补贴 | 政府补贴 |
| 47 | 3期免息 | 3期免息 |
| 48 | 补贴估到手价 | 补贴估到手价 |
| 49 | 国家补贴至 | 国家补贴至 |
| 50 | 仅剩1件799弄 | 仅剩1件799弄 |
| 51 | 今10:15起送好评率99% | 今10:15起送好评率99% |
| 52 | 9限部分地区部分机型与 | 9限部分地区部分机型与 |
| 53 | 本周上新vivo体验店-泰州万象.. | 本周上新vivo体验店-泰州万象.. |
| 54 | vivo | vivo |
| 55 | 出游季 | 出游季 |
| 56 | 自营 | 自营 |
| 57 | vivoXFold5专业折叠旗舰 | vivoXFold5专业折叠旗舰 |
| 58 | NFC功能\|IPX8防护\|轻薄机身 | NFC功能\|IPX8防护\|轻薄机身 |
| 59 | XFold5 | XFold5 |
| 60 | 票司联合研发 | 票司联合研发 |
| 61 | ￥6464.01政府补贴价 | ¥6464.01政府补贴价 |
| 62 | ￥6999 | ¥6999 |
| 63 | + | + |
| 64 | 到手价 | 到手价 |
| 65 | 6999 | 6999 |
| 66 | 人 | 人 |
| 67 | 明日达 | 明日达 |
| 68 | 政府补贴 | 政府补贴 |
| 69 | 京补合约 | 京补合约 |
| 70 | 只换不修 | 只换不修 |
| 71 | 等效6000mAh蓝海电池 | 等效6000mAh蓝海电池 |
| 72 | 超可靠三防折叠屏 | 超可靠三防折叠屏 |
| 73 | 蔡司超级长焦 | 蔡司超级长焦 |
| 74 | vivo京东自营旗舰店> | vivo京东自营旗舰店 |
| 75 | 155件同款在售 | 155件同款在售 |
| 76 | 低至￥5965.44 | 低至¥5965.44 |
| 77 | vivo | vivo |
| 78 | 出游季 | 出游季 |
| 79 | vivoXFold5新品5G手机折叠屏 | vivoXFold5新品5G手机折叠屏 |
| 80 | XFold5 | XFold5 |
| 81 | 频PWM\|2K师彩\|原作台 | 频PWM\|2K师彩\|原作台 |
| 82 | 更轻了更强了 | 更轻了更强了 |
| 83 | 12+256GB到手价 | 12+256GB到手价 |
| 84 | 6499 | 6499 |
| 85 | 12GB | 12GB |
| 86 | 8.03英寸 | 8.03英寸 |
| 87 | 5000万像素 | 5000万像素 |
| 88 | 元 | 元 |
| 89 | 运行内存 | 运行内存 |
| 90 | 屏幕尺寸 | 屏幕尺寸 |
| 91 | 后摄主像素 | 后摄主像素 |
| 92 | IOS生态破壁 | IOS生态破壁 |
| 93 | 2K蔡司大师色彩 | 2K蔡司大师色彩 |
| 94 | ￥6499.05到手价 | ¥6499.05到手价 |
| 95 | ￥6999 | ¥6999 |
| 96 | + | + |
| 97 | 专属原子工作台 | 专属原子工作台 |
| 98 | 现货速发快至次日达 | 现货速发快至次日达 |
| 99 | 超可靠三防折叠屏 | 超可靠三防折叠屏 |
| 100 | 购礼150元 | 购礼150元 |
| 101 | 免费上门退换 | 免费上门退换 |
| 102 | 7天价保 | 7天价保 |
| 103 | 晒单享10元红包 | 晒单享10元红包 |
| 104 | 已售1000+2万+人种草 | 已售1000+2万+人种草 |
| 105 | □ | □ |
| 106 | 年度五星店铺炜东电商旗舰店 | 年度五星店铺炜东电商旗舰店 |
| 107 | 京东指数 | 京东指数 |
| 108 | vivoXFold512+256G明 | vivoXFold512+256G明 |
| 109 | AI模型\|频PWM\|2K师屏 | AI模型\|频PWM\|2K师屏 |
| 110 | ￥6758 | ¥6758 |
| 111 | 全网低价 | 全网低价 |
| 112 | + | + |
| 113 | 明日达 | 明日达 |
| 114 | 京东指数 | 京东指数 |
| 115 | 指数验真 | 指数验真 |
| 116 | 包邮 | 包邮 |
| 117 | □佳10工 | □佳10工 |
| 118 | 0：评 | 0：评 |

clean 后送入 detector 的拼接文本：
```text
vivo xfold5手机 X AI o0 00[SEMANTIC_BREAK]全部 秒送 店铺 口碑[SEMANTIC_BREAK]华润国际社区.综合推荐 销量 筛选了[SEMANTIC_BREAK]黑色星期五 京东物流/时效 机身内存 成色[SEMANTIC_BREAK]HOT 国家补贴|vivo授权体验店 自营秒送 vivoXFold5等效6000[SEMANTIC_BREAK]vivo X Fold5 100+人已买 1千+人加购[SEMANTIC_BREAK]联合研发[SEMANTIC_BREAK]6000mAh蓝海电池蔡司超级长 至高12期免息 第三代骁龙8 NFC 支持5G[SEMANTIC_BREAK]快至30分钟送达[SEMANTIC_BREAK]免费贴膜免费保养购机送积分官网兑好礼[SEMANTIC_BREAK]CPU型号[SEMANTIC_BREAK]特征特质 5G网络[SEMANTIC_BREAK]晒单有礼联系门店领取 ¥7999政府补贴价 ¥8499[SEMANTIC_BREAK]+[SEMANTIC_BREAK]补贴估到手价[SEMANTIC_BREAK]20分钟达 政府补贴 3期免息[SEMANTIC_BREAK]9限部分地区部分机型与 国家补贴至 仅剩1件799弄 今10:15起送好评率99%本周上新vivo体验店-泰州万象..[SEMANTIC_BREAK]vivo[SEMANTIC_BREAK]出游季 自营 vivoXFold5专业折叠旗舰[SEMANTIC_BREAK]XFold5[SEMANTIC_BREAK]NFC功能|IPX8防护|轻薄机身[SEMANTIC_BREAK]票司联合研发[SEMANTIC_BREAK]到手价 6999 人[SEMANTIC_BREAK]¥6464.01政府补贴价 ¥6999 +[SEMANTIC_BREAK]等效6000mAh蓝海电池[SEMANTIC_BREAK]明日达 政府补贴 京补合约 只换不修[SEMANTIC_BREAK]超可靠三防折叠屏蔡司超级长焦[SEMANTIC_BREAK]vivo京东自营旗舰店155件同款在售 低至¥5965.44[SEMANTIC_BREAK]vivo[SEMANTIC_BREAK]出游季 vivoXFold5新品5G手机折叠屏[SEMANTIC_BREAK]XFold5更轻了更强了[SEMANTIC_BREAK]频PWM|2K师彩|原作台[SEMANTIC_BREAK]12+256GB到手价[SEMANTIC_BREAK]6499 元[SEMANTIC_BREAK]12GB 8.03英寸 5000万像素[SEMANTIC_BREAK]IOS生态破壁[SEMANTIC_BREAK]运行内存 屏幕尺寸 后摄主像素[SEMANTIC_BREAK]2K蔡司大师色彩专属原子工作台现货速发快至次日达[SEMANTIC_BREAK]¥6499.05到手价 ¥6999[SEMANTIC_BREAK]+[SEMANTIC_BREAK]超可靠三防折叠屏 购礼150元 免费上门退换 7天价保[SEMANTIC_BREAK]晒单享10元红包[SEMANTIC_BREAK]已售1000+2万+人种草[SEMANTIC_BREAK]年度五星店铺炜东电商旗舰店 □[SEMANTIC_BREAK]京东指数 vivoXFold512+256G明
```

raw block 按当前组装顺序得到的文本：
```text
vivo xfold5手机 X AI o0 00[SEMANTIC_BREAK]全部 秒送 店铺 口碑[SEMANTIC_BREAK]华润国际社区. 综合推荐 销量 筛选了[SEMANTIC_BREAK]黑色星期五 京东物流/时效 机身内存 成色 <[SEMANTIC_BREAK]HOT 国家补贴|vivo授权体验店 自营秒送 vivoXFold5等效6000[SEMANTIC_BREAK]vivo X Fold5 100+人已买 1千+人加购[SEMANTIC_BREAK]联合研发[SEMANTIC_BREAK]6000mAh蓝海电池蔡司超级长 至高12期免息 第三代骁龙8 NFC 支持5G[SEMANTIC_BREAK]快至 30分钟送达[SEMANTIC_BREAK]免费贴膜免费保养 购机送积分官网兑好礼[SEMANTIC_BREAK]CPU型号[SEMANTIC_BREAK]特征特质 5G网络[SEMANTIC_BREAK]晒单有礼联系门店领取 ￥7999政府补贴价 ￥8499[SEMANTIC_BREAK]+[SEMANTIC_BREAK]补贴估到手价[SEMANTIC_BREAK]20分钟达 政府补贴 3期免息[SEMANTIC_BREAK]9限部分地区部分机型与 国家补贴至 仅剩1件799弄 今10:15起送好评率99% 本周上新vivo体验店-泰州万象..[SEMANTIC_BREAK]vivo[SEMANTIC_BREAK]出游季 自营 vivoXFold5专业折叠旗舰[SEMANTIC_BREAK]XFold5[SEMANTIC_BREAK]NFC功能|IPX8防护|轻薄机身[SEMANTIC_BREAK]票司联合研发[SEMANTIC_BREAK]到手价 6999 人[SEMANTIC_BREAK]￥6464.01政府补贴价 ￥6999 +[SEMANTIC_BREAK]等效6000mAh蓝海电池[SEMANTIC_BREAK]明日达 政府补贴 京补合约 只换不修[SEMANTIC_BREAK]超可靠三防折叠屏 蔡司超级长焦[SEMANTIC_BREAK]vivo京东自营旗舰店> 155件同款在售 低至￥5965.44[SEMANTIC_BREAK]vivo[SEMANTIC_BREAK]出游季 vivoXFold5新品5G手机折叠屏[SEMANTIC_BREAK]XFold5 更轻了更强了[SEMANTIC_BREAK]频PWM|2K师彩|原作台[SEMANTIC_BREAK]12+256GB到手价[SEMANTIC_BREAK]6499 元[SEMANTIC_BREAK]12GB 8.03英寸 5000万像素[SEMANTIC_BREAK]IOS生态破壁[SEMANTIC_BREAK]运行内存 屏幕尺寸 后摄主像素[SEMANTIC_BREAK]2K蔡司大师色彩 专属原子工作台 现货速发快至次日达[SEMANTIC_BREAK]￥6499.05到手价 ￥6999[SEMANTIC_BREAK]+[SEMANTIC_BREAK]超可靠三防折叠屏 购礼150元 免费上门退换 7天价保[SEMANTIC_BREAK]晒单享10元红包[SEMANTIC_BREAK]已售1000+2万+人种草[SEMANTIC_BREAK]年度五星店铺炜东电商旗舰店 □[SEMANTIC_BREAK]京东指数 vivoXFold512+256G明
```

## 55b69a3f4e97be3ced0c0ff8ed2f82e8.jpg

- OCR blocks：`40`
- 裁剪后 blocks：`37`
- 视觉行数：`19`
- 区域数：`6`
- 语义组数：`20`

区域与分组：
- Region 1: lines 0..0, layout=flow, groups=2
  raw: 收货地址
  clean: 收货地址
  raw: 管理 | 新增地址
  clean: 管理 | 新增地址
- Region 2: lines 1..1, layout=flow, groups=2
  raw: 找不到地址？试试搜索吧
  clean: 找不到地址？试试搜索吧
  raw: ×
  clean: ×
- Region 3: lines 2..7, layout=flow, groups=8
  raw: 福满生活超市
  clean: 福满生活超市
  raw: 110号
  clean: 110号
  raw: 京文盛印刷 | 材料有限公司
  clean: 京文盛印刷 | 材料有限公司
  raw: 77 | 16m|北京市昌平区百善镇下东廓村2号库 | 北京丽图文化传播有限公司库房
  clean: 77 | 16m|北京市昌平区百善镇下东廓村2号库 | 北京丽图文化传播有限公司库房
  raw: 使用 | 作室
  clean: 使用 | 作室
  raw: 110m北京市昌平区昌平区
  clean: 110m北京市昌平区昌平区
  raw: 高德地图 | 恒达发电机出租
  clean: 高德地图 | 恒达发电机出租
  raw: 航博家属院
  clean: 航博家属院
- Region 4: lines 8..12, layout=flow, groups=6
  raw: 搜索地址，更快填写
  clean: 搜索地址，更快填写
  raw: T
  clean: T
  raw: 智能粘贴
  clean: 智能粘贴
  raw: *北京北京市昌平区百善镇
  clean: *北京北京市昌平区百善镇
  raw: 默认地址
  clean: 默认地址
  raw: *详细地址与门牌号 | 虚拟道具专用地址
  clean: *详细地址与门牌号 | 虚拟道具专用地址
- Region 5: lines 13..16, layout=flow, groups=1
  raw: *收货人名字 | VVV | *手机号 | +86 | 18244520251
  clean: *收货人名字 | VVV | *手机号 | +86 | 18244520251
- Region 6: lines 17..18, layout=flow, groups=1
  raw: 地址标签 | 家 | 公司 | 学校 | 父母 | 朋友 | 自定义
  clean: 地址标签 | 家 | 公司 | 学校 | 父母 | 朋友 | 自定义

block 级 clean 结果：

| block | raw_text | clean_text |
|---:|---|---|
| 0 | 01:20 | 01:20 |
| 1 | 88 | 88 |
| 2 | 收货地址 | 收货地址 |
| 3 | 管理 | 管理 |
| 4 | 新增地址 | 新增地址 |
| 5 | 找不到地址？试试搜索吧 | 找不到地址？试试搜索吧 |
| 6 | × | × |
| 7 | 福满生活超市 | 福满生活超市 |
| 8 | 110号 | 110号 |
| 9 | 京文盛印刷 | 京文盛印刷 |
| 10 | 材料有限公司 | 材料有限公司 |
| 11 | 16m\|北京市昌平区百善镇下东廓村2号库 | 16m\|北京市昌平区百善镇下东廓村2号库 |
| 12 | 作室 | 作室 |
| 13 | 使用 | 使用 |
| 14 | 77 | 77 |
| 15 | 北京丽图文化传播有限公司库房 | 北京丽图文化传播有限公司库房 |
| 16 | 110m北京市昌平区昌平区 | 110m北京市昌平区昌平区 |
| 17 | 高德地图 | 高德地图 |
| 18 | 航博家属院 | 航博家属院 |
| 19 | 恒达发电机出租 | 恒达发电机出租 |
| 20 | T | T |
| 21 | 搜索地址，更快填写 | 搜索地址，更快填写 |
| 22 | 智能粘贴 | 智能粘贴 |
| 23 | *北京北京市昌平区百善镇 | *北京北京市昌平区百善镇 |
| 24 | 默认地址 | 默认地址 |
| 25 | *详细地址与门牌号 | *详细地址与门牌号 |
| 26 | 虚拟道具专用地址 | 虚拟道具专用地址 |
| 27 | *收货人名字 | *收货人名字 |
| 28 | VVV | VVV |
| 29 | *手机号 | *手机号 |
| 30 | +86 | +86 |
| 31 | 18244520251 | 18244520251 |
| 32 | 地址标签 | 地址标签 |
| 33 | 家 | 家 |
| 34 | 公司 | 公司 |
| 35 | 学校 | 学校 |
| 36 | 父母 | 父母 |
| 37 | 朋友 | 朋友 |
| 38 | 自定义 | 自定义 |
| 39 | 保存地址 | 保存地址 |

clean 后送入 detector 的拼接文本：
```text
收货地址[SEMANTIC_BREAK]管理 新增地址[SEMANTIC_BREAK]找不到地址？试试搜索吧[SEMANTIC_BREAK]×[SEMANTIC_BREAK]福满生活超市[SEMANTIC_BREAK]110号[SEMANTIC_BREAK]京文盛印刷材料有限公司[SEMANTIC_BREAK]16m|北京市昌平区百善镇下东廓村2号库77 北京丽图文化传播有限公司库房[SEMANTIC_BREAK]使用 作室[SEMANTIC_BREAK]110m北京市昌平区昌平区[SEMANTIC_BREAK]高德地图 恒达发电机出租[SEMANTIC_BREAK]航博家属院[SEMANTIC_BREAK]搜索地址，更快填写[SEMANTIC_BREAK]T[SEMANTIC_BREAK]智能粘贴[SEMANTIC_BREAK]*北京北京市昌平区百善镇[SEMANTIC_BREAK]默认地址[SEMANTIC_BREAK]*详细地址与门牌号虚拟道具专用地址[SEMANTIC_BREAK]*收货人名字VVV*手机号+86 18244520251[SEMANTIC_BREAK]地址标签家 公司 学校 父母 朋友 自定义
```

raw block 按当前组装顺序得到的文本：
```text
收货地址[SEMANTIC_BREAK]管理 新增地址[SEMANTIC_BREAK]找不到地址？试试搜索吧[SEMANTIC_BREAK]×[SEMANTIC_BREAK]福满生活超市[SEMANTIC_BREAK]110号[SEMANTIC_BREAK]京文盛印刷 材料有限公司[SEMANTIC_BREAK]16m|北京市昌平区百善镇下东廓村2号库 77 北京丽图文化传播有限公司库房[SEMANTIC_BREAK]使用 作室[SEMANTIC_BREAK]110m北京市昌平区昌平区[SEMANTIC_BREAK]高德地图 恒达发电机出租[SEMANTIC_BREAK]航博家属院[SEMANTIC_BREAK]搜索地址，更快填写[SEMANTIC_BREAK]T[SEMANTIC_BREAK]智能粘贴[SEMANTIC_BREAK]*北京北京市昌平区百善镇[SEMANTIC_BREAK]默认地址[SEMANTIC_BREAK]*详细地址与门牌号 虚拟道具专用地址[SEMANTIC_BREAK]*收货人名字 VVV *手机号 +86 18244520251[SEMANTIC_BREAK]地址标签 家 公司 学校 父母 朋友 自定义
```

## ac01bbac18d2aab9d85aa07ed4b8fac0.jpg

- OCR blocks：`85`
- 裁剪后 blocks：`77`
- 视觉行数：`24`
- 区域数：`7`
- 语义组数：`30`

区域与分组：
- Region 1: lines 0..5, layout=table, groups=6
  raw: 特价 | 首页 | 秒送 | 外卖 | 新品 | 0 | 百亿补贴 | 抢外卖券
  clean: 特价 | 首页 | 秒送 | 外卖 | 新品 | 0 | 百亿补贴 | 抢外卖券
  raw: 荣耀magicv6 | AI | 搜索
  clean: 荣耀magicv6 | AI | 搜索
  raw: 关注 | 推荐 | 国家补贴 | 电脑办公 | 数码 | 食品 | 分类
  clean: 关注 | 推荐 | 国家补贴 | 电脑办公 | 数码 | 食品 | 分类
  raw: 领京豆 | 省 | 便宜 | 国补
  clean: 领京豆 | 省 | 便宜 | 国补
  raw: 秒杀 | 拍拍二手 | 手机数码 | 手机馆 | 机票 | 京东
  clean: 秒杀 | 拍拍二手 | 手机数码 | 手机馆 | 机票 | 京东
  raw: 国家补贴×百亿补贴 | 品质生活 | 999 | 感冒灵
  clean: 国家补贴×百亿补贴 | 品质生活 | 999 | 感冒灵
- Region 2: lines 6..10, layout=flow, groups=6
  raw: 泰州
  clean: 泰州
  raw: 24h
  clean: 24h
  raw: 超市秒送 | 买药秒送
  clean: 超市秒送 | 买药秒送
  raw: 百亿补贴 | 外卖
  clean: 百亿补贴 | 外卖
  raw: ￥599 | 补贴价 | ￥900.2补贴价
  clean: ¥599 | 补贴价 | ¥900.2补贴价
  raw: 外卖 | 京东旅行 | 京东点评
  clean: 外卖 | 京东旅行 | 京东点评
- Region 3: lines 11..11, layout=flow, groups=3
  raw: 9.9包邮
  clean: 9.9包邮
  raw: 抽3000京
  clean: 抽3000京
  raw: 直播低价
  clean: 直播低价
- Region 4: lines 12..12, layout=flow, groups=1
  raw: MAKE
  clean: MAKE
- Region 5: lines 13..14, layout=flow, groups=5
  raw: 关注主播超值修
  clean: 关注主播超值修
  raw: ￥14.88
  clean: ¥14.88
  raw: ￥26.99
  clean: ¥26.99
  raw: ￥446
  clean: ¥446
  raw: ￥ | 100
  clean: ¥ | 100
- Region 6: lines 15..17, layout=table, groups=3
  raw: 学生专区 | 1元包邮 | 春日好物
  clean: 学生专区 | 1元包邮 | 春日好物
  raw: 百亿补贴
  clean: 百亿补贴
  raw: 省 | JELLYCAT
  clean: 省 | JELLYCAT
- Region 7: lines 18..23, layout=table, groups=6
  raw: 国补直降 | 最高 | 17 | 元
  clean: 国补直降 | 最高 | 17 | 元
  raw: 20%
  clean: 20%
  raw: 领60元优惠 | 直降88折起
  clean: 领60元优惠 | 直降88折起
  raw: 教育优惠礼金 | 17元外卖餐补
  clean: 教育优惠礼金 | 17元外卖餐补
  raw: 出游季 | 国补5折起>
  clean: 出游季 | 国补5折起
  raw: AM | 怒喵歪歪线 | SLANT | AngrvMiao | 超市黑五 | 资质与规则
  clean: AM | 怒喵歪歪线 | SLANT | AngrvMiao | 超市黑五 | 资质与规则

block 级 clean 结果：

| block | raw_text | clean_text |
|---:|---|---|
| 0 | 01:19 | 01:19 |
| 1 | 90 | 90 |
| 2 | 百亿补贴 | 百亿补贴 |
| 3 | 特价 | 特价 |
| 4 | 首页 | 首页 |
| 5 | 秒送 | 秒送 |
| 6 | 外卖 | 外卖 |
| 7 | 新品 | 新品 |
| 8 | 0 | 0 |
| 9 | 抢外卖券 | 抢外卖券 |
| 10 | 荣耀magicv6 | 荣耀magicv6 |
| 11 | AI | AI |
| 12 | 搜索 | 搜索 |
| 13 | 关注 | 关注 |
| 14 | 推荐 | 推荐 |
| 15 | 国家补贴 | 国家补贴 |
| 16 | 电脑办公 | 电脑办公 |
| 17 | 数码 | 数码 |
| 18 | 食品 | 食品 |
| 19 | 分类 | 分类 |
| 20 | 领京豆 | 领京豆 |
| 21 | 便宜 | 便宜 |
| 22 | 国补 | 国补 |
| 23 | 省 | 省 |
| 24 | 秒杀 | 秒杀 |
| 25 | 拍拍二手 | 拍拍二手 |
| 26 | 手机数码 | 手机数码 |
| 27 | 手机馆 | 手机馆 |
| 28 | 机票 | 机票 |
| 29 | 京东 | 京东 |
| 30 | 国家补贴×百亿补贴 | 国家补贴×百亿补贴 |
| 31 | 品质生活 | 品质生活 |
| 32 | 999 | 999 |
| 33 | 感冒灵 | 感冒灵 |
| 34 | 泰州 | 泰州 |
| 35 | 24h | 24h |
| 36 | 超市秒送 | 超市秒送 |
| 37 | 买药秒送 | 买药秒送 |
| 38 | 百亿补贴 | 百亿补贴 |
| 39 | 外卖 | 外卖 |
| 40 | ￥599 | ¥599 |
| 41 | 补贴价 | 补贴价 |
| 42 | ￥900.2补贴价 | ¥900.2补贴价 |
| 43 | 外卖 | 外卖 |
| 44 | 京东旅行 | 京东旅行 |
| 45 | 京东点评 | 京东点评 |
| 46 | 9.9包邮 | 9.9包邮 |
| 47 | 抽3000京 | 抽3000京 |
| 48 | 直播低价 | 直播低价 |
| 49 | MAKE | MAKE |
| 50 | 关注主播超值修 | 关注主播超值修 |
| 51 | ￥14.88 | ¥14.88 |
| 52 | ￥26.99 | ¥26.99 |
| 53 | ￥446 | ¥446 |
| 54 | 100 | 100 |
| 55 | ￥ | ¥ |
| 56 | 学生专区 | 学生专区 |
| 57 | 1元包邮 | 1元包邮 |
| 58 | 春日好物 | 春日好物 |
| 59 | 百亿补贴 | 百亿补贴 |
| 60 | 省 | 省 |
| 61 | JELLYCAT | JELLYCAT |
| 62 | 国补直降 | 国补直降 |
| 63 | 17 | 17 |
| 64 | 最高 | 最高 |
| 65 | 20% | 20% |
| 66 | 元 | 元 |
| 67 | 领60元优惠 | 领60元优惠 |
| 68 | 直降88折起 | 直降88折起 |
| 69 | 教育优惠礼金 | 教育优惠礼金 |
| 70 | 17元外卖餐补 | 17元外卖餐补 |
| 71 | 出游季 | 出游季 |
| 72 | 国补5折起> | 国补5折起 |
| 73 | 超市黑五 | 超市黑五 |
| 74 | AM | AM |
| 75 | SLANT | SLANT |
| 76 | 资质与规则 | 资质与规则 |
| 77 | 怒喵歪歪线 | 怒喵歪歪线 |
| 78 | AngrvMiao | AngrvMiao |
| 79 | SNANT | SNANT |
| 80 | ikbc | ikbc |
| 81 | 5+ | 5+ |
| 82 | 消息 | 消息 |
| 83 | 购物车 | 购物车 |
| 84 | 我的 | 我的 |

clean 后送入 detector 的拼接文本：
```text
特价 首页 秒送 外卖 新品 0 百亿补贴 抢外卖券[SEMANTIC_BREAK]荣耀magicv6 AI 搜索[SEMANTIC_BREAK]关注 推荐 国家补贴 电脑办公 数码 食品 分类[SEMANTIC_BREAK]领京豆 省 便宜 国补[SEMANTIC_BREAK]秒杀 拍拍二手 手机数码 手机馆 机票 京东[SEMANTIC_BREAK]国家补贴×百亿补贴 品质生活 999 感冒灵[SEMANTIC_BREAK]泰州[SEMANTIC_BREAK]24h[SEMANTIC_BREAK]超市秒送 买药秒送[SEMANTIC_BREAK]百亿补贴外卖[SEMANTIC_BREAK]¥599 补贴价 ¥900.2补贴价[SEMANTIC_BREAK]外卖 京东旅行 京东点评[SEMANTIC_BREAK]9.9包邮[SEMANTIC_BREAK]抽3000京[SEMANTIC_BREAK]直播低价[SEMANTIC_BREAK]MAKE[SEMANTIC_BREAK]关注主播超值修[SEMANTIC_BREAK]¥14.88[SEMANTIC_BREAK]¥26.99[SEMANTIC_BREAK]¥446[SEMANTIC_BREAK]¥ 100[SEMANTIC_BREAK]学生专区 1元包邮 春日好物[SEMANTIC_BREAK]百亿补贴[SEMANTIC_BREAK]省 JELLYCAT[SEMANTIC_BREAK]国补直降 最高 17 元[SEMANTIC_BREAK]20%[SEMANTIC_BREAK]领60元优惠 直降88折起[SEMANTIC_BREAK]教育优惠礼金 17元外卖餐补[SEMANTIC_BREAK]出游季 国补5折起[SEMANTIC_BREAK]AM 怒喵歪歪线 SLANT AngrvMiao 超市黑五 资质与规则
```

raw block 按当前组装顺序得到的文本：
```text
特价 首页 秒送 外卖 新品 0 百亿补贴 抢外卖券[SEMANTIC_BREAK]荣耀magicv6 AI 搜索[SEMANTIC_BREAK]关注 推荐 国家补贴 电脑办公 数码 食品 分类[SEMANTIC_BREAK]领京豆 省 便宜 国补[SEMANTIC_BREAK]秒杀 拍拍二手 手机数码 手机馆 机票 京东[SEMANTIC_BREAK]国家补贴×百亿补贴 品质生活 999 感冒灵[SEMANTIC_BREAK]泰州[SEMANTIC_BREAK]24h[SEMANTIC_BREAK]超市秒送 买药秒送[SEMANTIC_BREAK]百亿补贴 外卖[SEMANTIC_BREAK]￥599 补贴价 ￥900.2补贴价[SEMANTIC_BREAK]外卖 京东旅行 京东点评[SEMANTIC_BREAK]9.9包邮[SEMANTIC_BREAK]抽3000京[SEMANTIC_BREAK]直播低价[SEMANTIC_BREAK]MAKE[SEMANTIC_BREAK]关注主播超值修[SEMANTIC_BREAK]￥14.88[SEMANTIC_BREAK]￥26.99[SEMANTIC_BREAK]￥446[SEMANTIC_BREAK]￥ 100[SEMANTIC_BREAK]学生专区 1元包邮 春日好物[SEMANTIC_BREAK]百亿补贴[SEMANTIC_BREAK]省 JELLYCAT[SEMANTIC_BREAK]国补直降 最高 17 元[SEMANTIC_BREAK]20%[SEMANTIC_BREAK]领60元优惠 直降88折起[SEMANTIC_BREAK]教育优惠礼金 17元外卖餐补[SEMANTIC_BREAK]出游季 国补5折起>[SEMANTIC_BREAK]AM 怒喵歪歪线 SLANT AngrvMiao 超市黑五 资质与规则
```

## amazon_0.png

- OCR blocks：`26`
- 裁剪后 blocks：`22`
- 视觉行数：`14`
- 区域数：`7`
- 语义组数：`16`

区域与分组：
- Region 1: lines 0..1, layout=flow, groups=2
  raw: amazon.co.uk | Hello, keVIN dANiEl
  clean: amazon.co.uk | Hello,keVIN dANiEl
  raw: 米 | EN
  clean: 米 | EN
- Region 2: lines 2..5, layout=flow, groups=5
  raw: Orders
  clean: Orders
  raw: Buy Again
  clean: Buy Again
  raw: Account
  clean: Account
  raw: Lists
  clean: Lists
  raw: Your Orders | Hi, you have no recent orders. | Return to the home page
  clean: Your Orders | Hi,you have no recent orders. | Return to the home page
- Region 3: lines 6..8, layout=flow, groups=1
  raw: Buy again | See what others are reordering on buy again | Visit Buy Again
  clean: Buy again | See what others are reordering on buy again | Visit Buy Again
- Region 4: lines 9..9, layout=flow, groups=2
  raw: Who's shopping?
  clean: Who's shopping?
  raw: X
  clean: X
- Region 5: lines 10..11, layout=flow, groups=3
  raw: keVIN dANiEI
  clean: keVIN dANiEI
  raw: View
  clean: View
  raw: Account holder
  clean: Account holder
- Region 6: lines 12..12, layout=flow, groups=2
  raw: Add profile
  clean: Add profile
  raw: Remove profile
  clean: Remove profile
- Region 7: lines 13..13, layout=flow, groups=1
  raw: Signed in as homer dos santos4318@outlook.gov
  clean: Signed in as homer dos santos4318@outlook.gov

block 级 clean 结果：

| block | raw_text | clean_text |
|---:|---|---|
| 0 | 15:24 | 15:24 |
| 1 | 25 | 25 |
| 2 | amazon.co.uk | amazon.co.uk |
| 3 | Hello, keVIN dANiEl | Hello,keVIN dANiEl |
| 4 | 米 | 米 |
| 5 | EN | EN |
| 6 | Orders | Orders |
| 7 | Buy Again | Buy Again |
| 8 | Account | Account |
| 9 | Lists | Lists |
| 10 | Your Orders | Your Orders |
| 11 | Hi, you have no recent orders. | Hi,you have no recent orders. |
| 12 | Return to the home page | Return to the home page |
| 13 | Buy again | Buy again |
| 14 | See what others are reordering on buy again | See what others are reordering on buy again |
| 15 | Visit Buy Again | Visit Buy Again |
| 16 | Who's shopping? | Who's shopping? |
| 17 | X | X |
| 18 | keVIN dANiEI | keVIN dANiEI |
| 19 | View | View |
| 20 | Account holder | Account holder |
| 21 | Add profile | Add profile |
| 22 | Remove profile | Remove profile |
| 23 | Signed in as homer dos santos4318@outlook.gov | Signed in as homer dos santos4318@outlook.gov |
| 24 | Switch Accounts | Switch Accounts |
| 25 | Sign Out | Sign Out |

clean 后送入 detector 的拼接文本：
```text
amazon.co.ukHello,keVIN dANiEl[SEMANTIC_BREAK]米 EN[SEMANTIC_BREAK]Orders[SEMANTIC_BREAK]Buy Again[SEMANTIC_BREAK]Account[SEMANTIC_BREAK]Lists[SEMANTIC_BREAK]Your OrdersHi,you have no recent orders.Return to the home page[SEMANTIC_BREAK]Buy againSee what others are reordering on buy againVisit Buy Again[SEMANTIC_BREAK]Who's shopping?[SEMANTIC_BREAK]X[SEMANTIC_BREAK]keVIN dANiEI[SEMANTIC_BREAK]View[SEMANTIC_BREAK]Account holder[SEMANTIC_BREAK]Add profile[SEMANTIC_BREAK]Remove profile[SEMANTIC_BREAK]Signed in as homer dos santos4318@outlook.gov
```

raw block 按当前组装顺序得到的文本：
```text
amazon.co.uk Hello, keVIN dANiEl[SEMANTIC_BREAK]米 EN[SEMANTIC_BREAK]Orders[SEMANTIC_BREAK]Buy Again[SEMANTIC_BREAK]Account[SEMANTIC_BREAK]Lists[SEMANTIC_BREAK]Your Orders Hi, you have no recent orders. Return to the home page[SEMANTIC_BREAK]Buy again See what others are reordering on buy again Visit Buy Again[SEMANTIC_BREAK]Who's shopping?[SEMANTIC_BREAK]X[SEMANTIC_BREAK]keVIN dANiEI[SEMANTIC_BREAK]View[SEMANTIC_BREAK]Account holder[SEMANTIC_BREAK]Add profile[SEMANTIC_BREAK]Remove profile[SEMANTIC_BREAK]Signed in as homer dos santos4318@outlook.gov
```

## booking_50.png

- OCR blocks：`18`
- 裁剪后 blocks：`14`
- 视觉行数：`14`
- 区域数：`7`
- 语义组数：`10`

区域与分组：
- Region 1: lines 0..2, layout=flow, groups=2
  raw: Your personal info
  clean: Your personal info
  raw: Name | MiChELle zHaNg
  clean: Name | MiChELIe zHaNg
- Region 2: lines 3..4, layout=flow, groups=1
  raw: Email Address | alicewilliams@yahoo.org
  clean: Email Address | alicewilliams@yahoo.org
- Region 3: lines 5..8, layout=flow, groups=2
  raw: Mobile number | (380) 852-5146
  clean: Mobile number | (380)852-5146
  raw: Country/region | Sweden
  clean: Country/region | Sweden
- Region 4: lines 9..9, layout=flow, groups=1
  raw: Save this info to your account
  clean: Save this info to your account
- Region 5: lines 10..10, layout=flow, groups=1
  raw: What is the primary purpose for your trip?
  clean: What is the primary purpose for your trip?
- Region 6: lines 11..12, layout=flow, groups=2
  raw: Work
  clean: Work
  raw: Leisure
  clean: Leisure
- Region 7: lines 13..13, layout=flow, groups=1
  raw: £245 £221
  clean: £245 £221

block 级 clean 结果：

| block | raw_text | clean_text |
|---:|---|---|
| 0 | 09:39 | 09:39 |
| 1 | 56 | 56 |
| 2 | Your personal info | Your personal info |
| 3 | Name | Name |
| 4 | MiChELle zHaNg | MiChELIe zHaNg |
| 5 | Email Address | Email Address |
| 6 | alicewilliams@yahoo.org | alicewilliams@yahoo.org |
| 7 | Mobile number | Mobile number |
| 8 | (380) 852-5146 | (380)852-5146 |
| 9 | Country/region | Country/region |
| 10 | Sweden | Sweden |
| 11 | Save this info to your account | Save this info to your account |
| 12 | What is the primary purpose for your trip? | What is the primary purpose for your trip? |
| 13 | Work | Work |
| 14 | Leisure | Leisure |
| 15 | £245 £221 | £245 £221 |
| 16 | Includes taxes and charges | Includes taxes and charges |
| 17 | Next step | Next step |

clean 后送入 detector 的拼接文本：
```text
Your personal info[SEMANTIC_BREAK]NameMiChELIe zHaNg[SEMANTIC_BREAK]Email Addressalicewilliams@yahoo.org[SEMANTIC_BREAK]Mobile number(380)852-5146[SEMANTIC_BREAK]Country/regionSweden[SEMANTIC_BREAK]Save this info to your account[SEMANTIC_BREAK]What is the primary purpose for your trip?[SEMANTIC_BREAK]Work[SEMANTIC_BREAK]Leisure[SEMANTIC_BREAK]£245 £221
```

raw block 按当前组装顺序得到的文本：
```text
Your personal info[SEMANTIC_BREAK]Name MiChELle zHaNg[SEMANTIC_BREAK]Email Address alicewilliams@yahoo.org[SEMANTIC_BREAK]Mobile number (380) 852-5146[SEMANTIC_BREAK]Country/region Sweden[SEMANTIC_BREAK]Save this info to your account[SEMANTIC_BREAK]What is the primary purpose for your trip?[SEMANTIC_BREAK]Work[SEMANTIC_BREAK]Leisure[SEMANTIC_BREAK]£245 £221
```

## email_100.png

- OCR blocks：`34`
- 裁剪后 blocks：`27`
- 视觉行数：`9`
- 区域数：`3`
- 语义组数：`7`

区域与分组：
- Region 1: lines 0..3, layout=flow, groups=3
  raw: × | 目 | New Message | ramesh_petrov@msn.net
  clean: × | 目 | New Message | ramesh_petrov@msn.net
  raw: To:
  clean: To:
  raw: Subject:
  clean: Subject:
- Region 2: lines 4..5, layout=flow, groups=1
  raw: + | o
  clean: + | o
- Region 3: lines 6..8, layout=flow, groups=3
  raw: q | W | e | r | t
  clean: q | W | e | r | t
  raw: p
  clean: p
  raw: a | S | d | f | g | 0000 | Z | X | C | V | b | n | m
  clean: a | S | d | f | g | 0000 | Z | X | C | V | b | n | m

block 级 clean 结果：

| block | raw_text | clean_text |
|---:|---|---|
| 0 | 10:30 | 10:30 |
| 1 | 5 | 5 |
| 2 | 1 | 1 |
| 3 | New Message | New Message |
| 4 | × | × |
| 5 | 目 | 目 |
| 6 | ramesh_petrov@msn.net | ramesh_petrov@msn.net |
| 7 | To: | To: |
| 8 | Subject: | Subject: |
| 9 | + | + |
| 10 | o | o |
| 11 | q | q |
| 12 | t | t |
| 13 | p | p |
| 14 | W | W |
| 15 | e | e |
| 16 | r | r |
| 17 | 0000 | 0000 |
| 18 | d | d |
| 19 | f | f |
| 20 | g | g |
| 21 | a | a |
| 22 | S | S |
| 23 | b | b |
| 24 | V | V |
| 25 | n | n |
| 26 | Z | Z |
| 27 | X | X |
| 28 | C | C |
| 29 | m | m |
| 30 | 123 | 123 |
| 31 | space | space |
| 32 | return | return |
| 33 | 0 | 0 |

clean 后送入 detector 的拼接文本：
```text
× 目 New Messageramesh_petrov@msn.net[SEMANTIC_BREAK]To:[SEMANTIC_BREAK]Subject:[SEMANTIC_BREAK]+o[SEMANTIC_BREAK]q W e r t[SEMANTIC_BREAK]p[SEMANTIC_BREAK]a S d f g 0000Z X C V b n m
```

raw block 按当前组装顺序得到的文本：
```text
× 目 New Message ramesh_petrov@msn.net[SEMANTIC_BREAK]To:[SEMANTIC_BREAK]Subject:[SEMANTIC_BREAK]+ o[SEMANTIC_BREAK]q W e r t[SEMANTIC_BREAK]p[SEMANTIC_BREAK]a S d f g 0000 Z X C V b n m
```

## ins_200.png

- OCR blocks：`26`
- 裁剪后 blocks：`22`
- 视觉行数：`14`
- 区域数：`6`
- 语义组数：`15`

区域与分组：
- Region 1: lines 0..0, layout=flow, groups=1
  raw: Edit profile
  clean: Edit profile
- Region 2: lines 1..6, layout=table, groups=6
  raw: Edit picture or avatar
  clean: Edit picture or avatar
  raw: Name | CaROlIne mCinTyRe
  clean: Name | CaROIIne mCinTyRe
  raw: Username | +27 90989 6629
  clean: Username | +27 90989 6629
  raw: Pronouns | Pronouns
  clean: Pronouns | Pronouns
  raw: Bio | Bio
  clean: Bio | Bio
  raw: Links | Add links
  clean: Links | Add links
- Region 3: lines 7..7, layout=flow, groups=2
  raw: Banners
  clean: Banners
  raw: 1
  clean: 1
- Region 4: lines 8..11, layout=flow, groups=3
  raw: Music
  clean: Music
  raw: Add music to your profile
  clean: Add music to your profile
  raw: Show Threadsbanner | When turned off, the lnstagram badge on your | Threads profile will also disappear.
  clean: Show Threadsbanner | When turned off,the lnstagram badge on your | Threads profile will also disappear.
- Region 5: lines 12..12, layout=flow, groups=2
  raw: Gender
  clean: Gender
  raw: Gender
  clean: Gender
- Region 6: lines 13..13, layout=flow, groups=1
  raw: Switch to professional account
  clean: Switch to professional account

block 级 clean 结果：

| block | raw_text | clean_text |
|---:|---|---|
| 0 | 10:31 | 10:31 |
| 1 | 51 | 51 |
| 2 | Edit profile | Edit profile |
| 3 | Edit picture or avatar | Edit picture or avatar |
| 4 | Name | Name |
| 5 | CaROlIne mCinTyRe | CaROIIne mCinTyRe |
| 6 | Username | Username |
| 7 | +27 90989 6629 | +27 90989 6629 |
| 8 | Pronouns | Pronouns |
| 9 | Pronouns | Pronouns |
| 10 | Bio | Bio |
| 11 | Bio | Bio |
| 12 | Links | Links |
| 13 | Add links | Add links |
| 14 | Banners | Banners |
| 15 | 1 | 1 |
| 16 | Music | Music |
| 17 | Add music to your profile | Add music to your profile |
| 18 | Show Threadsbanner | Show Threadsbanner |
| 19 | When turned off, the lnstagram badge on your | When turned off,the lnstagram badge on your |
| 20 | Threads profile will also disappear. | Threads profile will also disappear. |
| 21 | Gender | Gender |
| 22 | Gender | Gender |
| 23 | Switch to professional account | Switch to professional account |
| 24 | Personal information settings | Personal information settings |
| 25 | Show that your profile is verified | Show that your profile is verified |

clean 后送入 detector 的拼接文本：
```text
Edit profile[SEMANTIC_BREAK]Edit picture or avatar[SEMANTIC_BREAK]Name CaROIIne mCinTyRe[SEMANTIC_BREAK]Username +27 90989 6629[SEMANTIC_BREAK]Pronouns Pronouns[SEMANTIC_BREAK]Bio Bio[SEMANTIC_BREAK]Links Add links[SEMANTIC_BREAK]Banners[SEMANTIC_BREAK]1[SEMANTIC_BREAK]Music[SEMANTIC_BREAK]Add music to your profile[SEMANTIC_BREAK]Show ThreadsbannerWhen turned off,the lnstagram badge on yourThreads profile will also disappear.[SEMANTIC_BREAK]Gender[SEMANTIC_BREAK]Gender[SEMANTIC_BREAK]Switch to professional account
```

raw block 按当前组装顺序得到的文本：
```text
Edit profile[SEMANTIC_BREAK]Edit picture or avatar[SEMANTIC_BREAK]Name CaROlIne mCinTyRe[SEMANTIC_BREAK]Username +27 90989 6629[SEMANTIC_BREAK]Pronouns Pronouns[SEMANTIC_BREAK]Bio Bio[SEMANTIC_BREAK]Links Add links[SEMANTIC_BREAK]Banners[SEMANTIC_BREAK]1[SEMANTIC_BREAK]Music[SEMANTIC_BREAK]Add music to your profile[SEMANTIC_BREAK]Show Threadsbanner When turned off, the lnstagram badge on your Threads profile will also disappear.[SEMANTIC_BREAK]Gender[SEMANTIC_BREAK]Gender[SEMANTIC_BREAK]Switch to professional account
```

## meituan_waimai_300.png

- OCR blocks：`35`
- 裁剪后 blocks：`30`
- 视觉行数：`19`
- 区域数：`8`
- 语义组数：`19`

区域与分组：
- Region 1: lines 0..5, layout=flow, groups=3
  raw: ×
  clean: ×
  raw: 97 Lincoln Street | >
  clean: 97 Lincoln Street
  raw: Name: Bobby JacksOn | Phone number: (95) 94215-7906 | 立即配送 | 预计12:53送达
  clean: Name:Bobby Jackson | Phone number:(95)94215-7906 | 立即配送 | 预计12:53送达
- Region 2: lines 6..6, layout=flow, groups=1
  raw: 预约配送 | 选择时间>
  clean: 预约配送 | 选择时间
- Region 3: lines 7..7, layout=flow, groups=1
  raw: 点餐请适量，环保又健康
  clean: 点餐请适量，环保又健康
- Region 4: lines 8..13, layout=flow, groups=6
  raw: 麦当劳&麦咖啡（北京善缘街店）
  clean: 麦当劳&麦咖啡（北京善缘街店）
  raw: 商家自配
  clean: 商家自配
  raw: 神抢手3 | 【爆卖千万单】经典麦辣双...￥123券价￥39.9 | 本单使用1张券，兑换以下商品 | 【神抢手专享】经典麦辣双人餐8件套
  clean: 神抢手3 | 【爆卖千万单】经典麦辣双...¥123券价¥39.9 | 本单使用1张券，兑换以下商品 | 【神抢手专享】经典麦辣双人餐8件套
  raw: 券后￥0
  clean: 券后¥0
  raw: 【神抢手专享】经典麦辣双人餐8件套...
  clean: 【神抢手专享】经典麦辣双人餐8件套...
  raw: x1
  clean: x1
- Region 5: lines 14..15, layout=table, groups=2
  raw: 用户配送费 | ③活动减3元配送费 | ￥6￥3
  clean: 用户配送费 | 3活动减3元配送费 | ¥6¥3
  raw: 美团红包 | 暂无可用>
  clean: 美团红包 | 暂无可用
- Region 6: lines 16..16, layout=flow, groups=2
  raw: 总计
  clean: 总计
  raw: 已优惠¥86.1￥42.9
  clean: 已优惠¥86.1¥42.9
- Region 7: lines 17..17, layout=flow, groups=2
  raw: 备注
  clean: 备注
  raw: 请填写您的要求>
  clean: 请填写您的要求
- Region 8: lines 18..18, layout=flow, groups=2
  raw: 餐具
  clean: 餐具
  raw: 请选择
  clean: 请选择

block 级 clean 结果：

| block | raw_text | clean_text |
|---:|---|---|
| 0 | 12:23 | 12:23 |
| 1 | 54 | 54 |
| 2 | × | × |
| 3 | 97 Lincoln Street | 97 Lincoln Street |
| 4 | > |   |
| 5 | Name: Bobby JacksOn | Name:Bobby Jackson |
| 6 | Phone number: (95) 94215-7906 | Phone number:(95)94215-7906 |
| 7 | 立即配送 | 立即配送 |
| 8 | 预计12:53送达 | 预计12:53送达 |
| 9 | 预约配送 | 预约配送 |
| 10 | 选择时间> | 选择时间 |
| 11 | 点餐请适量，环保又健康 | 点餐请适量，环保又健康 |
| 12 | 麦当劳&麦咖啡（北京善缘街店） | 麦当劳&麦咖啡（北京善缘街店） |
| 13 | 商家自配 | 商家自配 |
| 14 | 神抢手3 | 神抢手3 |
| 15 | 【爆卖千万单】经典麦辣双...￥123券价￥39.9 | 【爆卖千万单】经典麦辣双...¥123券价¥39.9 |
| 16 | 本单使用1张券，兑换以下商品 | 本单使用1张券，兑换以下商品 |
| 17 | 【神抢手专享】经典麦辣双人餐8件套 | 【神抢手专享】经典麦辣双人餐8件套 |
| 18 | 券后￥0 | 券后¥0 |
| 19 | 【神抢手专享】经典麦辣双人餐8件套... | 【神抢手专享】经典麦辣双人餐8件套... |
| 20 | x1 | x1 |
| 21 | 用户配送费 | 用户配送费 |
| 22 | ③活动减3元配送费 | 3活动减3元配送费 |
| 23 | ￥6￥3 | ¥6¥3 |
| 24 | 美团红包 | 美团红包 |
| 25 | 暂无可用> | 暂无可用 |
| 26 | 总计 | 总计 |
| 27 | 已优惠¥86.1￥42.9 | 已优惠¥86.1¥42.9 |
| 28 | 备注 | 备注 |
| 29 | 请填写您的要求> | 请填写您的要求 |
| 30 | 餐具 | 餐具 |
| 31 | 请选择 | 请选择 |
| 32 | 合计￥42.9 | 合计¥42.9 |
| 33 | 提交订单 | 提交订单 |
| 34 | 已优惠￥86.1 | 已优惠¥86.1 |

clean 后送入 detector 的拼接文本：
```text
×[SEMANTIC_BREAK]97 Lincoln Street[SEMANTIC_BREAK]Name:Bobby JacksonPhone number:(95)94215-7906立即配送 预计12:53送达[SEMANTIC_BREAK]预约配送 选择时间[SEMANTIC_BREAK]点餐请适量，环保又健康[SEMANTIC_BREAK]麦当劳&麦咖啡（北京善缘街店）[SEMANTIC_BREAK]商家自配[SEMANTIC_BREAK]神抢手3【爆卖千万单】经典麦辣双...¥123券价¥39.9本单使用1张券，兑换以下商品【神抢手专享】经典麦辣双人餐8件套[SEMANTIC_BREAK]券后¥0[SEMANTIC_BREAK]【神抢手专享】经典麦辣双人餐8件套...[SEMANTIC_BREAK]x1[SEMANTIC_BREAK]用户配送费 3活动减3元配送费 ¥6¥3[SEMANTIC_BREAK]美团红包 暂无可用[SEMANTIC_BREAK]总计[SEMANTIC_BREAK]已优惠¥86.1¥42.9[SEMANTIC_BREAK]备注[SEMANTIC_BREAK]请填写您的要求[SEMANTIC_BREAK]餐具[SEMANTIC_BREAK]请选择
```

raw block 按当前组装顺序得到的文本：
```text
×[SEMANTIC_BREAK]97 Lincoln Street >[SEMANTIC_BREAK]Name: Bobby JacksOn Phone number: (95) 94215-7906 立即配送 预计12:53送达[SEMANTIC_BREAK]预约配送 选择时间>[SEMANTIC_BREAK]点餐请适量，环保又健康[SEMANTIC_BREAK]麦当劳&麦咖啡（北京善缘街店）[SEMANTIC_BREAK]商家自配[SEMANTIC_BREAK]神抢手3 【爆卖千万单】经典麦辣双...￥123券价￥39.9 本单使用1张券，兑换以下商品 【神抢手专享】经典麦辣双人餐8件套[SEMANTIC_BREAK]券后￥0[SEMANTIC_BREAK]【神抢手专享】经典麦辣双人餐8件套...[SEMANTIC_BREAK]x1[SEMANTIC_BREAK]用户配送费 ③活动减3元配送费 ￥6￥3[SEMANTIC_BREAK]美团红包 暂无可用>[SEMANTIC_BREAK]总计[SEMANTIC_BREAK]已优惠¥86.1￥42.9[SEMANTIC_BREAK]备注[SEMANTIC_BREAK]请填写您的要求>[SEMANTIC_BREAK]餐具[SEMANTIC_BREAK]请选择
```

## rednote_450.png

- OCR blocks：`31`
- 裁剪后 blocks：`24`
- 视觉行数：`11`
- 区域数：`7`
- 语义组数：`15`

区域与分组：
- Region 1: lines 0..0, layout=flow, groups=2
  raw: 三
  clean: 三
  raw: 二
  clean: 二
- Region 2: lines 1..3, layout=flow, groups=3
  raw: KeiTH JohnSoN | Xiaohongshu ID: 0733 714 323
  clean: KeiTH JohnSoN | Xiaohongshu ID:0733 714 323
  raw: +
  clean: +
  raw: IP Address: Poland
  clean: IP Address:Poland
- Region 3: lines 4..4, layout=flow, groups=2
  raw: 14 | 18
  clean: 14 | 18
  raw: 35
  clean: 35
- Region 4: lines 5..5, layout=flow, groups=2
  raw: Following | Followers | Likes & Saves
  clean: Following | Followers | Likes&Saves
  raw: Edit Profile
  clean: Edit Profile
- Region 5: lines 6..7, layout=table, groups=2
  raw: Inspiration | History | Group chat
  clean: Inspiration | History | Group chat
  raw: Find inspiration | Notes I've read | View details
  clean: Find inspiration | Notes I've read | View details
- Region 6: lines 8..8, layout=flow, groups=3
  raw: Notes
  clean: Notes
  raw: Saves
  clean: Saves
  raw: Likes
  clean: Likes
- Region 7: lines 9..10, layout=flow, groups=1
  raw: Happy moments in life | post
  clean: Happy moments in life | post

block 级 clean 结果：

| block | raw_text | clean_text |
|---:|---|---|
| 0 | 10:33 | 10:33 |
| 1 | 51 | 51 |
| 2 | 三 | 三 |
| 3 | 二 | 二 |
| 4 | KeiTH JohnSoN | KeiTH JohnSoN |
| 5 | Xiaohongshu ID: 0733 714 323 | Xiaohongshu ID:0733 714 323 |
| 6 | + | + |
| 7 | IP Address: Poland | IP Address:Poland |
| 8 | 14 | 14 |
| 9 | 18 | 18 |
| 10 | 35 | 35 |
| 11 | Edit Profile | Edit Profile |
| 12 | Following | Following |
| 13 | Followers | Followers |
| 14 | Likes & Saves | Likes&Saves |
| 15 | Inspiration | Inspiration |
| 16 | History | History |
| 17 | Group chat | Group chat |
| 18 | Find inspiration | Find inspiration |
| 19 | Notes I've read | Notes I've read |
| 20 | View details | View details |
| 21 | Notes | Notes |
| 22 | Saves | Saves |
| 23 | Likes | Likes |
| 24 | Happy moments in life | Happy moments in life |
| 25 | post | post |
| 26 | + | + |
| 27 | Home | Home |
| 28 | Market | Market |
| 29 | Messages | Messages |
| 30 | Me | Me |

clean 后送入 detector 的拼接文本：
```text
三[SEMANTIC_BREAK]二[SEMANTIC_BREAK]KeiTH JohnSoNXiaohongshu ID:0733 714 323[SEMANTIC_BREAK]+[SEMANTIC_BREAK]IP Address:Poland[SEMANTIC_BREAK]14 18[SEMANTIC_BREAK]35[SEMANTIC_BREAK]Following Followers Likes&Saves[SEMANTIC_BREAK]Edit Profile[SEMANTIC_BREAK]Inspiration History Group chat[SEMANTIC_BREAK]Find inspiration Notes I've read View details[SEMANTIC_BREAK]Notes[SEMANTIC_BREAK]Saves[SEMANTIC_BREAK]Likes[SEMANTIC_BREAK]Happy moments in lifepost
```

raw block 按当前组装顺序得到的文本：
```text
三[SEMANTIC_BREAK]二[SEMANTIC_BREAK]KeiTH JohnSoN Xiaohongshu ID: 0733 714 323[SEMANTIC_BREAK]+[SEMANTIC_BREAK]IP Address: Poland[SEMANTIC_BREAK]14 18[SEMANTIC_BREAK]35[SEMANTIC_BREAK]Following Followers Likes & Saves[SEMANTIC_BREAK]Edit Profile[SEMANTIC_BREAK]Inspiration History Group chat[SEMANTIC_BREAK]Find inspiration Notes I've read View details[SEMANTIC_BREAK]Notes[SEMANTIC_BREAK]Saves[SEMANTIC_BREAK]Likes[SEMANTIC_BREAK]Happy moments in life post
```

## tiktok_500.png

- OCR blocks：`26`
- 裁剪后 blocks：`19`
- 视觉行数：`10`
- 区域数：`5`
- 语义组数：`16`

区域与分组：
- Region 1: lines 0..0, layout=flow, groups=1
  raw: 88
  clean: 88
- Region 2: lines 1..2, layout=flow, groups=4
  raw: bRENda fULleR
  clean: bRENda fULIeR
  raw: 0
  clean: 0
  raw: 0
  clean: 0
  raw: 0
  clean: 0
- Region 3: lines 3..3, layout=flow, groups=3
  raw: Following
  clean: Following
  raw: Followers
  clean: Followers
  raw: Likes
  clean: Likes
- Region 4: lines 4..6, layout=flow, groups=7
  raw: Edit profile
  clean: Edit profile
  raw: Share profile
  clean: Share profile
  raw: 0
  clean: 0
  raw: + Add bio
  clean: + Add bio
  raw: iii | 111
  clean: iii | 111
  raw: D
  clean: D
  raw: 心
  clean: 心
- Region 5: lines 7..9, layout=flow, groups=1
  raw: What are some good photos | you've taken recently? | Upload
  clean: What are some good photos | you've taken recently? | Upload

block 级 clean 结果：

| block | raw_text | clean_text |
|---:|---|---|
| 0 | 15:23 | 15:23 |
| 1 | 26 | 26 |
| 2 | 88 | 88 |
| 3 | bRENda fULleR | bRENda fULIeR |
| 4 | 0 | 0 |
| 5 | 0 | 0 |
| 6 | 0 | 0 |
| 7 | Following | Following |
| 8 | Followers | Followers |
| 9 | Likes | Likes |
| 10 | 0 | 0 |
| 11 | Edit profile | Edit profile |
| 12 | Share profile | Share profile |
| 13 | + Add bio | + Add bio |
| 14 | 111 | 111 |
| 15 | D | D |
| 16 | 心 | 心 |
| 17 | iii | iii |
| 18 | What are some good photos | What are some good photos |
| 19 | you've taken recently? | you've taken recently? |
| 20 | Upload | Upload |
| 21 | Oo | Oo |
| 22 | Home | Home |
| 23 | Friends | Friends |
| 24 | Inbox | Inbox |
| 25 | Profile | Profile |

clean 后送入 detector 的拼接文本：
```text
88[SEMANTIC_BREAK]bRENda fULIeR[SEMANTIC_BREAK]0[SEMANTIC_BREAK]0[SEMANTIC_BREAK]0[SEMANTIC_BREAK]Following[SEMANTIC_BREAK]Followers[SEMANTIC_BREAK]Likes[SEMANTIC_BREAK]Edit profile[SEMANTIC_BREAK]Share profile[SEMANTIC_BREAK]0[SEMANTIC_BREAK]+ Add bio[SEMANTIC_BREAK]111iii[SEMANTIC_BREAK]D[SEMANTIC_BREAK]心[SEMANTIC_BREAK]What are some good photosyou've taken recently?Upload
```

raw block 按当前组装顺序得到的文本：
```text
88[SEMANTIC_BREAK]bRENda fULleR[SEMANTIC_BREAK]0[SEMANTIC_BREAK]0[SEMANTIC_BREAK]0[SEMANTIC_BREAK]Following[SEMANTIC_BREAK]Followers[SEMANTIC_BREAK]Likes[SEMANTIC_BREAK]Edit profile[SEMANTIC_BREAK]Share profile[SEMANTIC_BREAK]0[SEMANTIC_BREAK]+ Add bio[SEMANTIC_BREAK]111 iii[SEMANTIC_BREAK]D[SEMANTIC_BREAK]心[SEMANTIC_BREAK]What are some good photos you've taken recently? Upload
```

## wechat_550.png

- OCR blocks：`29`
- 裁剪后 blocks：`22`
- 视觉行数：`9`
- 区域数：`6`
- 语义组数：`13`

区域与分组：
- Region 1: lines 0..1, layout=flow, groups=3
  raw: © | Weixin ID: 0513 499 990 | bRiAn FoSTER
  clean: © | Weixin ID:0513 499 990 | bRiAn FoSTER
  raw: 品 | >
  clean: 品
  raw: + Status
  clean: + Status
- Region 2: lines 2..2, layout=flow, groups=2
  raw: Pay and Services
  clean: Pay and Services
  raw: T
  clean: T
- Region 3: lines 3..3, layout=flow, groups=2
  raw: Favorites
  clean: Favorites
  raw: J
  clean: J
- Region 4: lines 4..5, layout=table, groups=2
  raw: M | Moments | J
  clean: M | Moments | J
  raw: ▷ | Channels | 7
  clean: ▷ | Channels | 7
- Region 5: lines 6..7, layout=table, groups=2
  raw: Orders and Cards | J
  clean: Orders and Cards | J
  raw: Sticker Gallery | J
  clean: Sticker Gallery | J
- Region 6: lines 8..8, layout=flow, groups=2
  raw: Settings
  clean: Settings
  raw: 7
  clean: 7

block 级 clean 结果：

| block | raw_text | clean_text |
|---:|---|---|
| 0 | 10:32 | 10:32 |
| 1 | 51 | 51 |
| 2 | © | © |
| 3 | bRiAn FoSTER | bRiAn FoSTER |
| 4 | 品 | 品 |
| 5 | Weixin ID: 0513 499 990 | Weixin ID:0513 499 990 |
| 6 | > |   |
| 7 | + Status | + Status |
| 8 | Pay and Services | Pay and Services |
| 9 | T | T |
| 10 | Favorites | Favorites |
| 11 | J | J |
| 12 | M | M |
| 13 | Moments | Moments |
| 14 | J | J |
| 15 | Channels | Channels |
| 16 | 7 | 7 |
| 17 | ▷ | ▷ |
| 18 | Orders and Cards | Orders and Cards |
| 19 | J | J |
| 20 | Sticker Gallery | Sticker Gallery |
| 21 | J | J |
| 22 | Settings | Settings |
| 23 | 7 | 7 |
| 24 | 2= | 2= |
| 25 | Chats | Chats |
| 26 | Contacts | Contacts |
| 27 | Discover | Discover |
| 28 | Me | Me |

clean 后送入 detector 的拼接文本：
```text
© Weixin ID:0513 499 990 bRiAn FoSTER[SEMANTIC_BREAK]品[SEMANTIC_BREAK]+ Status[SEMANTIC_BREAK]Pay and Services[SEMANTIC_BREAK]T[SEMANTIC_BREAK]Favorites[SEMANTIC_BREAK]J[SEMANTIC_BREAK]M Moments J[SEMANTIC_BREAK]▷ Channels 7[SEMANTIC_BREAK]Orders and Cards J[SEMANTIC_BREAK]Sticker Gallery J[SEMANTIC_BREAK]Settings[SEMANTIC_BREAK]7
```

raw block 按当前组装顺序得到的文本：
```text
© Weixin ID: 0513 499 990 bRiAn FoSTER[SEMANTIC_BREAK]品 >[SEMANTIC_BREAK]+ Status[SEMANTIC_BREAK]Pay and Services[SEMANTIC_BREAK]T[SEMANTIC_BREAK]Favorites[SEMANTIC_BREAK]J[SEMANTIC_BREAK]M Moments J[SEMANTIC_BREAK]▷ Channels 7[SEMANTIC_BREAK]Orders and Cards J[SEMANTIC_BREAK]Sticker Gallery J[SEMANTIC_BREAK]Settings[SEMANTIC_BREAK]7
```

## whatsapp_600.png

- OCR blocks：`46`
- 裁剪后 blocks：`39`
- 视觉行数：`26`
- 区域数：`2`
- 语义组数：`16`

区域与分组：
- Region 1: lines 0..3, layout=flow, groups=4
  raw: New chat
  clean: New chat
  raw: Q Type name or number
  clean: Q Type name or number
  raw: 2 | New group | D | ö | +
  clean: 2 | New group | D | ö | +
  raw: New contact
  clean: New contact
- Region 2: lines 4..25, layout=flow, groups=12
  raw: 20% | New community | Bring together topic-based groups
  clean: 20% | New community | Bring together topic-based groups
  raw: A | B | C
  clean: A | B | C
  raw: New broadcast
  clean: New broadcast
  raw: D | E | F | G
  clean: D | E | F | G
  raw: Contacts on WhatsApp
  clean: Contacts on WhatsApp
  raw: H | _ | J
  clean: H | J
  raw: 0396 127 8788
  clean: 0396 127 8788
  raw: K
  clean: K
  raw: Message yourself
  clean: Message yourself
  raw: L | M | N | 0 | P
  clean: L | M | N | 0 | P
  raw: Share invite link
  clean: Share invite link
  raw: Q | R | S | T | U | V | W
  clean: Q | R | S | T | U | V | W

block 级 clean 结果：

| block | raw_text | clean_text |
|---:|---|---|
| 0 | 10:31 | 10:31 |
| 1 | 5 | 5 |
| 2 | 1 | 1 |
| 3 | New chat | New chat |
| 4 | Q Type name or number | Q Type name or number |
| 5 | 2 | 2 |
| 6 | New group | New group |
| 7 | ö | ö |
| 8 | New contact | New contact |
| 9 | D | D |
| 10 | + | + |
| 11 | New community | New community |
| 12 | 20% | 20% |
| 13 | A | A |
| 14 | Bring together topic-based groups | Bring together topic-based groups |
| 15 | B | B |
| 16 | C | C |
| 17 | New broadcast | New broadcast |
| 18 | D | D |
| 19 | E | E |
| 20 | F | F |
| 21 | G | G |
| 22 | Contacts on WhatsApp | Contacts on WhatsApp |
| 23 | H | H |
| 24 | _ |   |
| 25 | J | J |
| 26 | 0396 127 8788 | 0396 127 8788 |
| 27 | K | K |
| 28 | Message yourself | Message yourself |
| 29 | L | L |
| 30 | M | M |
| 31 | N | N |
| 32 | 0 | 0 |
| 33 | P | P |
| 34 | Share invite link | Share invite link |
| 35 | Q | Q |
| 36 | R | R |
| 37 | S | S |
| 38 | T | T |
| 39 | U | U |
| 40 | V | V |
| 41 | W | W |
| 42 | X | X |
| 43 | Y | Y |
| 44 | ž | ž |
| 45 | # | # |

clean 后送入 detector 的拼接文本：
```text
New chat[SEMANTIC_BREAK]Q Type name or number[SEMANTIC_BREAK]2 New groupöD +[SEMANTIC_BREAK]New contact[SEMANTIC_BREAK]20%New communityBring together topic-based groups[SEMANTIC_BREAK]ABC[SEMANTIC_BREAK]New broadcast[SEMANTIC_BREAK]DEFG[SEMANTIC_BREAK]Contacts on WhatsApp[SEMANTIC_BREAK]HJ[SEMANTIC_BREAK]0396 127 8788[SEMANTIC_BREAK]K[SEMANTIC_BREAK]Message yourself[SEMANTIC_BREAK]LMN0P[SEMANTIC_BREAK]Share invite link[SEMANTIC_BREAK]QRSTUVW
```

raw block 按当前组装顺序得到的文本：
```text
New chat[SEMANTIC_BREAK]Q Type name or number[SEMANTIC_BREAK]2 New group ö D +[SEMANTIC_BREAK]New contact[SEMANTIC_BREAK]20% New community Bring together topic-based groups[SEMANTIC_BREAK]A B C[SEMANTIC_BREAK]New broadcast[SEMANTIC_BREAK]D E F G[SEMANTIC_BREAK]Contacts on WhatsApp[SEMANTIC_BREAK]H _ J[SEMANTIC_BREAK]0396 127 8788[SEMANTIC_BREAK]K[SEMANTIC_BREAK]Message yourself[SEMANTIC_BREAK]L M N 0 P[SEMANTIC_BREAK]Share invite link[SEMANTIC_BREAK]Q R S T U V W
```

## xiecheng_650.png

- OCR blocks：`42`
- 裁剪后 blocks：`34`
- 视觉行数：`19`
- 区域数：`5`
- 语义组数：`17`

区域与分组：
- Region 1: lines 0..6, layout=flow, groups=4
  raw: 轻奢连锁酒店
  clean: 轻奢连锁酒店
  raw: 10月3日今天－10月4日明天 | 1晚
  clean: 10月3日今天－10月4日明天 | 1晚
  raw: 套餐详情>
  clean: 套餐详情
  raw: 简约大床房 | 大床|无早餐装饰性假窗部分禁烟 | 享1项|免费接送机 | 10月3日20:00前可免费取消|可立即确认> | 订房必读
  clean: 简约大床房 | 大床|无早餐装饰性假窗部分禁烟 | 享1项|免费接送机 | 10月3日20:00前可免费取消|可立即确认 | 订房必读
- Region 2: lines 7..8, layout=flow, groups=1
  raw: 入住信息 | 房间数量 | 1间 (每间最多住2人)
  clean: 入住信息 | 房间数量 | 1间(每间最多住2人)
- Region 3: lines 9..12, layout=table, groups=4
  raw: 住客姓名
  clean: 住客姓名
  raw: 住客姓名 | ? | Cm | o
  clean: 住客姓名 | ? | Cm | o
  raw: STEvEngoodwIN
  clean: STEvEngoodwIN
  raw: 联系手机 | √ | 018-2756-4896 | 日
  clean: 联系手机 | √ | 018-2756-4896 | 日
- Region 4: lines 13..13, layout=flow, groups=1
  raw: 房间将整晚保留
  clean: 房间将整晚保留
- Region 5: lines 14..18, layout=flow, groups=7
  raw: 黄金会员
  clean: 黄金会员
  raw: 可享优惠
  clean: 可享优惠
  raw: -￥185
  clean: -¥185
  raw: 神券
  clean: 神券
  raw: 神券 | -¥15>
  clean: 神券 | -¥15
  raw: 神券 | 您有神券可膨胀，每张最高优惠100元 | 去膨胀 | 促销活动
  clean: 神券 | 您有神券可膨胀，每张最高优惠100元 | 去膨胀 | 促销活动
  raw: 共3项优惠-￥170>
  clean: 共3项优惠-¥170

block 级 clean 结果：

| block | raw_text | clean_text |
|---:|---|---|
| 0 | 12:33 | 12:33 |
| 1 | 52 | 52 |
| 2 | 轻奢连锁酒店 | 轻奢连锁酒店 |
| 3 | 10月3日今天－10月4日明天 | 10月3日今天－10月4日明天 |
| 4 | 1晚 | 1晚 |
| 5 | 套餐详情> | 套餐详情 |
| 6 | 简约大床房 | 简约大床房 |
| 7 | 大床\|无早餐装饰性假窗部分禁烟 | 大床\|无早餐装饰性假窗部分禁烟 |
| 8 | 享1项\|免费接送机 | 享1项\|免费接送机 |
| 9 | 10月3日20:00前可免费取消\|可立即确认> | 10月3日20:00前可免费取消\|可立即确认 |
| 10 | 订房必读 | 订房必读 |
| 11 | 入住信息 | 入住信息 |
| 12 | 房间数量 | 房间数量 |
| 13 | 1间 (每间最多住2人) | 1间(每间最多住2人) |
| 14 | 住客姓名 | 住客姓名 |
| 15 | 住客姓名 | 住客姓名 |
| 16 | o | o |
| 17 | ? | ? |
| 18 | Cm | Cm |
| 19 | STEvEngoodwIN | STEvEngoodwIN |
| 20 | 联系手机 | 联系手机 |
| 21 | 日 | 日 |
| 22 | √ | √ |
| 23 | 018-2756-4896 | 018-2756-4896 |
| 24 | 房间将整晚保留 | 房间将整晚保留 |
| 25 | 黄金会员 | 黄金会员 |
| 26 | 可享优惠 | 可享优惠 |
| 27 | -￥185 | -¥185 |
| 28 | 神券 | 神券 |
| 29 | 神券 | 神券 |
| 30 | -¥15> | -¥15 |
| 31 | 神券 | 神券 |
| 32 | 您有神券可膨胀，每张最高优惠100元 | 您有神券可膨胀，每张最高优惠100元 |
| 33 | 去膨胀 | 去膨胀 |
| 34 | 促销活动 | 促销活动 |
| 35 | 共3项优惠-￥170> | 共3项优惠-¥170 |
| 36 | 抵用券 | 抵用券 |
| 37 | 暂无可用> | 暂无可用 |
| 38 | ￥166.76 | ¥166.76 |
| 39 | 已优惠￥185へ | 已优惠¥185へ |
| 40 | 提交订单 | 提交订单 |
| 41 | 下单后订门票返现5元 | 下单后订门票返现5元 |

clean 后送入 detector 的拼接文本：
```text
轻奢连锁酒店[SEMANTIC_BREAK]10月3日今天－10月4日明天 1晚[SEMANTIC_BREAK]套餐详情[SEMANTIC_BREAK]简约大床房大床|无早餐装饰性假窗部分禁烟享1项|免费接送机10月3日20:00前可免费取消|可立即确认订房必读[SEMANTIC_BREAK]入住信息房间数量 1间(每间最多住2人)[SEMANTIC_BREAK]住客姓名[SEMANTIC_BREAK]住客姓名?Cm o[SEMANTIC_BREAK]STEvEngoodwIN[SEMANTIC_BREAK]联系手机 √ 018-2756-4896 日[SEMANTIC_BREAK]房间将整晚保留[SEMANTIC_BREAK]黄金会员[SEMANTIC_BREAK]可享优惠[SEMANTIC_BREAK]-¥185[SEMANTIC_BREAK]神券[SEMANTIC_BREAK]神券-¥15[SEMANTIC_BREAK]神券 您有神券可膨胀，每张最高优惠100元 去膨胀促销活动[SEMANTIC_BREAK]共3项优惠-¥170
```

raw block 按当前组装顺序得到的文本：
```text
轻奢连锁酒店[SEMANTIC_BREAK]10月3日今天－10月4日明天 1晚[SEMANTIC_BREAK]套餐详情>[SEMANTIC_BREAK]简约大床房 大床|无早餐装饰性假窗部分禁烟 享1项|免费接送机 10月3日20:00前可免费取消|可立即确认> 订房必读[SEMANTIC_BREAK]入住信息 房间数量 1间 (每间最多住2人)[SEMANTIC_BREAK]住客姓名[SEMANTIC_BREAK]住客姓名 ? Cm o[SEMANTIC_BREAK]STEvEngoodwIN[SEMANTIC_BREAK]联系手机 √ 018-2756-4896 日[SEMANTIC_BREAK]房间将整晚保留[SEMANTIC_BREAK]黄金会员[SEMANTIC_BREAK]可享优惠[SEMANTIC_BREAK]-￥185[SEMANTIC_BREAK]神券[SEMANTIC_BREAK]神券 -¥15>[SEMANTIC_BREAK]神券 您有神券可膨胀，每张最高优惠100元 去膨胀 促销活动[SEMANTIC_BREAK]共3项优惠-￥170>
```
