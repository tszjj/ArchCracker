# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 ArchCracker contributors
from PIL import Image, ImageDraw, ImageFont
import os, math

W, H = 1800, 1275
BG = (247, 248, 250)
INK = (31, 41, 55)
MUTED = (107, 114, 128)

F = r"C:\Windows\Fonts\msyh.ttc"
FB = r"C:\Windows\Fonts\msyhbd.ttc"
def font(size, bold=False):
    return ImageFont.truetype(FB if bold else F, size)

img = Image.new("RGB", (W, H), BG)
d = ImageDraw.Draw(img)

def text(x, y, s, size=16, color=INK, bold=False, anchor="la"):
    d.text((x, y), s, font=font(size, bold), fill=color, anchor=anchor)

def rounded(x, y, w, h, r=14, fill=(255,255,255), outline=(220,225,233), width=2):
    d.rounded_rectangle([x, y, x + w, y + h], radius=r, fill=fill, outline=outline, width=width)

def box(x, y, w, h, title, lines, fill, border, tsize=17, lsize=13, tcolor=INK, lcolor=(75,85,99)):
    rounded(x, y, w, h, 12, fill, border, 2)
    text(x + 14, y + 10, title, tsize, tcolor, True)
    yy = y + 10 + tsize + 8
    for line in lines:
        if yy + lsize > y + h - 6:
            break
        text(x + 14, yy, line, lsize, lcolor)
        yy += lsize + 5

def arrow(x1, y1, x2, y2, color=(124,135,152), width=3):
    d.line([x1, y1, x2, y2], fill=color, width=width)
    ang = math.atan2(y2 - y1, x2 - x1)
    L = 12
    for s in (0.5, -0.5):
        d.line([x2, y2, x2 - L * math.cos(ang - s), y2 - L * math.sin(ang - s)], fill=color, width=width)

def band(y, h, label, sub=""):
    rounded(45, y, 1710, h, 16, (255,255,255), (226,230,237), 2)
    d.rectangle([45, y, 51, y + h], fill=(203,213,225))
    text(66, y + 10, label, 19, (55,65,81), True)
    if sub:
        text(66 + d.textlength(label, font=font(19, True)) + 12, y + 14, sub, 13, MUTED)

# header
text(55, 30, "ArchCracker", 42, (17,24,39), True)
text(55 + d.textlength("ArchCracker", font=font(42, True)) + 16, 44, "跨平台压缩包密码恢复工具 · 架构 v0.2", 22, (75,85,99))
text(55, 92, "Rust 内核 + C ABI + 三套原生前端 · 五平台 · Apache-2.0", 16, MUTED)

rounded(1310, 38, 445, 50, 25, (232,245,233), (129,199,132), 2)
text(1532, 52, "Apache-2.0 · 离线 · 无遥测", 15, (46,125,50), True, "ma")

# OS chips
os_list = [
    ("Windows 10/11", "P1 · 首发", (234,242,254), (143,180,232)),
    ("Linux x64/arm64", "P4", (234,242,254), (143,180,232)),
    ("macOS 13+", "P4", (234,242,254), (143,180,232)),
    ("Android 11+", "P5", (234,247,239), (134,199,155)),
    ("HarmonyOS 6+", "P6", (244,237,251), (177,151,214)),
]
x = 55
for name, stage, fill, border in os_list:
    rounded(x, 145, 320, 52, 12, fill, border, 2)
    text(x + 16, 154, name, 15, INK, True)
    text(x + 16, 175, stage, 12, (90,98,112))
    x += 340

# frontends
band(215, 205, "① 前端层", "Frontends · 只做交互与平台胶水")
fe = [
    (55, 270, 480, 130, "Desktop · Avalonia 12 (.NET 10)", ["Windows / Linux / macOS", "MVVM · 拖放 · 进度/暂停 · 自动解压"], (234,242,254), (143,180,232)),
    (555, 270, 370, 130, "Android · Compose", ["Kotlin · SAF/fd · 前台服务", "JNI 薄层 · 按 ABI 打包"], (234,247,239), (134,199,155)),
    (945, 270, 370, 130, "HarmonyOS · ArkUI", ["ArkTS · Picker · 前台/断点", "NAPI 薄层 · HAP 签名"], (244,237,251), (177,151,214)),
    (1335, 270, 400, 130, "CLI · acx", ["Rust · 桌面全平台", "脚本 / CI / 无 UI · 同一内核"], (240,242,245), (174,182,194)),
]
for (bx, by, bw, bh, t, lines, fill, border) in fe:
    box(bx, by, bw, bh, t, lines, fill, border, 17, 13)

# ABI strip
rounded(55, 440, 1680, 92, 14, (232,240,252), (143,180,232), 2)
text(72, 452, "② C ABI 边界", 18, (30,64,120), True)
text(72, 478, "稳定契约：不透明句柄 · 错误码 · 回调 · JSON 配置 · panic 隔离", 13, (60,80,110))
abi = ["acx.h", "P/Invoke (C#)", "JNI (Kotlin)", "NAPI (ArkTS)", "sidecar 可选"]
ax = 760
for i, a in enumerate(abi):
    w = 150 if len(a) <= 9 else 175
    rounded(ax, 458, w, 34, 10, (255,255,255), (143,180,232), 1)
    text(ax + w/2, 475, a, 12, (30,64,120), True, "mm")
    ax += w + 12
text(72, 500, "前端不复制算法/错误码；契约以 acx.h 为准", 12, (90,98,112))

# core band
band(555, 300, "③ Rust 内核 acx-core", "纯逻辑 · 无 UI 依赖 · 可交叉编译")
cols = [
    (72, 610, 390, 205, "任务与编排", ["JobManager · 队列/批量", "AttackPlanner · 成本估算", "Scheduler · 有界队列/线程", "ResumeManager · 原子断点", "Stats · EWMA/ETA"]),
    (482, 610, 390, 205, "候选源", ["字典 · 流式/编码/去重", "掩码 · ?d?l?u?s/?1-?4", "暴力 · 字符集/长度/UInt128", "混合 · 字典×掩码", "规则（P2）· hashcat 风格"]),
    (892, 610, 390, 205, "引擎与探针", ["7z · AES/头加密/PPMd", "ZIP · ZipCrypto/AES", "RAR · 外部 unrar（桌面）", "Volume/SFX · 自建容器层", "Probe → 结构/签名 → 确认"]),
    (1302, 610, 410, 205, "平台抽象 / 质量", ["文件/路径 · 线程 · 进程 · locale", "cfg 隔离 · 无 Windows API 泄漏", "取消/暂停 · 批边界", "错误分类 · 缺卷/损坏/不支持", "测试向量 · 差分 oracle"]),
]
for (cx, cy, cw, ch, title, lines) in cols:
    rounded(cx, cy, cw, ch, 12, (255,250,240), (226,184,119), 2)
    text(cx + 14, cy + 10, title, 17, (120,72,20), True)
    yy = cy + 38
    for line in lines:
        text(cx + 14, yy, line, 12, (90,80,60))
        yy += 20

# engines band
band(875, 185, "④ 引擎与第三方", "许可边界：RAR 不链接、不随包、不自动下载")
eng = [
    (55, 935, 390, 100, "sevenz-rust2", ["Apache-2.0 · 7z", "AES-256 / 头加密 / PPMd"], (255,250,240), (226,184,119)),
    (465, 935, 340, 100, "zip", ["MIT · ZIP", "ZipCrypto / AES（P1 实测）"], (255,250,240), (226,184,119)),
    (825, 935, 430, 100, "外部 unrar（桌面）", ["用户自装 · 仅进程调用", "不随包 / 不链接 / 不自动下载"], (255,235,235), (220,120,120)),
    (1275, 935, 450, 100, "Volume / SFX / 编码", ["自建拼接 Reader · PE overlay", "UTF-8/GBK 字节变体"], (255,250,240), (226,184,119)),
]
for (ex, ey, ew, eh, t, lines, fill, border) in eng:
    box(ex, ey, ew, eh, t, lines, fill, border, 16, 12)
text(825, 1044, "RAR 许可边界：Apache-2.0 主项目 vs unRAR restriction", 12, (170,40,40), True)

# infra
band(1080, 120, "⑤ 质量与交付", "CI · 语料 · 签名 · 许可扫描")
inf = [
    (55, 1128, 380, 56, "CI 三平台", "windows / ubuntu / macos"),
    (455, 1128, 380, 56, "语料/差分", "7-Zip/unrar oracle"),
    (855, 1128, 380, 56, "打包/签名", "MSIX · DMG · APK · HAP"),
    (1255, 1128, 470, 56, "许可扫描", "cargo-deny · 无 Rar* · 源码归档"),
]
for (ix, iy, iw, ih, t, sub) in inf:
    rounded(ix, iy, iw, ih, 10, (240,242,245), (174,182,194), 1)
    text(ix + 14, iy + 8, t, 14, INK, True)
    text(ix + 14, iy + 30, sub, 12, (90,98,112))

# footer
text(55, 1222, "核心原则：每 worker 独占会话 · 每候选只做最便宜的证据 · 命中必须由参考引擎复核 · 移动端首发不含 RAR。", 14, (55,65,81), True)
text(55, 1248, "规划稿 · 性能数字需基准验证 · 本图不构成法律意见", 11, (156,163,175))

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.makedirs(os.path.join(root, "docs"), exist_ok=True)
out = os.path.join(root, "docs", "architecture.png")
img.save(out, "PNG")
print("saved", out, img.size)
