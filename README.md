# Fake Nmap

Một bộ quét mạng mô phỏng **Nmap** từ giao diện đến tính năng, được viết bằng hai lớp:

- **`frontend/`** – Giao diện đồ họa Python (Tkinter), phong cách **Zenmap**: chọn Profile, nhập lệnh, xem kết quả theo tab. Chạy engine Rust và stream kết quả trực tiếp như Nmap.
- **`backend/`** – Engine quét mạng viết bằng **Rust**: `fakenmap.exe` / `fakenmap`, đầu ra đúng định dạng text của Nmap kèm JSON/XML.

```
 ┌──────────────────────────────┐        stdout (Nmap-style text)
 │  Python GUI (Tkinter)        │ ───────────────────────────────►  Output tab
 │  - Profiles / Command        │        stderr (cảnh báo)
 │  - Scan / Cancel             │
 │  - Output / Ports / Topology │ ◄── JSON (-oJ file) ── biên dịch layout
 └──────────────────────────────┘
              │ spawn
              ▼
      fakenmap.exe (Rust engine)
```

## Tính năng (theo kiểu Nmap)

| Cờ | Ý nghĩa | Trạng thái |
|---|---|---|
| `-sT` | TCP Connect scan | hoạt động đầy đủ |
| `-sS` | SYN half-open scan | đầy đủ trên Linux (cần root); trên Windows tự động fallback về `-sT` |
| `-sU` | UDP scan | hoạt động; phân biệt "closed" khi có quyền raw ICMP |
| `-sP` / `-sn` | Ping scan (dò host) | hoạt động (ICMP `ping`) |
| `-sV` | Version/service detection | bắt banner theo giao thức (HTTP, SSH, FTP, SMTP, DNS, MySQL…) |
| `-O` / `-A` | Dò hệ điều hành | heuristic từ TTL + dịch vụ + banner |
| `-p`, `-p-`, `--top-ports`, `-F` | Chọn cổng | port range, tên dịch vụ, CIDR, dãy octet `192.168.1.1-50`, `*` |
| `-Pn`, `-n`, `-R`, `-T0..5`, `-v`, `--open`, `-iL`, `--exclude` | Tùy chọn | hỗ trợ |
| `-oN` `-oG` `-oJ` `-oX` | Xuất file | Normal / Grepable / JSON / XML |

Target hỗ trợ: IP đơn, hostname, `192.168.1.1/24`, `192.168.1.1-50`, `10.0.0.*`, danh sách phân tách bằng dấu phẩy.

## Cài đặt & chạy

Yêu cầu: **Python 3.8+** (tkinter), **Rust toolchain** (cargo).

```powershell
# 1. Build engine Rust (bản release)
cd backend
cargo build --release

# 2. Chạy GUI
cd ..
python frontend\fakenmap_gui.py
# hoặc bấm đúp run.bat
```

GUI tự tìm engine tại `backend\target\release\fakenmap.exe` (hoặc biến môi trường `FAKENMAP_BIN`). Nếu bấm Scan mà chưa build, GUI sẽ tự chạy `cargo build --release`.

### Dùng trực tiếp từ terminal

```powershell
backend\target\release\fakenmap.exe -sT -sV -p 22,80,443 192.168.1.1
backend\target\release\fakenmap.exe -sS -T4 -v scanme.example.com
backend\target\release\fakenmap.exe -sP 192.168.1.0/24
backend\target\release\fakenmap.exe -p- -T4 -A localhost
backend\target\release\fakenmap.exe -sT -oJ report.json --open 192.168.1.1-20
```

## Cấu trúc

```
Fake Nmap\
├── backend\                       # Rust engine
│   └── src\
│       ├── main.rs                # điều phối
│       ├── cli.rs                 # parse lệnh kiểu Nmap
│       ├── targets.rs             # CIDR / range / wildcard / DNS
│       ├── scan.rs                # connect, UDP, ping, song song hóa
│       ├── rawscan.rs             # raw socket: SYN scan (+ ICMP unreachable) trên Unix
│       ├── services.rs            # bảng dịch vụ + fingerprint banner
│       ├── osdetect.rs            # đoán OS
│       └── output.rs              # text kiểu Nmap + Grepable/JSON/XML
├── frontend\
│   └── fakenmap_gui.py            # GUI Tkinter kiểu Zenmap
└── run.bat                        # bấm đúp để mở GUI
```

## Ghi chú

- **SYN scan real** (`-sS`) cần raw socket: trên Linux chạy bằng `root`/`sudo` (quyền `CAP_NET_RAW`); trên Windows hệ điều hành chặn gửi gói TCP thô nên engine tự note và fallback sang connect scan.
- **UDP "closed"** cần đọc được ICMP Port Unreachable (raw socket) – máy thường, không root, cổng đóng sẽ hiện `open|filtered`, đúng như Nmap thiếu quyền.
- Gói dịch vụ trong `services.rs` là 1 tập con; nhánh TCP receive mở chủ động để đọc banner — nhớ fire cổng 8000 trên máy đang test để xem `-sV` bắt được version.