# BÁO CÁO PHÂN TÍCH PHẦN MỀM ĐỘC HẠI

**Mã Hash (SHA256):** `9d171fb14d096f5a49f8d04bb08f0e023ac08c051532e6d5a834bb752637f567`  
**Chuyên gia phân tích:** Phong  
**Mức độ nguy hiểm:** CAO

---

## 1. TÓM TẮT

Mẫu được phân tích là một malware dropper đa giai đoạn, được đóng gói dưới dạng tệp tự giải nén (SFX RAR). Nó triển khai hai payload chính:
- **Phemedrone Stealer**: Thành phần chuyên đánh cắp thông tin.
- **Xeno RAT**: Trojan cung cấp khả năng truy cập từ xa.

Mục tiêu chính của malware là đánh cắp dữ liệu nhạy cảm (thông tin đăng nhập trình duyệt, ví tiền điện tử, thông tin hệ thống) và thiết lập một backdoor bền bỉ để kẻ tấn công có thể điều khiển hệ thống từ xa.

---

## 2. NHẬN DẠNG MẪU VẬT

| Thuộc tính | Giá trị |
|---|---|
| **Tên tệp** | `9d171fb14d096f5a49f8d04bb08f0e023ac08c051532e6d5a834bb752637f567.exe` |
| **Kích thước** | 758.32 KB |
| **Loại tệp** | PE64 Executable (GUI) |
| **Trình đóng gói** | SFX RAR Archive |
| **Ngôn ngữ** | C++ (Có chứa chuỗi ký tự tiếng Nga) |
| **Điểm VirusTotal** | 54/71 |

### Các mã Hash

- **MD5:** `567c23cda6266437d4d63fd1642bd933`
- **SHA1:** `872feb9c8ed56954d3401df4f02df9a482d37ccf`
- **SHA256:** `9d171fb14d096f5a49f8d04bb08f0e023ac08c051532e6d5a834bb752637f567`

---

## 3. KHẢ NĂNG GÂY HẠI

### Đánh cắp thông tin
- Thông tin đăng nhập, cookie, lịch sử từ các trình duyệt (Chrome, Firefox, etc.).
- Dữ liệu ví tiền điện tử.
- Thông tin hệ thống: tên máy, tên người dùng, phiên bản HĐH, quy trình đang chạy, phần cứng.
- Quét và thu thập các tệp tin theo cấu hình từ C2.

### Truy cập & Điều khiển từ xa (RAT)
- Giao tiếp với máy chủ Điều khiển & Chỉ huy (C2) tại `192.248.152.36`.
- Thực thi lệnh từ xa.
- Tải lên/tải xuống tệp tin.
- Triển khai các payload độc hại khác.

### Cơ chế tồn tại (Persistence)
- Tự động khởi động cùng hệ thống thông qua việc tạo Tác vụ theo lịch (Scheduled Tasks) với tên `XenoUpdateManager`.
- Ghi vào khóa Registry `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`.

### Kỹ thuật lẩn tránh (Defense Evasion)
- Mã nguồn .NET bị làm rối (obfuscation) nặng.
- Sử dụng các hàm kiểm tra anti-analysis (ví dụ: `IsDebuggerPresent`).
- Đóng gói dưới dạng SFX để qua mặt các giải pháp phòng chống dựa trên chữ ký.

---

## 4. PHÂN TÍCH KỸ THUẬT

### Các thành phần được thả (Dropped Components)

| Tệp tin | Kích thước | Loại | Mục đích |
|---|---|---|---|
| `core.exe` | 138.00 KB | PE32 | Phemedrone Stealer |
| `cmd.exe` | 45.50 KB | PE32 | Xeno RAT |

Các tệp này thường được thả vào thư mục `%TEMP%` hoặc `%APPDATA%`.

### Hạ tầng mạng
- **Máy chủ C2:** `192.248.152.36`
- **Giao thức:** TCP, sử dụng giao thức tùy chỉnh, có mã hóa.

### Chi tiết cơ chế tồn tại
- **Scheduled Task:** Tạo một tác vụ với quyền cao nhất (HighestAvailable) được kích hoạt mỗi khi người dùng đăng nhập.
  ```xml
  <Task xmlns='http://schemas.microsoft.com/windows/2004/02/mit/task'>
    <Triggers>
      <LogonTrigger><Enabled>true</Enabled></LogonTrigger>
    </Triggers>
    <Principals>
      <Principal id='Author'>
        <RunLevel>HighestAvailable</RunLevel>
      </Principal>
    </Principals>
  </Task>
  ```
- **Registry:**
  - **Key:** `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
  - **Value Name:** `XenoUpdateManager`

---

## 5. CHUỖI LÂY NHIỄM

1.  **Thực thi ban đầu:** Nạn nhân chạy tệp SFX.
2.  **Giải nén Payload:** `core.exe` (Stealer) và `cmd.exe` (RAT) được giải nén ra hệ thống.
3.  **Thu thập dữ liệu:** `core.exe` được thực thi, bắt đầu quét và thu thập dữ liệu nhạy cảm.
4.  **Thiết lập tồn tại:** `cmd.exe` được chạy để tạo Scheduled Task và/hoặc khóa Registry, đảm bảo tự khởi động lại.
5.  **Kết nối C2:** RAT kết nối đến `192.248.152.36` để nhận lệnh.
6.  **Gửi dữ liệu:** Dữ liệu bị đánh cắp được gửi về cho kẻ tấn công.
7.  **Duy trì Backdoor:** RAT lắng nghe lệnh, cho phép kẻ tấn công toàn quyền kiểm soát hệ thống.

---

## 6. CÁC CHỈ SỐ XÂM NHẬP (IOCs)

### Mã Hash
```
9d171fb14d096f5a49f8d04bb08f0e023ac08c051532e6d5a834bb752637f567 (Dropper)
[Hash của core.exe và cmd.exe cần được bổ sung khi có]
```

### Chỉ số mạng
```
192.248.152.36 (C2 Server)
```

### Khóa Registry
```
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\XenoUpdateManager
```

### Đường dẫn tệp
```
%APPDATA%\XenoManager\
%TEMP%\core.exe
%TEMP%\cmd.exe
```

---

## 7. PHÁT HIỆN & GIẢM THIỂU

### Hành động tức thời
1.  **Cách ly** các máy bị nhiễm khỏi mạng.
2.  **Chặn** địa chỉ IP C2 `192.248.152.36` tại tường lửa.
3.  **Xóa** các tác vụ theo lịch (Scheduled Tasks) có tên `XenoUpdateManager`.
4.  **Xóa** các khóa registry trong `CurrentVersion\Run`.
5.  **Thay đổi** toàn bộ mật khẩu đã lưu trên các trình duyệt bị ảnh hưởng.

### Truy vấn săn lùng (Hunting Queries)
```shell
# Tìm Scheduled Task
schtasks /query /v /fo csv | findstr "XenoUpdateManager"

# Tìm khóa Registry
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v XenoUpdateManager

# Tìm tệp độc hại
dir %APPDATA%\XenoManager\ /s
dir %TEMP%\core.exe /s
```

### Luật YARA
```yara
rule Phemedrone_Xeno_Dropper_VN {
    meta:
        description = "Phat hien Dropper chua Phemedrone Stealer + Xeno RAT"
        hash = "9d171fb14d096f5a49f8d04bb08f0e023ac08c051532e6d5a834bb752637f567"
    
    strings:
        $c2 = "192.248.152.36"
        $name1 = "XenoUpdateManager" wide
        $name2 = "core.exe" wide
        $name3 = "xeno rat client" wide
    
    condition:
        2 of them
}
```

---

## 8. KẾT LUẬN

Mẫu `9d171fb...exe` là một mối đe dọa kép nguy hiểm, kết hợp khả năng **đánh cắp thông tin** mạnh mẽ và thiết lập **backdoor bền bỉ** để truy cập lâu dài. Sự phối hợp giữa Phemedrone Stealer và Xeno RAT tạo ra một nền tảng tấn công toàn diện, có khả năng gây ra thiệt hại tài chính và rò rỉ dữ liệu nghiêm trọng cho cá nhân và tổ chức.

**Hành động đề xuất:**
- Thực hiện quy trình ứng phó sự cố khẩn cấp.
- Phân vùng mạng đối với các hệ thống bị ảnh hưởng.
- Yêu cầu người dùng thay đổi mật khẩu cho tất cả các tài khoản có khả năng bị xâm phạm.
- Tăng cường giám sát để phát hiện các dấu hiệu di chuyển ngang trong mạng. 
