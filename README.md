# NEURON Scanner version 2.0 🛡️

- **Web application phân tích an ninh chuyên sâu cho URL và File thông qua các kỹ thuật nhận diện thủ công (Static Analysis).**
- Dự án được xây dựng bằng **Python + Flask**, giao diện dễ nhìn & sử dụng, hỗ trợ lưu lịch sử scan bằng SQLite.

## Tính năng chính

- 🔗 Phân tích URL Heuristic – Tự động phát hiện Phishing qua TLD rủi ro, từ khóa nhạy cảm và dấu hiệu giả mạo thương hiệu.
- 📁 Kiểm tra File chuyên sâu – Hỗ trợ phân tích Magic Bytes (chữ ký file), tính toán Entropy (phát hiện packed malware) và tạo mã băm SHA-256.
- 📊 Lịch sử Scan chuyên nghiệp – Giao diện bảng chi tiết, phân loại màu sắc trạng thái an toàn/nguy hiểm trực quan.
- 🎨 Giao diện đẹp mắt – Phong cách hiện đại, tối ưu cho trải nghiệm người dùng với các thông số kỹ thuật thời gian thực.
- 🔒 An toàn & riêng tư – không lưu file lâu dài, database chỉ chứa metadata.
- 🔑 Zero-Execution Policy – Phân tích tĩnh hoàn toàn thủ công, không thực thi mã nguồn, đảm bảo an toàn tuyệt đối cho hệ thống máy chủ.

## Ảnh minh họa

<img width="1920" height="1028" alt="{2DE8650B-8724-47C8-8524-CA576AE7A828}" src="https://github.com/user-attachments/assets/5ed31443-15ad-4ad1-9b36-7afe5c8573f4" />

*Giao diện trang chủ với form scan URL/file*

<img width="1920" height="1031" alt="{B7CDCBAE-FCCA-4ACA-A2CF-1D7A365D1580}" src="https://github.com/user-attachments/assets/f3771d53-8260-44ca-bab9-f5bb0ad1fe81" />

*Trang lịch sử scan với bảng chi tiết và phân màu an toàn/rủi ro*

##🛠️ Kỹ thuật phân tích thủ công (Static Analysis)

**Dự án tập trung vào việc hiểu sâu bản chất mã độc thông qua các thuật toán nội tại thay vì chỉ sử dụng API bên ngoài:**
- Magic Bytes Verification: Đối chiếu Byte đầu tiên (File Header) để phát hiện hành vi giả mạo định dạng (ví dụ: file .exe núp bóng .jpg).
- Shannon Entropy: Tính toán độ hỗn loạn dữ liệu (ngưỡng rủi ro > 7.5) để nhận diện malware bị mã hóa hoặc nén (Packed).
- Brand Spoofing Detection: Thuật toán phân tích cấu trúc Domain để nhận diện các trang web giả mạo ngân hàng hoặc mạng xã hội.

## Hướng dẫn cài đặt & chạy

1. **Clone repository**
   ```bash
   git clone https://github.com/whoisry4n/neuron-scanner.git
   cd neuron-scanner
2. **Cài đặt các thư viện cần thiết**
   ```bash
   pip install flask requests
   pip install flask werkzeug
   pip install python-whois
3. **Chạy ứng dụng**
   ```bash
   python app2.py
4. **Truy cập**
   - Mở trình duyệt và vào địa chỉ: http://127.0.0.1:5000

## Cấu trúc dự án
<img width="641" height="194" alt="{81051ACF-ACCC-489F-827F-FA1723BB734A}" src="https://github.com/user-attachments/assets/606d0f06-bc5a-4e9c-8f19-5fb5788ffd2a" />

## Tác giả

- Nhóm SV an ninh mạng.
- Dự án thực hiện theo yêu cầu môn học CS-447.

## License
Dự án sử dụng MIT License – bạn được tự do sử dụng, chỉnh sửa và chia sẻ.
