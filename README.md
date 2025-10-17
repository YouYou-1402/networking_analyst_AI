Xây dựng hệ thống giám sát mạng tích hợp AI

Yêu cầu:
- Sử dụng ngôn ngữ lập trình C/C++ để tối ưu hóa hiệu suất.
- Thiết kế giao diện trực quan, dễ nhìn, cho phép người dùng cấu hình hệ thống thông qua các thiết lập.
(chỉ cần đua ra cấu trúc file)
Cấu trúc hệ thống:
1. Gói tin đi vào (Packet Ingress)
   - Hành động: Gói tin từ mạng đi vào card mạng (NIC) của máy tính.
   
2. Tiền lọc cực nhanh (eBPF/XDP Pre-filtering)
   - Công nghệ: XDP (eXpress Data Path).
   - Nơi thực thi: Tại driver của card mạng trước khi kernel hệ điều hành xử lý.
   - Mục tiêu: Loại bỏ lưu lượng rõ ràng là xấu.
   - Logic phân tích:
     - Kiểm tra danh sách đen: Hủy gói tin nếu địa chỉ IP có trong danh sách đen (XDP_DROP).
     - Chống DDoS cơ bản: Hủy gói tin nếu là phần của cuộc tấn công SYN Flood (XDP_DROP).
     - Cho phép gói tin đi tiếp nếu không có vấn đề xảy ra (XDP_PASS).

3. Điều phối và Cân bằng tải (Dispatcher & Load Balancer)
   - Công nghệ: DPDK (Data Plane Development Kit).
   - Nơi thực thi: Một luồng (thread) riêng biệt trên một lõi CPU.
   - Hành động:
     - Đọc gói tin đã vượt qua Bước 1.
     - Thực hiện phép băm (hash) dựa trên thông tin gói.

4. Tái lập luồng và Giải mã giao thức (Worker Thread - Flow Assembly & Protocol Decode)
   - Nơi thực thi: Mỗi Worker Thread chạy trên một lõi CPU riêng.
   - Hành động:
     - Lấy gói tin từ hàng đợi.
     - Tra cứu trong "Flow Table" để xem gói tin thuộc luồng đã tồn tại không.
     - Nếu luồng chưa tồn tại, tạo bản ghi mới; nếu đã tồn tại, cập nhật trạng thái.
     - Giải mã gói tin qua các lớp: Ethernet, IP, TCP/UDP, và ứng dụng (HTTP, DNS, SMB).

5. Kiểm tra sâu và Phát hiện mối đe dọa (Worker Thread - Deep Packet Inspection & Detection)
   - Công cụ 1: Phân tích Dựa trên Dấu hiệu (Aho-Corasick).
   - Công cụ 2: Phân tích Giao thức.
   - Công cụ 3: Phân tích Bất thường.

6. Quyết định và Hành động (Worker Thread - Action)
   - Dựa trên kết quả từ Bước 4, có thể thực hiện hành động:
     - Hủy gói tin, ghi log, gửi cảnh báo, hoặc chặn kết nối.

7. Gói tin đi ra (Packet Egress)
   - Công nghệ: DPDK.
   - Hành động: Đẩy gói tin "sạch" vào hàng đợi truyền của card mạng.

Tầng 2 - Phân tích AI/ML
1. Tích hợp Tầng 2
   - Kích hoạt khi Tầng 1 không phát hiện mối đe dọa.
   
2. Thiết kế chi tiết các Module
   - Module 2.1: Feature Extraction - Trích xuất Đặc trưng.
   - Module 2.2: Data Bus / Message Queue.
   - Module 2.3: AI/ML Analysis Engine - Phát hiện Bất thường Thời gian thực và Phân tích Sâu.
   - Module 2.4: Feedback Loop & Action - Cập nhật Rule và Xử lý Ngay lập tức.

Dashboard Tổng hợp
- Hiển thị tất cả kết quả phân tích, cảnh báo từ cả Tầng 1 và Tầng 2 trên một hệ thống giám sát tập trung.
- Hiển thị dự đoán xu hướng, đánh giá ...