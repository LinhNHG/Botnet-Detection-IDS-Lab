# Chapter 9 IDS Botnet - CE181900

Bài thực hiện từ `Chapter9_IDS_Botnet_Lab_Assignment.docx` và file Friday CSV được cung cấp.
Báo cáo và chú giải bằng tiếng Việt; tên feature/code giữ tiếng Anh.

## Mở kết quả

- Đọc `report.pdf` trước.
- Mở `notebook/ids_botnet_detection.ipynb` bằng Jupyter hoặc VS Code.
- Kết quả thực đo ở `results/`, các hình ở `figures/`.
- Mô hình đã fit ở `model/ids_model.joblib`; cấu hình vận hành ở `model/threshold.json`.
- `results/false_positive.csv` và `false_negative.csv` giữ cột gốc để điều tra.

## Chạy lại trên Windows

Nên dùng Python 3.12 trong môi trường riêng; chạy từ thư mục CE181900_Chapter9_IDS.
CSV gốc không được nhân bản trong ZIP. Tạo `data/` và chép CSV gốc vào đó.

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe source\ids_botnet_detection.py --csv "data\Friday-WorkingHours-Morning.pcap_ISCX.csv" --output .
.venv\Scripts\python.exe source\generate_report.py
.venv\Scripts\python.exe -m jupyterlab notebook\ids_botnet_detection.ipynb
```

Linux/macOS: dùng `python3 -m venv .venv`, `.venv/bin/python` và dấu `/`.
Huấn luyện và GridSearchCV chạy trên toàn bộ dữ liệu đã làm sạch, có thể mất vài phút hoặc lâu hơn tùy máy.
Script dùng n_jobs=1 và cache RFE theo fold trong `.ids_cv_cache` cạnh thư mục output.
Có thể xóa cache sau khi chạy; cache không nằm trong ZIP nộp bài.

## Dự đoán flow khác

CSV mới phải có đủ các numerical predictor như `feature_columns` trong threshold.json.
Có thể có thêm Label và cột định danh; chúng không được dùng làm predictor.

```powershell
.venv\Scripts\python.exe source\stream_inference.py --csv "data\new_flows.csv" --output flow_predictions.csv
```

Script kiểm tra cột, xử lý Infinity/NaN, gọi pipeline đã lưu và dùng đúng threshold JSON.
Không phải phần mềm bắt gói tin trực tiếp; dữ liệu đầu vào cần được trích xuất theo schema CICFlowMeter tương ứng.
Chỉ nạp file joblib đáng tin cậy và dùng phiên bản scikit-learn tương thích (requirements.txt).

## Quy tắc tránh leakage

1. Loại bản ghi trùng trước chia tập; không dùng IP, Flow ID hoặc Timestamp làm predictor.
2. Chia ngoài 70/30 bằng stratify và random_state=42.
3. Trong training70, tách validation 20%: development56 / validation14 / test30.
4. Fit preprocessing/RFE/SMOTE trên development; CV fit lại từng bước trong từng fold.
5. Chọn model và threshold trên validation, giữ nguyên model để đánh giá test.
6. Bảng threshold test chỉ để mô tả sau lựa chọn, không dùng để tối ưu lại threshold.

## Các tệp bổ sung

- data_schema.csv: tên cột, kiểu dữ liệu, missing và infinite.
- split_manifest.csv: nguồn dòng và phân vùng để tái kiểm tra.
- feature_selection.csv: Feature / Selected / Rank, bao gồm feature hằng.
- high_correlation_pairs.csv: các cặp |r| > 0.90 trên development.
- scaling_comparison.csv và scaler_validation_metrics.csv: so sánh hai scaler.
- gridsearch_results.csv, tuning.json: 8 cấu hình x 3 fold và best parameters.
- validation_thresholds_all_models.csv: chọn trong 7 mô hình x 9 threshold.
- error_review_10_samples.csv: FN thật; nếu FN ít hơn 10, bổ sung TP ghi nhãn rõ ràng.
- streaming_inference.csv: replay 10 flow test thật, không phải live capture.
- verification.json: kiểm tra artifact, confusion matrix, threshold, split và inference.

SMOTE được triển khai bằng sklearn NearestNeighbors, không cần imbalanced-learn.
Các giá trị tổng hợp cho port/biến rời rạc có thể là phân số; hạn chế được trình bày trong báo cáo.
PR-AUC được định nghĩa là Average Precision (AP).
Mọi kết luận chỉ áp dụng cho phép thử nội bộ file này; chưa kiểm định theo host, thời gian hay dataset ngoài.
