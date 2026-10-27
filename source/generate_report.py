from pathlib import Path
import json, pandas as pd, numpy as np
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.enums import TA_CENTER
from xml.sax.saxutils import escape
R=Path(__file__).resolve().parents[1]; D=R/'results'; F=R/'figures'
e=json.loads((D/'eda.json').read_text()); c=json.loads((R/'model/threshold.json').read_text()); tune=json.loads((D/'tuning.json').read_text()); m=c['test_metrics']; v=c['validation_metrics']
pdfmetrics.registerFont(TTFont('DejaVu',str(Path(__file__).parent/'fonts/DejaVuSans.ttf')))
pdfmetrics.registerFont(TTFont('DejaVuBold',str(Path(__file__).parent/'fonts/DejaVuSans-Bold.ttf')))
styles=getSampleStyleSheet()
styles.add(ParagraphStyle(name='VBody',fontName='DejaVu',fontSize=9,leading=14,spaceAfter=7))
styles.add(ParagraphStyle(name='VTitle',fontName='DejaVuBold',fontSize=22,leading=28,spaceAfter=15,textColor=colors.black))
styles.add(ParagraphStyle(name='VH',fontName='DejaVuBold',fontSize=14,leading=20,spaceAfter=12,textColor=colors.black))
styles.add(ParagraphStyle(name='VS',fontName='DejaVuBold',fontSize=10,leading=15,spaceAfter=7))
styles.add(ParagraphStyle(name='Cell',fontName='DejaVu',fontSize=7.5,leading=11))
styles.add(ParagraphStyle(name='Small',fontName='DejaVu',fontSize=7.5,leading=11,spaceAfter=6))
story=[]
def p(t,style='VBody'): story.append(Paragraph(t,styles[style]))
def title(t): p(t,'VH')
def page(t): story.append(PageBreak()); title(t)
def table(rows,widths=None):
    rr=[[Paragraph(escape(str(x)),styles['Cell']) for x in row] for row in rows]
    t=Table(rr,colWidths=widths,repeatRows=1,hAlign='LEFT'); t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#DBEAFE')),('GRID',(0,0),(-1,-1),.4,colors.HexColor('#D9D9D9')),('VALIGN',(0,0),(-1,-1),'MIDDLE'),('LEFTPADDING',(0,0),(-1,-1),7),('RIGHTPADDING',(0,0),(-1,-1),7),('TOPPADDING',(0,0),(-1,-1),5),('BOTTOMPADDING',(0,0),(-1,-1),5)])); story.append(t); story.append(Spacer(1,10))
def image(name,w=460,h=None):
    from PIL import Image as PI
    a=PI.open(F/name); h=h or w*a.height/a.width; story.append(Image(str(F/name),width=w,height=h)); story.append(Spacer(1,8))
def pct(a): return f'{a*100:.2f}%'
def num(a): return f'{a:,.0f}'
p('IDS phát hiện Botnet','VTitle'); p('Bài lab Chapter 9 trên dữ liệu CICIDS2017','VH'); p('Nguyễn Hoàng Gia Linh | CE181900 | AIC211')
p('Mục tiêu là phân biệt BENIGN = 0 và Bot = 1, đồng thời đáp ứng Recall Bot tối thiểu 95%. Báo cáo sử dụng kết quả thực thi trên toàn bộ file CSV được cung cấp; không dùng số liệu mô phỏng để thay thế kết quả huấn luyện.')
p(f"Cấu hình được chọn từ validation: <b>{escape(c['candidate'])}</b>, threshold <b>{c['threshold']:.2f}</b>. Trên test độc lập, Precision = <b>{pct(m['Precision'])}</b>, Recall = <b>{pct(m['Recall'])}</b>, F1 = {m['F1']:.4f}; FP = {m['FP']}, FN = {m['FN']}. " + ('Kết quả test đạt mục tiêu SOC.' if c['test_target_met'] else 'Kết quả test chưa đạt mục tiêu SOC; không khẳng định mô hình đáp ứng yêu cầu vận hành.'))
title('1 Dữ liệu và khảo sát ban đầu')
p('Nguồn dữ liệu: Friday-WorkingHours-Morning.pcap_ISCX.csv do đề bài cung cấp. Mỗi dòng mô tả một network flow. Label là target; các cột còn lại gồm thông tin nhận dạng và thống kê lưu lượng.')
table([['Chỉ tiêu','Kết quả'],['Kích thước ban đầu','191.033 dòng x 85 cột'],['BENIGN','189.067 (98,97%)'],['Bot','1.966 (1,03%)'],['Missing / infinite / duplicate đầy đủ',f"{e['raw_missing_cells']} / {e['raw_infinite_cells']} / {e['raw_exact_duplicates']}"],['Sau làm sạch',f"{num(e['clean_shape'][0])} dòng x {e['clean_shape'][1]} predictor"],[ 'Tên cột và kiểu dữ liệu','results/data_schema.csv chứa đầy đủ 85 cột']],[210,282])
image('class_distribution.png',350)
p('Tỷ lệ ban đầu gần 96 BENIGN trên 1 Bot. Nếu luôn dự đoán BENIGN, Accuracy đạt 98,97% nhưng Recall Bot bằng 0. Vì vậy, Accuracy chỉ là chỉ số bổ sung; quyết định IDS dựa vào Recall, Precision, F1, AP và số FP/FN.')
page('2 Làm sạch và thiết kế thực nghiệm')
p('Đã bỏ 2 dòng trùng hoàn toàn. Flow ID, Source IP, Destination IP, Source Port và Timestamp được loại khỏi predictor để hạn chế ghi nhớ danh tính máy hoặc lịch tấn công; chúng vẫn được giữ trong bảng lỗi để điều tra. Fwd Header Length.1 là cột lặp nên bị bỏ. Destination Port và Protocol được giữ như thông tin dịch vụ và giao thức.')
p(f"Sau khi bỏ cột nhận dạng, loại thêm {e['additional_predictor_duplicates_removed']:,} dòng có predictor giống nhau để tránh chia cùng bản ghi vào train/test. Có {e['conflicting_predictor_rows_removed']} dòng thuộc nhóm predictor có nhãn mâu thuẫn. Không bỏ các cặp tương quan cao trước RFE để tránh xóa tín hiệu bằng quy tắc tùy ý; RFE thực hiện giảm chiều.")
p('NaN và ±Infinity được chuẩn hóa thành NaN. SimpleImputer thay bằng median chỉ học từ development; VarianceThreshold loại feature hằng chỉ theo development. Không tính median, scaler, RFE hoặc SMOTE từ test. Hàng thiếu không bị loại hàng loạt, tránh làm mất mẫu Bot hiếm.')
rows=[['Phân vùng','Số flow','BENIGN','Bot']]
for name,z in e['splits'].items(): rows.append([name,num(z['rows']),num(z['benign']),num(z['bot'])])
table(rows,[170,105,110,107])
p('Chia ngoài: Training 70% và Testing 30%, stratify=y, random_state=42. Trong 70% training, giữ 20% làm validation: development tương đương 56% toàn dữ liệu, validation tương đương 14%. Các mô hình được fit trên development, chọn mô hình/ngưỡng trên validation rồi giữ nguyên khi đánh giá test. Không refit sau chọn threshold để tránh đổi phân bố score.')
p('Stratify giữ gần đúng tỷ lệ Bot ở mỗi tập, giảm nguy cơ tập test/validation có quá ít Bot. GridSearchCV dùng development với StratifiedKFold 3 fold. Mỗi fold tự fit imputer, variance filter, scaler, RFE và SMOTE; validation ngoài và test không tham gia fit.')
p('Chia ngẫu nhiên theo flow chưa bảo đảm độc lập theo host hay phiên mạng. Những flow khác nhau từ cùng máy hoặc cùng đợt tấn công vẫn có thể nằm ở hai tập. Vì vậy, đây là đánh giá nội bộ một file, chưa phải bằng chứng khái quát sang doanh nghiệp khác.')
title('3 So sánh scaling và xử lý mất cân bằng')
p('StandardScaler dùng mean và standard deviation, nên traffic spike làm thay đổi tâm và độ co giãn. RobustScaler dùng median và IQR, ít bị spike chi phối hơn nhưng không loại outlier. Với mô hình cây, scaling đơn lẻ thường ít ảnh hưởng; ở đây scaling còn quyết định khoảng cách láng giềng của SMOTE nên vẫn cần so sánh.')
s=pd.read_csv(D/'scaler_validation_metrics.csv'); table([['RF với SMOTE','Precision val','Recall val','F1 val']]+[[str(r.Candidate).replace('RF SMOTE ',''),pct(r.Precision),pct(r.Recall),f'{r.F1:.4f}'] for r in s.itertuples()],[195,99,99,99])
p('RobustScaler được chọn trước thí nghiệm chính vì dữ liệu có spike; bảng so sánh StandardScaler là thí nghiệm bổ sung trên validation, không dùng test để chọn scaler. Chi tiết median, IQR, P99 và max sau scaling nằm trong scaling_comparison.csv.')
page('4 Feature Selection và class imbalance')
co=pd.read_csv(D/'high_correlation_pairs.csv'); fs=pd.read_csv(D/'feature_selection.csv')
p(f"Correlation Pearson tính chỉ trên development. Có {len(co)} cặp có |r| &gt; 0,90, lưu đầy đủ tại high_correlation_pairs.csv. NaN trong ma trận tương quan có thể do feature hằng; không diễn giải NaN là không tương quan.")
table([['Feature 1','Feature 2','r']]+[[r.Feature_1,r.Feature_2,f'{r.Correlation:.4f}'] for r in co.head(5).itertuples()],[220,220,52])
p('RFE sử dụng Random Forest 30 cây, max_depth=12, class_weight=balanced; mỗi vòng loại tối đa 20 feature, cuối cùng giữ 12 feature. Rank = 1 là được chọn; rank lớn hơn là bị loại sớm hơn. Feature hằng có Selected=False và Rank trống vì đã bị VarianceThreshold loại trước RFE.')
table([['Feature','Selected','Rank']]+[[r.Feature,str(r.Selected),int(float(str(r.Rank)))] for r in fs[fs.Selected==True].itertuples()],[330,90,72])
p('Giảm từ 78 predictor xuống 12 giúp giảm chi phí inference, bộ nhớ và dữ liệu nhiễu. RFE không bảo đảm một tập feature duy nhất hay tối ưu toàn cục; các feature tương quan có thể thay thế nhau khi chia dữ liệu khác.')
p(f"Thí nghiệm A dùng development gốc với {e['splits']['development56']['benign']:,} BENIGN và {e['splits']['development56']['bot']:,} Bot. Thí nghiệm B dùng SMOTE tăng Bot lên {e['smote_counts']['1']:,}, cân bằng với BENIGN. Validation và test luôn giữ phân bố tự nhiên.")
p('SMOTE được triển khai trực tiếp bằng NearestNeighbors của sklearn: với mỗi Bot, chọn ngẫu nhiên một trong 5 Bot lân cận rồi nội suy x_new = x_i + u(x_j - x_i), u thuộc [0,1]. Chỉ tạo mẫu từ fold đang train. Làm SMOTE trước chia tập có thể tạo các mẫu gần như cùng nguồn ở cả train/test, gây data leakage và kết quả quá lạc quan.')
p('Hạn chế: SMOTE chuẩn xem Destination Port và các biến rời rạc như số liên tục, nên mẫu tổng hợp có thể mang giá trị phân số không biểu diễn flow thật. Không đưa các mẫu tổng hợp vào bảng replay. Có thể cải thiện bằng SMOTENC hoặc class_weight với kiểm định theo host/time.')
page('5 So sánh các mô hình IDS')
mc=pd.read_csv(D/'model_comparison.csv')
p('Ba mô hình bắt buộc được so sánh trên đúng cùng development, validation và test. Decision Tree dùng max_depth=12, min_samples_leaf=2; Random Forest baseline dùng 100 cây; Gradient Boosting dùng 100 cây, max_depth=3. A là training gốc, B là SMOTE. Tất cả dùng random_state=42.')
p('Bảng dưới dùng threshold 0,50 để so sánh baseline. PR-AUC trong bài này được định nghĩa là Average Precision (AP), không phải tích phân trapezoid. Các giá trị test chỉ để báo cáo; việc chọn cấu hình triển khai sử dụng bảng validation ở phần sau.')
rows=[['Mô hình','TN/FP/FN/TP','Acc','Prec','Recall','F1','ROC AUC','AP']]
for r in mc.itertuples(): rows.append([str(r.Model)+' '+str(r.Experiment).split()[0],f'{r.TN}/{r.FP}/{r.FN}/{r.TP}',f'{r.Accuracy:.4f}',f'{r.Precision:.4f}',f'{r.Recall:.4f}',f'{r.F1:.4f}',f'{r.ROC_AUC:.4f}',f'{r.PR_AUC:.4f}'])
table(rows,[100,100,48,48,48,48,50,50])
p('ROC-AUC đo khả năng xếp hạng Bot cao hơn BENIGN trên toàn dải threshold. AP tập trung hơn vào lớp dương hiếm. Precision giảm nghĩa là SOC nhận nhiều cảnh báo giả hơn; Recall giảm nghĩa là nhiều Bot bị bỏ sót. SMOTE không mặc định cải thiện mọi chỉ số, nên cần đọc đồng thời các kết quả thực đo.')
vm=pd.read_csv(D/'validation_model_comparison.csv')
table([['Candidate trên validation','Precision','Recall','F1']]+[[r.Candidate,pct(r.Precision),pct(r.Recall),f'{r.F1:.4f}'] for r in vm.itertuples()],[270,74,74,74])
p(f"Lựa chọn cuối cùng là {escape(c['candidate'])} với threshold {c['threshold']:.2f}; lựa chọn này ưu tiên Precision cao nhất trong các cấu hình đạt Recall validation ≥ 95%, xét tất cả 7 candidate x 9 threshold. Không chọn đơn thuần theo Accuracy hoặc coi mô hình được tuning chắc chắn là mô hình tốt nhất.")
page('6 Confusion Matrix và tác động với SOC')
image('confusion_matrix.png',360)
table([['Ô','Ý nghĩa trong IDS','Số lượng'],['TN','BENIGN được nhận diện NORMAL',m['TN']],['FP','BENIGN bị cảnh báo BOT ALERT',m['FP']],['FN','Bot bị dự đoán NORMAL',m['FN']],['TP','Bot được phát hiện BOT ALERT',m['TP']]],[50,350,92])
p(f"Recall = TP/(TP+FN) = {m['TP']}/{m['TP']+m['FN']} = {pct(m['Recall'])}. Precision = TP/(TP+FP) = {m['TP']}/{m['TP']+m['FP']} = {pct(m['Precision'])}. Tỷ lệ cảnh báo giả trên flow BENIGN là {pct(m['FP']/(m['TN']+m['FP']))}.")
p('FP làm SOC mất thời gian phân tích lưu lượng hợp lệ, tăng workload và alert fatigue. Nếu cảnh báo dẫn tới tự động chặn, FP còn có thể gián đoạn dịch vụ. FN khiến máy nhiễm Bot tiếp tục liên lạc, thực thi tác vụ hoặc tạo rủi ro lan rộng; đây là lý do ưu tiên Recall tối thiểu 95%.')
p('false_positive.csv và false_negative.csv giữ toàn bộ cột gốc, source_row_0based, nhãn thực, xác suất và nhãn dự đoán. Chỉ số dòng là chỉ số 0-based của bản ghi CSV khi đọc bằng Pandas; số dòng vật lý trong file thường bằng chỉ số + 2 do có header.')
p('Phân tích lỗi ở trang tiếp theo dựa trên giá trị quan sát; không khẳng định C2, hành vi mã độc hay nguyên nhân nhân quả chỉ từ một feature. Cần PCAP hoặc điều tra máy đầu cuối để xác nhận.')
page('7 Phân tích các flow bị bỏ sót')
fn=pd.read_csv(D/'false_negative.csv'); reviewed=pd.read_csv(D/'error_review_10_samples.csv'); med=pd.read_csv(D/'class_feature_medians.csv')
p(f"Có {len(fn)} False Negative thực tế trên test. " + ('Bảng dưới phân tích 10 FN có score thấp nhất.' if len(fn)>=10 else 'Đã phân tích toàn bộ FN; nếu ít hơn 10, bổ sung TP gần threshold để đủ 10 mẫu rà soát, ghi rõ TP và không đổi nhãn thành FN. Đây là giới hạn thực tế đối với yêu cầu tối thiểu 10 FN.'))
rows=[['Dòng 0-based','Loại','p(Bot)','Dst port','Flow duration','Bwd mean','Nhận xét']]
for _,r in reviewed.iterrows():
    port=r['Destination Port']; dur=r['Flow Duration']; bwd=r['Bwd Packet Length Mean']
    kind='FN' if r.Review_type=='Test False Negative' else 'TP'
    if bwd==0:
        comment='Bwd mean bằng 0; thiếu tín hiệu độ dài phản hồi.'
    elif dur<=5:
        comment='Flow cực ngắn (≤5 µs); ít ngữ cảnh thời gian.'
    elif dur<=100:
        comment='Flow ngắn (≤100 µs), gói chiều ngược chỉ 6 B.'
    else:
        comment='Đối chiếu thời lượng và độ dài phản hồi với train.'
    rows.append([str(int(r.source_row_0based)),kind,f'{r.Attack_probability:.5f}',f'{port:.0f}',f'{dur:.0f}',f'{bwd:.2f}',comment])
table(rows,[65,30,58,48,70,65,156])
p('Chín mẫu trong bảng có thời lượng 3-68 µs và Bwd mean = 6 B, cho thấy flow rất ngắn, ít ngữ cảnh để phân biệt hành vi. Dòng 141987 khác nhóm: cổng 8080, thời lượng 50.856 µs và Bwd mean = 0 B. Đây là giả thuyết lỗi từ đặc điểm quan sát, chưa phải giải thích nhân quả của cây. Các median từ development lưu trong class_feature_medians.csv để đối chiếu thêm.')
if len(fn):
    p(f"Score của FN nằm từ {fn.Attack_probability.min():.5f} đến {fn.Attack_probability.max():.5f}, median {fn.Attack_probability.median():.5f}. FN có {fn['Destination Port'].nunique()} cổng đích khác nhau và {fn['Source IP'].nunique()} Source IP khác nhau. Các đặc điểm này mô tả tập lỗi, không chứng minh nguồn gây lỗi.")
p('Đề xuất điều tra: gom lỗi theo host và thời điểm; đối chiếu flow cùng phiên; bổ sung ngữ cảnh theo chuỗi thời gian, DNS và liên lạc lặp lại. Giảm threshold có thể tăng Recall nhưng cần đo lại FP; không tự đổi threshold sau khi nhìn test để tuyên bố đạt chỉ tiêu.')
page('8 ROC Curve và Precision Recall Curve')
image('roc_curve.png',330); image('pr_curve.png',330)
p(f"Tại test: ROC-AUC = {m['ROC_AUC']:.5f}, Average Precision = {m['PR_AUC']:.5f}. Đường nền của PR tương ứng tỷ lệ Bot trong test ({pct(e['splits']['test30']['bot']/e['splits']['test30']['rows'])}). Hai đường cong sử dụng score liên tục; điểm vận hành thực tế vẫn phụ thuộc threshold.")
p('AP cao cho thấy khả năng ưu tiên mẫu Bot trong dữ liệu này, nhưng không chứng minh độ tin cậy xác suất hoặc phát hiện Botnet mới. Score predict_proba chưa được probability calibration; không diễn giải 0,80 thành xác suất rủi ro ngoài thực tế đã được bảo đảm.')
page('9 Threshold đáp ứng yêu cầu vận hành')
th=pd.read_csv(D/'threshold_analysis.csv')
p('Quét các threshold 0,10 đến 0,90, bước 0,10. Bảng chính là validation; test_threshold_analysis_descriptive.csv là bảng test tham khảo được xuất sau khi đóng băng lựa chọn. Không dùng bảng test để chọn lại ngưỡng.')
table([['Threshold','Precision','Recall','F1','FP','FN']]+[[f'{r.Threshold:.2f}',pct(r.Precision),pct(r.Recall),f'{r.F1:.4f}',r.FP,r.FN] for r in th.itertuples()],[78,90,90,78,78,78])
image('threshold_analysis.png',390)
p(f"Ngưỡng được chốt: <b>{c['threshold']:.2f}</b>. Trên validation: Recall {pct(v['Recall'])}, Precision {pct(v['Precision'])}, FP {v['FP']}, FN {v['FN']}. Trên test giữ nguyên ngưỡng: Recall {pct(m['Recall'])}, Precision {pct(m['Precision'])}, FP {m['FP']}, FN {m['FN']}.")
p('Trong các cấu hình đạt Recall ≥ 95% trên validation, chọn Precision lớn nhất. Nếu hòa, ưu tiên Recall rồi F1 rồi threshold lớn hơn. Mục tiêu này xét trên mẫu hữu hạn, không phải cam kết Recall tối thiểu 95% cho mọi traffic tương lai.')
page('10 GridSearchCV và Explainable IDS')
p('Random Forest được tuning bằng 3-fold Stratified CV, scoring=f1, shuffle=True, random_state=42. Grid gồm n_estimators=[40,80], max_depth=[10,None], min_samples_split=[2,10]: 8 cấu hình, 24 lượt fit CV và một lượt refit. n_jobs=1 để chạy ổn định trong môi trường thực thi.')
p('Pipeline trong từng fold: median imputation → loại feature hằng → RobustScaler → RFE → SMOTE → Random Forest. Cache preprocessing chỉ tái sử dụng bước có cùng dữ liệu/fold/tham số; không chia sẻ thông tin từ fold validation.')
p('Best Parameters: '+escape(json.dumps({k.replace('clf__estimator__',''):v for k,v in tune['best_params'].items()}))+f". Best CV F1 = {tune['best_cv_f1']:.5f}.")
rf=mc[mc.Model.isin(['Random Forest','Random Forest Tuned']) & (mc.Experiment=='B SMOTE')]
table([['RF SMOTE tại threshold 0,50','Prec test','Recall test','F1 test','AP test']]+[[r.Model,f'{r.Precision:.4f}',f'{r.Recall:.4f}',f'{r.F1:.4f}',f'{r.PR_AUC:.4f}'] for r in rf.itertuples()],[200,73,73,73,73])
image('feature_importance.png',430)
p('Đây là impurity importance của mô hình cuối cùng đã chọn, không mặc định là Random Forest tuning. Destination Port phản ánh dịch vụ đích; Flow Duration/IAT phản ánh nhịp trao đổi; các độ dài gói và byte theo chiều cho biết quy mô, tính bất đối xứng của phiên; Init_Win_bytes phản ánh cửa sổ TCP ban đầu, có thể liên hệ với đặc điểm endpoint hoặc kết nối.')
p('Không suy ra một cổng hay kích thước gói cụ thể luôn là độc hại. Impurity importance có thể thiên về feature nhiều giá trị và phân tán giữa các feature tương quan. Cần kiểm tra permutation importance hoặc SHAP trên dữ liệu đánh giá mới trước khi dùng làm căn cứ điều tra độc lập.')
page('11 Streaming inference và kết luận')
p('ids_model.joblib lưu preprocessing và classifier đã fit; threshold.json lưu threshold, tên feature theo đúng thứ tự, candidate, chỉ số và phiên bản sklearn. Khi replay: chuẩn hóa tên cột → lấy predictor → chuyển số, Infinity thành NaN → median → loại hằng → RobustScaler → RFE → predict_proba → so threshold đã lưu → NORMAL hoặc BOT ALERT.')
st=pd.read_csv(D/'streaming_inference.csv')
table([['Flow row','Actual','p(Bot)','Threshold','Decision']]+[[r.source_row_0based,'Bot' if r.Actual else 'BENIGN',f'{r.Attack_probability:.5f}',f'{r.Threshold:.2f}',r.Decision] for r in st.itertuples()],[90,90,100,90,122])
p('Mười flow trên là replay các bản ghi test thật (5 BENIGN và 5 Bot), không phải kết nối trực tiếp với card mạng hoặc traffic mới thu thập. Pipeline đã được tải lại bằng joblib và kiểm tra score trùng với trước khi lưu. Script source/stream_inference.py đọc file flow khác và luôn lấy threshold từ JSON, không quay về 0,50.')
p(f"Kết luận: mô hình {escape(c['candidate'])}, threshold {c['threshold']:.2f}, đạt Recall test {pct(m['Recall'])}, Precision {pct(m['Precision'])}. " + ('Đạt yêu cầu Recall Bot ≥ 95% trong tập test này.' if c['test_target_met'] else 'Chưa đạt Recall test ≥ 95%; cần cải thiện mô hình và kiểm tra trên dữ liệu mới.'))
p('Hạn chế chính gồm dữ liệu từ một buổi ghi mạng, chia ngẫu nhiên theo flow, chỉ 586 Bot trên test, nhãn có thể chưa hoàn hảo, mẫu SMOTE có thể phi thực tế, score chưa calibration và chưa đo latency theo tải SOC. Mô hình cần được kiểm định theo thời gian/host, đánh giá drift và điều chỉnh theo chi phí cảnh báo thực trước triển khai.')
title('Tái lập và kiểm tra sản phẩm')
p('Giải nén thư mục; cài requirements.txt; đặt CSV gốc ở thư mục data rồi chạy lệnh trong README.md. CSV gốc không đóng gói lại để tránh tạo bản sao lớn. Notebook chứa toàn bộ logic và các bảng/biểu đồ tải từ kết quả thực thi; có tùy chọn chạy lại huấn luyện. Mọi tỷ lệ trong báo cáo được tính trực tiếp từ kết quả CSV/JSON đi kèm.')
p('Nguồn tham chiếu của bài: Chapter9_IDS_Botnet_Lab_Assignment.docx (yêu cầu 2.1-2.9) và Friday-WorkingHours-Morning.pcap_ISCX.csv (dữ liệu đầu vào do người dùng cung cấp). Không sử dụng dữ liệu bên ngoài để thay thế.')
def footer(canvas,doc):
    canvas.setFont('DejaVu',8); canvas.setFillColor(colors.HexColor('#555555')); canvas.drawString(42,27,'CE181900  |  Chapter 9 IDS Botnet'); canvas.drawRightString(570,27,str(doc.page))
SimpleDocTemplate(str(R/'report.pdf'),title='IDS phat hien Botnet CICIDS2017',author='Nguyen Hoang Gia Linh CE181900',pagesize=(612,792),leftMargin=42,rightMargin=42,topMargin=38,bottomMargin=44).build(story,onFirstPage=footer,onLaterPages=footer)
print('report.pdf generated')
