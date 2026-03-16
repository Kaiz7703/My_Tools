import csv
import argparse
from collections import Counter

def analyze_csv(file_path, status_filter):
    try:
        # Sử dụng utf-8-sig để xử lý lỗi BOM (Byte Order Mark) nếu file được xuất từ Excel
        with open(file_path, mode='r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            
            # Kiểm tra xem có cột 'Template Name' hay không
            if not reader.fieldnames or 'Template Name' not in reader.fieldnames:
                print("Lỗi: File CSV không có cột 'Template Name'.")
                if reader.fieldnames:
                    print(f"Các cột tìm thấy: {', '.join(reader.fieldnames)}")
                return
            fieldnames = reader.fieldnames
            if status_filter is not None:
                if fieldnames is None or 'Status' not in fieldnames:
                    print("Lỗi: File CSV không có cột 'Status' để thực hiện lọc.")
                    return

            template_names = []
            for row in reader:
                # Kiểm tra Status nếu có flag
                if status_filter is not None:
                    status = row.get('Status')
                    if status is None or status.strip() != status_filter:
                        continue # Bỏ qua dòng này nếu khác status_filter
                        
                # Đọc giá trị của cột 'Template Name'
                name = row.get('Template Name')
                if name is not None and name.strip() != "":
                    # Loại bỏ khoảng trắng thừa ở hai đầu
                    template_names.append(name.strip())

            total_rows = len(template_names)
            if total_rows == 0:
                print(f"Lỗi: Không tìm thấy dữ liệu hợp lệ (hoặc không có dòng nào thỏa mãn Status = '{status_filter}').")
                return

            # Đếm số lần xuất hiện của từng 'Template Name'
            counter = Counter(template_names)
            
            if status_filter:
                print(f"Tổng số dòng (chỉ tính Status = '{status_filter}'): {total_rows}")
            else:
                print(f"Tổng số dòng (bỏ qua dòng trống): {total_rows}")
            print("-" * 90)
            print(f"{'Template Name':<60} | {'Số lượng':<10} | {'Tỉ lệ (%)'}")
            print("-" * 90)
            
            # Sắp xếp theo số lượng (từ nhiều nhất đến ít nhất)
            for name, count in counter.most_common():
                percentage = (count / total_rows) * 100
                print(f"{name:<60} | {count:<10} | {count}/{total_rows} ({percentage:.2f}%)")
            print("-" * 90)

    except FileNotFoundError:
        print(f"Lỗi: Không tìm thấy file '{file_path}'.")
    except Exception as e:
        print(f"Đã xảy ra lỗi không mong muốn: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Công cụ phân tích file CSV theo cột 'Template Name'.")
    parser.add_argument("-f", "--file", dest="file_path", required=True, help="Đường dẫn đến file CSV cần phân tích")
    parser.add_argument("-s", "--status", dest="status_filter", default=None, help="Lọc theo cột Status (ví dụ: 'Blocked')")
    args = parser.parse_args()
    
    analyze_csv(args.file_path, args.status_filter)
