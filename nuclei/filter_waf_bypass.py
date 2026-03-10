import csv
from collections import defaultdict

def print_bypassed_cves(csv_file):
    # Cấu trúc lưu trữ: dictionary với key là tuple (Target URL, Template ID)
    # value là một dictionary lưu total_flow dự kiến và set() chứa các Flow Index thực tế đã bị bypass
    results: dict = defaultdict(lambda: {"total_flow": 0, "bypassed_indices": set()})

    try:
        with open(csv_file, mode='r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                template_id = row.get('Template ID', '').strip()
                target_url = row.get('Target URL', '').strip()
                flow_index_str = row.get('Flow Index', '').strip()
                total_flow_str = row.get('Total Flow', '').strip()
                
                # Bỏ qua nếu dòng bị trống Template ID
                if not template_id:
                    continue
                
                # Xử lý an toàn cho Flow Index và Total Flow
                try:
                    flow_index = int(flow_index_str) if flow_index_str else 1
                except ValueError:
                    flow_index = 1
                    
                try:
                    total_flow = int(total_flow_str) if total_flow_str else 1
                except ValueError:
                    total_flow = 1
                
                # Cập nhật context cho target này
                key = (target_url, template_id)
                results[key]["total_flow"] = total_flow
                
                # Vì file là "waf_test_results_bypassed.csv" nên mặc định các line trong này đều
                # đang ở trạng thái bypass (nếu file có mix cả 'blocked' thì bổ sung điều kiện Status)
                status = row.get('Status', '').strip().lower()
                if not status or 'bypass' in status or 'success' in status or status:
                    results[key]["bypassed_indices"].add(flow_index)
                    
    except FileNotFoundError:
        print(f"Error: File not found {csv_file}")
        return

    # Duyệt lại kết quả và lọc những cve có số flow_index ghi nhận được bằng với total_flow
    completely_bypassed_cves = set()
    
    for (target_url, template_id), data in results.items():
        if len(data["bypassed_indices"]) >= data["total_flow"]:
            completely_bypassed_cves.add(template_id)
            
    # In kết quả
    if completely_bypassed_cves:
        print(f"Result: {len(completely_bypassed_cves)} CVE IDs (Template IDs) were FULLY bypassed:")
        for cve in sorted(list(completely_bypassed_cves)):
            print(f" - {cve}")
    else:
        print("Result: No CVE ID was fully bypassed (Not all flows bypassed).")

if __name__ == "__main__":
    csv_file_path = r"d:\dowload\Payload\nuclei\waf_test_results_bypassed.csv"
    print_bypassed_cves(csv_file_path)
