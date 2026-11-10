from pathlib import Path
from openpyxl import load_workbook

path = Path(r"C:\Users\Z667109\OneDrive - ZF Friedrichshafen AG\Desktop\VPC CAB build\VulnerabilityScan_report_AG_SCN_CN_QD2_PROD_14_05_2026.xlsx")
print('Path:', path)
wb = load_workbook(path, read_only=True, data_only=True)
print('Worksheets:', wb.sheetnames)
for name in ['ALL', 'PITS required', 'VMP required', 'VMP recommended', 'Misconfigurations required', 'Misconfigurations recommended']:
    if name not in wb.sheetnames:
        print(f'Sheet missing: {name}')
        continue
    sheet = wb[name]
    rows = sheet.iter_rows(values_only=True)
    try:
        headers = next(rows)
    except StopIteration:
        print(f'Sheet {name} is empty')
        continue
    print('\n===', name, '===')
    print('headers =', headers)
    for i, row in enumerate(rows):
        if i >= 8:
            break
        print(row)
