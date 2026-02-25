import os

def split_file(filepath, chunk_size=40*1024*1024):
    print(f"Splitting {filepath}...")
    with open(filepath, 'rb') as f:
        part_num = 1
        while True:
            chunk = f.read(chunk_size)
            if not chunk: 
                break
            out_name = filepath + f'.part{part_num}'
            with open(out_name, 'wb') as out_f:
                out_f.write(chunk)
            print(f" -> Created {out_name}")
            part_num += 1

split_file('waf-efficacy-tool/Data/legi4.rar')
split_file('waf-efficacy-tool/Data/legi5.rar')
print("Done splitting.")
