import os

def join_files(output_filepath):
    print(f"Joining parts into {output_filepath}...")
    part_num = 1
    
    with open(output_filepath, 'wb') as outfile:
        while True:
            # Tìm tuần tự từng file part1, part2,...
            part_name = f"{output_filepath}.part{part_num}"
            if not os.path.exists(part_name):
                break
                
            print(f" -> Reading {part_name}")
            with open(part_name, 'rb') as infile:
                outfile.write(infile.read())
            
            part_num += 1
            
    if part_num > 1:
        print(f"Successfully joined {part_num - 1} parts into {output_filepath}")
    else:
        print(f"No parts found for {output_filepath}")

join_files('waf-efficacy-tool/Data/legi4.rar')
join_files('waf-efficacy-tool/Data/legi5.rar')
