
import os
import json
import re

def open_json(path):
    with open(path, 'r', encoding='utf8') as f:
        return json.loads(f.read())


def save_json(path, data):
    with open(path, 'w', encoding='utf8') as f:
        f.write(json.dumps(data, ensure_ascii=False))

def save_file_b(path, data):
    with open(path, 'wb') as f:
        f.write(data)

class Lilim:
    def output_hook_dict(dict_name='test'):
        jp_chs = open_json('jp_chs.json')
        ans = bytearray()
        cnt = 0
        for key in jp_chs:
            if jp_chs[key]:
                ans += key.encode('cp932') + b'\x00'
                ans += jp_chs[key].encode('gbk', errors='ignore') + b'\x00'
                cnt += 1
        print('替换：', cnt)
        save_file_b(dict_name, ans+b'\xFF')

    def extract_for_hook_aos2(path):
        '''
        输入文本目录
        '''
        def get_scenario_from_origin(data: list) -> list:
            text_all = []
            buff = ''
            cnt = 0
            # START FIXME
            for line in data:
                line = line[:-1]
                if not line and buff:
                    text_all.append(buff+'\\f\n')
                    buff = ''
                elif line:
                    if line[0] not in '#:^%\t$ｔ' and not ('a' <= line[0] <= 'z'):
                        if buff and buff[-1] != ']':
                            buff += '\\n'

                        buff += line
                    elif line.count('slctwnd'):
                        text_all.append(line.split('\"')[-2]+'\n')
                cnt += 1
            # END

            return text_all
    
        file_origial = os.listdir(path)
        file_origial = list(map(lambda x: path+'\\'+x, file_origial))

        jp = []
        encoding = 'cp932'
        for file_name in file_origial:
            if file_name[-1] != 'r':
                continue
            with open(file_name, 'r', encoding=encoding, errors='ignore') as f:
                text_t = f.readlines()
            jp += get_scenario_from_origin(text_t)

        with open('jp_all.txt', 'w', encoding='utf8') as f:
            for line in jp:
                f.write(line)
        

        try:
            j_c = open_json('jp_chs.json')
        except Exception as e:
            print('第一次建立字典！')
            j_c = dict()
        print('总共', len(jp), '条')
        cnt = 0
        for line in jp:
            # 去掉每行多余的符号
            _t = line[:-1]
            if _t not in j_c:
                j_c[_t] = ''
                cnt += 1
        print('添加关键字：', cnt, '条')
        save_json('jp_chs.json', j_c)


    def fix_dixt(dict_path="jp_chs.json"):
        '''
        文本中不能出现半角的字母和\\f|\\n|[|]以外的符号
        删除(~|\(|\))
        替换 
        [a-z]->全角
        [0-9]->全角
        [A-A]->全角
        '''
        cnt = 0
        jp_chs = open_json(dict_path)
        for key in jp_chs:
            value = jp_chs[key]
            value = value.replace('\\n', '※')
            value = value.replace('\\f', '☆')
            value = strB2Q(value, exclude=('[]\\'))
            value = value.replace('☆', '\\f')
            value = value.replace('※', '\\n')
            if value != jp_chs[key]:
                jp_chs[key] = value
                cnt+=1
        print('修复：', cnt)
        save_json(dict_path, jp_chs)


if __name__ == "__main__":
    # Lilim.extract_for_hook_aos2('E:\Tools\VNR\[LiLiM]\[120629][LiLiM DARKNESS]WEDDING BLUE\scr2')
    Lilim.output_hook_dict()