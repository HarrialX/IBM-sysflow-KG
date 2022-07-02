import os, json
from tqdm import tqdm
from collections import defaultdict


cwe_detail = json.load(open('/data/zhaohan/adv-reasoning/data/cyberkg-raw/cwe/cwe_detail.json', 'r'))
# print(cwe_detail['79']['mitigation']['Architecture and Design'])

cwe_phase_st_dict = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))

# generate cwe miti text
save_dir = '/home/zxx5113/IBM/cyberkg_sysflow/save/cwe_miti/'
os.makedirs(save_dir, exist_ok=True)

def sum_miti(save: bool = True):
    for cwe in cwe_detail:
        for phase, miti_txt in cwe_detail[cwe]['mitigation'].items():
            if phase not in ['Operation']:
                continue

            # with/without strategy
            cur_st = 'No Strategy'
            st_desc_dict = defaultdict(list)
            st_txt = []
            for _txt in miti_txt.strip().split('\n'):
                _txt = _txt.strip()
                if len(_txt) == 0:
                    continue
                if _txt.startswith('Strategy:'):
                    if len(st_txt) > 0:
                        cwe_phase_st_dict[cwe][phase][cur_st].append(' \n'.join(st_txt))
                        st_txt = []
                    cur_st = _txt[len('Strategy:'):].strip()
                    # print(cwe, '|', phase, '|', _txt)
                else:
                    st_desc_dict[cur_st].append(_txt)
                    st_txt.append(_txt)

            if len(st_txt) > 0:
                cwe_phase_st_dict[cwe][phase][cur_st].append(' \n'.join(st_txt))
                

            if save:
                for st, st_desc in st_desc_dict.items():
                    with open(os.path.join(save_dir + "%s_%s_%s" % (cwe, phase, st)), "w") as f:
                        f.write('\n'.join(st_desc))
                        f.close()

    return cwe_phase_st_dict

# if __name__ == '__main__':
#     cwe_phase_st_dict = sum_miti(save=True)

#     cwe, phase = 22, 'Operation'
#     print('CWE - %d, Phase - %s\n' % (cwe, phase))
#     for st, txt_list in cwe_phase_st_dict[str(cwe)][phase].items():
#         idx = 0
#         for txt in txt_list:
#             first_s = txt.split('. ')[0] + '.'
#             if first_s.startswith("Effectiveness:"):
#                 continue
#             idx += 1
#             print(st, '|', '(%d)' % idx, first_s)
                
