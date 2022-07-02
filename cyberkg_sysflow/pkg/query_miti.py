
# import os, sys
# sys.path.append(os.path.abspath('../..'))

import json
import numpy as np
from collections import defaultdict
from cyberkg_sysflow.pkg.sim_mitre import cwe_mitre_miti_cossim
import cyberkg_sysflow.pkg.sysflow as sf
import cyberkg_sysflow.pkg.cwe_miti as cm


CVE_THRESHOLD = 100
N_CWE = 20
MITI_SCORE_THRESHOLD = 0.1

def query_mitigation(TTP: str, group: list = ['cwe', 'mitre-attack', 'mitre-defend']):
    thre_cves, thre_scores = sf.ttp_cve_link(n_cve = CVE_THRESHOLD, tech = TTP, multiview=False, verbose=False)
    cwe_sort, score_sort = sf.cwe_cve_link(thre_cves, thre_scores) # sorted
    # for i in range(len(cwe_sort)):
    #     print(cwe_sort[i], ' \t', score_sort[i])
        
    cwe_miti_curtech = []
    cwe_miti_msg_to_cwe = defaultdict(set)

    cwe_phase_st_dict = cm.sum_miti(save=True)
    for i in range(min(len(cwe_sort), N_CWE)):
        cwe, phase = cwe_sort[i], 'Operation'
        cwe = cwe.split(':')[-1]
    #     print('CWE - %s, Phase - %s' % (str(cwe), phase))

        for st, txt_list in cwe_phase_st_dict[str(cwe)][phase].items():
            idx = 0
            for txt in txt_list:
                first_s = txt.split('. ')[0] + '.'
                if first_s.startswith("Effectiveness:"):
                    continue
                idx += 1
    #             print(st, '|', '(%d)' % idx, first_s)
                if first_s not in cwe_miti_curtech:
                    msg = st + ': ' + first_s
                    cwe_miti_curtech.append(msg)
                    cwe_miti_msg_to_cwe[msg].add(cwe)
                    
    cwe_miti_curtech_catstr = ''
    if 'cwe' in group:
        print('NOTE: Mitigation for Operation-stage only\n')
        for msg in cwe_miti_curtech:
            print(' '.join(list(cwe_miti_msg_to_cwe[msg])), '\t', msg)
            cwe_miti_curtech_catstr += ' ' + msg
        # cwe_miti_curtech = '\n'.join(cwe_miti_curtech)
        # cwe_miti_curtech

    mitre_miti = json.load(open('/home/zxx5113/IBM/cyberkg_sysflow/save/mitre-attack/mitigations.json', 'r'))

    miti_codes, miti_names, miti_descs = [], [], []
    for code, data in mitre_miti.items():
        miti_codes.append(code)
        miti_names.append(data['name'])
        miti_descs.append(data['desc'])
        
    cossim = cwe_mitre_miti_cossim(cwe_miti_curtech_catstr, miti_descs)
    sort_idx = np.argsort(cossim)[::-1]

    if 'mitre-attack' in group:
        print('\n')
        for idx in sort_idx:
            if cossim[idx] >= MITI_SCORE_THRESHOLD:
                print(miti_codes[idx], cossim[idx], miti_names[idx])
            
    miti2def = json.load(open('/home/zxx5113/IBM/cyberkg_sysflow/save/mitre-defend/miti2def.json', 'r'))
    mitre_def = json.load(open('/home/zxx5113/IBM/cyberkg_sysflow/save/mitre-defend/defence.json', 'r'))
    def2score = defaultdict(float)
    def2miti = defaultdict(set)

    for idx in sort_idx:
        if cossim[idx] >= MITI_SCORE_THRESHOLD:
            miti_code = miti_codes[idx]
            for def_code in miti2def[miti_code]:
                def2score[def_code] += cossim[idx]
                def2miti[def_code].add(miti_code)

    if 'mitre-defend' in group:
        print('\n')
        for def_code, def_score in sorted(def2score.items(), key=lambda item: item[1], reverse=True):
            print(def_code, round(def_score, 4),  list(def2miti[def_code]), mitre_def[def_code]['name'])