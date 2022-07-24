
# This file queries CWE mitigation, mitre-attack mitigation, and mitre-defend mitigation based on input TTP
#
# - To query CWE mitigation:
#       we must use KG data and text similarity to do linking, i.e., TTP -> CVE -> CWE,
#       where the TTP -> CVE is based on text similarity and CVE -> CWE is based on KG structure,
#       then we find CWE mitigation based on website reports
#
# - To query mitre-attack mitigation:
#       we can either extract

import os
import json
import numpy as np
from collections import defaultdict
from pkg.sim_mitre import cwe_mitre_miti_cossim
import pkg.sysflow as sf
import pkg.cwe_miti as cm


CVE_THRESHOLD = 100
N_CWE = 20
MITI_SCORE_THRESHOLD = 0.1

def query_mitigation(TTP: str, group: list = ['cwe', 'mitre-attack', 'mitre-defend'], source: list = ['kg', 'web']):
    ''' used by <project root>/API/query mitigation.ipynb
        
        Inputs: 
            - TTP: string of TTP codes
            - group: which type(s) of mitigation aim to get
            - source: how to get results (from KG linking or website reports)
    '''
    ###  PART I: CWE mitigation

    thre_cves, thre_scores = sf.ttp_cve_link(n_cve = CVE_THRESHOLD, tech = TTP, multiview=False, verbose=False)
    cwe_sort, score_sort = sf.cwe_cve_link(thre_cves, thre_scores) # sorted
    # for i in range(len(cwe_sort)):
    #     print(cwe_sort[i], ' \t', score_sort[i])
        
    cwe_miti_curtech = []
    cwe_miti_msg_to_cwe = defaultdict(set)

    cwe_phase_st_dict = cm.sum_miti(save=True)
    for i in range(min(len(cwe_sort), N_CWE)):
        cwe, phase = cwe_sort[i], 'Operation'  # NOTE: only consider 'Operation' phase for CWE mitigation
        cwe = cwe.split(':')[-1]
        # print('CWE - %s, Phase - %s' % (str(cwe), phase))

        for st, txt_list in cwe_phase_st_dict[str(cwe)][phase].items():
            idx = 0
            for txt in txt_list:
                first_s = txt.split('. ')[0] + '.'
                if first_s.startswith("Effectiveness:"):
                    continue
                idx += 1
                # print(st, '|', '(%d)' % idx, first_s)
                if first_s not in cwe_miti_curtech:
                    msg = st + ': ' + first_s

                    if msg not in cwe_miti_curtech:  # bypass duplicated contents when running query_mitigation multiple times
                        cwe_miti_curtech.append(msg)
                    cwe_miti_msg_to_cwe[msg].add(cwe)
                    
    cwe_miti_curtech_catstr = ''
    if 'cwe' in group:
        assert 'kg' in source, "CWE Mitigation can be only get by using KG, add 'kg' into source"
        print('CWE mitigation (Operation-stage only):\n')
        print('CWE | Mitigation by Strategy')

    for msg in cwe_miti_curtech:
        if 'cwe' in group:
            print(' '.join(list(cwe_miti_msg_to_cwe[msg])), '\t', msg)
        cwe_miti_curtech_catstr += ' ' + msg
        # cwe_miti_curtech = '\n'.join(cwe_miti_curtech)
        # cwe_miti_curtech

    ###  PART II: MITRE-ATT&CK mitigation

    mitre_miti = json.load(open(os.path.join(os.getcwd(), '../save/mitre-attack/mitigations.json'), 'r'))
    ttp_info = json.load(open(os.path.join(os.getcwd(), '../save/mitre-attack/techniques.json'), 'r'))

    miti_codes, miti_names, miti_descs = [], [], []
    for code, data in mitre_miti.items():
        miti_codes.append(code)
        miti_names.append(data['name'])
        miti_descs.append(data['desc'])
        
    cossim = cwe_mitre_miti_cossim(cwe_miti_curtech_catstr, miti_descs)
    sort_idx = np.argsort(cossim)[::-1]

    if 'mitre-attack' in group:
        if 'web' in source:
            print('-'*100)
            print('\nMITRE-ATT&CK Mitigation (ground-truth, by official web reports)\n')
            print('Miti | Name')
            for _miti_code in ttp_info[TTP]['miti']:
                print(_miti_code,  mitre_miti[_miti_code]['name'])

        if 'kg' in source:
            print('-'*100)
            print('\nMITRE-ATT&CK Mitigation (by document similarity between CWE Mitigation & ATT&CK Mitigation)\n')
            print('Miti | CosSim | Name')
            for idx in sort_idx:
                if cossim[idx] >= MITI_SCORE_THRESHOLD:
                    print(miti_codes[idx], cossim[idx], miti_names[idx])
            
    ###  PART III: MITRE-D3FEND mitigation

    miti2def = json.load(open(os.path.join(os.getcwd(), '../save/mitre-defend/miti2def.json'), 'r'))
    mitre_def = json.load(open(os.path.join(os.getcwd(), '../save/mitre-defend/defence.json'), 'r'))
    def2score = defaultdict(float)
    def2miti = defaultdict(set)

    for idx in sort_idx:
        if cossim[idx] >= MITI_SCORE_THRESHOLD:
            miti_code = miti_codes[idx]
            for def_code in miti2def[miti_code]:
                def2score[def_code] += cossim[idx]
                def2miti[def_code].add(miti_code)

    if 'mitre-defend' in group:
        if 'web' in source:
            print('-'*100)
            print('\nMITRE-D3FEND Mitigation (ground-truth, by official web reports related to Att&ck Mitigation)\n')
            print('Def | Source Att&ck Miti | Def Name')
            for _miti_code in ttp_info[TTP]['miti']:
                if _miti_code in mitre_def:
                    for _def_code in mitre_def[_miti_code]:
                        print(_def_code, _miti_code, mitre_def[def_code]['name'])

        if 'kg' in source:
            print('-'*100)
            print('\nMITRE-D3FEND Mitigation (by document similarity between CWE Mitigation & D3FEND Mitigation)\n')
            print('Def | Score | Source Att&ck Miti | Def Name')
            for def_code, def_score in sorted(def2score.items(), key=lambda item: item[1], reverse=True):
                print(def_code, round(def_score, 4), list(def2miti[def_code]), mitre_def[def_code]['name'])