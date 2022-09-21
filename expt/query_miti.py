import os, sys
sys.path.append(os.path.abspath('..'))
import csv
import json
import argparse
import numpy as np
from tqdm import tqdm
from collections import defaultdict
from pkg.sim_mitre import cwe_mitre_miti_cossim
import pkg.sysflow as sf
import pkg.cwe_miti as cm

def cwe_by_bron(techs: list):
    capecs = set()
    for h, r, t in sf.factset[sf.rel_dict['technique:attack-pattern']]:
        assert h in sf.entset['technique']
        assert t in sf.entset['attack-pattern']
        for tech in techs:
            
            if tech in h:
                capecs.add(t)

    cwes = set()
    for h, r, t in sf.factset[sf.rel_dict['attack-pattern:weakness']]:
        assert h in sf.entset['attack-pattern']
        assert t in sf.entset['weakness']
        if h in capecs:
            cwes.add(t)
    return cwes


def all_bron_cwe():
    capecs = set()
    for h, r, t in sf.factset[sf.rel_dict['technique:attack-pattern']]:
        capecs.add(t)

    cwes = set()
    for h, r, t in sf.factset[sf.rel_dict['attack-pattern:weakness']]:
        if h in capecs:
            cwes.add(t)
    return cwes

all_bron_cwe = all_bron_cwe()

mitre_miti = json.load(open(os.path.join(os.getcwd(), '../save/mitre-attack/mitigations.json'), 'r'))
ttp_info = json.load(open(os.path.join(os.getcwd(), '../save/mitre-attack/techniques.json'), 'r'))
miti2def = json.load(open(os.path.join(os.getcwd(), '../save/mitre-defend/miti2def.json'), 'r'))
mitre_def = json.load(open(os.path.join(os.getcwd(), '../save/mitre-defend/defence.json'), 'r'))


def query_mitigation(args, TTP: str):
    
    ''' this function is derived from <project root>/pkg/query_miti.py but focus on statistics

        given a TTP, calculate its top-k cwe list, miti list, defend list, and calculate precision and recall
    '''

    # save_path = os.path.join(save_dir, TTP)
    # os.makedirs(save_path, exist_ok=True)

    cwe_rst, miti_rst, def_rst = [], [], []
    ###  PART I: CWE

    bron_cwe = cwe_by_bron([TTP])
    # if len(bron_cwe)==0:
    #     continue

    thre_cves, thre_scores = sf.ttp_cve_link(n_cve = args.n_cve, tech = TTP, multiview=False, verbose=False)
    cwe_sort, score_sort = sf.cwe_cve_link(thre_cves, thre_scores) # sorted
    
    link_cwe = {}
    for i in range(len(cwe_sort)):
        link_cwe[cwe_sort[i]] = score_sort[i]
    link_cwe = [k for k, v in sorted(link_cwe.items(), key=lambda item: item[1], reverse=True) 
                if k in all_bron_cwe]
    # if len(link_cwe)==0:
    #     return [], [], []

    if len(bron_cwe) > 0 and len(link_cwe) > 0:
        top_link_cwe = link_cwe[:args.topk_rst]
        cwe_precision = len(set(top_link_cwe) & set(bron_cwe)) / len(top_link_cwe)
        cwe_recall = len(set(top_link_cwe) & set(bron_cwe)) / len(bron_cwe)

        cwe_rst = [cwe_precision, cwe_recall]
    
    # for i in range(len(cwe_sort)):
    #     print(cwe_sort[i], ' \t', score_sort[i])
        
    cwe_miti_curtech = []
    cwe_miti_msg_to_cwe = defaultdict(set)

    cwe_phase_st_dict = cm.sum_miti(save=True)
    for i in range(len(cwe_sort)):
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
    for msg in cwe_miti_curtech:  
        cwe_miti_curtech_catstr += ' ' + msg

    ###  PART II: MITRE-ATT&CK mitigation

    if TTP in ttp_info:
        groundtruth_miti = [_miti_code for _miti_code in ttp_info[TTP]['miti']]
    else:
        groundtruth_miti = []

    miti_codes, miti_descs = [], []
    for code, data in mitre_miti.items():
        miti_codes.append(code)
        miti_descs.append(data['desc'])
        
    cossim = cwe_mitre_miti_cossim(cwe_miti_curtech_catstr, miti_descs)
    sort_idx = np.argsort(cossim)[::-1]
  
    link_miti = [miti_codes[idx] for idx in sort_idx]

    if len(groundtruth_miti) > 0 and len(link_miti) > 0:
        top_link_miti = link_miti[:args.topk_rst]
        miti_precision = len(set(top_link_miti) & set(groundtruth_miti)) / len(top_link_miti)
        miti_recall = len(set(top_link_miti) & set(groundtruth_miti)) / len(groundtruth_miti)

        miti_rst = [miti_precision, miti_recall]

    ###  PART III: MITRE-D3FEND mitigation

    def2score = defaultdict(float)
    def2miti = defaultdict(set)
    for _miti_code in miti2def:
        for _def_code in miti2def[_miti_code]:
            def2miti[_def_code].add(_miti_code)

    groundtruth_def = []
    if TTP in ttp_info:
        for _miti_code in ttp_info[TTP]['miti']:
            if _miti_code in miti2def:
                for _def_code in miti2def[_miti_code]:
                    groundtruth_def.append(_def_code)

    for idx in sort_idx:
        miti_code = miti_codes[idx]
        if miti_code in miti2def:
            for def_code in miti2def[miti_code]:
                def2score[def_code] += cossim[idx]
                
    link_def = []
    for _def_code, def_score in sorted(def2score.items(), key=lambda item: item[1], reverse=True):
        link_def.append(_def_code)

    if len(groundtruth_def) > 0 and len(link_def) > 0:
        top_link_def = link_def[:args.topk_rst]
        def_precision = len(set(top_link_def) & set(groundtruth_def)) / len(top_link_def)
        def_recall = len(set(top_link_def) & set(groundtruth_def)) / len(groundtruth_def)

        def_rst = [def_precision, def_recall]

    return cwe_rst, miti_rst, def_rst


def parse_args(args=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--n_cve', default=500, type=int)
    parser.add_argument('--topk_rst', default=5, type=int)
    parser.add_argument('--group', nargs='+', default=['cwe', 'mitre-attack', 'mitre-defend'], type=str)
    parser.add_argument('--save_dir', default='/home/zxx5113/IBM/save/mitigations', type=str)
    return parser.parse_args(args)

def main(args):
    
    cwe_precision, cwe_recall = [], []
    miti_precision, miti_recall = [], []
    def_precision, def_recall = [], []
    for ttp in tqdm(sf.tech_scores, desc='calculating all TTPS', disable=True):
        results = query_mitigation(args, TTP=ttp)  
        if len(results[0]) > 0:
            cwe_precision.append(results[0][0])
            cwe_recall.append(results[0][1])
        
        if len(results[1]) > 0:
            miti_precision.append(results[1][0])
            miti_recall.append(results[1][1])

        if len(results[2]) > 0:
            def_precision.append(results[2][0])
            def_recall.append(results[2][1])
    return np.mean(cwe_precision), np.mean(cwe_recall), np.mean(miti_precision), np.mean(miti_recall), np.mean(def_precision), np.mean(def_recall)
    # print(np.mean(cwe_precision), np.mean(cwe_recall))
    # print(np.mean(miti_precision), np.mean(miti_recall))
    # print(np.mean(def_precision), np.mean(def_recall))


args = parse_args()
os.makedirs(args.save_dir, exist_ok=True)
writer = csv.writer(open(os.path.join(args.save_dir, 'top%d.csv' % args.topk_rst), 'w'))
for n_cve in tqdm([50, 100, 200, 300, 500, 1000, 2000]):
    args.n_cve = n_cve
    rst = main(args)
    writer.writerow([n_cve] + list(rst))

