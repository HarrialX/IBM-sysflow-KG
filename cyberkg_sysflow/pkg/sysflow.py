# find path from sysflow evidence to CVE/miti

from email.policy import default
import os, sys
sys.path.append(os.path.abspath('../..'))

import csv
import copy
import pickle
import numpy as np
from tqdm import tqdm
from collections import defaultdict


ent_prefix = { # also serves as abbrevation
    'vendor': 'VD',
    'product': 'PD',
    'version': 'VER',
    'campaign': 'CAMP',
    # 'threat-actor': 'ACTOR',
    # 'incident': 'INCID',
    # 'TTP': 'TTP',
    'tactic': 'TA',
    'technique': 'TECH',
    'attack-pattern': 'AP',
    'weakness': 'CWE',
    'mitigation': 'MITI',
}
ent_prefix_delimiter = ':'
rel_dict = {
    'cve-id:vendor':      'CVE:affects:%s' %  ent_prefix['vendor'],
    'cve-id:product':     'CVE:affects:%s' % ent_prefix['product'],
    'cve-id:version':     'CVE:affects:%s' % ent_prefix['version'],
    'vendor:product':     '%s:has:%s' % (ent_prefix['vendor'], ent_prefix['product']),
    'product:version':    '%s:has:%s' % (ent_prefix['product'], ent_prefix['version']),
    'cve-id:cve-id':      'CVE:is:related:to:CVE',           
    
    'cve-id:campaign':       'CVE:has:propose:%s' % ent_prefix['campaign'],
    # 'cve-id:threat-actor': 'CVE:has:threat:actor:%s' % ent_prefix['threat-actor'],
    # 'cve-id:incident':     'CVE:causes:incident:%s' % ent_prefix['incident'],
    # 'cve-id:TTP':          'CVE:has:technique:%s' % ent_prefix['TTP'],

    # 'threat-actor:incident': '%s:carries:out:%s' % (ent_prefix['threat-actor'], ent_prefix['incident']),
    # 'threat-actor:TTP':      '%s:uses:%s' % (ent_prefix['threat-actor'], ent_prefix['TTP']),
    # 'threat-actor:campaign': '%s:causes:%s' % (ent_prefix['threat-actor'], ent_prefix['campaign']),
    # 'incident:TTP':          '%s:uses:%s' % (ent_prefix['incident'], ent_prefix['TTP']),
    # 'incident:campaign':     '%s:causes:%s' % (ent_prefix['incident'], ent_prefix['campaign']),
    # 'TTP:campaign':          '%s:causes:%s' % (ent_prefix['TTP'], ent_prefix['campaign']),
    
    'tactic:technique':         '%s:includes:%s' % (ent_prefix['tactic'], ent_prefix['technique']),
    'technique:attack-pattern': '%s:leverages:%s' % (ent_prefix['technique'], ent_prefix['attack-pattern']),
    'attack-pattern:weakness':  '%s:is:related:to:%s' % (ent_prefix['attack-pattern'], ent_prefix['weakness']),
    'weakness:cve-id':          '%s:includes:CVE' % ent_prefix['weakness'],

    'mitigation:cve-id':        '%s:mitigates:CVE' % ent_prefix['mitigation'],

    'sysflow:technique':        'SF:leverages:%s' % ent_prefix['technique'],
}
ver_delimiter = ':ver:'
rev_rel_prefix = 'reverse:'


#------ load computed cosine similarity ------#

file = open("/data/zhaohan/adv-reasoning/data/cyberkg-raw/mitre-attack/tech-cve-cossim.csv")
csvreader = csv.reader(file)

# first row
header = next(csvreader) 
cve_codes = header[1:]

tech_codes = []
tech_scores = {}
for row in tqdm(csvreader): # contents starts with 2nd row
    tech_codes.append(row[0])
    tech_scores[row[0]] = list(map(float, row[1:]))

file.close()

#-------- load generated cisco cyberkg --------#

kg_path = '/home/zxx5113/IBM/data/cyberkg_IBM/cyberkg_sysflow'

entset = pickle.load(open(os.path.join(kg_path, 'entset.pkl'), 'rb'))
factset = pickle.load(open(os.path.join(kg_path, 'factset.pkl'), 'rb'))
sysflow_graphs = pickle.load(open(os.path.join(kg_path, 'sysflow_graphs.pkl'), 'rb'))

# print('number of sysflow graphs: %d\n' % len(sysflow_graphs.keys()))
# print('sysflow id\t TTPs')
# for gid, data in sysflow_graphs.items():
#     print(gid, '\t', list(data['ttpnodes']))

#------- other preparations to use later -------#

cve2cwe = defaultdict(str)
cwe2cve = defaultdict(set)
for h, r, t in factset[rel_dict['weakness:cve-id']]:
    assert h in entset['weakness']
    assert t in entset['cve-id']
    cve2cwe[t] = h
    cwe2cve[h].add(t)
    
tech2capec = defaultdict(set)
capec2cwe = defaultdict(set)
for h, r, t in factset[rel_dict['technique:attack-pattern']]:
    tech2capec[h].add(t)
for h, r, t in factset[rel_dict['attack-pattern:weakness']]:
    capec2cwe[h].add(t)
    
tech2cwe = defaultdict(set)
for tech, capecs in tech2capec.items():
    for capec in capecs:
        if len(capec2cwe[capec])>0:
            tech2cwe[tech] |= capec2cwe[capec]


# ----------- multi view part ------------#

file = open("/data/zhaohan/adv-reasoning/data/cyberkg-raw/mitre-attack/cve-tech-cossim.csv")
csvreader = csv.reader(file)

# first row
header = next(csvreader) 
 
cve_scores = defaultdict(dict)  # cve-tech sim
for row in tqdm(csvreader): # contents starts with 2nd row
    for i, t_code in enumerate(header[1:]):
        # t_code: without prefix
        t_code = ent_prefix['technique'] + ent_prefix_delimiter + t_code
        cve_scores[row[0]][t_code] = float(row[i+1]) 

file.close()

tech2ta = defaultdict(set)
ta2tech = defaultdict(set)
for h, r, t in tqdm(factset[rev_rel_prefix + rel_dict['tactic:technique']]):
    assert h in entset['technique']
    assert t in entset['tactic']
    tech2ta[h].add(t)
    ta2tech[t].add(h)

cve_ta_scores = defaultdict(dict)  # cve-ta-sim
for cve in tqdm(cve_scores):
    for ta in ta2tech:  # ta with prefix
        for tech in ta2tech[ta]:
            if ta not in cve_ta_scores[cve]:
                cve_ta_scores[cve][ta] = 0

            # some tech are removed from original website (but still in BRON)
            cve_ta_scores[cve][ta] += cve_scores[cve][tech] if tech in cve_scores[cve] else 0  

tech_scores_mv = {}
for tech, scores in tqdm(tech_scores.items()):
    tech_scores_mv[tech] = [0] * len(scores)
    for ta in tech2ta[ent_prefix['technique'] + ent_prefix_delimiter + tech]:
        tech_scores_mv[tech] = [tech_scores_mv[tech][i] + s * cve_ta_scores[cve_codes[i]][ta] for i, s in enumerate(scores)]


#------------- some functions -------------#

def link_BRON(gid: int = None, ttp: int or list = None):
    if gid:
        gid = str(gid)
        ttps = sysflow_graphs[gid]['ttpnodes']
    elif isinstance(ttp, list):
        ttps = ttp
    elif isinstance(ttp, int):
        ttps = [ttp]
        
    capecs = set()
#     print(sysflow_graphs[gid]['ttpnodes'])
    for h, r, t in factset[rel_dict['technique:attack-pattern']]:
        assert h in entset['technique']
        assert t in entset['attack-pattern']
        for tech in ttps:
            
            if tech in h:
                capecs.add(t)

    cwes = set()
    for h, r, t in factset[rel_dict['attack-pattern:weakness']]:
        assert h in entset['attack-pattern']
        assert t in entset['weakness']
        if h in capecs:
            cwes.add(t)
    return cwes


def cdd_cve_by_kw(cate, keyword):
    assert cate in entset, 'please specify the cate in entset.keys()'
    kw_cve_dict = defaultdict(set)

    for h, r, t in factset[rev_rel_prefix + rel_dict['cve-id:'+cate]]:
        # cate to cve
        assert h in entset[cate] and t in entset['cve-id']
        kw_cve_dict[h].add(t)

    keep_cve = set()
    for e in entset[cate]:
        if keyword in e:
            keep_cve |= kw_cve_dict[e]

    return keep_cve

def ttp_cve_link(
    gid: int = None, 
    thre: float = None, 
    n_cve: int = None, 
    tech: str or list = None, 
    multiview = False, 
    filtering = False,
    cdd_cve = None,
    verbose = False):
    
    if multiview:
        tech_cve_sim = tech_scores_mv
    else:
        tech_cve_sim = tech_scores

    if gid:
        gid = str(gid)
        data = sysflow_graphs[gid]
        sum_scores = None
        for tech in data['ttpnodes']:
            if not sum_scores:
                sum_scores = copy.deepcopy(tech_cve_sim[tech])
            else:
                sum_scores = [sum_scores[i] + s for i, s in enumerate(tech_cve_sim[tech])]
        sum_scores = np.array(sum_scores) / len(data['ttpnodes'])
        if verbose:
            print('Techniques: ', data['ttpnodes'])
        
    elif isinstance(tech, str): 
        sum_scores = copy.deepcopy(tech_cve_sim[tech])
        if verbose:
            print('Technique: ', tech)     
            
    elif isinstance(tech, list):
        sum_scores = None
        for ttp in tech:
            if not sum_scores:
                sum_scores = copy.deepcopy(tech_cve_sim[ttp])
            else:
                sum_scores = [sum_scores[i] + s for i, s in enumerate(tech_cve_sim[ttp])]
        sum_scores = np.array(sum_scores) / len(tech)
        if verbose:
            print('Techniques: ', tech)
    else:
        raise NotImplementedError('must input gid (int) or tech (str or list)')

    top_ind = np.argsort(sum_scores)[::-1]
    top_cves = [cve_codes[i] for i in top_ind]
    top_scores = [round(sum_scores[i], 4) for i in top_ind]
    
    if filtering:
        ft_cve_list, ft_score_list = [], []
        for i, cve in enumerate(top_cves):
            if cve in cdd_cve:
                ft_cve_list.append(cve)
                ft_score_list.append(top_scores[i])
        top_cves, top_scores = ft_cve_list, ft_score_list

    assert thre is not None or n_cve is not None
    assert not (thre is not None and n_cve is not None), 'cannot assign both thresholding or top-k to filter CVEs'
    if thre is not None:
        thre_ind = [i for i, s in enumerate(top_scores) if s>=thre]
    elif n_cve is not None:
        thre_ind = list(range(min(n_cve, len(top_cves))))

    thre_cves = [top_cves[i] for i in thre_ind]
    thre_scores = [top_scores[i] for i in thre_ind]

    if verbose:
        print('\nCVE-ID\t\t TF-IDF Score')
        for i in thre_ind:
            print(thre_cves[i], '\t', thre_scores[i])
    
    return thre_cves, thre_scores


def cwe_cve_link(thre_cves: list, thre_scores: list):
    cwe_scores = defaultdict(int)
    cwe_count = defaultdict(int)
    for i, cve in enumerate(thre_cves):
        cwe = cve2cwe[cve]
        if len(cwe)>0:
            cwe_scores[cwe] += thre_scores[i]
            cwe_scores[cwe] = round(cwe_scores[cwe], 4)
#         else:
#             cwe_scores[cwe] += 0
        cwe_count[cwe] += 1
    
    for cwe, score in cwe_scores.items():
        cnt = cwe_count[cwe]
#         cwe_scores[cwe] = round(score/cnt, 4)

    cwe_sort = [k for k, v in sorted(cwe_scores.items(), key=lambda item: item[1], reverse=True)]
    score_sort = [v for k, v in sorted(cwe_scores.items(), key=lambda item: item[1], reverse=True)]
    return cwe_sort, score_sort


