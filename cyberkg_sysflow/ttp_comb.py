
import os, sys
sys.path.append(os.path.abspath('../..'))

import csv
import json
import argparse
import numpy as np
from tqdm import tqdm
import networkx as nx
from collections import defaultdict
from nltk.corpus import stopwords
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.cluster import KMeans
from scipy.spatial.distance import cdist

import data.cyberkg_IBM.pkg.sysflow as sf
from data.cyberkg_IBM.pkg.sim_cve_tech import tokenize


TTPS = ['T1082', 'T1083', 'T1222.002', 'T1105', 'T1552.003', 'T1087.001', 'T1033', 'T1059.004', 'T1106', 'T1574', 'T1087', 'T1020']

# Get the top-k CWEs (e.g. top-3) for each TTP. - This would involve the normal query using the KG. After this step, you should have 12 CWE lists.

# For each TTP, compute its similarity to the other TTPs based on the similarity of their top-k CWE lists. Below I have one simple method, but you are probably aware of better ways to go about the comparison
# First, identify any shared CWE in the CWE lists. For each shared CWE, remove it from each list and add 1 to the similarity score
# Next, compare the remaining CWEs in each list. Compute all similarity pairs based on the textual similarity of their mitigation subclasses and use the highest scoring CWE pairing. This would generate another value between [0,1] indicating similarity (e.g. exactly the same text would be similarity score of 1. Note that each CWE can only be used once
# Sum up all of the similarity scores and then divide by the number of CWE (including the ones that weren't used in step 2).
# Two TTPs can be combined if their score in step 3 is above some threshold

# - We probably only want to compare same phase mitigations in step 2
# - For computing score between CWEs, maybe we apply a similar procecss as steps 2 and 3, but compare pairs of mitigations instead.


def ttp_sim(cwes_1_org: list, cwes_2_org: list, cwe_miti_tk: dict):
    sim = len(set(cwes_1_org) & set(cwes_2_org))
    cwes_1 = list(set(cwes_1_org) - set(cwes_2_org))
    cwes_2 = list(set(cwes_2_org) - set(cwes_1_org))

    # temp corpus
    phase_idx_map, corpus = {}, []
    for cwe_id in list(set(cwes_1) | set(cwes_2)):
        for phase, miti_text_tk in cwe_miti_tk[cwe_id].items():
            key = cwe_id+'::'+phase
            assert key not in phase_idx_map
            phase_idx_map[key] = len(corpus)
            corpus.append(miti_text_tk)

    if len(corpus) == 0:
        return sim / sim

    vectorizer = TfidfVectorizer(stop_words=list(stopwords.words('english')))
    X = vectorizer.fit_transform(corpus).todense()
    
    # max cossim score
    cossim = 0
    for cwe_1 in cwes_1:
        for cwe_2 in cwes_2:
            for ph1 in cwe_miti_tk[cwe_1]:
                for ph2 in cwe_miti_tk[cwe_2]:
                    if ph1 != ph2:
                        continue
                    x1 = X[phase_idx_map[cwe_1+'::'+ph1]]
                    x2 = X[phase_idx_map[cwe_2+'::'+ph2]]
                    cossim = max(cossim, cosine_similarity(x1, x2)[0][0])

    return (sim + cossim) / (sim + 1)


# maximum spanning tree
class Graph:
 
    def __init__(self, vertices, gnum, TTPS):
        self.V = vertices  # No. of vertices, 0-based index
        self.graph = []  # default dictionary
        self.nx_graph = nx.Graph() # to count graph num
        self.nx_graph.add_nodes_from(range(self.V))

        self.gnum = gnum
        self.TTPS = TTPS

    # function to add an edge to graph
    def addEdge(self, u, v, w):
        self.graph.append([u, v, w])
 
    # A utility function to find set of an element i
    # (uses path compression technique)
    def find(self, parent, i):
        if parent[i] == i:
            return i
        return self.find(parent, parent[i])
 
    # A function that does union of two sets of x and y
    # (uses union by rank)
    def union(self, parent, rank, x, y):
        xroot = self.find(parent, x)
        yroot = self.find(parent, y)
 
        # Attach smaller rank tree under root of
        # high rank tree (Union by Rank)
        if rank[xroot] < rank[yroot]:
            parent[xroot] = yroot
        elif rank[xroot] > rank[yroot]:
            parent[yroot] = xroot
 
        # If ranks are same, then make one as root
        # and increment its rank by one
        else:
            parent[yroot] = xroot
            rank[xroot] += 1
 
    # The main function to construct MST using Kruskal's
        # algorithm
    def KruskalMST(self):
 
        result = []  # This will store the resultant MST
         
        # An index variable, used for sorted edges
        i = 0
         
        # An index variable, used for result[]
        e = 0
 
        # Step 1:  Sort all the edges in
        # decreasing order of their weight.  
        # If we are not allowed to change the
        # given graph, we can create a copy of graph
        self.graph = sorted(self.graph,
                            key=lambda item: item[2], reverse=True)
 
        parent = []
        rank = []
 
        # Create V subsets with single elements
        for node in range(self.V):
            parent.append(node)
            rank.append(0)
 
        # Number of edges to be taken is equal to V-1 # TODO
        while e < self.V - 1:
 
            # Step 2: Pick the largest edge and increment
            # the index for next iteration
            u, v, w = self.graph[i]
            i = i + 1
            x = self.find(parent, u)
            y = self.find(parent, v)
 
            # If including this edge does't
            #  cause cycle, include it in result
            #  and increment the indexof result
            # for next edge

            if x != y:
                e = e + 1
                result.append([u, v, w])
                self.union(parent, rank, x, y)
                self.nx_graph.add_edge(u, v)
            
            # termination
            count = 0
            for g in nx.connected_components(self.nx_graph):
                # components.append([g, len(g)])
                count += 1
            if count <= self.gnum:
                break 

            # Else discard the edge
 
        # maximumCost = 0
        # print ("\nEdges in the constructed MST")
        # for u, v, weight in result:
            # maximumCost += weight
            # print("%s -- %s == %.2f" % (TTPS[u], TTPS[v], weight))
        # print("Maximum Spanning Tree %.4f" % maximumCost)

        print("\nGroup of graphs")
        for g in nx.connected_components(self.nx_graph):
            print(set([TTPS[n] for n in g]))
        


def ttp_cluster(args):
    # cwe_list = list(sf.entset['weakness'])
    # cwe_idx = {cwe: i for i, cwe in enumerate(cwe_list)}
    ttp_idx = {ttp: idx for idx, ttp in enumerate(TTPS)}

    cwe_list = set()
    for ttp in tqdm(TTPS):
        thre_cves, thre_scores = sf.ttp_cve_link(thre = 0, tech = ttp, verbose=False)
        cwe_sort, score_sort = sf.cwe_cve_link(thre_cves, thre_scores)
        cwe_sort = cwe_sort[:args.K]
        cwe_list |= set(cwe_sort)
    cwe_list = list(cwe_list)
    cwe_idx = {cwe: i for i, cwe in enumerate(cwe_list)}

    ttp_mat = np.zeros((len(TTPS), len(cwe_list)))
    for ttp in tqdm(TTPS):
        thre_cves, thre_scores = sf.ttp_cve_link(thre = 0, tech = ttp, verbose=False)
        cwe_sort, score_sort = sf.cwe_cve_link(thre_cves, thre_scores)
        cwe_sort = cwe_sort[:args.K]
        for i, cwe in enumerate(cwe_sort):
            ttp_mat[ttp_idx[ttp]][cwe_idx[cwe]] = 1

    model = KMeans(n_clusters=args.N, random_state=0).fit(ttp_mat)
    # return kmeans.labels_, kmeans.cluster_centers_

    clusters = []
    for y in range(min(model.labels_), max(model.labels_)+1):
        clu = []
        for i, _y in enumerate(model.labels_):
            if y == _y:
                clu.append(TTPS[i])
        clusters.append(clu)
        
        
    def find_nearest(array, value):
        array = np.asarray(array)
        idx = (np.abs(array - value)).argmin()
        return idx

    centers = []
    for cen in model.cluster_centers_:
        dist = cdist(np.array([cen]), ttp_mat, 'euclidean')[0]
        idx = find_nearest(dist, 0)
        centers.append(TTPS[idx])

    return centers, clusters

def parse_args(args=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--N', default=4, type=int, help='number of graph clusters')
    parser.add_argument('--K', default=20, type=int, help='number of CWEs get from each TTP')
    parser.add_argument('--model', default='kmeans', type=str, help='cluster models')
    parser.add_argument('--cve_thre', default=0.12, type=float, help='CVE threshold during linking')
    parser.add_argument('--save_dir', default='/home/zxx5113/adv-reasoning/data/cyberkg_IBM/save', type=str)

    return parser.parse_args(args)

# if __name__ == '__main__':
    # args = parse_args()
    # centers, clusters = ttp_cluster(args)
    # print(centers)
    # print(clusters)

if __name__ == '__main__':
    ''' N: num of ttp clusters
        K: num of cwes per ttp
    '''
    args = parse_args()
    N = args.N
    K = args.K
    cve_thre = args.cve_thre
    save_dir = args.save_dir

    ttp_cwes_dict = defaultdict(list) # str: [str]
    for ttp in TTPS:
        thre_cves, thre_scores = sf.ttp_cve_link(thre = cve_thre, tech = ttp, verbose=False)
        cwe_sort, score_sort = sf.cwe_cve_link(thre_cves, thre_scores)
        ttp_cwes_dict[ttp] = cwe_sort[:K]
    
    # remove prefix
    for ttp in ttp_cwes_dict:
        ttp_cwes_dict[ttp] = [cwe.split(':')[-1] for cwe in ttp_cwes_dict[ttp]]
        
    ttp_mat = np.zeros((len(TTPS), len(TTPS)))
    ttp_idx = {ttp: idx for idx, ttp in enumerate(TTPS)}

    cwe_detail = json.load(open('/data/zhaohan/adv-reasoning/data/cyberkg-raw/cwe/cwe_detail.json', 'r'))
    cwe_miti_tk = defaultdict(lambda: defaultdict(list))
    for cwe_id in cwe_detail:
        for phase, miti_txt in cwe_detail[cwe_id]['mitigation'].items():
            tk = tokenize(miti_txt)
            cwe_miti_tk[cwe_id][phase] = tk if len(tk)>0 else ['']

    for ttp1 in TTPS:
        for ttp2 in TTPS:
            if ttp1 == ttp2: ttp_mat[ttp_idx[ttp1]][ttp_idx[ttp2]] = 1
            ttp_mat[ttp_idx[ttp1]][ttp_idx[ttp2]] = ttp_sim(ttp_cwes_dict[ttp1], ttp_cwes_dict[ttp2], cwe_miti_tk)

    writer = csv.writer(open('/home/zxx5113/adv-reasoning/data/cyberkg_IBM/save/ttp-comb-sim-%s-%s.csv' % (str(K), str(cve_thre)), 'w'))
    head = ['TTP/TTP']+TTPS
    writer.writerow(head)
    print('\t'.join(head))
    for ttp in TTPS:
        idx = ttp_idx[ttp]
        row = [str(ele) for ele in [ttp]+[round(n, 4) for n in ttp_mat[idx]]]
        writer.writerow(row)
        print('\t'.join(row))

    # MST part
    # g = Graph(len(TTPS), N, TTPS)
    # for i, ttp1 in enumerate(TTPS):
    #     for ttp2 in TTPS[i+1:]:
    #         idx1 = ttp_idx[ttp1]
    #         idx2 = ttp_idx[ttp2]
    #         g.addEdge(idx1, idx2, ttp_mat[idx1][idx2])

    # # Function call
    # g.KruskalMST()


    # nohup python -u ttp_comb.py --N 3 --K 20 --cve_thre 0.05 > ./save/ttp_comb_3_20_0.05.txt 2>&1 &
    