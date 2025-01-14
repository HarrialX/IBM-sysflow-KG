import os
import string
from tqdm import tqdm
import nltk
nltk.download('stopwords')
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

import csv
import json
import pickle
from collections import defaultdict


ps = PorterStemmer()
def tokenize(text):
    tokens = nltk.word_tokenize(text)
    tokens = ' '.join([ps.stem(i) for i in tokens if i not in string.punctuation])
    return tokens


def tech_cve_cossim(tech_codes, cve_codes, tech_descs_tk, cve_descs_tk):
    '''calculate text similarity for each TTP to all CVE
    '''

    writer = csv.writer(open(os.path.join(os.getcwd(), '../data/mitre-attack/tech-cve-cossim.csv'), 'w'))
    writer.writerow(['TECH/CVE']+cve_codes)
    
    for i, tech_code in tqdm(enumerate(tech_codes)):
        corpus = [tech_descs_tk[i]] + cve_descs_tk
        vectorizer = TfidfVectorizer(stop_words=list(stopwords.words('english')))
        X = vectorizer.fit_transform(corpus).todense()
        # print(vectorizer.get_feature_names())
        cos = cosine_similarity(X[0], X[1:])[0].tolist()  # (1, N)[0] -> (N,)
        writer.writerow([tech_code]+[round(n, 4) for n in cos])
        
def cve_tech_cossim(tech_codes, cve_codes, tech_descs_tk, cve_descs_tk):
    '''calculate text similarity for each CVE to all TTP
    '''

    writer = csv.writer(open(os.path.join(os.getcwd(), '../data/mitre-attack/cve-tech-cossim.csv'), 'w'))
    writer.writerow(['CVE/TECH']+tech_codes)
    
    for i, cve in tqdm(enumerate(cve_codes)):
        corpus = [cve_descs_tk[i]] + tech_descs_tk
        vectorizer = TfidfVectorizer(stop_words=list(stopwords.words('english')))
        X = vectorizer.fit_transform(corpus).todense()
        # print(vectorizer.get_feature_names())
        cos = cosine_similarity(X[0], X[1:])[0].tolist()  # (1, N)[0] -> (N,)
        writer.writerow([cve]+[round(n, 4) for n in cos])

# NOTE: we already have calculated CSV files, don't run this file again

# if __name__ == '__main__':
#     tech_codes = []
#     tech_descs = []
#     tech_dict = json.load(open(os.path.join(os.getcwd(), '../data/mitre-attack/techniques.json'), 'r'))
#     for code, info in tech_dict.items():
#         tech_codes.append(code)
#         tech_descs.append(info['desc'])

#     cve_desc = pickle.load(open(os.path.join(os.getcwd(), '../data/cyberkg/cve_desc.pkl'), 'rb'))  # NOTE: delete cve_desc.pkl so far
#     cve_codes = sorted(list(cve_desc.keys())) 
#     cve_descs = [cve_desc[cve] for cve in cve_codes]

#     # tokenized documents
#     cve_descs_tk  = [tokenize(s) for s in cve_descs]
#     tech_descs_tk = [tokenize(s) for s in tech_descs]

#     tech_cve_cossim(tech_codes, cve_codes, tech_descs_tk, cve_descs_tk)
#     cve_tech_cossim(tech_codes, cve_codes, tech_descs_tk, cve_descs_tk)

# need to backup run