# tf-idf similarity between MITRE ATTACK mitigation and CWE mitigation
from lib2to3.pgen2 import token
from nltk.corpus import stopwords
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from cyberkg_sysflow.pkg.sim_cve_tech import tokenize


def cwe_mitre_miti_cossim(cwe_miti_desc: str, mitre_miti_desc: list[str]):
    cwe_miti_desc_tk = tokenize(cwe_miti_desc)
    mitre_miti_desc_tk = [tokenize(s) for s in mitre_miti_desc]
    
    corpus = [cwe_miti_desc_tk] + mitre_miti_desc_tk
    vectorizer = TfidfVectorizer(stop_words=list(stopwords.words('english')))
    X = vectorizer.fit_transform(corpus).todense()
    cos = cosine_similarity(X[0], X[1:])[0].tolist()  # (1, N)[0] -> (N,)
    cos = [round(n, 4) for n in cos]

    return cos


def cwe_mitre_def_cossim(cwe_def_desc: str, mitre_def_desc: list[str]):
    cwe_def_desc_tk = tokenize(cwe_def_desc)
    mitre_def_desc_tk = [tokenize(s) for s in mitre_def_desc]
    
    corpus = [cwe_def_desc_tk] + mitre_def_desc_tk
    vectorizer = TfidfVectorizer(stop_words=list(stopwords.words('english')))
    X = vectorizer.fit_transform(corpus).todense()
    cos = cosine_similarity(X[0], X[1:])[0].tolist()  # (1, N)[0] -> (N,)
    cos = [round(n, 4) for n in cos]

    return cos
