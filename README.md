# IBM - Sysflow - CyberKG 
This repository contains packages and running demo using sysflow + CyberKG. The sysflow data and a constructed KG are provided.

## Guide

We organize the structure of our files as follows:
```latex
.
└──  API/
│   └──  query mitigation.ipynb  # an API for querying different groups of mitigations
│
└──  cyberkg_sysflow/
    ├──  pkg/                    # packages called by notebook demo
    │   ├──  cwe_miti.py         # CWE-mitigation related codes, used to synthesize mitigation phases
    │   ├──  sim_cve_tech.py     # calculating tf-idf similarity between CVE and TTP descriptions
    │   ├──  sim_mitre.py        # calculating tf-idf similarity between MITRE projects (e.g., TTP mitigation and defence)
    │   └──  sysflow.py          # sysflow-related functions
    │
    ├──  save/                   # temporary save dir for different demo
    │   ├──  cwe_miti/           # temporary save dir for CWE-related data
    │   ├──  mitre-attack/       # temporary save dir for MITRE ATT&CK data
    │   └──  mitre-defend        # temporary save dir for MITRE D3FEND data
    │
    ├──  sysflow_data/           # parsed and raw sysflow instances
    │
    ├──  crawler - mitre attack.ipynb/             # crawling codes for MITRE ATT&CK data
    ├──  crawler - mitre defend.ipynb/             # crawling codes for MITRE D3FEND data
    ├──  crawler - nvd.ipynb/                      # crawling codes for NVD data
    ├──  demo - prioritize ttp.ipynb/              # find the prioritized TTPs within a TTP set
    ├──  demo - summariatize mitigation.ipynb/     # explore potential mitigations/defences for a given TTP
    ├──  demo - sysflow.ipynb/                     # linking demo about TTP/sysflow -> CVE -> CWE
    ├──  demo - ttp cluster.ipynb/                 # cluster TTPs with a given TTP set (tentative codes)
    ├──  demo - wordcloud.ipynb/                   # wordcloud codes
    ├──  ttp_comb.py                               # formal codes of clustering TTPs
    └──  ttp_prediction.py                         # predict TTPs by GCN, using sysflow graphs
```   

## Use the API

We provide a [mitigation querying API](https://github.com/HarrialX/IBM-sysflow-KG/blob/main/API/query%20mitigation.ipynb).

To play with it, simply specify the **TTP** code and which type of mitigation you want to get. Simply seeing the jupyter notebook for running details.