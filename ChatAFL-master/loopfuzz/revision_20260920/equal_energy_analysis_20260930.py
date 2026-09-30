#!/usr/bin/env python3
"""Equal-energy subset analysis for tab:mechanisms (2026-09-30).

Input: episodes extracted from every C/D/E archive in Key_Experiment
(state-episodes.jsonl; fields mutations, new_code_edges, reward,
posterior_mean_before). K=265 is the most frequent nonzero mutation count
shared by the three arms. Outputs the per-arm n, mean code edges per
episode, proxy-reward base rate, BS, 10-bin ECE, and non-interpolated AP
reported in the manuscript.
"""
import json, sys
data=json.load(open(sys.argv[1] if len(sys.argv)>1 else '/tmp/episodes_cde.json'))
K=265
for arm in ['C','D','E']:
    sub=[e for e in data[arm][0] if e[0]==K]
    n=len(sub); ys=[1 if (e[2] or 0)>0 else 0 for e in sub]; ps=[e[3] for e in sub if e[3] is not None]
    bs=sum((p-y)**2 for p,y in zip(ps,ys))/len(ps)
    bins=[[] for _ in range(10)]
    for p,y in zip(ps,ys): bins[min(int(p*10),9)].append((p,y))
    ece=sum(len(b)/len(ps)*abs(sum(p for p,_ in b)/len(b)-sum(y for _,y in b)/len(b)) for b in bins if b)
    order=sorted(range(len(ps)), key=lambda i:-ps[i]); hits=0; ap=0.0
    for rank,i in enumerate(order,1):
        if ys[i]==1: hits+=1; ap+=hits/rank
    print(f"{arm}: n={n} gain={sum(e[1] or 0 for e in sub)/n:.4f} base={sum(ys)/n:.4f} BS={bs:.4f} ECE={ece:.4f} AP={ap/max(hits,1):.4f}")
