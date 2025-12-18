import pandas as pd
import matplotlib
import matplotlib.pyplot as plt
import sys
import json
from statistics import mean, median, stdev
import numpy as np
from collections import OrderedDict

plt.rcParams.update({'font.size': 20, 'font.family': 'Times New Roman'})
fig, axes = plt.subplots(2, 2, figsize=(8,6.5), constrained_layout=True)

fig.get_layout_engine().set(hspace=0.1)

def load_datapoint(n, f, s, op):
    lines = open('../results/rocksdb/%d-%s-%s/%s/report.tsv' % (n, f, s, op)).readlines()
    return float(lines[-1].split()[0]) / 1000


name = 'kSFS'

file_systems = [('ntfs', 'NTFS'), ('exfat', 'exFAT'), ('ext4', 'ext4')]
operations = [('bulkload', 'Bulk Load'), ('readrandom', 'Random Read'), ('overwrite', 'Overwrite'), ('readwhilewriting', 'Read While Writing')]
systems = [('bento', 'Bento'), ('native', 'Linux'), ('fuse', 'FUSE'), ('fuse-opt', 'FUSE-zc'), ('ksfs', name)]
ylimits = {
    'bulkload': 2500,
    'readrandom': 2500,
    'overwrite': 20,
    'readwhilewriting': 2500
}
file_systems_index = [x for _, x in file_systems]

colors = ["#0b522e", "#35618f", "#5ac4f8", "#6c218e", "#63ef85"]
patterns = ['\\\\', '|', 'x', '///', '']

def load_data(op):
    data = OrderedDict()
    err = OrderedDict()
    for s, n in systems:
        y = []
        er = []
        for f, _ in file_systems:
            x = []
            if s == 'bento' and f != 'exfat':
                y.append(np.nan)
                er.append(np.nan)
                continue
            if s != 'native' and f == 'ext4':
                y.append(np.nan)
                er.append(np.nan)
                continue
            for i in range(1, 11):
                try:
                    d = load_datapoint(i, f, s, op)
                    x.append(d)
                except:
                    pass
            m = median(x)
            st = stdev(x)
            y.append(m)
            er.append(st)
        data[n] = y
        err[n] = er
    return pd.DataFrame(data, index=file_systems_index), pd.DataFrame(err, index=file_systems_index)

for i, (op, opn) in enumerate(operations):
    ax = axes[i // 2][i % 2]
    data, err = load_data(op)
    data.plot(kind='barh', legend=False, color=colors, xerr=err, ax=ax, width=0.8)
    print(opn)
    print(data)
    print(err)
    for j, bar in enumerate(ax.patches):
        bar.set_hatch(patterns[j // len(file_systems)])
        bar.set_edgecolor('white')
    #ax.set_ylabel(opn)
    ax.set_title(opn)
    ax.set_xlabel('Throughput (kOp/s)')
    ax.set_xlim(0, ylimits[op])
    ax.set_ylim(-0.3, 2.0)
    if op == 'readrandom' or op == 'readwhilewriting':
        ax.bar_label(ax.containers[5], fmt=lambda x: '%.0f' % x if x != 0 else '', fontsize=20)
    ax.xaxis.set_minor_locator(matplotlib.ticker.AutoMinorLocator())
axes[0][0].legend(handlelength=1.0, handletextpad=0.3, labelspacing=0.3, borderpad=0.2, reverse=True)
plt.savefig('fig-rocksdb.pdf')
plt.savefig('fig-rocksdb.png')
