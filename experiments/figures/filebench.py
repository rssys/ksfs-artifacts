import pandas as pd
import matplotlib
import matplotlib.pyplot as plt
import sys
import json
from statistics import mean, median, stdev
import numpy as np
from collections import OrderedDict

plt.rcParams.update({'font.size': 20, 'font.family': 'Times New Roman'})
fig, axes = plt.subplots(3, 1, figsize=(4,10), constrained_layout=True)

fig.get_layout_engine().set(hspace=0.1)

def load_datapoint(n, f, s, op):
    lines = open('../results/filebench/%d-%s-%s-%s.txt' % (n, f, s, op)).readlines()
    for line in lines:
        if 'IO Summary' in line:
            x = line.split('ops')[1].split()[0]
            return float(x) / 1000
    return None


name = 'kSFS'

file_systems = [('ntfs', 'NTFS'), ('exfat', 'exFAT'), ('ext4', 'ext4')]
operations = [('webserver', 'Webserver'), ('varmail', 'Varmail'), ('fileserver', 'Fileserver')]
systems = [('bento', 'Bento'), ('native', 'Linux'), ('fuse', 'FUSE'), ('fuse-opt', 'FUSE-zc'), ('ksfs', name)]
ylimits = {
    'webserver': 1250,
    'varmail': 10,
    'fileserver': 320
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
                d = load_datapoint(i, f, s, op)
                if d is None:
                    print(i, f, s, op)
                    continue
                x.append(d)
            m = median(x)
            st = stdev(x)
            y.append(m)
            er.append(st)
        data[n] = y
        err[n] = er
    return pd.DataFrame(data, index=file_systems_index), pd.DataFrame(err, index=file_systems_index)

for i, (op, opn) in enumerate(operations):
    ax = axes[i]
    data, err = load_data(op)
    data.plot(kind='barh', legend=False, width=0.8, color=colors, xerr=err, ax=ax)
    for j, bar in enumerate(ax.patches):
        bar.set_hatch(patterns[j // len(file_systems)])
        bar.set_edgecolor('white')
    print(opn)
    print(data)
    if op == 'fileserver':
        ax.text(250, 0, '%d' % data['Linux']['NTFS'])
        ax.text(250, 1.5, '%d' % data['Linux']['ext4'])
    ax.set_title(opn)
    ax.set_xlabel('Throughput (kOp/s)')
    ax.set_xlim(0, ylimits[op])
    ax.set_ylim(-0.3, 2.0)
    ax.xaxis.set_minor_locator(matplotlib.ticker.AutoMinorLocator())
axes[2].legend(handlelength=1.0, handletextpad=0.2, labelspacing=0.2, borderpad=0.1, ncols=2, columnspacing=0.3, reverse=True, prop={'size': 17})
plt.savefig('fig-filebench.pdf')
plt.savefig('fig-filebench.png')
