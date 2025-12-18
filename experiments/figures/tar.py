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
    lines = open('../results/tar/%d-%s-%s-%s.txt' % (n, f, s, op)).readlines()
    for line in lines:
        if 'real' in line:
            x = line.split('real')[1].split()[0]
            m, s = x.split('m')
            return float(m) * 60 + float(s.split('s')[0])
    return None

name = 'kSFS'

file_systems = [('ntfs', 'NTFS'), ('exfat', 'exFAT'), ('ext4', 'ext4')]
operations = [('untar', 'Extracting Tarball'), ('copy', 'Copying Files'), ('tar', 'Creating Tarball')]
systems = [('bento', 'Bento'), ('native', 'Linux'), ('fuse', 'FUSE'), ('fuse-opt', 'FUSE-zc'), ('ksfs', name)]
ylimits = {
    'untar': 80,
    'copy': 80,
    'tar': 80,
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
    print(op)
    print(data)
    data.plot(kind='barh', legend=False, width=0.8, color=colors, xerr=err, ax=ax)
    for j, bar in enumerate(ax.patches):
        bar.set_hatch(patterns[j // len(file_systems)])
        bar.set_edgecolor('white')
    ax.set_title(opn)
    ax.set_xlabel('Time (s)')
    ax.set_xlim(0, ylimits[op])
    ax.set_ylim(-0.3, 2.0)
    ax.xaxis.set_minor_locator(matplotlib.ticker.AutoMinorLocator())

axes[2].legend(handlelength=1.0, handletextpad=0.3, labelspacing=0.3, borderpad=0.1, reverse=True, prop={'size': 16})
plt.savefig('fig-tar.pdf')
plt.savefig('fig-tar.png')
