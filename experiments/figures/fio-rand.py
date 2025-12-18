import pandas as pd
import matplotlib
import matplotlib.pyplot as plt
import sys
import json
from statistics import mean, median, stdev
import numpy as np

plt.rcParams.update({'font.size': 20, 'font.family': 'Times New Roman'})
fig, axes = plt.subplots(3, 2, figsize=(8,12), constrained_layout=True)

fig.get_layout_engine().set(hspace=0.1)

def parse_throughput(x):
    if 'MiB/s' in x:
        return float(x.split('MiB/s')[0]) * 1024 / 4 / 1000
    elif 'KiB/s' in x:
        return float(x.split('KiB/s')[0]) / 4 / 1000
    return None

def load_datapoint(n, f, s, op, th):
    lines = open('../results/fio-rand/%d-%s-%s-%s-%s.txt' % (n, f, s, op, th)).readlines()
    for line in lines:
        if 'bw=' in line:
            x = line.split('bw=')[1].split()[0]
            return parse_throughput(x)
    return None

name = 'kSFS'

file_systems = [('ntfs', 'NTFS'), ('exfat', 'exFAT'), ('ext4', 'ext4')]
operations = [('randread', 'Random Read'), ('randwrite', 'Random Write')]
systems = [('bento', 'Bento'), ('native', 'Linux'), ('fuse', 'FUSE'), ('fuse-opt', 'FUSE-zc'), ('ksfs', name)]
threads = {
    'randread': [1,2,4,6,8,12,16,24,32,40,48,56,64,72,80,88,96,104,112,120,128],
    'randwrite': [1,2,4,6,8,10,12,14,16],
}

def get_systems(fs, s):
    if fs == 'ext4':
        return [s[1]]
    elif fs == 'exfat':
        return s
    else:
        return s[1:]

colors = ["#0b522e", "#35618f", "#5ac4f8", "#6c218e", "#63ef85"]
markers = ['v', 'D', 'x', 'o', '.']

ylimits = {
    'randread': 1200,
    'randwrite': 1200
}

def load_data(f, op):
    data = {}
    err = {}
    for s, n in get_systems(f, systems):
        y = []
        er = []
        for th in threads[op]:
            x = []
            for i in range(1, 11):
                d = load_datapoint(i, f, s, op, th)
                x.append(d)
            m = median(x)
            st = stdev(x)
            y.append(m)
            er.append(st)
        data[s] = y
        err[s] = er
    return data, err

ticks = {
    'randread': [1,32,64,96,128],
    'randwrite': [1,4,8,12,16]
}

for i, (op, opn) in enumerate(operations):
    for j, (fs, fsn) in enumerate(file_systems):
        ax = axes[j][i]
        data, err = load_data(fs, op)
        systems_ = list(zip(systems, markers, colors))
        for (s, sn), m, c in get_systems(fs, systems_):
            d = pd.DataFrame({
                sn: data[s]
            }, index = threads[op])
            e = pd.DataFrame({
                sn: err[s]
            }, index = threads[op])
            print(opn, fs, sn)
            print(d)
            d.plot(kind='line', rot=0, legend=False, color=c, marker=m, ax=ax, yerr=e)
        ax.set_xlabel('Number of Threads')
        ax.set_title('%s %s' % (fsn, opn))
        ax.set_ylabel('Throughput (kIOPS)')
        ax.set_xticks(ticks[op])
        ax.set_ylim(0, ylimits[op])
axes[1][0].legend(handlelength=1.0, handletextpad=0.2, labelspacing=0.2, borderpad=0.1, columnspacing=0.5, reverse=True, prop={'size': 17})
plt.savefig('fig-fio-rand.pdf')
plt.savefig('fig-fio-rand.png')
