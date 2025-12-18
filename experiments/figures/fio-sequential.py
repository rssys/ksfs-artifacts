import sys
import json
from statistics import mean, median, stdev

def parse_throughput(x):
    if 'MiB/s' in x:
        return float(x.split('MiB/s')[0])
    elif 'KiB/s' in x:
        return float(x.split('KiB/s')[0]) / 1024
    return None

def load_datapoint(n, f, s, op, bs):
    lines = open('../results/fio-sequential/%d-%s-%s-%s-%s.txt' % (n, f, s, op, bs)).readlines()
    for line in lines:
        if 'bw=' in line:
            x = line.split('bw=')[1].split()[0]
            return parse_throughput(x)
    return None

name = 'kSFS'

file_systems = ['ntfs', 'exfat', 'ext4']
operations = ['read', 'write']
systems = ['ksfs', 'fuse', 'fuse-opt', 'bento', 'native']
bs = '4096'

def get_systems(fs):
    if fs == 'ext4':
        return systems[-1:]
    elif fs == 'exfat':
        return systems
    else:
        return systems[:-2] + systems[-1:]

def load_data(f, op):
    data = {}
    err = {}
    for s in get_systems(f):
        x = []
        for i in range(1, 11):
            d = load_datapoint(i, f, s, op, bs)
            x.append(d)
        m = median(x)
        st = stdev(x)
        data[s] = m
        err[s] = st
    return data, err

template = r"""
\begin{table}[]
\caption{Sequential read/write throughput.}
\begin{center}
\begin{tabular}{ccrr}
\hline
                       &          & \multicolumn{1}{c}{\textbf{Read (MiB/s)}} & \multicolumn{1}{c}{\textbf{Write (MiB/s)}} \\ \hline
\multirow{3}{*}{NTFS}  & \sysname & $%s$                              & $%s$                               \\
                       & FUSE     & $%s$                              & $%s$                                \\
                       & FUSE-zc     & $%s$                              & $%s$                                \\
                       & Linux   & $%s$                              & $%s$                                \\ \hline
\multirow{3}{*}{exFAT} & \sysname & $%s$                              & $%s$                               \\
                       & FUSE     & $%s$                              & $%s$                               \\
                       & FUSE-zc     & $%s$                              & $%s$                               \\
                       & Bento     & $%s$                              & $%s$                               \\
                       & Linux   & $%s$                              & $%s$                               \\ \hline
ext4 & Linux   & $%s$                              & $%s$                               \\ \hline

\end{tabular}
\end{center}
\label{tab:fio}
\end{table}
"""

def format_datapoint(throughput, err):
    return '%d\\pm%02d' % (throughput, err)

data = {}
texts = []

for op in operations:
    data_op = {}
    for fs in file_systems:
        d, e = load_data(fs, op)
        data_op[fs] = {k : (d[k], e[k]) for k in d.keys()}
    data[op] = data_op

for fs in file_systems:
    systems_ = get_systems(fs)
    for s in systems_:
        for op in operations:
            d, e = data[op][fs][s]
            texts.append(format_datapoint(d, e))
print(template % tuple(texts))
