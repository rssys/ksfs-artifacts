def load_data(s, fs):
    lines = open('../results/pjdfstest/%s-%s.txt' % (fs, s)).readlines()
    total_num_failed = 0
    for line in lines:
        if 'Failed: ' in line:
            num_failed = int(line.split('Failed: ')[1].split(')')[0])
            total_num_failed += num_failed
        elif 'Tests=' in line:
            num_tests = int(line.split('Tests=')[1].split(',')[0])
    return num_tests, total_num_failed

name = 'kSFS'
file_systems = [('ntfs', 'NTFS'), ('exfat', 'exFAT')]
systems = [('native', 'Linux'), ('fuse', 'FUSE'), ('ksfs', name)]

for s, sn in systems:
    for fs, fsn in file_systems:
        print(sn, fsn)
        print(load_data(s, fs))
