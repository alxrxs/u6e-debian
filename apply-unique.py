#!/usr/bin/env python3
"""Apply a patch whose context drifted, without fuzz's misplacement risk.

Each hunk is placed by text, not line number: the old side must occur exactly
once in the file, or, with its full context, several times, where the copy
nearest the hunk's expected line wins (patch -F0's rule; a tie fails). When it
does not occur at all, context lines are trimmed
from both ends, one at a time, keeping at least one; the hunk applies at the
first level where the trimmed old side is unique, and fails the moment a
level matches twice. Hunks that fail are printed for a hand port; the rest
are written. Exit status 1 if any hunk failed.
Usage (in the tree): apply-unique.py [--check] <patch>  (--check writes nothing)
"""
import re
import sys


def parse(text):
    files, cur, hunk = [], None, None
    for line in text.splitlines(keepends=True):
        if line.startswith('--- '):
            cur = {'old': line[4:].split('\t')[0].strip(), 'hunks': []}
            files.append(cur)
            hunk = None
        elif line.startswith('+++ ') and cur is not None and not cur.get('new'):
            cur['new'] = line[4:].split('\t')[0].strip()
        elif line.startswith('@@') and cur is not None:
            hunk = {'head': line.rstrip('\n'), 'lines': []}
            cur['hunks'].append(hunk)
        elif hunk is not None and line[:1] in (' ', '-', '+') :
            hunk['lines'].append(line)
        elif hunk is not None and line.startswith('\\'):
            continue
        else:
            hunk = None
    return files


def place(content, hunk, expect):
    lines = hunk['lines']
    changed = [i for i, l in enumerate(lines) if l[0] != ' ']
    lead, trail = changed[0], len(lines) - 1 - changed[-1]
    for k in range(max(lead, trail) + 1):
        a = min(k, lead)
        b = min(k, trail)
        if lead + trail and (lead - a) + (trail - b) == 0:
            break  # keep at least one context line
        body = lines[a:len(lines) - b]
        old = ''.join(l[1:] for l in body if l[0] in ' -')
        new = ''.join(l[1:] for l in body if l[0] in ' +')
        n = content.count(old) if old else 0
        if n == 1:
            return content.replace(old, new, 1), ('exact' if k == 0 else f'trimmed {k}')
        if n > 1 and k == 0:
            starts = [m.start() for m in re.finditer(re.escape(old), content)]
            dist = sorted((abs(content.count('\n', 0, i) + 1 - expect), i) for i in starts)
            if dist[0][0] == dist[1][0]:
                return None, 'ambiguous (tie)'
            i = dist[0][1]
            return content[:i] + new + content[i + len(old):], 'nearest'
        if n > 1:
            return None, f'ambiguous at trim {k}'
    return None, 'no match'


def main():
    check = sys.argv[1] == '--check'
    files = parse(open(sys.argv[-1]).read())
    failed = False
    for f in files:
        path = re.sub(r'^[ab]/', '', f['new'] if f['old'] == '/dev/null' else f['old'])
        if f['old'] == '/dev/null':
            content = ''
        else:
            content = open(path).read()
        delta = 0
        for h in f['hunks']:
            if f['old'] == '/dev/null':
                content += ''.join(l[1:] for l in h['lines'] if l[0] == '+')
                print(f'new    {path}')
                continue
            m = re.match(r'@@ -(\d+)', h['head'])
            res, how = place(content, h, int(m.group(1)) + delta)
            if res is None:
                failed = True
                print(f'FAILED {path} {h["head"]} ({how})')
                sys.stdout.write(''.join(h['lines']))
            else:
                delta += res.count('\n') - content.count('\n')
                content = res
                print(f'{how:7.7} {path} {h["head"]}')
        if not check:
            open(path, 'w').write(content)
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()
