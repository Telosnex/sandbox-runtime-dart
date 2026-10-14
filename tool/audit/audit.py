import os, re, sys, glob
_HERE = os.path.dirname(os.path.abspath(__file__))
DA = os.path.dirname(os.path.dirname(_HERE))  # this repo
UP = os.environ.get('SRT_UPSTREAM') or os.path.join(os.path.dirname(DA), 'sandbox-runtime')
hdr = re.compile(r'^// (Ported from|STUB: pending port of|PARTIAL: ported .*?pending port of the rest of) sandbox-runtime (\S+?)\.? @ (\w+)')
hdr2 = re.compile(r'(Ported from sandbox-runtime|STUB: pending port of|PARTIAL:.*?of(?: the rest of)?)\s+(\S+\.(?:ts|mjs))\s+@\s+(\w+)')
def comment_lines_ts(t):
    n=0; inblk=False
    for line in t.splitlines():
        s=line.strip()
        if inblk:
            n+=1
            if '*/' in s: inblk=False
            continue
        if s.startswith('/*'):
            n+=1
            if '*/' not in s[2:]: inblk=True
        elif s.startswith('//'): n+=1
        elif re.search(r'[^:]//\s', s) and not s.startswith("'") : n+=1  # trailing
    return n
def comment_lines_dart(t):
    n=0; inblk=False
    for line in t.splitlines():
        s=line.strip()
        if inblk:
            n+=1
            if '*/' in s: inblk=False
            continue
        if s.startswith('/*'):
            n+=1
            if '*/' not in s[2:]: inblk=True
        elif s.startswith('//') and not s.startswith('// ignore') and not s.startswith('// Ported') and not s.startswith('// STUB') and not s.startswith('// PARTIAL'): n+=1
        elif re.search(r'[^:]//\s', s): n+=1
    return n
rows=[]
for f in sorted(glob.glob(DA+'/lib/src/**/*.dart', recursive=True)+glob.glob(DA+'/test/**/*.dart', recursive=True)+glob.glob(DA+'/tool/*.dart')):
    rel=os.path.relpath(f,DA)
    t=open(f).read()
    first='\n'.join(t.splitlines()[:3])
    m=hdr2.search(first)
    if not m:
        rows.append((rel,'NOHEADER','','','')); continue
    kind=m.group(1).split()[0]; src=m.group(2); commit=m.group(3)
    upf=os.path.join(UP,src)
    if not os.path.exists(upf):
        rows.append((rel,kind,src,'MISSING-UPSTREAM',commit)); continue
    ut=open(upf).read()
    # name mapping
    exp=os.path.splitext(os.path.basename(src))[0].replace('-','_').replace('.test','_test')
    if src.endswith('.mjs'): exp=exp+'_test' if not exp.endswith('_test') else exp
    namech = 'ok' if os.path.splitext(os.path.basename(f))[0]==exp else 'NAME:'+exp
    rows.append((rel,kind,src,f'cm {comment_lines_ts(ut)}->{comment_lines_dart(t)}',commit+' '+namech))
for r in rows: print(' | '.join(r))
