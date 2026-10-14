import os, re, sys, glob
_HERE = os.path.dirname(os.path.abspath(__file__))
DA = os.path.dirname(os.path.dirname(_HERE))  # this repo
UP = os.environ.get('SRT_UPSTREAM') or os.path.join(os.path.dirname(DA), 'sandbox-runtime')
hdr=re.compile(r'(?:Ported from sandbox-runtime|STUB: pending port of|PARTIAL:.*?of(?: the rest of)?)\s+(\S+\.(?:ts|mjs))\s+@')
def ts_comments(t):
    out=[]; i=0; n=len(t); st=None
    # simple lexer: skip strings/template/regex roughly
    while i<n:
        c=t[i]
        if t.startswith('//',i):
            j=t.find('\n',i); j=n if j<0 else j
            out.append(t[i+2:j]); i=j; continue
        if t.startswith('/*',i):
            j=t.find('*/',i+2); j=n if j<0 else j
            out.extend(t[i+2:j].split('\n')); i=j+2; continue
        if c in '\'"`':
            q=c; i+=1
            while i<n and t[i]!=q:
                if t[i]=='\\': i+=1
                i+=1
            i+=1; continue
        i+=1
    return out
def norm(s):
    s=s.strip()
    s=re.sub(r'\{@link\s+([^}\s]+)\s*\}',r'[\1]',s)
    s=s.replace('**\\/','**/').replace('*\\/','*/')
    s=s.replace('`','')
    s=re.sub(r'\[([A-Za-z0-9_.]+)\]',r'\1',s)
    s=re.sub(r'^[/*!\s]+','',s)
    s=re.sub(r'\s+',' ',s).strip()
    return s
def dart_text(t):
    # all comment text in dart, joined, normalized
    lines=[]
    for line in t.split('\n'):
        m=re.search(r'//+(.*)$',line)
        if m: lines.append(m.group(1))
        lines.append(line)  # also allow strings/body occurrences
    return re.sub(r'\s+',' ',' '.join(norm(l) for l in lines))
total={}
for f in sorted(glob.glob(DA+'/lib/src/**/*.dart',recursive=True)+glob.glob(DA+'/test/**/*.dart',recursive=True)+glob.glob(DA+'/tool/*.dart')):
    t=open(f).read(); m=hdr.search('\n'.join(t.split('\n')[:6]))
    if not m: continue
    up=os.path.join(UP,m.group(1))
    if not os.path.exists(up): continue
    uc=[norm(x) for x in ts_comments(open(up).read())]
    uc=[x for x in uc if len(x)>=12 and not x.startswith('eslint') and not x.startswith('@ts-') and not x.startswith('biome-ignore')]
    dt=dart_text(t)
    miss=[x for x in uc if x not in dt]
    rel=os.path.relpath(f,DA)
    total[rel]=(len(uc),miss)
if __name__=='__main__':
  for rel,(n,miss) in total.items():
    flag='' if not miss else f'  MISSING {len(miss)}'
    print(f'{rel}: {n-len(miss)}/{n}{flag}')
if __name__=='__main__' and len(sys.argv)>1:
    for rel,(n,miss) in total.items():
        if sys.argv[1] in rel:
            print('\n'.join('  - '+m for m in miss))
