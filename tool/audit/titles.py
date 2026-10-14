import os,re,glob,sys
_HERE = os.path.dirname(os.path.abspath(__file__))
DA = os.path.dirname(os.path.dirname(_HERE))  # this repo
UP = os.environ.get('SRT_UPSTREAM') or os.path.join(os.path.dirname(DA), 'sandbox-runtime')
hdr=re.compile(r'Ported from sandbox-runtime\s+(\S+\.(?:ts|mjs))\s+@')
def lit(t,i):
    # parse a JS/Dart string literal starting at i (after spaces); handles '..' ".." `..` and concatenation with +
    parts=[];
    while True:
        while i<len(t) and t[i] in ' \t\n\r': i+=1
        if i>=len(t) or t[i] not in '\'"`':
            break
        q=t[i]; raw=False
        j=i+1; s=''
        while j<len(t) and t[j]!=q:
            if t[j]=='\\': s+=t[j:j+2]; j+=2; continue
            s+=t[j]; j+=1
        parts.append(s); i=j+1
        k=i
        while k<len(t) and t[k] in ' \t\n\r': k+=1
        if k<len(t) and t[k]=='+': i=k+1; continue
        # dart adjacent strings
        if k<len(t) and t[k] in '\'"' : i=k; continue
        break
    return ''.join(parts) if parts else None
def titles(t,kinds):
    out=[]
    for m in re.finditer(r'(?<![\w.$])(%s)(?:\.(?:skip|skipIf|if|only|todo|each|concurrent|serial)(?:\([^()]*(?:\([^()]*\)[^()]*)*\))?)*\s*\(' % '|'.join(kinds), t):
        s=lit(t,m.end())
        if s is not None: out.append(s)
    return out
def normt(s):
    s=s.replace("\\'","'").replace('\\"','"').replace('\\`','`').replace('\\$','$')
    s=re.sub(r'\$\{[^}]*\}|\$\w+','<v>',s)
    # test.each placeholders in the upstream title
    s=re.sub(r'%[sjdifpo#%]','<v>',s)
    return s
res=[]
for f in sorted(glob.glob(DA+'/test/**/*_test.dart',recursive=True)):
    t=open(f).read(); m=hdr.search('\n'.join(t.split('\n')[:5]))
    if not m: res.append((os.path.relpath(f,DA),'NOHEADER',[],[])); continue
    up=open(os.path.join(UP,m.group(1))).read()
    a=[normt(x) for x in titles(up,['describe','it','test'])]
    b=[normt(x) for x in titles(t,['group','test'])]
    res.append((os.path.relpath(f,DA),m.group(1),a,b))
for rel,src,a,b in res:
    if src=='NOHEADER': print(f'{rel}: NOHEADER'); continue
    ok = a==b
    print(f"{rel}: up {len(a)} dart {len(b)} {'OK' if ok else 'DIFF'}")
    if not ok and (len(sys.argv)>1 and sys.argv[1] in rel or len(sys.argv)>1 and sys.argv[1]=='all'):
        import difflib
        for l in difflib.unified_diff(a,b,lineterm='',n=0): print('   ',l)
