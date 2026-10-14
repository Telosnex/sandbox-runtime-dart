"""Rough TypeScript (bun:test) -> Dart (package:test) translator for test files.

Usage: python3 tool/audit/ts2dart.py <upstream .test.ts> > draft.dart

Handles object-literal keys, expect(...) matchers, test.each / test.if,
for...of, const/let, semicolons. The output is a draft: it still needs the
Dart header, imports, typed local functions and hand fixes; then run
dart analyze, comments.py and titles.py on it. Used for config-validation.
"""
import re, sys
src=open(sys.argv[1]).read()

# ---------- tokenizer-aware helpers ----------
def scan_string(t,i):
    q=t[i]; j=i+1
    while j<len(t):
        if t[j]=='\\': j+=2; continue
        if q=='`' and t.startswith('${',j):
            d=1; j+=2
            while d:
                if t[j] in '\'"`': j=scan_string(t,j); continue
                if t[j]=='{': d+=1
                elif t[j]=='}': d-=1
                j+=1
            continue
        if t[j]==q: return j+1
        j+=1
    raise Exception('unterminated')

def match_close(t,i):
    """t[i] is ( [ {; return index after its match"""
    pairs={'(':')','[':']','{':'}'}
    stack=[pairs[t[i]]]; j=i+1
    while stack:
        c=t[j]
        if c in '\'"`': j=scan_string(t,j); continue
        if t.startswith('//',j): j=t.index('\n',j); continue
        if t.startswith('/*',j): j=t.index('*/',j)+2; continue
        if c in pairs: stack.append(pairs[c])
        elif c in ')]}':
            assert c==stack[-1], (t[i:j+1][-200:])
            stack.pop()
        j+=1
    return j

# ---------- expect(x).matcher(y) ----------
MATCH={'toBe':'{a}','toEqual':'{a}','toContain':'contains({a})','toBeDefined':'isNotNull',
       'toBeUndefined':'isNull','toHaveLength':'hasLength({a})','toBeNull':'isNull',
       'toMatch':'matches({a})','toBeGreaterThan':'greaterThan({a})','toThrow':'throwsA(anything)',
       'toBeTruthy':'isTrue','toBeFalsy':'isFalse'}
def conv_expect(t):
    out=[]; i=0
    while True:
        k=t.find('expect(',i)
        if k<0: out.append(t[i:]); break
        if k>0 and (t[k-1].isalnum() or t[k-1]=='_'):
            out.append(t[i:k+7]); i=k+7; continue
        out.append(t[i:k])
        e=match_close(t,k+6)
        arg=conv_expect(t[k+7:e-1]).rstrip()
        if arg.endswith(','): arg=arg[:-1]
        m=re.match(r'\s*\.(not\.)?(\w+)\(',t[e:])
        if not m: out.append('expect('+arg+')'); i=e; continue
        neg,name=m.group(1),m.group(2)
        p=e+m.end()-1; q=match_close(t,p)
        a=conv_expect(t[p+1:q-1]).strip()
        if a.endswith(','): a=a[:-1]
        if name=='toBe' and a in('true','false'): mt='isTrue' if a=='true' else 'isFalse'
        elif name=='toBe' and a=='undefined': mt='isNull'
        else: mt=MATCH[name].format(a=a)
        if neg: mt=f'isNot({mt})'
        out.append(f'expect({arg.strip()}, {mt})'); i=q
    return ''.join(out)

# ---------- object keys -> quoted ----------
def quote_keys(t):
    out=[]; i=0; stack=[]
    while i<len(t):
        c=t[i]
        if c in '\'"`':
            j=scan_string(t,i); s=t[i:j]
            if c=='`':
                s="'"+s[1:-1].replace("'","\\'")+"'" if '\n' not in s else "'''"+s[1:-1]+"'''"
            out.append(s); i=j; continue
        if t.startswith('//',i):
            j=t.find('\n',i); out.append(t[i:j]); i=j; continue
        if t.startswith('/*',i):
            j=t.index('*/',i)+2; out.append(t[i:j]); i=j; continue
        if c in '([{':
            # object literal if '{' preceded by = : ( , [ return or start of value
            prev=''.join(out).rstrip()[-1:] if out else ''
            kind = c
            if c=='{':
                kind='obj' if prev in ('=',':','(',',','[','?','') or ''.join(out).rstrip().endswith('return') else 'block'
            stack.append(kind); out.append(c); i+=1; continue
        if c in ')]}':
            stack.pop(); out.append(c); i+=1; continue
        if stack and stack[-1]=='obj':
            m=re.match(r'([A-Za-z_$][\w$]*)(\s*):',t[i:])
            before=''.join(out).rstrip()[-1:]
            if m and before in ('{',','):
                out.append(f"'{m.group(1)}'{m.group(2)}:"); i+=m.end(); continue
            m=re.match(r'([A-Za-z_$][\w$]*)(\s*)(?=[,}\n])',t[i:])
            if m and before in ('{',',') and m.group(1) not in('true','false','null','undefined'):
                # shorthand {foo} -> {'foo': foo}
                out.append(f"'{m.group(1)}': {m.group(1)}{m.group(2)}"); i+=m.end(); continue
        out.append(c); i+=1
    return ''.join(out)

t=src
def conv_find(t):
    out=[]; i=0
    while True:
        k=t.find('.find(',i)
        if k<0: out.append(t[i:]); break
        e=match_close(t,k+5)
        out.append(t[i:k]+'.where('+conv_find(t[k+6:e-1])+').firstOrNull'); i=e
    return ''.join(out)
t=conv_find(t)
t=conv_expect(t)
t=re.sub(r"(?<=[(,\s])([A-Za-z_]\w*) =>", r"(\1) =>", t)
t=t.replace('?.[','?[')
t=re.sub(r"\bbase\.(\w+)", r"base['\1']!", t)
t=quote_keys(t)
# arrow functions / declarations
t=re.sub(r"\bdescribe\((.*?), \(\) => \{", r"group(\1, () {", t)
t=re.sub(r"\btest\(", "test(", t)
t=re.sub(r"\(\) => \{", "() {", t)
t=re.sub(r"\bconst (\w+)\s*=", r"final \1 =", t)
t=re.sub(r"\blet (\w+)\s*=", r"var \1 =", t)
t=re.sub(r"\bundefined\b", "null", t)
t=re.sub(r" as const\b", "", t)
t=re.sub(r"===", "==", t); t=re.sub(r"!==", "!=", t)
t=re.sub(r"\.slice\(", ".sublist(", t)
t=re.sub(r"\(i\) => ", "(i) => ", t)
# statement terminators: lines ending in ) ] } or identifier without ; , { ( [ need ';' -- do per-line heuristics
t=re.sub(r"for \(const (\w+) of ", r"for (final \1 in ", t)
def split_comment(l):
    # returns (code, comment) honoring strings
    i=0
    while i<len(l):
        c=l[i]
        if c in '\'"':
            try: i=scan_string(l,i); continue
            except Exception: return l,''
        if l.startswith('//',i): return l[:i].rstrip(), ' '+l[i:]
        i+=1
    return l,''
lines=t.split('\n'); out=[]
for idx,l in enumerate(lines):
    s0=l.rstrip()
    s,cm=split_comment(s0)
    if not s.strip(): out.append(s0); continue
    nxt=next((split_comment(x)[0].strip() for x in lines[idx+1:] if split_comment(x)[0].strip()),'')
    code=s.strip()
    if code and not code.startswith('//') and not code.startswith('*') and not code.startswith('/*') \
       and not s.endswith((';',',','{','(','[','=','?',':','&&','||','+')) \
       and not nxt.startswith(('.', '?', ':', '&&','||','+',')',']',',')) \
       and not re.match(r'^(if|else|for|while)\b',code) and not code.endswith('=>'):
        s+=';'
    out.append(s+(cm if cm else ''))
t='\n'.join(out)
# '};' that closes a block (if/for/else/function/arrow body), not an object
def fix_block_semis(t):
    res=list(t)
    for m in re.finditer(r'\}\);?|\};', t):
        pass
    out=[]; stack=[]; i=0
    while i<len(t):
        c=t[i]
        if c in '\'"':
            try: j=scan_string(t,i)
            except Exception: j=i+1
            out.append(t[i:j]); i=j; continue
        if t.startswith('//',i):
            j=t.find('\n',i); j=len(t) if j<0 else j; out.append(t[i:j]); i=j; continue
        if c=='{':
            before=''.join(out[-40:]).rstrip()
            stack.append('block' if before.endswith((')','else','=>')) and not before.endswith('=>') or before.endswith(('else',)) or re.search(r'\)\s*$',before) else 'obj')
        if c=='}':
            kind=stack.pop() if stack else 'obj'
            if kind=='block' and t.startswith('};',i) and (i+2>=len(t) or t[i+2]=='\n'):
                out.append('}'); i+=2; continue
        out.append(c); i+=1
    return ''.join(out)
t=fix_block_semis(t)

def split_args(a):
    """split top-level comma-separated args"""
    parts=[]; depth=0; cur=''; i=0
    while i<len(a):
        c=a[i]
        if c in '\'"`':
            j=scan_string(a,i); cur+=a[i:j]; i=j; continue
        if a.startswith('//',i):
            j=a.find('\n',i); j=len(a) if j<0 else j; cur+=a[i:j]; i=j; continue
        if c in '([{': depth+=1
        if c in ')]}': depth-=1
        if c==',' and depth==0: parts.append(cur); cur=''; i+=1; continue
        cur+=c; i+=1
    if cur.strip(): parts.append(cur)
    return parts

def conv_each_if(t):
    out=[]; i=0
    while True:
        m=re.search(r'\btest\.(each|if)\(',t[i:])
        if not m: out.append(t[i:]); break
        k=i+m.start(); out.append(t[i:k])
        p1=k+len('test.'+m.group(1)); e1=match_close(t,p1)
        first=t[p1+1:e1-1]
        assert t[e1]=='(', t[e1:e1+30]
        e2=match_close(t,e1)
        args=split_args(t[e1+1:e2-1])
        title=args[0].strip(); fn=args[1].strip(); extra=[a.strip() for a in args[2:]]
        ind=re.search(r'[^\n]*$',''.join(out)).group(0)
        if m.group(1)=='if':
            cond=first.strip()
            res=f"test(\n{ind}  {title},\n{ind}  {fn.strip()},\n{ind}  skip: ({cond}) ? false : 'requires {cond.replace(chr(39),'')}',\n{ind})"
        else:
            fm=re.match(r"\(([\w, ]+)\)\s*=>\s*(.*)$",fn,re.S)
            params=[x.strip() for x in fm.group(1).split(',')]
            body=fm.group(2).strip()
            rows=first.strip()
            var=params[0]
            pat=var
            if len(params)>1 or re.match(r'\[\s*\[',rows): pat='['+', '+join(params)+']' if False else '['+', '.join(params)+']'
            dt=title
            for v in params:
                dt=dt.replace('%s','$'+v,1).replace('%j','${jsonEncode('+v+')}',1)
            if body.startswith('{'):
                fnb='() '+body
            else:
                fnb='() => '+body
            res=f"for (final {pat} in {rows}) {{\n{ind}  test(\n{ind}    {dt},\n{ind}    {fnb},\n{ind}  );\n{ind}}}"
        out.append(conv_each_if(res)); i=e2
        if t.startswith(';',i): i+=1
    return ''.join(out)
t=conv_each_if(t)
t=t.replace('});;','});')
sys.stdout.write(t)
