// ignore_for_file: constant_identifier_names, dangling_library_doc_comments
// ignore_for_file: non_constant_identifier_names, slash_for_doc_comments
// ignore_for_file: unintended_html_in_doc_comment

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import '../node/fetch.dart' as fetch;
import '../node/stream.dart' as stream;
import 'request_filter.dart';

const int DECIDER_PROTO = 1;
const int _MAX_READ_FRAME = 1 << 20;
const int _MAX_BODY = 32 << 20;
const int _MAX_BODY_BYTES_HELD = 2 * _MAX_BODY;
const int _QUEUED_REQUEST_FRAME_ROOM = 32 << 20;
int get MAX_QUEUED_BYTES => ((_MAX_BODY_BYTES_HELD * 4) / 3).ceil() + _QUEUED_REQUEST_FRAME_ROOM;
const int _MAX_HEADER_ENTRIES = 190;
const int _MAX_HEADER_BYTES = 64 << 10;
const int _MAX_HOST_PATH = 8 << 10;
const int _MAX_ID = 9007199254740991;
const int _ID_WINDOW = 4096;
const int _BASE64_SLICE = 3 << 16;

class DeciderHello {
  const DeciderHello({required this.t, required this.proto, required this.allowedDomains, required this.deniedDomains});
  final String t;
  final int proto;
  final List<String> allowedDomains;
  final List<String> deniedDomains;
}
sealed class CredentialPlacement {
  const CredentialPlacement({this.credentialClass, this.host});
  final String? credentialClass;
  final String? host;
}
class CredentialPlacementBearer extends CredentialPlacement {
  const CredentialPlacementBearer({super.credentialClass, super.host});
  final String scheme = 'bearer';
}
class CredentialPlacementBasic extends CredentialPlacement {
  const CredentialPlacementBasic({super.credentialClass, super.host, required this.user});
  final String scheme = 'basic';
  final String user;
}
class DeciderOptions {
  const DeciderOptions({required this.input, required this.output, this.timeoutMs, this.credentialPlacements, this.onDead, this.maxBodyBytesHeld, this.maxQueuedBytes});
  final stream.Readable input;
  final stream.Writable output;
  final int? timeoutMs;
  final List<CredentialPlacement>? credentialPlacements;
  final void Function(String why)? onDead;
  final int? maxBodyBytesHeld;
  final int? maxQueuedBytes;
}
abstract interface class Decider {
  Future<DeciderHello> get hello;
  FilterRequestCallback get filterRequest;
  void close();
  int bodyBytesHeld();
}

Uint8List encodeFrame(Map<String, Object?> msg) {
  final body = Uint8List.fromList(utf8.encode(jsonEncode(msg)));
  final out = Uint8List(body.length + 4);
  ByteData.sublistView(out).setUint32(0, body.length, Endian.big);
  out.setRange(4, out.length, body);
  return out;
}

Uint8List encodeBodyFrame(int id, Uint8List data, bool cut) {
  final head = latin1.encode('{"t":"body","id":$id,"data":"');
  final tail = latin1.encode(cut ? '","cut":true}' : '"}');
  final out = Uint8List(4 + head.length + ((data.length + 2) ~/ 3) * 4 + tail.length);
  ByteData.sublistView(out).setUint32(0, out.length - 4, Endian.big);
  var at = 4;
  out.setRange(at, at + head.length, head); at += head.length;
  for (var i = 0; i < data.length; i += _BASE64_SLICE) {
    final encoded = base64.encode(data.sublist(i, i + _BASE64_SLICE > data.length ? data.length : i + _BASE64_SLICE));
    final b = latin1.encode(encoded); out.setRange(at, at + b.length, b); at += b.length;
  }
  out.setRange(at, at + tail.length, tail);
  return out;
}

int _utf8(String s) => utf8.encode(s).length;
bool _control(String s) => s.codeUnits.any((c) => (c < 32 && c != 9) || (c >= 127 && c <= 159));
bool _wellFormed(String s) { try { utf8.encode(s); return !s.codeUnits.any((c) => c >= 0xd800 && c <= 0xdfff) || s.runes.length < s.length; } catch (_) { return false; } }
final RegExp _token = RegExp(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$");
bool _headersFit(Map<String,List<String>> headers) {
  var count=0, bytes=0;
  for (final e in headers.entries) { count += e.value.isEmpty ? 1 : e.value.length; bytes += _utf8(e.key); for(final v in e.value) { bytes += _utf8(v); } if(count>_MAX_HEADER_ENTRIES || bytes>_MAX_HEADER_BYTES) return false; }
  return true;
}
Object reqFrameFields(fetch.Request request, RequestInfo? info) {
  final uri = Uri.parse(request.url);
  final host = info?.target?.host ?? uri.host;
  final port = info?.target?.port ?? (uri.hasPort ? uri.port : uri.scheme == 'https' ? 443 : 80);
  final target = info?.requestTarget ?? '${uri.path.isEmpty ? '/' : uri.path}${uri.hasQuery ? '?${uri.query}' : ''}';
  final q=target.indexOf('?'); final path=q<0?target:target.substring(0,q); final query=q<0?'':target.substring(q+1);
  final raw=info?.rawHeaders ?? <String>[]; final headers=<String,List<String>>{}; String? hostHeader; var hosts=0;
  for(var i=0;i+1<raw.length;i+=2) { final name=raw[i].toLowerCase(), value=raw[i+1]; if(!_token.hasMatch(name)||_control(value)) return 'request header the decider cannot be asked about'; if(name=='host'){hosts++;hostHeader=value;} else { (headers[name]??=<String>[]).add(value); } }
  if(hosts>1) return 'more than one Host header'; if(!_headersFit(headers)) return 'request headers too large';
  if(request.method.isEmpty||host.isEmpty||path.isEmpty||port<1||port>65535) return 'request the decider cannot be asked about';
  for(final v in [host,hostHeader??'',info?.sni??'',path]) {if(_utf8(v)>_MAX_HOST_PATH)return 'request target too large';}
  final fields=<String,Object?>{'method':request.method,'host':host,'port':port,if(hostHeader!=null)'hostHeader':hostHeader,if((info?.sni??'').isNotEmpty)'sni':info!.sni,'path':path,if(query.isNotEmpty)'query':query,if(headers.isNotEmpty)'headers':headers};
  if(_utf8(jsonEncode({'t':'req','id':_MAX_ID,...fields}))>_MAX_READ_FRAME)return 'request too large for the decider';
  return fields;
}
bool isEgressEntry(String s) {
  if(s.isEmpty || s.contains(RegExp(r'[\s/@?#]'))) return false;
  if(_ip(s)!=0) return true;
  var host=s; String? port;
  if(s.startsWith('[')){final end=s.indexOf(']');if(end<0)return false;host=s.substring(1,end);final rest=s.substring(end+1);if(rest.isNotEmpty){if(!rest.startsWith(':'))return false;port=rest.substring(1);}return _ip(host)==6&&(port==null||_isPort(port));}
  final i=s.lastIndexOf(':'); if(i>=0){host=s.substring(0,i);port=s.substring(i+1);if(!_isPort(port))return false;}
  final ip=_ip(host); if(ip!=0)return ip==4;
  final wild=host.startsWith('*.'); final base=wild?host.substring(2):host; final labels=base.split('.'); if(base.isEmpty||base.length>253||(wild&&labels.length<2))return false;
  for(final l in labels){if(!RegExp(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$').hasMatch(l))return false;}
  return RegExp(r'^[a-z]').hasMatch(labels.last);
}
int _ip(String s){try { return InternetAddress.tryParse(s)?.type==InternetAddressType.IPv4?4: InternetAddress.tryParse(s)?.type==InternetAddressType.IPv6?6:0; }catch(_){return 0;}}
bool _isPort(String s)=>RegExp(r'^[1-9][0-9]{0,4}$').hasMatch(s)&&int.parse(s)<=65535;

class _Decider implements Decider {
  _Decider(this.opts) { _start(); }
  final DeciderOptions opts;
  final _hello = Completer<DeciderHello>();
  final Map<int, Completer<Map<String,Object?>>> _waiters={};
  final Map<int,String> _late={};
  final List<int> _buffer=[];
  bool _dead=false, _gotHello=false; int _lastId=0, _held=0, _queued=0;
  @override Future<DeciderHello> get hello=>_hello.future;
  @override FilterRequestCallback get filterRequest=>_filter;
  @override int bodyBytesHeld()=>_held;
  @override void close()=>_die('closed');
  void _die(String why){if(_dead)return;_dead=true;if(!_hello.isCompleted)_hello.completeError(StateError('decider unavailable: $why'));for(final c in _waiters.values){if(!c.isCompleted)c.completeError(StateError(why));}_waiters.clear();opts.onDead?.call(why);}
  void _start(){opts.input.on('data',(dynamic d){if(d is List<int>)_consume(d);});opts.input.on('end',(_)=>_die('decider closed the stream'));opts.input.on('error',(dynamic e)=>_die('read error: $e'));opts.output.on('error',(dynamic e)=>_die('write error: $e'));opts.output.on('close',(_)=>_die('decider closed the output stream'));_send({'t':'hello','proto':1});}
  void _send(Map<String,Object?> msg){if(_dead)return;final f=encodeFrame(msg);_queued+=f.length;opts.output.write(f,(){_queued-=f.length;});if(_queued>(opts.maxQueuedBytes??MAX_QUEUED_BYTES))_die('not reading: $_queued bytes queued');}
  void _consume(List<int> data){_buffer.addAll(data);while(!_dead&&_buffer.length>=4){final n=(_buffer[0]<<24)|(_buffer[1]<<16)|(_buffer[2]<<8)|_buffer[3];if(n>_MAX_READ_FRAME){_die('oversized frame');return;}if(_buffer.length<4+n)return;final bytes=_buffer.sublist(4,4+n);_buffer.removeRange(0,4+n);Map<String,Object?> m;try{final x=jsonDecode(utf8.decode(bytes,allowMalformed:false));if(x is! Map<String,dynamic>)throw const FormatException();m=x.cast<String,Object?>();}catch(_){_die('bad JSON frame');return;}if(!_gotHello){if(m['t']!='hello'||m['proto']!=1||m.keys.toSet().difference({'t','proto','allowedDomains','deniedDomains'}).isNotEmpty||m['allowedDomains'] is! List||m['deniedDomains'] is! List){_die('bad hello');return;}final a=(m['allowedDomains'] as List),d=(m['deniedDomains'] as List);if([...a,...d].any((e)=>e is! String||!isEgressEntry(e))){_die('bad hello');return;}_gotHello=true;_hello.complete(DeciderHello(t:'hello',proto:1,allowedDomains:a.cast<String>(),deniedDomains:d.cast<String>()));continue;}final id=m['id'];if(id is! int){_die('bad verdict frame');return;}final c=_waiters.remove(id);if(c!=null){c.complete(m);continue;}if(_late.containsKey(id)){if(m['action']=='need_body'&&_late[id]!='verdict'){_die('need_body where none may come');return;}if(m['action']!='need_body')_late.remove(id);continue;}if(id<_lastId&&_lastId-id>=_ID_WINDOW)continue;_die('verdict for id $id, which nothing waits on');}}
  Future<Map<String,Object?>> _await(int id,{bool timeout=true}){final c=Completer<Map<String,Object?>>();_waiters[id]=c;if(timeout)Timer(Duration(milliseconds:opts.timeoutMs??5000),(){if(_waiters.remove(id)==c&&!c.isCompleted){_late[id]='verdict';c.completeError(TimeoutException('decider timed out'));}});return c.future;}
  Future<RequestDecision> _filter(fetch.Request request,[RequestInfo? info]) async {
    if(_dead)return const RequestDecision(action:'deny',status:503,mark:'decider_unavailable',reason:'request decider unavailable');
    if(!_gotHello)return const RequestDecision(action:'deny',status:503,mark:'decider_unavailable',reason:'request decider not ready');
    final req=reqFrameFields(request,info); if(req is String)return RequestDecision(action:'deny',status:400,reason:req,mark:'bad_request');
    final id=_lastId+1; if(id>_MAX_ID){_die('request ids exhausted');return const RequestDecision(action:'deny',status:503,mark:'decider_unavailable');} _lastId=id;
    final host=(req as Map<String,Object?>)['host']! as String;
    var reserved=0;
    try {
      _send({'t':'req','id':id,...req}); var v=await _await(id);
      if(!_validVerdict(v,id)){_die('bad verdict frame');throw StateError('decider broke the protocol');}
      if(v['action']=='need_body') {
        final max=v['max'] as int;
        if(info?.unshownBody!=null && await info!.unshownBody!()) { _late[id]='verdict_shown'; return const RequestDecision(action:'deny',reason:'the decider asked to see the body of a request whose method normally has none, and it has one',mark:'bodyless_method_body'); }
        final cl=int.tryParse(request.headers.get('content-length')??''); final want=request.body==null?0:(cl!=null&&cl>=0?(cl<max?cl:max):max);
        final maxHeld=opts.maxBodyBytesHeld??_MAX_BODY_BYTES_HELD;
        if(_held+want>maxHeld){_late[id]='verdict_shown';throw StateError('too many request bodies held for inspection');}
        _held+=want; reserved=want;
        final reading=_readUpTo(request,max);
        final during=_await(id,timeout:false);
        final first=await Future.any<Object>([reading,during]);
        if(first is Map<String,Object?>){
          if(!_validVerdict(first,id)||first['action']!='deny'){_die('a verdict other than deny while the body was read');throw StateError('decider broke the protocol');}
          return RequestDecision(action:'deny',status:first['status'] as int,reason:first['reason'] as String?,mark:'decider');
        }
        final body=first as (Uint8List,bool);
        _sendBytes(encodeBodyFrame(id,body.$1,body.$2));
        v=await _await(id);
        if(!_validVerdict(v,id)||v['action']=='need_body'){_die(v['action']=='need_body'?'a second need_body':'bad verdict frame');throw StateError('decider broke the protocol');}
      }
      if(v['action']=='deny')return RequestDecision(action:'deny',status:v['status'] as int,reason:v['reason'] as String?,mark:'decider');
      final set=< (String,String)>[]; final h=v['setHeaders']; if(h is Map)for(final e in h.entries){for(final value in e.value as List)set.add((e.key as String,value as String));}
      final remove=<String>[]; if(v['removeHeaders'] is List)remove.addAll((v['removeHeaders'] as List).cast<String>());
      if(v['cred']!=null){remove.addAll(['authorization','proxy-authorization','cookie','x-api-key']);final cls=v['cred'] as String,val=v['credential'] as String; final rule=(opts.credentialPlacements??[]).where((p)=>(p.credentialClass==null||p.credentialClass==cls)&&(p.host==null||p.host==host)).firstOrNull; if(rule is CredentialPlacementBasic){set.add(('authorization','Basic ${base64.encode(utf8.encode('${rule.user}:$val'))}'));}else{set.add(('authorization','Bearer $val'));}}
      return RequestDecision(action:'allow',setHeaders:set,removeHeaders:remove);
    } catch(e){return RequestDecision(action:'deny',status:503,mark:'decider_unavailable',reason:'request decider: $e');} finally {_held-=reserved;}
  }
  void _sendBytes(Uint8List frame){if(_dead)return;_queued+=frame.length;opts.output.write(frame,(){_queued-=frame.length;});if(_queued>(opts.maxQueuedBytes??MAX_QUEUED_BYTES))_die('not reading: $_queued bytes queued');}
  bool _validVerdict(Map<String,Object?> v,int id){if(v['t']!='verdict'||v['id']!=id)return false; final a=v['action']; if(a=='deny')return v.keys.every({'t','id','action','status','reason'}.contains)&&v['status'] is int&&(v['status'] as int)>=400&&(v['status'] as int)<=599&&(v['reason']==null||v['reason'] is String&&(v['reason'] as String).isNotEmpty&&_utf8(v['reason'] as String)<=1024&&!_control(v['reason'] as String)); if(a=='need_body')return v.keys.toSet().difference({'t','id','action','max'}).isEmpty&&v['max'] is int&&(v['max'] as int)>0&&(v['max'] as int)<=_MAX_BODY; if(a!='allow'||v.keys.toSet().difference({'t','id','action','setHeaders','removeHeaders','cred','credential'}).isNotEmpty)return false; final h=v['setHeaders']; if(h!=null){if(h is! Map||h.isEmpty)return false;var count=0,bytes=0; for(final e in h.entries){final name=e.key; if(name is! String||!_token.hasMatch(name)||name!=name.toLowerCase()||e.value is! List||(e.value as List).isEmpty||(e.value as List).any((x)=>x is! String||_control(x)))return false;count+=(e.value as List).length;bytes+=_utf8(name);for(final x in e.value as List){bytes+=_utf8(x as String);}if(count>_MAX_HEADER_ENTRIES||bytes>_MAX_HEADER_BYTES)return false;if({'authorization','proxy-authorization','cookie','x-api-key','host','content-length','transfer-encoding','connection','upgrade','te','trailer','keep-alive','proxy-connection'}.contains(foldHeaderName(name)))return false;}} final r=v['removeHeaders'];if(r!=null&&(r is! List||r.isEmpty||r.length>190||r.any((x)=>x is! String||!_token.hasMatch(x)||x!=x.toLowerCase()||{'host','content-length','transfer-encoding','connection','upgrade','te','trailer','keep-alive','proxy-connection'}.contains(foldHeaderName(x)))))return false;return (v['cred']==null)==(v['credential']==null)&&(v['cred']==null||v['cred'] is String&&(v['cred'] as String).isNotEmpty&&v['credential'] is String&&RegExp(r'^[\x21-\x7e]{1,8192}$').hasMatch(v['credential'] as String));}
  Future<(Uint8List,bool)> _readUpTo(fetch.Request req,int max) async {if(req.body==null)return (Uint8List(0),false);final reader=req.body!.getReader();final parts=<int>[];var cut=false;while(true){final r=await reader.read();if(r.done)break;final b=r.value;if(b==null)continue;final bytes=b as List<int>;final room=max-parts.length;if(bytes.length>room){parts.addAll(bytes.take(room));cut=true;unawaited(reader.cancel());break;}parts.addAll(bytes);}return (Uint8List.fromList(parts),cut);}
}
Decider createDecider(DeciderOptions opts)=>_Decider(opts);
