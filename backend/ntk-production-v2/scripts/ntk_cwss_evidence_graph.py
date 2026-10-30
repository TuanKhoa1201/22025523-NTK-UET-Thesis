"""Versioned normalized Java evidence, no lexical taint promotion or code execution.

Javac supplies callsites, scopes and declared types. This is bounded type binding,
not whole-program javac symbol attribution; unresolved owners remain conflicts.
"""
import copy
import hashlib
import re
import ntk_cwss_automatic as v1
import ntk_cwss_v101 as scoring

VERSION = 'NTK_CWSS_GRAPH_V2'
CWE_APPLICABILITY={'java.lang':78,'java.sql':89,'java.nio.file':22,'java.io':79}
# Discrete overload parameter TYPES, not arbitrary formal-parameter names.
REGISTRY = {
 ('java.lang','Runtime','exec'): {('String',),('String[]',),('String','String[]'),('String[]','String[]'),('String','String[]','File'),('String[]','String[]','File')},
 ('java.lang','ProcessBuilder','start'): {()},
 ('java.sql','Statement','executeQuery'): {('String',)},
 ('java.sql','Statement','executeUpdate'): {('String',),('String','int'),('String','int[]'),('String','String[]')},
 ('java.sql','Statement','execute'): {('String',)},
 ('java.sql','Statement','executeBatch'): {()},
 ('java.sql','PreparedStatement','executeQuery'): {()},
 ('java.sql','CallableStatement','executeQuery'): {()},
 ('java.sql','PreparedStatement','executeUpdate'): {()},
 ('java.sql','CallableStatement','executeUpdate'): {()},
 ('java.nio.file','Files','readAllBytes'): {('Path',)},
}
for name in ('format','printf'):
    REGISTRY['java.io','PrintWriter',name]={('String','Object[]'),('java.util.Locale','String','Object[]')}
for sql_type in ('PreparedStatement','CallableStatement'):
    for name in ('executeQuery','executeUpdate','execute'):
        REGISTRY['java.sql',sql_type,name]=REGISTRY.get(('java.sql',sql_type,name),set()) | REGISTRY['java.sql','Statement',name]
for method in ('print','println','write'):
    REGISTRY['java.io','PrintWriter',method] = {('String',),('Object',),('char[]',),('String','int','int'),('char[]','int','int')}


def signature(value):
    m = re.search(r'([\w$]+)\s*\(([^()]*)\)\s*(?:throws .*)?$', str(value))
    if not m:
        return None
    params = []
    names = []
    for p in m[2].split(',') if m[2].strip() else []:
        p = re.sub(r'\bfinal\s+', '', p.strip()).replace('...', '[]')
        bits = p.split()
        typ = bits[0].replace('java.lang.','').replace('java.nio.file.','').replace('java.io.','')
        params.append(typ)
        names.append(bits[-1] if len(bits)>1 else None)
    return {'method':m[1], 'types':params, 'names':names}


def collect(root, findings, provenance=None):
    """Reuse V1 collector; add bounded semantic AST snapshots, cached where possible."""
    import ntk_alert_verification as av
    snapshot = v1.collect(root, findings, provenance)
    snapshot['inference_version'] = VERSION
    snapshot['java_ast'] = {}
    # 64 relevant sources, per-file bridge timeout5s, aggregate time budget15s.
    import time
    deadline = time.monotonic()+15
    for row in snapshot['files']:
        if row['path'] not in snapshot['finding_source_paths'].values():
            continue
        if len(snapshot['java_ast']) >= 64 or time.monotonic() >= deadline:
            snapshot['limitations'].append('CWSS_AST_BUDGET_EXCEEDED');break
        try:
            ast = av.parse_java_source_with_javac_ast(row['text'], str(__import__('pathlib').Path(root)/row['path']), timeout_sec=5)
            if ast:
                ast=copy.deepcopy(ast);ast['file_path']=row['path']
                snapshot['java_ast'][row['path']] = {'sha256':row['sha256'], 'ast':ast}
        except (OSError, ValueError, TimeoutError):
            snapshot['limitations'].append('CWSS_AST_UNAVAILABLE:'+row['path'])
    from pathlib import Path
    import json
    path=Path(root)/'ntk-cwss-deployment-context.json'
    if path.exists():
        try:
            if path.is_symlink() or path.stat().st_size>32768:raise ValueError('Context size/link')
            data=path.read_bytes()
            if len(data)>32768:raise ValueError('Context size')
            from ntk_cwss_auto_v2 import validate_context
            snapshot['declared_context_v2']=validate_context(json.loads(data))
        except (OSError, ValueError, TypeError, KeyError):
            snapshot['limitations'].append('DECLARED_V2_CONTEXT_REJECTED')
    snapshot['servlet_mappings']=[]
    import xml.etree.ElementTree as ET
    for rel in ('web.xml','WEB-INF/web.xml','src/main/webapp/WEB-INF/web.xml'):
        path=Path(root)/rel
        try:
            row=v1._read(Path(root).resolve(),path.resolve()) if path.exists() and not path.is_symlink() else None
            if not row or '<!' in row['text']:continue
            xml=ET.fromstring(row['text'])
            for node in xml.iter():node.tag=node.tag.split('}')[-1]
            names={n.findtext('servlet-name'):n.findtext('servlet-class') for n in xml.findall('servlet')}
            for node in xml.findall('servlet-mapping'):
                for url in node.findall('url-pattern'):
                    snapshot['servlet_mappings'].append({'class':names.get(node.findtext('servlet-name')),
                        'url':url.text,'reference':rel,'sha256':row['sha256']})
        except (OSError, ValueError, ET.ParseError):
            snapshot['limitations'].append('WEB_XML_UNSUPPORTED:'+rel)
    return snapshot


def _method(ast, line):
    candidates = [(cls,m) for cls in ast.get('classes',[]) for m in cls.get('methods',[])
                  if int(m.get('start_line',0)) <= line <= int(m.get('end_line',0))]
    return min(candidates,key=lambda pair:int(pair[1]['end_line'])-int(pair[1]['start_line'])) if candidates else ({},{})


def normalize(finding, snapshot):
    import ntk_cwss_workflow as w
    fid = finding['finding_id']; iris = finding.get('iris_evidence') or {}
    conflicts = []; blocked = []
    path = snapshot.get('finding_source_paths',{}).get(fid)
    row = next((r for r in snapshot.get('files',[]) if r['path']==path),None)
    astrow = snapshot.get('java_ast',{}).get(path) or {}
    expected = snapshot.get('analysis_source_bindings',{}).get(fid)
    bound = bool(row and row['sha256']==expected and hashlib.sha256(row['text'].encode()).hexdigest()==row['content_sha256'])
    if not bound:blocked.append('SOURCE_HASH_UNBOUND')
    ast = astrow.get('ast',{}) if bound and astrow.get('sha256')==expected else {}
    cls, method = _method(ast,int(finding.get('line_number') or 0))
    identity = iris.get('target_callee_identity') or finding.get('target_callee_identity') or {}
    iris_identity=copy.deepcopy(identity)
    target = signature(identity.get('signature'))
    all_calls=[c for c in method.get('invocations',[]) if int(c.get('start_line',0))<=int(finding.get('line_number') or 0)<=int(c.get('end_line',0))]
    formatting=[c for c in all_calls if c.get('method_name') in ('format','printf')]
    format_binding=None
    # IRIS V1 represents PrintWriter output as an aggregate println(String x).
    # Recover only the exact JDK formatting call and a trace-linked format value.
    if identity.get('package')=='java.io' and identity.get('class')=='PrintWriter' and identity.get('method') in ('println','format','printf') and len(formatting)==1:
        actual=formatting[0];args=actual.get('arguments',[])
        locale=bool(args and (re.fullmatch(r'java.util.Locale\.[A-Z_]+',args[0]) or re.fullmatch(r'Locale\.[A-Z_]+',args[0]) and any(x in ast.get('imports',[]) for x in ('java.util.Locale','java.util.*')) and not any(c.get('class_name')=='Locale' for c in ast.get('classes',[]))))
        offset=1 if locale else 0
        value=args[offset] if len(args)>offset else ''
        linked=bool(re.fullmatch(r'[A-Za-z_$][\w$]*',value) and any(step.startswith(value+' = ') for step in iris.get('taint_trace_steps',[])))
        if len(args)==offset+2 and linked:
            types=['String','Object[]'] if offset==0 else ['java.util.Locale','String','Object[]']
            identity={**identity,'method':actual['method_name'],'signature':'PrintWriter '+actual['method_name']+'('+', '.join(types)+')'}
            target={'method':actual['method_name'],'types':types,'names':[None]*len(types)}
            format_binding={'slot':'arg'+str(offset),'expression':value,'origin':'IRIS_AGGREGATE_RETURN_PATH_TO_AST_FORMAT_ARGUMENT'}
            conflicts.append('IRIS_AGGREGATE_PRINTWRITER_IDENTITY_REFINED')
    calls = [c for c in method.get('method_invocations',method.get('invocations',[])) if c.get('method_name')==identity.get('method')
             and int(c.get('start_line',0)) <= int(finding.get('line_number') or 0) <= int(c.get('end_line',0))]
    call = calls[0] if len(calls)==1 else {}
    observed=all_calls+[c for c in method.get('new_classes',[]) if int(c.get('start_line',0))<=int(finding.get('line_number') or 0)<=int(c.get('end_line',0))]
    observed.sort(key=lambda c:c.get('stmt_order',0))
    observed_call=call or (observed[0] if observed else {})
    if not call:
        blocked.append('AST_CALLSITE_MISSING_OR_AMBIGUOUS')
        if observed:conflicts.append('IRIS_TARGET_NOT_AST_CALL')
    owner = (identity.get('package') or '', identity.get('class') or '', identity.get('method') or '')
    raw_astsig=signature(iris.get('ast_overloaded_signature'))
    overload_refined=False
    def arg_type(expr):
        if expr=='null':return 'null'
        if re.fullmatch(r'-?\d+',expr):return 'int'
        if expr.startswith('"') and expr.endswith('"'):return 'String'
        if re.match(r'new (?:java.lang.)?String\[',expr):return 'String[]'
        typed=[d for d in method.get('local_variables',[]) if d.get('name')==expr and d.get('scope_id') in call.get('ancestor_scopes',[]) and d.get('stmt_order',0)<=call.get('stmt_order',0)]
        typed.sort(key=lambda d:(call.get('ancestor_scopes',[]).index(d['scope_id']),-d.get('stmt_order',0)))
        typed=typed or [d for d in method.get('parameters',[]) if d.get('name')==expr]
        if typed:return typed[0].get('type','').replace('java.lang.','').replace('java.io.','').replace('java.nio.file.','')
        return None
    if call and target and not format_binding:
        types=[arg_type(x) for x in call.get('arguments',[])]
        refined=None
        if owner==('java.lang','Runtime','exec') and len(types) in (2,3) and types[0] in ('String','String[]') and types[1] in ('String[]','null') and (len(types)==2 or types[2] in ('File','null')):
            refined=[types[0],'String[]']+(['File'] if len(types)==3 else [])
        elif owner==('java.io','PrintWriter','write') and len(types)==3 and types[0] in ('String','char[]') and types[1:]==['int','int']:
            refined=types
        elif owner in {('java.sql',c,'executeUpdate') for c in ('Statement','PreparedStatement','CallableStatement')} and len(types)==2 and types[0]=='String' and types[1] in ('int','int[]','String[]'):
            refined=types
        if refined and tuple(refined) in REGISTRY.get(owner,set()) and (target['types']!=refined or len(target['types'])!=len(types)):
            target={'method':owner[2],'types':refined,'names':[None]*len(refined)}
            overload_refined=True
            conflicts.append('JDK_OVERLOAD_REFINED_FROM_AST_ARGUMENT_TYPES')
    overload = bool(target and tuple(target['types']) in REGISTRY.get(owner,set()) and call and len(call.get('arguments',[]))==len(target['types']))
    astsig = signature(iris.get('ast_overloaded_signature'))
    if format_binding or overload_refined:astsig=None
    if astsig and astsig['method']==method.get('name') and astsig['method']!=identity.get('method'):
        conflicts.append('ENCLOSING_SIGNATURE_METADATA_IGNORED');astsig=None
    if astsig and target and (astsig['method'],astsig['types']) != (target['method'],target['types']):
        conflicts.append('AST_TARGET_OVERLOAD_CONFLICT');overload=False
    if target and target['types'] and call and not format_binding:
        actual_type=arg_type(call.get('arguments',[''])[0]) if call.get('arguments') else None
        if actual_type and actual_type!='null' and target['types'][0]!='Object' and actual_type!=target['types'][0]:
            conflicts.append('AST_ARGUMENT_TYPE_CONFLICT');overload=False
    # No java.sql.Statement.batchUpdate API exists. Do not alias to executeBatch.
    if not overload:blocked.append('UNSUPPORTED_OR_UNPROVEN_OVERLOAD')
    receiver = call.get('receiver','')
    local_decls = [d for d in method.get('local_variables',[]) if d.get('name')==receiver
                   and d.get('scope_id') in call.get('ancestor_scopes',[]) and d.get('stmt_order',0)<=call.get('stmt_order',0)]
    local_decls.sort(key=lambda d:(call.get('ancestor_scopes',[]).index(d['scope_id']),-d.get('stmt_order',0)))
    declarations = method.get('parameters',[])+cls.get('fields',[])
    declared = [local_decls[0].get('type','')] if local_decls else [d.get('type','') for d in declarations if d.get('name')==receiver][:1]
    short = identity.get('class','')
    imports = ast.get('imports',[])
    imports_text = ' '.join(str(i) for i in imports)
    # Imported known type, full qualification or implicit java.lang. Reject shadow classes.
    known_type = lambda typ: typ==identity.get('package','')+'.'+short or (typ==short and (identity.get('package')=='java.lang' or identity.get('package','')+'.'+short in imports_text or identity.get('package','')+'.*' in imports_text))
    shadow = any(c.get('class_name')==short for c in ast.get('classes',[]))
    receiver_bound = not shadow and (any(known_type(t) for t in declared)
        or short=='Runtime' and receiver in ('Runtime.getRuntime()','java.lang.Runtime.getRuntime()')
        or short=='Files' and known_type(receiver)
        or short=='ProcessBuilder' and re.match(r'new (?:java.lang.)?ProcessBuilder\(',receiver) is not None)
    # response.getWriter() requires an actual servlet response parameter type.
    if short=='PrintWriter' and re.fullmatch(r'\w+\.getWriter\(\)',receiver):
        base=receiver.split('.')[0]
        receiver_bound=any(d.get('name')==base and 'HttpServletResponse' in d.get('type','') for d in declarations)
    if not receiver_bound:blocked.append('RECEIVER_TYPE_UNPROVEN')
    slot = format_binding['slot'] if format_binding else ('this' if target and not target['types'] else 'arg0')
    aliases = {slot}
    if astsig and astsig['types'] and astsig['names']:aliases.add(astsig['names'][0])
    if slot=='arg0' and target:
        aliases.add('0')
        if target['names']:aliases.add(target['names'][0])
        if overload_refined and raw_astsig and raw_astsig['names']:aliases.add(raw_astsig['names'][0])
    covered = iris.get('covered_sink_args') or []
    receiver_origin = call.get('receiver','') if slot=='this' else None
    if slot=='this' and local_decls:
        receiver_origin=local_decls[0].get('init_expr','')
    receiver_alias_path=[]
    for _ in range(4):
        if slot!='this' or not receiver_origin or not re.fullmatch(r'[A-Za-z_$][\w$]*',receiver_origin):break
        if receiver_origin in receiver_alias_path:break
        receiver_alias_path.append(receiver_origin)
        candidates=[d for d in method.get('local_variables',[]) if d.get('name')==receiver_origin
            and d.get('scope_id') in call.get('ancestor_scopes',[]) and d.get('stmt_order',0)<=call.get('stmt_order',0)]
        if len(candidates)!=1 or not known_type(candidates[0].get('type','')):break
        receiver_origin=candidates[0].get('init_expr','')
    receiver_state_bound = bool(slot!='this' or (receiver_origin and
        (short=='ProcessBuilder' and re.match(r'new (?:java.lang.)?ProcessBuilder\(',receiver_origin)
         or short in ('PreparedStatement','CallableStatement') and re.search(r'\.prepare(?:Call|Statement)\(',receiver_origin))))
    coverage = bool(set(covered)&(aliases-{None})) and receiver_state_bound
    if format_binding:coverage=bool(set(covered)&{'x','0','arg0'}) and receiver_state_bound
    if not receiver_state_bound:blocked.append('RECEIVER_ORIGIN_UNPROVEN')
    if not coverage:blocked.append('SINK_SLOT_UNCOVERED')
    role = finding.get('llm_api_role') or {}
    prediction = finding.get('llm_prediction') or {}
    if isinstance(prediction,dict) and prediction.get('method') and prediction.get('method')!=identity.get('method'):
        conflicts.append('QWEN_IDENTITY_CONFLICT_AST_PREFERRED')
    if role.get('predicted_role') not in (None,'sink'):
        conflicts.append('QWEN_ROLE_CONFLICT_AST_PREFERRED')
    # Role is advisory, never a replacement for AST and local proof.
    applicable=CWE_APPLICABILITY.get(owner[0]) == scoring._parse_cwe(finding.get('cwe'))
    if not applicable:
        blocked.append('CWE_SINK_APPLICABILITY_CONFLICT');conflicts.append('CWE_SINK_APPLICABILITY_CONFLICT')
    local = bool(applicable and bound and call and receiver_bound and overload and coverage and iris.get('ast_parser_engine')=='OPENJDK17_JAVAC_TASK_AST')
    state=iris.get('flow_proof_state','UNKNOWN')
    if state=='UNKNOWN':blocked.append('IRIS_UNKNOWN_NO_LOCAL_FLOW_PROOF')
    taint=bool(local and state=='PROVEN_TAINT' and iris.get('taint_reaches_sink') is True
               and iris.get('source_sink_trace_status') in ('VERIFIED_TAINT_FLOW','PARTIAL_OR_INSUFFICIENT_GUARD')
               and iris.get('explicit_ast_release_verified') is not True)
    safe=bool(local and not (owner[:2]==('java.lang','Runtime') and len(target['types'])>1) and state=='PROVEN_SAFE' and iris.get('taint_reaches_sink') is False
              and iris.get('explicit_ast_release_verified') is True and iris.get('source_sink_trace_status') in ('SAFE_CONSTANT_OR_PARAMETERIZED','SAFE_SANITIZED_OR_GUARDED'))
    entry = endpoint(ast,cls,method,row) if bound else {'observed':False}
    mapped=[r for r in snapshot.get('servlet_mappings',[]) if r['class']=='.'.join(filter(None,[ast.get('package_name'),cls.get('class_name')]))]
    if entry.get('framework')=='SERVLET' and mapped:entry.update(route_mapped=True,mappings=mapped)
    output_context=iris.get('output_context')
    # MIME is evidence of an HTML response, not a particular encoding context.
    html=[c for c in method.get('invocations',[]) if c.get('method_name')=='setContentType'
          and c.get('receiver') in {d.get('name') for d in method.get('parameters',[]) if 'HttpServletResponse' in d.get('type','')}
          and c.get('stmt_order',0)<call.get('stmt_order',0)]
    if html and html[-1].get('scope_id') in call.get('ancestor_scopes',[]) and str((html[-1].get('arguments') or [''])[0]).startswith('"text/html'):
        output_context=output_context or 'SERVLET_HTML_RESPONSE'
    graph={'version':VERSION,'finding_id':fid,'cwe':finding.get('cwe'),'file_path':path,'line':finding.get('line_number'),
        'source_hash':expected,'source_bound':bound,'ast_callsite':call,'observed_callsite':observed_call,'resolved_method_identity':identity if receiver_bound and overload else None,'identity':identity,'iris_identity':iris_identity,'format_slot_binding':format_binding,'declaring_type':'.'.join(owner[:2]),
        'signature':target,'overload_binding':'JAVAC_SCOPED_TYPES_AND_REGISTERED_JDK_SUMMARY','sink_slot':slot,'covered_slots':covered,'receiver':receiver,
        'receiver_origin':receiver_origin,'receiver_alias_path':receiver_alias_path,'slot_binding_verified':coverage and local,'receiver_type_verified':bool(receiver_bound),'iris_proof':state,
        'trace_status':iris.get('source_sink_trace_status'),'source_nodes':iris.get('taint_source_params',[]),
        'unresolved_flow_steps':[s for s in iris.get('taint_trace_steps',[]) if 'UNKNOWN' in s or 'UNPROVEN' in s],
        'source_to_sink_steps':iris.get('taint_trace_steps',[]),'sink_node':call.get('call_expr'),
        'control':{'status':iris.get('sanitizer_status'),'proof_node':iris.get('ast_proof_node'),'context':output_context},
        'qwen_role':role,'entry_point':entry,'local_taint_proven':taint,'local_safe_proven':safe,
        'status':'VERIFIED' if taint or safe else ('CONFLICT' if any(c in conflicts for c in ('AST_TARGET_OVERLOAD_CONFLICT','AST_ARGUMENT_TYPE_CONFLICT','CWE_SINK_APPLICABILITY_CONFLICT','IRIS_TARGET_NOT_AST_CALL')) else 'UNKNOWN'),
        'origin':'JAVAC_SCOPED_DECLARATIONS_AND_IRIS','confidence':'LOCAL_PROOF' if taint or safe else 'INSUFFICIENT',
        'conflicts':conflicts,'blocked_rules':blocked,'rule_id':'NORMALIZE_JAVA_V2'}
    graph['evidence_hash']=w.digest(graph)
    return graph


def endpoint(ast,cls,method,row):
    name=method.get('name',''); text=v1.uncomment(row['text']) if row else ''
    parameters=method.get('parameters',[])
    servlet=bool(name in ('doGet','doPost','doPut','doDelete') and any(p.get('type') in ('HttpServletRequest','javax.servlet.http.HttpServletRequest','jakarta.servlet.http.HttpServletRequest') for p in parameters)
                 and any(p.get('type') in ('HttpServletResponse','javax.servlet.http.HttpServletResponse','jakarta.servlet.http.HttpServletResponse') for p in parameters)
                 and re.search(r'\bclass\s+'+re.escape(cls.get('class_name',''))+r'\s+extends\s+(?:javax.servlet.http.|jakarta.servlet.http.)?HttpServlet\b',text)
                 and re.search(r'import\s+(?:javax|jakarta)\.servlet\.http\.',text)
                 and not any(c.get('class_name') in ('HttpServlet','HttpServletRequest','HttpServletResponse') for c in ast.get('classes',[])))
    start=int(method.get('start_line',1)); prefix='\n'.join(text.splitlines()[start-1:min(start+4,len(text.splitlines()))]).split('{',1)[0]
    mapping=re.search(r'@(GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping)\s*\(([^)]*)\)',prefix)
    spring=bool(mapping and 'org.springframework.web.bind.annotation.' in text)
    guarded=bool(re.search(r'@(PreAuthorize|Secured|RolesAllowed)\b',prefix))
    return {'observed':servlet or spring,'framework':'SERVLET' if servlet else ('SPRING' if spring else 'UNKNOWN'),
        'method':name,'http_method':name[2:].upper() if servlet else (mapping[1].replace('Mapping','').upper() if spring else None),
        'route_mapped':bool(spring or servlet and '@WebServlet' in text),
        'mapping':mapping[2] if spring else None,'method_security_observed':guarded,
        'external_reachability_established':False,'authentication_verified':False}
