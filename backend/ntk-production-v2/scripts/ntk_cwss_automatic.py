"""Bounded, passive CWSS evidence collection. Never executes project code.

VERIFIED means a supported *local static* fact, not deployed exploitability.
Repository configuration provides estimates only; FC needs the V2 reviewer gate.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

import ntk_cwss_v101 as scoring

VERSION = 'NTK_CWSS_AUTO_V1'
MODES = ('CWSS_AUTO_EVIDENCE', 'CWSS_AUTO_ESTIMATE')
MAX_FILE = 128 * 1024
MAX_FILES = 2048
MAX_TOTAL = 2 * 1024 * 1024
SKIP = {'.git', '.venv', 'node_modules', 'target', 'build', '.gradle', '__pycache__'}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def uncomment(text):
    # Retain Java literals; comments cannot manufacture annotations or API calls.
    return re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*[\s\S]*?\*/',
                  lambda m: m[0] if m[0][0] in '\"\'' else re.sub(r'[^\n]', ' ', m[0]), text)


def _read(root, path):
    """Reject symlinks (including parent components), traversal and oversized files."""
    relative = path.relative_to(root)
    if any(part.is_symlink() for part in [path, *path.parents] if part != root.parent):
        return None
    if not path.is_file() or path.stat().st_size > MAX_FILE:
        return None
    data = path.read_bytes()
    if len(data) > MAX_FILE:
        return None
    return {'path': relative.as_posix(), 'sha256': hashlib.sha256(data).hexdigest(),
            'text': data.decode('utf-8', errors='strict')}


def collect(root, findings, provenance=None):
    """Bounded inventory plus only finding Java and security/deployment candidates.

    A root is supplied by the existing scan, never a CWSS HTTP request. Missing or
    partial repositories are normal: all affected inferences stay unverified.
    """
    snapshot = {'collector_version': VERSION, 'files': [], 'inventory_complete': True,
                'limitations': [], 'finding_evidence_hashes': {}, 'finding_source_paths': {}, 'analysis_source_bindings': {}}
    import ntk_cwss_workflow as w
    snapshot['finding_evidence_hashes'] = {f['finding_id']: w.evidence_hash(f) for f in findings}
    original_records = {r['finding_id']: r for r in (provenance or {}).get('per_finding_records', [])}
    for f in findings:
        rec = original_records.get(f['finding_id']) or f.get('source_provenance_record') or {}
        if rec.get('verified') is True and re.fullmatch(r'[0-9a-f]{64}', str(rec.get('file_sha256', ''))):
            snapshot['analysis_source_bindings'][f['finding_id']] = rec['file_sha256']
    if root is None:
        snapshot.update(inventory_complete=False, limitations=['SOURCE_REPOSITORY_UNAVAILABLE'])
        return snapshot
    root = Path(root).resolve()
    wanted = set()
    for f in findings:
        p = Path(str(f.get('file_path', '')))
        try:
            candidate = p if p.is_absolute() else root / p
            relative = candidate.relative_to(root)
            if '..' not in relative.parts and str(relative).endswith('.java'):
                wanted.add(relative.as_posix())
                snapshot['finding_source_paths'][f['finding_id']] = relative.as_posix()
        except ValueError:
            pass
    count = total = 0
    try:
        for directory, dirs, names in os.walk(root, followlinks=False):
            count += 1
            if count > MAX_FILES:
                snapshot['inventory_complete'] = False
                snapshot['limitations'].append('INVENTORY_LIMIT')
                break
            if any((Path(directory)/d).is_symlink() for d in dirs):
                snapshot['inventory_complete'] = False
                snapshot['limitations'].append('SYMLINK_DIRECTORY_SKIPPED')
            dirs[:] = sorted(d for d in dirs if d not in SKIP and not (Path(directory)/d).is_symlink())
            for name in sorted(names):
                count += 1
                if count > MAX_FILES:
                    snapshot['inventory_complete'] = False
                    snapshot['limitations'].append('INVENTORY_LIMIT')
                    break
                path = Path(directory)/name
                rel = path.relative_to(root).as_posix()
                java = name.endswith('.java')
                config = name == 'Dockerfile' or name.endswith(('.yaml', '.yml', '.properties'))
                if not java and not config:
                    continue
                row = _read(root, path)
                if row is None:
                    snapshot['inventory_complete'] = False
                    snapshot['limitations'].append('UNREADABLE_OR_OVERSIZED:' + rel)
                    continue
                total += len(row['text'].encode())
                if total > MAX_TOTAL:
                    snapshot['inventory_complete'] = False
                    snapshot['limitations'].append('CONTENT_LIMIT')
                    break
                if rel in wanted or config or (java and re.search(r'SecurityFilterChain|EnableWebSecurity|WebSecurityConfigurerAdapter|FilterRegistrationBean', uncomment(row['text']))):
                    if config:
                        # Retain routing intent only; never archive secret/env payloads.
                        row['text'] = '\n'.join(line for line in row['text'].splitlines()
                            if re.fullmatch(r'\s*(?:kind:\s*(?:Ingress|Service)|(?:-\s*)?host:\s*[A-Za-z0-9.-]+|(?:-\s*)?path:\s*/[A-Za-z0-9/_-]*|pathType:\s*Exact|type:\s*(?:LoadBalancer|ClusterIP)|EXPOSE\s+[0-9 /tcpud]+)\s*', line))
                    row['content_sha256'] = hashlib.sha256(row['text'].encode()).hexdigest()
                    snapshot['files'].append(row)
            if count > MAX_FILES or total > MAX_TOTAL:
                break
    except (OSError, UnicodeError):
        snapshot['inventory_complete'] = False
        snapshot['limitations'].append('COLLECTION_READ_ERROR')
    snapshot['files'].sort(key=lambda r: r['path'])
    return snapshot


def _route(finding, files, source_path=None):
    """Recognize one simple GET method in its actual enclosing source method.

    No nested blocks, overloaded names, dynamic/multiple mappings, custom
    composed annotations or method security accepted. These fail closed.
    """
    name = (finding.get('iris_evidence') or {}).get('enclosing_method', '')
    if not re.fullmatch(r'[A-Za-z_$][\w$]*', name):
        return None
    path = source_path or str(finding.get('file_path', ''))
    for row in files:
        if row['path'] != path:
            continue
        text = uncomment(row['text'])
        if not re.search(r'import\s+org\.springframework\.web\.bind\.annotation\.(?:\*|RestController)\s*;', text):
            continue
        if '"""' in text or '@RestController' not in text or re.search(r'@(?:PreAuthorize|Secured|RolesAllowed)|@interface|class\s+(?:RestController|GetMapping)\b', text):
            continue
        if not re.search(r'import\s+(?:jakarta|javax)\.servlet\.http\.HttpServletRequest\s*;', text):
            continue
        if re.search(r'\b(?:class|interface|enum|record)\s+(?:HttpServletRequest|Runtime|Files|Statement|PrintWriter|GetMapping)\b', text):
            continue
        if len(re.findall(r'\b' + re.escape(name) + r'\s*\(', text)) != 1:
            continue
        pattern = (r'@GetMapping\("([^"{}*]+)"\)\s+public\s+[\w<>.]+\s+'
                   + re.escape(name) + r'\s*\(HttpServletRequest\s+request\)\s*(?:throws\s+[\w., ]+)?\{((?:[^{}]|new\s+String\[\]\s*\{[^{}]*\})*)\}')
        matches = list(re.finditer(pattern, text))
        if len(matches) != 1:
            continue
        match = matches[0]
        line = finding.get('line_number')
        start = text.count('\n', 0, match.start(2)) + 1
        end = text.count('\n', 0, match.end(2)) + 1
        if type(line) is not int or not start <= line <= end:
            continue
        if row['text'].splitlines()[line-1].strip() != str(finding.get('matched_code', '')).strip():
            continue
        return {'path': match[1], 'file': row, 'body': match[2]}
    return None


def infer(finding, snapshot):
    """Only registered rules produce local proof; guesses never become proof."""
    import ntk_cwss_workflow as w
    if snapshot.get('collector_version') != VERSION:
        raise ValueError('Unsupported automatic collector version')
    if snapshot.get('finding_evidence_hashes', {}).get(finding['finding_id']) != w.evidence_hash(finding):
        raise ValueError('Automatic snapshot does not match finding evidence')
    files = snapshot.get('files', [])
    for row in files:
        if hashlib.sha256(row['text'].encode()).hexdigest() != row['content_sha256']:
            raise ValueError('Automatic source snapshot checksum mismatch')
    rules = []
    def add(metric, code, status, rule, reason, refs):
        rules.append({'metric': metric, 'code': code, 'classification': status,
                      'inference_status': status, 'rule_id': rule, 'reason': reason,
                      'evidence': refs, 'source': VERSION,
                      'provenance': {'finding_evidence_hash': w.evidence_hash(finding),
                                     'collector_version': VERSION, 'scope': 'LOCAL_STATIC_SOURCE_ONLY'}})
    iris = finding.get('iris_evidence') or {}
    role = finding.get('llm_api_role') or {}
    identity = iris.get('target_callee_identity') or {}
    cls = identity.get('class', '')
    method = identity.get('method', '')
    supported = {
        ('java.lang', 'Runtime', 'exec'): {'Process exec(String command)', 'Process exec(String[] cmdarray)'},
        ('java.sql', 'Statement', 'executeQuery'): {'ResultSet executeQuery(String sql)'},
        ('java.nio.file', 'Files', 'readAllBytes'): {'byte[] readAllBytes(Path path)'},
        ('java.io', 'PrintWriter', 'println'): {'void println(String x)', 'void println(String s)'},
    }
    signatures = supported.get((identity.get('package'), cls, method), set())
    identity_proven = identity.get('signature') in signatures and iris.get('ast_overloaded_signature') == identity.get('signature')
    expected = role.get('canonical_sink_args') or []
    covered = iris.get('covered_sink_args') or []
    formal = re.search(r'\b(\w+)\)$', identity.get('signature', ''))
    aliases = {'arg0', '0', formal[1]} if formal else {'arg0', '0'}
    proven = (iris.get('ast_parser_engine') == 'OPENJDK17_JAVAC_TASK_AST'
              and iris.get('flow_proof_state') == 'PROVEN_TAINT'
              and iris.get('source_sink_trace_status') == 'VERIFIED_TAINT_FLOW'
              and iris.get('taint_reaches_sink') is True
              and iris.get('explicit_ast_release_verified') is False
              and role.get('strict_json_valid') is True and role.get('predicted_role') == 'sink'
              and identity_proven and len(expected) == 1 and expected[0] in aliases
              and 'arg0' in covered and set(expected).issubset(covered))
    refs = [{'reference': 'finding:' + finding['finding_id'] + '#iris_evidence',
             'sha256': w.evidence_hash(finding)}]
    source_path = snapshot.get('finding_source_paths', {}).get(finding['finding_id'])
    source = next((row for row in files if row['path'] == source_path), None)
    source_bound = (source is not None and source['sha256'] == snapshot.get('analysis_source_bindings', {}).get(finding['finding_id']))
    route = _route(finding, files, source_path) if source_bound else None
    # Reuse the accepted IRIS guard proof, never infer complete control from a
    # sanitizer name, a constant, or a machine role. Scope is this finding only.
    controlled = (source_bound and identity_proven and identity.get('package') == 'java.nio.file'
        and cls == 'Files' and method == 'readAllBytes'
        and iris.get('ast_parser_engine') == 'OPENJDK17_JAVAC_TASK_AST'
        and iris.get('flow_proof_state') == 'PROVEN_SAFE'
        and iris.get('source_sink_trace_status') == 'SAFE_SANITIZED_OR_GUARDED'
        and iris.get('explicit_ast_release_verified') is True and iris.get('taint_reaches_sink') is False
        and iris.get('sanitizer_status') == 'VERIFIED_NORMALIZED_PATH_WITH_PREFIX_GUARD'
        and 'STARTSWITH_PREFIX_GUARD:' in iris.get('ast_proof_node', '')
        and iris.get('ast_proof_node', '').startswith('SANITIZER_CALL:')
        and len(expected) == 1 and expected[0] in aliases and 'arg0' in covered and set(expected).issubset(covered))
    if controlled:
        add('IC', 'C', 'VERIFIED', 'IRIS_COMPLETE_CONTAINMENT_CONTROL',
            'Existing semantic IRIS proof verifies normalization and a dominating containment guard for every required sink slot at this finding. Does not claim application-wide or external control effectiveness.',
            refs + [{'reference': source['path'] + '#containment-proof', 'sha256': source['sha256']}])
    server_sink = (cls, method) in {('Runtime', 'exec'), ('java.lang.Runtime', 'exec'),
        ('Statement', 'executeQuery'), ('java.sql.Statement', 'executeQuery'),
        ('Files', 'readAllBytes'), ('java.nio.file.Files', 'readAllBytes')}
    if proven:
        # Sink identity + covered local flow is an estimate of impact, not a CWE lookup.
        known = server_sink or (cls, method) in {('PrintWriter', 'println'), ('java.io.PrintWriter', 'println')}
        if known:
            add('TI', 'H', 'MACHINE_SUGGESTED', 'LOCAL_CAPABILITY_IMPACT_ESTIMATE',
                'Potential significant technical impact from the resolved sink and covered local flow; data sensitivity, command scope and runtime permissions remain unverified.', refs)
        if iris.get('sanitizer_status') == 'NONE_DETECTED':
            add('IC', 'N', 'SCENARIO_ASSUMED', 'NO_LOCAL_CONTROL_ESTIMATE',
                'Estimate assumes no effective internal control beyond the examined flow. Absence of a detected sanitizer does not prove absence of controls.', refs)
        if route and server_sink and re.search(r'\brequest\.(?:getParameter|getHeader)\s*\(', route['body']):
            src = route['file']
            route_refs = refs + [{'reference': src['path'] + '#GET:' + route['path'], 'sha256': src['sha256']}]
            add('IN', 'A', 'VERIFIED', 'SYNCHRONOUS_GET_SERVER_SINK',
                'Supported synchronous GET request-to-server-sink local flow needs no victim action and is repeatable automatically. This proves interaction requirements only, not deployed reachability.', route_refs)
            # Local process execution through a shell has explicit code-execution capability.
            # Do not infer the process account, obtained privilege or business impact.
            if (cls, method) == ('Runtime', 'exec') and identity.get('signature') == 'Process exec(String[] cmdarray)' and re.search(
                    r'Runtime\.getRuntime\(\)\.exec\(new\s+String\[\]\s*\{\s*"/bin/sh"\s*,\s*"-c"\s*,\s*\w+\s*\}\)', route['body']):
                add('TI', 'H', 'VERIFIED', 'TAINTED_SHELL_COMMAND_CAPABILITY',
                    'Covered command slot plus explicit /bin/sh -c execution proves local arbitrary-command capability. Runtime privileges and business impact are not inferred.', route_refs)
    # Spring authorization is application configuration, not proof of deployed access.
    security = [r for r in files if re.search(r'SecurityFilterChain|WebSecurityConfigurerAdapter|EnableWebSecurity|FilterRegistrationBean', uncomment(r['text']))]
    if route and snapshot.get('inventory_complete') and len(security) == 1:
        row = security[0]
        text = uncomment(row['text'])
        # Only this intentionally small, entire configuration grammar is supported.
        grammar = (r'\s*(?:package\s+[\w.]+;\s*)?(?:import\s+[\w.*]+;\s*)+'
            r'@Configuration\s+@EnableWebSecurity\s+public\s+class\s+\w+\s*\{\s*'
            r'@Bean\s+(?:public\s+)?SecurityFilterChain\s+\w+\(HttpSecurity\s+(\w+)\)\s+throws\s+Exception\s*\{\s*'
            r'return\s+\1\.authorizeHttpRequests\(\w+\s*->\s*\w+\.anyRequest\(\)\.permitAll\(\)\)\.build\(\);\s*\}\s*\}\s*')
        trusted_imports = ('import org.springframework.security.web.SecurityFilterChain;' in text
                           and 'import org.springframework.security.config.annotation.web.builders.HttpSecurity;' in text)
        if trusted_imports and re.fullmatch(grammar, text):
            ref = [{'reference': row['path'] + '#anyRequest.permitAll', 'sha256': row['sha256']}]
            for metric in ('RP', 'AS'):
                add(metric, 'N', 'SCENARIO_ASSUMED', 'SPRING_PERMIT_ALL_SOURCE_CONFIGURATION',
                    'Single supported Spring chain permits this GET without application authentication. Estimate assumes this configuration is active and no upstream/custom security changes access.', ref)
    # Exposure manifests are source intent, not proof that a deployment exists.
    ingress = [r for r in files if re.search(r'^kind:\s*Ingress\s*$', r['text'], re.M)]
    for row in ingress if route and snapshot.get('inventory_complete') and len(ingress) == 1 else []:
        text = row['text']
        if row['path'].endswith(('.yaml', '.yml')) and re.search(r'^kind:\s*Ingress\s*$', text, re.M) and re.search(r'^\s*(?:-\s*)?host:\s*[a-zA-Z0-9.-]+\s*$', text, re.M) and re.search(r'^\s*(?:-\s*)?path:\s*' + re.escape(route['path']) + r'\s*$', text, re.M) and re.search(r'^\s*pathType:\s*Exact\s*$', text, re.M):
            add('AV', 'I', 'SCENARIO_ASSUMED', 'INGRESS_INTERNET_SCENARIO',
                'Single Ingress host and exact endpoint path suggest an Internet scenario only. Assumes manifest targets this application and is active; private ingress, DNS and firewall remain unverified.',
                [{'reference': row['path'] + '#Ingress', 'sha256': row['sha256']}])
            break
    return rules


def assess(finding, scan, snapshot, mode):
    import ntk_cwss_workflow as w
    if mode not in MODES:
        raise ValueError('Invalid automatic mode')
    rules = infer(finding, snapshot)
    codes = scoring.default_metric_codes()
    records = {}
    for m in scoring.FACTOR_ORDER:
        eligible = [r for r in rules if r['metric'] == m and (mode == MODES[1] or r['classification'] == 'VERIFIED')]
        # Verified local proof takes priority over estimates; deterministic rule order.
        eligible.sort(key=lambda r: (r['classification'] != 'VERIFIED', r['rule_id']))
        record = eligible[0] if eligible else {'metric': m, 'code': codes[m], 'classification': 'UNKNOWN',
            'inference_status': 'UNKNOWN', 'rule_id': 'NO_SUFFICIENT_RULE',
            'reason': 'No supported factor-specific evidence. FC requires independent V2 attestation; deployment, asset, privileges, discovery and exploit reliability are not inferred.',
            'evidence': [], 'source': VERSION, 'provenance': {'scope': 'LOCAL_STATIC_SOURCE_ONLY'}}
        record = dict(record)
        if m == 'P':
            record.update(code='NA', classification='NOT_APPLICABLE', inference_status='NOT_APPLICABLE',
                          rule_id='TARGETED_PREVALENCE_POLICY', reason='Prevalence excluded for targeted individual finding.',
                          evidence=[{'reference': scoring.STANDARD_URL + '#prevalence'}])
        codes[m] = record['code']
        applied = codes[m] not in ('UK', 'U')
        record.update(weight=scoring.WEIGHTS[m][codes[m]], meaning=w.VALUE_LABELS[m][codes[m]],
                      evidence_sufficient=record['classification'] in ('VERIFIED', 'NOT_APPLICABLE'),
                      applied_to_score=applied, name=w.METRIC_NAMES[m])
        records[m] = record
    profile = {'schema_version': VERSION, 'mode': mode, 'scan_id': scan, 'finding_id': finding['finding_id'],
               'source_evidence_hash': w.evidence_hash(finding), 'automatic_evidence': snapshot}
    result = scoring.score_codes(codes, fill_unknown=False)
    result.update(schema_version=w.VERSION, engine_version=w.ENGINE, engine_hash=w.ENGINE_HASH,
        inference_version=VERSION, inference_hash=digest({'version': VERSION, 'rules': rules, 'snapshot': snapshot}),
        mode=mode, assessment_status='INCOMPLETE' if result['unknown_metric_count'] else 'COMPLETE',
        fully_verified=False, risk_interpretation='STATIC_EVIDENCE_WITH_UNKNOWN_CONTEXT' if mode == MODES[0] else 'AUTOMATIC_ESTIMATE_NOT_VERIFIED_DEPLOYMENT',
        scan_id=scan, finding_id=finding['finding_id'], finding_anchor=w.context.finding_anchor(finding),
        source_evidence_hash=w.evidence_hash(finding), profile_hash=w.digest(profile),
        metric_assessments=records, machine_suggestions=[r for r in rules if r['classification'] != 'VERIFIED'],
        assessment_completeness={'unknown_count': result['unknown_metric_count'], 'unknown_ratio': result['unknown_metric_count']/16,
            'metric_count': 16, 'policy_na_count': 1,
            'verified_metric_count': sum(r['classification'] == 'VERIFIED' for r in records.values()),
            'estimated_metric_count': sum(r['classification'] in ('MACHINE_SUGGESTED', 'SCENARIO_ASSUMED') for r in records.values())},
        collection_limitations=snapshot['limitations'], triage_decision=finding.get('decision', 'REVIEW'),
        heuristic_evidence_score=finding.get('final_heuristic_score'), priority_policy='CWSS_0_100_WITH_ASSESSMENT_STATE',
        verification_scope='LOCAL_STATIC_SOURCE_ONLY_NOT_DEPLOYED_EXPLOITABILITY')
    return profile, result
