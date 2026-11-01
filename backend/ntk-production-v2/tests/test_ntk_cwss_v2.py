"""Real Javac/IRIS on synthetic servlet source; role outputs are test doubles.

No Qwen, GPU, OWASP E2E or real 25-case scan is executed here.
"""
import copy
import hashlib
import json
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import ntk_alert_verification as av
import ntk_iris_shared as shared
import ntk_cwss_auto_v2 as v
import ntk_cwss_automatic as old
import ntk_cwss_complete as complete
import ntk_cwss_workflow as w
import test_ast_false_suppression as bridge

FIX=Path(__file__).parent/'fixtures/cwss_v2'
SCAN='SCAN-CWSS-V2'
CWES={'ShellServlet':78,'SqlServlet':89,'ProcessServlet':78,'FileServlet':22,'HtmlServlet':79,
 'ConstantServlet':78,'ParameterizedServlet':89,'EncodedServlet':79,'GuardedPathServlet':22,
 'UnknownServlet':78,'HelperServlet':78,'FieldServlet':78}


def context():return json.loads((FIX/'high-risk-context.json').read_text())


class V2Tests(unittest.TestCase):
    setUpClass=classmethod(bridge.FalseSuppressionTests.setUpClass.__func__)

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.store=w.AssessmentStore(self.root/'store')

    def fixture(self,name,source=None):
        source=source or (FIX/(name+'.java')).read_text()
        path=self.root/(name+'.java');path.write_text(source)
        line=next(i for i,l in enumerate(source.splitlines(),1) if '// SINK' in l)
        analysis=av.analyze_java_site_ast_and_taint(source,str(path),line,CWES[name])
        ident=analysis.target_callee_identity
        sig=v.graph.signature(ident['signature'])
        pred=shared.parse_and_validate_callee_json(json.dumps({**ident,'type':'sink',
            'sink_args':['this'] if sig and not sig['types'] else ['arg0']}),expected_identity=ident,cwe=CWES[name])
        f=asdict(av.verify_and_triage_finding('FINDING-V2-'+name,CWES[name],path.name,line,'synthetic','ERROR',.7,analysis,pred))
        # Same sidecar binding contract as production source provenance verifier.
        provenance={'per_finding_records':[{'finding_id':f['finding_id'],'verified':True,
            'file_sha256':hashlib.sha256(source.encode()).hexdigest()}]}
        snap=v.graph.collect(self.root,[f],provenance)
        return f,snap

    def scored(self,name,mode=complete.MODE,declared=False):
        f,s=self.fixture(name)
        if declared:s['declared_context_v2']=context()
        return f,s,v.assess(f,SCAN,s,mode)[1]

    def test_two_high_fixtures_compile_with_servlet_api_contract(self):
        # Only trusted synthetic fixtures and tiny API contracts are compiled.
        # No class, servlet, shell command or SQL statement is executed.
        import subprocess,shutil
        stubs={
          'javax/servlet/ServletException.java':'package javax.servlet; public class ServletException extends Exception { public ServletException(Throwable cause) {super(cause);} }',
          'javax/servlet/http/HttpServlet.java':'package javax.servlet.http; public class HttpServlet { protected void doPost(HttpServletRequest r,HttpServletResponse s) throws javax.servlet.ServletException,java.io.IOException {} }',
          'javax/servlet/http/HttpServletRequest.java':'package javax.servlet.http; public interface HttpServletRequest { String getParameter(String key); String getHeader(String key); }',
          'javax/servlet/http/HttpServletResponse.java':'package javax.servlet.http; public interface HttpServletResponse {}'}
        for name,text in stubs.items():
            p=self.root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text)
        sources=list(self.root.rglob('*.java'))
        for name in ('ShellServlet','SqlServlet'):
            p=self.root/(name+'.java');p.write_bytes((FIX/p.name).read_bytes());sources.append(p)
        result=subprocess.run([shutil.which('javac'),'-d',str(self.root/'compiled'),*[str(p) for p in sources]],capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_real_post_high_risk_command_and_sql(self):
        for name in ('ShellServlet','SqlServlet'):
            f,s,r=self.scored(name,declared=True)
            self.assertEqual(f['iris_evidence']['flow_proof_state'],'PROVEN_TAINT')
            self.assertTrue(r['normalized_evidence']['local_taint_proven'])
            self.assertGreaterEqual(r['cwss_score'],80);self.assertLessEqual(r['cwss_score'],90)
            self.assertEqual(r['factor_codes']['FC'],'D')
            self.assertEqual(r['metric_assessments']['BI']['classification'],'REFERENCE_ASSUMPTION')
            self.assertFalse(r['fully_verified'])
            self.assertEqual(r['cwss_score_exact'],v.score.score_codes(r['factor_codes'])['cwss_score_exact'])

    def test_five_real_tainted_calls_have_usable_evidence(self):
        for name in ('ShellServlet','SqlServlet','ProcessServlet','FileServlet','HtmlServlet'):
            f,s,r=self.scored(name,old.MODES[0])
            self.assertEqual(f['iris_evidence']['flow_proof_state'],'PROVEN_TAINT')
            self.assertTrue(r['normalized_evidence']['local_taint_proven'],r['normalized_evidence'])
            self.assertTrue(r['normalized_evidence']['entry_point']['observed'])
            self.assertGreater(r['verified_metric_count'],0 if name!='HtmlServlet' else -1)
            estimated=v.assess(f,SCAN,s,old.MODES[1])[1]
            self.assertGreater(estimated['verified_metric_count']+estimated['estimated_metric_count'],0)

    def test_negative_controls_never_high(self):
        for name in ('ConstantServlet','ParameterizedServlet','EncodedServlet','GuardedPathServlet','UnknownServlet','FieldServlet'):
            f,s,r=self.scored(name,declared=True)
            self.assertLess(r['cwss_score'],80,(name,r['factor_codes']))
            if f['iris_evidence']['flow_proof_state']=='PROVEN_SAFE':
                self.assertFalse(r['normalized_evidence']['local_taint_proven'])
                self.assertEqual(r['factor_codes']['TI'],'N')

    def test_receiver_state_processbuilder(self):
        f,s,r=self.scored('ProcessServlet')
        self.assertEqual(r['normalized_evidence']['sink_slot'],'this')
        self.assertTrue(r['normalized_evidence']['receiver_origin'])
        self.assertTrue(r['normalized_evidence']['slot_binding_verified'])

    def test_repository_relative_snapshot_survives_subpath_cleanup_and_replay(self):
        import shutil
        f, _ = self.fixture('SqlServlet')
        checkout = self.root/'checkout'
        scoped = checkout/'src/main/java/sample'
        scoped.mkdir(parents=True)
        source = (self.root/'SqlServlet.java').read_bytes()
        (scoped/'SqlServlet.java').write_bytes(source)
        f['file_path'] = 'src/main/java/sample/SqlServlet.java'
        provenance = {'resolved_commit_sha': 'a'*40, 'per_finding_records': [{
            'finding_id': f['finding_id'], 'verified': True,
            'file_sha256': hashlib.sha256(source).hexdigest()}]}
        wrong = v.graph.collect(scoped, [f], provenance)
        self.assertFalse(v.graph.normalize(f, wrong)['source_bound'])
        self.assertTrue(any(x.startswith('FINDING_SOURCE_UNAVAILABLE:') for x in wrong['limitations']))
        snapshot = v.graph.collect(checkout, [f], provenance)
        self.assertEqual(snapshot['resolved_commit_sha'], 'a'*40)
        self.assertTrue(v.graph.normalize(f, snapshot)['local_taint_proven'])
        saved = self.store.publish_complete(f, SCAN, snapshot)
        shutil.rmtree(checkout)
        self.assertTrue(self.store.replay(SCAN, f['finding_id'], saved['revision'])['replay_verified'])

    def test_missing_or_forged_independent_proof_never_promotes_safe(self):
        f, snapshot = self.fixture('EncodedServlet')
        self.assertTrue(v.graph.normalize(f, snapshot)['local_safe_proven'])
        snapshot['independent_local_proofs'] = {}
        self.assertFalse(v.graph.normalize(f, snapshot)['local_safe_proven'])
        _, result = v.assess(f, SCAN, snapshot, complete.MODE)
        self.assertNotEqual(result['factor_codes']['TI'], 'N')

    def test_canonical_formal_names_and_positional_aliases(self):
        for name in ('ShellServlet','SqlServlet','FileServlet','HtmlServlet'):
            f,s=self.fixture(name)
            formal=v.graph.signature(f['iris_evidence']['target_callee_identity']['signature'])['names'][0]
            for alias in ('0','arg0',formal):
                changed=copy.deepcopy(f);changed['iris_evidence']['covered_sink_args']=[alias]
                s['finding_evidence_hashes'][f['finding_id']]=w.evidence_hash(changed)
                self.assertTrue(v.graph.normalize(changed,s)['local_taint_proven'])
            changed['iris_evidence']['covered_sink_args']=['wrongName']
            self.assertFalse(v.graph.normalize(changed,s)['local_taint_proven'])

    def test_equivalent_signature_representation(self):
        f,s=self.fixture('SqlServlet')
        f['iris_evidence']['ast_overloaded_signature']='java.sql.ResultSet executeUpdate(java.lang.String query)'
        # Return text does not affect overload; parameter type does.
        self.assertTrue(v.graph.normalize(f,s)['local_taint_proven'])
        f['iris_evidence']['ast_overloaded_signature']='int executeUpdate()'
        self.assertFalse(v.graph.normalize(f,s)['local_taint_proven'])

    def test_enclosing_signature_metadata_is_not_sink_overload(self):
        f,s=self.fixture('SqlServlet')
        f['iris_evidence']['ast_overloaded_signature']=f['iris_evidence']['enclosing_signature']
        g=v.graph.normalize(f,s)
        self.assertTrue(g['local_taint_proven'])
        self.assertIn('ENCLOSING_SIGNATURE_METADATA_IGNORED',g['conflicts'])

    def test_qwen_conflict_recorded_ast_used_without_forging_role(self):
        f,s=self.fixture('SqlServlet')
        f['llm_api_role']['predicted_role']='source'
        f['llm_prediction']={'method':'otherApi'}
        g=v.graph.normalize(f,s)
        self.assertTrue(g['local_taint_proven']);self.assertIn('QWEN_ROLE_CONFLICT_AST_PREFERRED',g['conflicts'])
        self.assertEqual(g['qwen_role']['predicted_role'],'source')

    def test_custom_receiver_does_not_inherit_java_identity(self):
        f,s=self.fixture('SqlServlet', (FIX/'SqlServlet.java').read_text().replace('Statement statement','CustomStatement statement'))
        self.assertFalse(v.graph.normalize(f,s)['local_taint_proven'])

    def test_nonexistent_batchupdate_is_not_execute_batch(self):
        f,s=self.fixture('SqlServlet')
        f['iris_evidence']['target_callee_identity']['method']='batchUpdate'
        self.assertFalse(v.graph.normalize(f,s)['local_taint_proven'])

    def test_slot_gaps_unknown_and_safe_not_promoted(self):
        for state in ('UNKNOWN','PROVEN_SAFE'):
            f,s=self.fixture('SqlServlet');f['iris_evidence']['flow_proof_state']=state
            self.assertFalse(v.graph.normalize(f,s)['local_taint_proven'])
        f,s=self.fixture('SqlServlet');f['iris_evidence']['covered_sink_args']=[]
        self.assertFalse(v.graph.normalize(f,s)['local_taint_proven'])

    def test_hash_and_inventory_are_independent(self):
        f,s=self.fixture('SqlServlet');s['analysis_source_bindings']={};s['inventory_complete']=True
        self.assertFalse(v.graph.normalize(f,s)['source_bound'])
        self.assertFalse(v.graph.normalize(f,s)['local_taint_proven'])

    def test_post_is_not_public_or_authenticated_proof(self):
        _,_,r=self.scored('SqlServlet')
        for m in ('RP','AS','AV','BI','EC','FC','IC'):
            self.assertEqual(r['factor_codes'][m],'D')
        self.assertFalse(r['normalized_evidence']['entry_point']['external_reachability_established'])

    def test_context_changes_score_not_provenance_class(self):
        _,s,high=self.scored('SqlServlet',declared=True)
        f,_=self.fixture('SqlServlet')
        s['declared_context_v2'].update(exposure='INTRANET',profile_id='USER_DECLARED_DEPLOYMENT',authentication='PRIVILEGED_MFA',external_controls='BEST_AVAILABLE')
        low=v.assess(f,SCAN,s,complete.MODE)[1]
        self.assertLess(low['cwss_score'],high['cwss_score'])
        self.assertEqual(low['metric_assessments']['EC']['classification'],'REFERENCE_ASSUMPTION')

    def test_context_missing_attribution_or_fc_injection_rejected(self):
        for change in ({'declared_at':'2026-10-30'},{'rationale':'short'},{'FC':'T'}):
            bad=context();bad.update(change)
            with self.assertRaises(ValueError):v.validate_context(bad)

    def test_all_metrics_policy_and_complete_vector(self):
        _,_,r=self.scored('SqlServlet')
        self.assertEqual(set(v.POLICY),set(v.score.FACTOR_ORDER))
        self.assertEqual(len(r['factor_codes']),16)
        self.assertFalse(set(r['factor_codes'].values())&{'UK','U'})
        for m,row in r['metric_assessments'].items():self.assertEqual(row['weight'],v.score.WEIGHTS[m][row['code']])

    def test_existing_helper_summary_and_unverified_field_preserved(self):
        f,s,_=self.scored('HelperServlet')
        self.assertEqual(f['iris_evidence']['flow_proof_state'],'PROVEN_TAINT')
        self.assertTrue(v.graph.normalize(f,s)['local_taint_proven'])
        f,s,_=self.scored('FieldServlet')
        self.assertEqual(f['iris_evidence']['flow_proof_state'],'UNKNOWN')
        self.assertFalse(v.graph.normalize(f,s)['local_taint_proven'])

    def test_deterministic_v2_publication_replay_and_immutable_history(self):
        f,s=self.fixture('ShellServlet')
        legacy=old.collect(None,[f]);self.store.publish_automatic(f,SCAN,legacy)
        before=self.store.history(SCAN,f['finding_id'])
        self.store.publish_automatic(f,SCAN,s)
        self.assertEqual(before,self.store.history(SCAN,f['finding_id'])[:2])
        for rev in self.store.history(SCAN,f['finding_id']):
            self.assertTrue(self.store.replay(SCAN,f['finding_id'],rev['revision'])['replay_verified'])
        self.store.publish_automatic(f,SCAN,s)
        self.assertEqual(len(self.store.history(SCAN,f['finding_id'])),4)

    def test_complete_v1_and_v2_replay(self):
        f,s=self.fixture('ShellServlet')
        self.store.publish_complete(f,SCAN,old.collect(None,[f]))
        self.store.publish_complete(f,SCAN,s)
        for rev in (1,2):self.assertTrue(self.store.replay(SCAN,f['finding_id'],rev)['replay_verified'])

    def test_no_triage_mutation(self):
        f,s=self.fixture('UnknownServlet');original=copy.deepcopy(f)
        for mode in v.MODES:v.assess(f,SCAN,s,mode)
        self.assertEqual(f,original)


class Persisted409CompatibilityTests(unittest.TestCase):
    setUpClass=classmethod(bridge.FalseSuppressionTests.setUpClass.__func__)
    setUp=V2Tests.setUp
    fixture=V2Tests.fixture
    # Three local equivalents, NOT the unavailable laptop correction tests.
    def test_index_enrichment_all_three_modes_no_409(self):
        f,s=self.fixture('ShellServlet')
        self.store.publish_automatic(f,SCAN,s)
        w.AssessmentStore(self.store.path.parent/'complete').publish_complete(f,SCAN,s)
        enriched=copy.deepcopy(f);enriched['review_status']='NOT_REVIEWED'
        enriched['source_provenance_record']={'finding_id':f['finding_id'],'verified':True,'file_sha256':s['analysis_source_bindings'][f['finding_id']]}
        for mode in v.MODES:self.assertEqual(w.ranking([enriched],SCAN,self.store,mode)[0]['finding_id'],f['finding_id'])

    def test_genuine_iris_or_source_change_still_conflicts(self):
        f,s=self.fixture('ShellServlet');self.store.publish_automatic(f,SCAN,s)
        changed=copy.deepcopy(f);changed['iris_evidence']['flow_proof_state']='UNKNOWN'
        with self.assertRaises(w.Conflict):w.ranking([changed],SCAN,self.store,old.MODES[0])
        changed=copy.deepcopy(f);changed['source_provenance_record']={'verified':True,'file_sha256':'0'*64}
        with self.assertRaises(w.Conflict):w.ranking([changed],SCAN,self.store,old.MODES[0])

    def test_old_revisions_replay_after_enriched_read_and_append(self):
        f,s=self.fixture('ShellServlet');self.store.publish_automatic(f,SCAN,s)
        original=self.store.history(SCAN,f['finding_id'])
        self.store.publish_automatic(f,SCAN,s)
        self.assertEqual(original,self.store.history(SCAN,f['finding_id']))
        self.assertTrue(self.store.replay(SCAN,f['finding_id'],1)['replay_verified'])


class ExtendedBindingTests(unittest.TestCase):
    setUpClass=classmethod(bridge.FalseSuppressionTests.setUpClass.__func__)
    setUp=V2Tests.setUp
    fixture=V2Tests.fixture

    def test_all_servlet_http_methods(self):
        for method in ('doGet','doPost','doPut','doDelete'):
            source=(FIX/'SqlServlet.java').read_text().replace('doPost(',method+'(')
            f,s=self.fixture('SqlServlet',source)
            self.assertTrue(v.graph.normalize(f,s)['entry_point']['observed'])

    def test_spring_post_and_requestmapping_with_method_security(self):
        source=(FIX/'SqlServlet.java').read_text().replace('class SqlServlet extends HttpServlet {','@RestController\nclass SqlServlet {').replace('import javax.servlet.http.*;','import javax.servlet.http.*;\nimport org.springframework.web.bind.annotation.*;').replace(' protected void doPost',' @PostMapping("/update")\n @PreAuthorize("hasRole(ADMIN)")\n public void doPost')
        f,s=self.fixture('SqlServlet',source)
        g=v.graph.normalize(f,s)
        self.assertTrue(g['entry_point']['observed']);self.assertTrue(g['entry_point']['method_security_observed'])
        self.assertFalse(g['entry_point']['authentication_verified'])
        s['finding_evidence_hashes'][f['finding_id']]=w.evidence_hash(f)
        r=v.assess(f,SCAN,s,complete.MODE)[1]
        self.assertEqual(r['metric_assessments']['RP']['classification'],'ESTIMATED')
        source=source.replace('@PostMapping("/update")','@RequestMapping(value="/update", method=RequestMethod.POST)')
        f,s=self.fixture('SqlServlet',source)
        self.assertTrue(v.graph.normalize(f,s)['entry_point']['observed'])

    def test_format_locale_slot_real_ast(self):
        for expression,slot in [('out.format(java.util.Locale.US, value, new Object[]{"fixed"})','arg1'),('out.printf(value, new Object[]{"fixed"})','arg0')]:
            source=(FIX/'HtmlServlet.java').read_text().replace('out.println(value)',expression)
            f,s=self.fixture('HtmlServlet',source)
            g=v.graph.normalize(f,s)
            self.assertTrue(g['local_taint_proven'],g)
            self.assertEqual(g['sink_slot'],slot)
            self.assertNotEqual(g['identity']['method'],g['iris_identity']['method'])

    def test_safe_format_not_bound_by_arbitrary_parameter_name(self):
        source=(FIX/'HtmlServlet.java').read_text().replace('out.println(value)','out.format("fixed", new Object[]{value})')
        f,s=self.fixture('HtmlServlet',source)
        self.assertIsNone(v.graph.normalize(f,s)['format_slot_binding'])

    def test_literal_locale_format_binds_named_varargs_array(self):
        source=(FIX/'HtmlServlet.java').read_text().replace(
            'String value = request.getParameter("value");', 'String value = "fixed";').replace(
            'out.println(value);', 'Object[] args = {"a", value};\n out.printf(java.util.Locale.US, "%s %s", args);')
        f,s=self.fixture('HtmlServlet',source)
        g=v.graph.normalize(f,s)
        self.assertTrue(g['local_safe_proven'],g)
        self.assertEqual(g['sink_slot'],'arg2')
        self.assertEqual(g['format_slot_binding']['expression'],'args')
        s['independent_local_proofs']={}
        self.assertFalse(v.graph.normalize(f,s)['local_safe_proven'])

    def test_web_xml_mapping_passive(self):
        (self.root/'web.xml').write_text('<web-app><servlet><servlet-name>s</servlet-name><servlet-class>SqlServlet</servlet-class></servlet><servlet-mapping><servlet-name>s</servlet-name><url-pattern>/query</url-pattern></servlet-mapping></web-app>')
        f,s=self.fixture('SqlServlet');g=v.graph.normalize(f,s)
        self.assertTrue(g['entry_point']['route_mapped'])
        self.assertFalse(g['entry_point']['external_reachability_established'])

    def test_ast_collection_budget_and_missing_identity_fail_closed(self):
        import ntk_cwss_evidence_graph as graph
        f,s=self.fixture('SqlServlet')
        f['iris_evidence']={};s['finding_evidence_hashes'][f['finding_id']]=w.evidence_hash(f)
        r=v.assess(f,SCAN,s,complete.MODE)[1]
        self.assertFalse(r['normalized_evidence']['local_taint_proven'])
        self.assertEqual(r['default_metric_count'],15)
        with patch('time.monotonic',side_effect=[0,16]):
            limited=graph.collect(self.root,[f])
        self.assertIn('CWSS_AST_BUDGET_EXCEEDED',limited['limitations'])
        self.assertEqual(limited['java_ast'],{})

    def test_receiver_alias_origin_is_bounded_and_proven(self):
        source=(FIX/'ProcessServlet.java').read_text().replace('builder.start();',
            'newBuilder.start();').replace(' builder.start()', ' newBuilder.start()')
        source=source.replace(' newBuilder.start();', ' ProcessBuilder newBuilder = builder;\n newBuilder.start();')
        f,s=self.fixture('ProcessServlet',source);g=v.graph.normalize(f,s)
        self.assertTrue(g['local_taint_proven'],g)
        self.assertTrue(g['receiver_alias_path'])

    def test_primitive_print_does_not_inherit_string_xss_overload(self):
        source=(FIX/'HtmlServlet.java').read_text().replace('String value = request.getParameter("value");','int value = Integer.parseInt(request.getParameter("value"));')
        f,s=self.fixture('HtmlServlet',source);g=v.graph.normalize(f,s)
        self.assertFalse(g['local_taint_proven'])
        self.assertIn('AST_ARGUMENT_TYPE_CONFLICT',g['conflicts'])

    def test_fc_requires_existing_independent_attestation_gate(self):
        from test_ntk_cwss_workflow import profile,metric
        f,s=self.fixture('SqlServlet');p=profile(f);p['scan_id']=SCAN;p['metrics']['FC']=metric('T')
        with self.assertRaises(ValueError):v.assess(f,SCAN,s,complete.MODE,attestation={'profile':p,'reviewer':'alice'})
        p['metrics']['FC']['classification']='MACHINE_SUGGESTED'
        r=v.assess(f,SCAN,s,complete.MODE,attestation={'profile':p,'reviewer':'alice'})[1]
        self.assertEqual(r['factor_codes']['FC'],'D')

    def test_runtime_registered_multi_argument_overloads(self):
        for call in ('Runtime.getRuntime().exec(value, new String[]{"A=B"})',
                     'Runtime.getRuntime().exec(new String[]{value}, new String[]{"A=B"}, null)'):
            source=(FIX/'ShellServlet.java').read_text().replace('Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", value})',call)
            f,s=self.fixture('ShellServlet',source);g=v.graph.normalize(f,s)
            self.assertTrue(g['local_taint_proven'],g)
            self.assertIn(len(g['signature']['types']),(2,3))

    def test_v2_policy_hash_replay_guard(self):
        f,s=self.fixture('SqlServlet');self.store.publish_automatic(f,SCAN,s)
        with patch.dict(v.POLICY['TI'],{'rule':'CHANGED_POLICY'}):
            with self.assertRaises(w.Conflict):self.store.replay(SCAN,f['finding_id'],1)

    def test_local_acceptance_export_and_append_do_not_change_archive(self):
        import ntk_cwss_v2_acceptance as acceptance
        f,s=self.fixture('SqlServlet')
        record={'findings':[f],'source_provenance_verification':{'per_finding_records':[{
            'finding_id':f['finding_id'],'verified':True,'file_sha256':s['analysis_source_bindings'][f['finding_id']]}]}}
        path=self.root/(SCAN+'.json');path.write_text(json.dumps(record));before=path.read_bytes()
        store=w.AssessmentStore(self.root/'cwss-assessments')
        store.publish_automatic(f,SCAN,s)
        exported=acceptance.export(self.root,SCAN)
        self.assertEqual(exported['row_count'],1);self.assertEqual(path.read_bytes(),before)
        self.assertEqual(len(store.history(SCAN,f['finding_id'])),2)
        acceptance.export(self.root,SCAN,append=True)
        self.assertEqual(path.read_bytes(),before)
        enriched=copy.deepcopy(f);enriched['source_provenance_record']=record['source_provenance_verification']['per_finding_records'][0]
        self.assertEqual(w.ranking([enriched],SCAN,store,complete.MODE)[0]['source_evidence_hash'],w.evidence_hash(enriched))

    def test_live_http_409_guard_and_v1_replay(self):
        import http.client,threading
        import ntk_web_backend_service as service
        f,s=self.fixture('SqlServlet')
        class Index:
            def get_all_finding_details(self,scan):return [indexed]
            def get_scan_summary(self,scan):return {'scan_id':scan}
        indexed=copy.deepcopy(f);indexed['source_provenance_record']={'finding_id':f['finding_id'],'verified':True,'file_sha256':s['analysis_source_bindings'][f['finding_id']]}
        state=SimpleNamespace(storage_dir=self.root,config=SimpleNamespace(cors_allowed_origins=()),result_index=Index())
        main=w.AssessmentStore(w.directory(state));other=w.AssessmentStore(w.directory(state)/'complete')
        main.publish_automatic(f,SCAN,s);other.publish_complete(f,SCAN,s)
        server=service.create_ntk_http_server(port=0,state=state)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            for mode in v.MODES:
                conn=http.client.HTTPConnection('127.0.0.1',server.server_port)
                conn.request('GET','/api/scans/'+SCAN+'/cwss/v1/ranking?mode='+mode)
                response=conn.getresponse();self.assertEqual(response.status,200);response.read();conn.close()
        finally:server.shutdown();thread.join();server.server_close()


class Real25PrivateDTOTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import os
        import ntk_cwss_v2_acceptance as acceptance
        root=os.environ.get('NTK_REAL25_DIR')
        if not root:raise unittest.SkipTest('Set NTK_REAL25_DIR to the privately supplied verified DTO directory')
        p=Path(root)
        cls.raw=json.loads((p/'01_ARCHIVED_FINDINGS_25.json').read_text())
        cls.indexed=json.loads((p/'02_INDEXED_FINDINGS_25.json').read_text())
        cls.snapshot=acceptance.hydrate(json.loads((p/'04_CWSS_COLLECTION_SNAPSHOT.json').read_text()))
        for raw,indexed in zip(cls.raw,cls.indexed):
            if cls.snapshot['finding_evidence_hashes'][raw['finding_id']] not in (w.evidence_hash(raw),w.evidence_hash(indexed)):
                raise AssertionError('Supplied DTO fingerprints differ')
            if not v.matches(indexed,{'finding_snapshot':raw,'profile':{'automatic_evidence':cls.snapshot}}):
                raise AssertionError('Unexpected DTO enrichment')
            cls.snapshot['finding_evidence_hashes'][indexed['finding_id']]=w.evidence_hash(indexed)

    def test_actual_25_five_taints_two_safe_eighteen_unknown(self):
        results=[v.assess(f,SCAN,self.snapshot,complete.MODE)[1] for f in self.indexed]
        self.assertEqual(len(results),25)
        self.assertEqual(sum(r['normalized_evidence']['entry_point']['observed'] for r in results),25)
        self.assertEqual(sum(r['normalized_evidence']['local_taint_proven'] for r in results),5)
        self.assertEqual(sum(r['normalized_evidence']['local_safe_proven'] for r in results),2)
        self.assertEqual(sum(r['normalized_evidence']['iris_proof']=='UNKNOWN' for r in results),18)
        self.assertEqual(sum(r['cwss_score']==12.6 for r in results),18)
        self.assertEqual(sum(r['cwss_score']==0 for r in results),2)
        for f,r in zip(self.indexed,results):
            self.assertEqual(r['triage_decision'],f['decision'])
            if r['normalized_evidence']['iris_proof']=='UNKNOWN':self.assertEqual(r['verified_metric_count'],0)

    def test_actual_25_http_api_modes_and_replay_after_persisted_index(self):
        with tempfile.TemporaryDirectory() as temp:
            state=SimpleNamespace(storage_dir=Path(temp))
            class Index:
                def get_all_finding_details(inner,scan):return copy.deepcopy(self.indexed)
                def get_scan_summary(inner,scan):return {'scan_id':scan}
            state.result_index=Index()
            store=w.AssessmentStore(w.directory(state));other=w.AssessmentStore(w.directory(state)/'complete')
            for f in self.indexed:
                store.publish_automatic(f,SCAN,self.snapshot);other.publish_complete(f,SCAN,self.snapshot)
            for mode in v.MODES:
                code,body=w.handle(state,'GET','/api/scans/'+SCAN+'/cwss/v1/ranking',{'mode':[mode]})
                self.assertEqual(code,200);self.assertEqual(len(body['findings']),25)
                selected=other if mode==complete.MODE else store
                for f in self.indexed:
                    revision=next(r for r in selected.history(SCAN,f['finding_id']) if r['profile']['mode']==mode)
                    self.assertTrue(selected.replay(SCAN,f['finding_id'],revision['revision'])['replay_verified'])
