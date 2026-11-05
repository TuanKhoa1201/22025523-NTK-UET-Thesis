"""Source-independent validated API cache, native parameter mining and telemetry."""
from pathlib import Path
import csv
import json
import re
import time

from ntk_engine_cache import key,write_json,file_hash
from ntk_local_role_batch import generate
from ntk_codeql_models import LibraryModels

VERSION='NTK_FULL_MINING_CANONICAL_BATCH_V1'


class MiningSession:
    def __init__(self,request,config,record):
        self.request=request;self.config=config;self.record=record;self.issues=[];self.stats={};self.batches=0
        self.root=Path(request['persistent_cache_root']);self.models=LibraryModels(request['java_all_pack'])
        self.model_key={'weights':request['model_identity'],'protocol':VERSION,
            'shared_prompt':file_hash(Path(__file__).with_name('ntk_iris_shared.py')),
            'generator':file_hash(Path(__file__).with_name('ntk_local_role_batch.py')),
            'mining_code':file_hash(Path(__file__))}
        self.total_input_tokens=0;self.total_output_tokens=0

    def cache_path(self,cwe,identity):
        return self.root/'api-roles'/key({**self.model_key,'cwe':cwe,'identity':identity})/'response.json'

    @staticmethod
    def specification(raw,cwe,identity):
        import ntk_iris_shared as shared
        prediction=shared.parse_and_validate_callee_json(raw,expected_identity=identity,cwe=cwe)
        if not prediction.strict_valid:raise ValueError('UNVALIDATED_MODEL_SPECIFICATION')
        data=json.loads(raw);slots=[]
        for slot in prediction.canonical_sink_args:
            if slot=='this':slots.append(slot)
            elif re.fullmatch(r'(?:arg|param|p)?[0-9]+',slot):slots.append('p'+re.search(r'[0-9]+',slot)[0])
            else:slots.append(slot)
        data.update(sink_args=slots,specification_origin='VALIDATED_LOCAL_QWEN_API_ROLE')
        return data

    def prepare(self,pipeline,cwe,rows):
        cache=[];stats={'required_api_identities':len(rows),'library_fact_hits':0,'model_cache_hits':0,
                       'model_cache_rejections':0,'fresh_api_requests':0,'unsupported':0,'unexamined':0}
        self.stats[str(cwe)]=stats
        for row in rows:
            identity=dict(zip(['package','class','method','signature'],[row[k] for k in ['package','clazz','func','full_signature']]))
            path=self.cache_path(cwe,identity)
            if path.exists():
                entry=json.loads(path.read_text())
                if entry['checksum']!=key(entry['payload']):raise ValueError('API_ROLE_CACHE_CORRUPT')
                if entry['payload']['strict_valid']:
                    cache.append(self.specification(entry['payload']['raw_output'],cwe,identity));stats['model_cache_hits']+=1
                else:stats['model_cache_rejections']+=1
                continue
            fact=self.models.specification(identity,cwe)
            if fact:
                # This is an explicitly attributed non-LLM specification in
                # upstream's cache, not a manufactured model response.
                cache.append(fact);stats['library_fact_hits']+=1
        pipeline.api_labels_cache_path=str(Path(self.request['workspace'])/('native-api-cache-'+str(cwe)+'.json'))
        write_json(pipeline.api_labels_cache_path,cache)

    def _generate(self,requests,messages=None,prefixes=None):
        if self.batches>=self.request.get('max_model_calls',2048):return None,None
        outputs,telemetry=generate(requests,self.config,batch_size=4,messages_override=messages,prefixes_override=prefixes)
        self.batches+=telemetry['generation_batches'];self.total_input_tokens+=telemetry['input_tokens'];self.total_output_tokens+=telemetry['output_tokens']
        return outputs,telemetry

    def api(self,prompts,cwe,identities):
        import ntk_iris_shared as shared
        output=[None]*len(prompts);pending=[]
        for index,prompt in enumerate(prompts):
            lines=[l for l in prompt[1]['content'].rsplit('Package,Class,Method,Signature',1)[1].splitlines() if l.strip()]
            if len(lines)!=1 or lines[0] not in identities:raise ValueError('NATIVE_API_PROMPT_IDENTITY_NOT_BOUND')
            identity=identities[lines[0]];path=self.cache_path(cwe,identity)
            if path.exists():
                entry=json.loads(path.read_text());payload=entry['payload']
                if entry['checksum']!=key(payload):raise ValueError('API_ROLE_CACHE_CORRUPT')
                if payload['strict_valid']:output[index]=[self.specification(payload['raw_output'],cwe,identity)]
                else:output[index]=[];self.stats[str(cwe)]['unsupported']+=1;self.issues.append('API_ROLE_CONTRACT_UNSUPPORTED')
            else:pending.append((index,identity,path))
        for start in range(0,len(pending),4):
            batch=pending[start:start+4];requests=[(cwe,identity) for _,identity,_ in batch]
            generated,telemetry=self._generate(requests)
            if generated is None:
                for index,identity,path in batch:output[index]=[];self.stats[str(cwe)]['unexamined']+=1
                self.issues.append('MODEL_GENERATION_BATCH_BUDGET_EXCEEDED');continue
            for position,((index,identity,path),(raw,_)) in enumerate(zip(batch,generated)):
                prediction=shared.parse_and_validate_callee_json(raw,expected_identity=identity,cwe=cwe)
                record={**telemetry['records'][position],'task':'API_ROLE_CANONICAL_BATCH',
                        'strict_valid':prediction.strict_valid,'rejection_reason':prediction.abstain_reason}
                self.record(record);self.stats[str(cwe)]['fresh_api_requests']+=1
                # Retry only rejected identity echoes. A valid canonical role
                # is never replaced by the experimentally different prefill.
                if self.request.get('experimental_identity_prefill',False) and not prediction.strict_valid and 'IDENTITY_ECHO' in prediction.abstain_reason:
                    from ntk_local_role_batch import identity_prefill
                    retry,rt=self._generate([(cwe,identity)],prefixes=[identity_prefill(identity)])
                    if retry:
                        raw=retry[0][0];prediction=shared.parse_and_validate_callee_json(raw,expected_identity=identity,cwe=cwe)
                        self.record({**rt['records'][0],'task':'REJECTED_IDENTITY_PREFILL_RETRY','strict_valid':prediction.strict_valid,
                                     'rejection_reason':prediction.abstain_reason})
                payload={'raw_output':raw,'strict_valid':prediction.strict_valid,'identity':identity,
                         'cwe':cwe,'model_identity':self.model_key,'rejection_reason':prediction.abstain_reason}
                write_json(path,{'payload':payload,'checksum':key(payload)})
                if prediction.strict_valid:output[index]=[self.specification(raw,cwe,identity)]
                else:output[index]=[];self.stats[str(cwe)]['unsupported']+=1;self.issues.append('API_ROLE_CONTRACT_UNSUPPORTED')
        return [json.dumps(x) for x in output]

    def parameters(self,prompts,rows,cwe):
        """Actual native task, cached by exact project-context prompt bytes.
        Empty validated model selections do not constitute a safe proof.
        """
        import ntk_iris_shared as shared
        outputs=[];stats=self.stats[str(cwe)]
        stats.update(required_parameter_prompts=len(prompts),parameter_cache_hits=0,parameter_unsupported=0)
        for prompt in prompts:
            path=self.root/'parameter-roles'/key({'model':self.model_key,'prompt':prompt})/'response.json'
            if path.exists():
                entry=json.loads(path.read_text())
                if entry['checksum']!=key(entry['payload']):raise ValueError('PARAMETER_CACHE_CORRUPT')
                result=entry['payload'];stats['parameter_cache_hits']+=1
            else:
                matches=[identity for identity in rows if ','.join([identity[0],identity[1],identity[3]])+',' in prompt[1]['content']]
                if len(matches)!=1:raise ValueError('NATIVE_PARAMETER_PROMPT_IDENTITY_AMBIGUOUS')
                identity=dict(zip(['package','class','method','signature'],matches[0]))
                # Identity prefill is bound to a real CodeQL row; tainted_input
                # is still generated by Qwen, never selected from ground truth.
                prefix='['+json.dumps(identity,separators=(',',':'))[:-1]+',"tainted_input":'
                generated,telemetry=self._generate([(0,identity)],messages=[prompt],prefixes=[prefix])
                valid=False;raw=''
                if generated:
                    raw=generated[0][0]
                    try:
                        data=json.loads(raw)
                        if not isinstance(data,list):raise ValueError('Expected native list')
                        for entry in data:
                            if set(entry)!=set(identity)|{'tainted_input'}:raise ValueError('Native parameter schema')
                            if any(entry[k]!=v for k,v in identity.items()):raise ValueError('Parameter identity mismatch')
                            slots={name for _,name in shared.extract_formal_params_from_signature(identity['signature']) if name}
                            if not isinstance(entry['tainted_input'],list) or any(x not in slots for x in entry['tainted_input']):raise ValueError('Parameter slot mismatch')
                        valid=True
                    except (ValueError,TypeError,KeyError):pass
                    self.record({**telemetry['records'][0],'task':'NATIVE_FUNCTION_PARAMETER_MINING','strict_valid':valid})
                result={'raw_output':raw,'strict_valid':valid}
                write_json(path,{'payload':result,'checksum':key(result)})
            if result['strict_valid']:outputs.append(result['raw_output'])
            else:
                outputs.append('[]');stats['parameter_unsupported']+=1;self.issues.append('NATIVE_PARAMETER_CONTRACT_UNSUPPORTED')
        return outputs
