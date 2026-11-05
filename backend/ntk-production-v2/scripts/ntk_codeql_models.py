"""Read installed CodeQL model facts; never turn guesses into library facts."""
from pathlib import Path
import hashlib
import json
import re

VERSION='INSTALLED_CODEQL_MODEL_FACTS_V1'
SINK_KINDS={22:{'path-injection','path-injection[read]'},78:{'command-injection'},
            79:{'html-injection','js-injection'},89:{'sql-injection'}}


class LibraryModels:
    def __init__(self,pack_root):
        import yaml
        self.root=Path(pack_root).resolve();self.index={};hashes={}
        for path in sorted(self.root.rglob('*.model.yml')):
            content=path.read_bytes();relative=path.relative_to(self.root).as_posix()
            hashes[relative]=hashlib.sha256(content).hexdigest()
            for extension in yaml.load(content,Loader=getattr(yaml,'CSafeLoader',yaml.SafeLoader)).get('extensions',[]):
                target=extension.get('addsTo',{});kind=target.get('extensible')
                if target.get('pack')!='codeql/java-all' or kind not in ['sourceModel','sinkModel','summaryModel','neutralModel']:continue
                for row in extension.get('data',[]):
                    if not isinstance(row,list):continue
                    # Model facts with generated/AI provenance are retained in
                    # stock CodeQL, but are not used to bypass local mining.
                    if not row or row[-1] not in ['manual','manual-batched']:continue
                    if kind=='neutralModel':package,clazz,name,signature=row[:4]
                    else:package,clazz,_,name,signature=row[:5]
                    self.index.setdefault((package,clazz,name),[]).append(
                        {'kind':kind,'row':row,'file':relative,'file_sha256':hashes[relative]})
        self.hash=hashlib.sha256(json.dumps(hashes,sort_keys=True).encode()).hexdigest()

    def facts(self,identity):
        import ntk_iris_shared as shared
        params=shared.extract_formal_params_from_signature(identity['signature'])
        signature='('+','.join(re.sub(r'\s+','',t) for t,_ in params)+')'
        candidates=self.index.get((identity['package'],identity['class'],identity['method']),[])
        return [f for f in candidates if (f['row'][3] if f['kind']=='neutralModel' else f['row'][4]) in ['',signature]]

    def specification(self,identity,cwe):
        """Return an exact, representable fact or None (must ask local model).

        Complex access paths, ambiguous roles and mere absence of a row are
        deliberately not interpreted as 'none'. Native CodeQL models remain
        active in the query independently of this conservative projection.
        """
        facts=self.facts(identity);roles=set();slots=set();used=[]
        for fact in facts:
            kind=fact['kind'];row=fact['row']
            if kind=='sourceModel' and row[6]=='ReturnValue' and row[7]=='remote':roles.add('source');used.append(fact)
            elif kind=='sinkModel' and row[7] in SINK_KINDS.get(cwe,set()):
                match=re.fullmatch(r'Argument\[(this|[0-9]+)\]',row[6])
                if match:roles.add('sink');slots.add('this' if match[1]=='this' else 'p'+match[1]);used.append(fact)
                else:return None
            elif kind=='summaryModel' and row[7]=='ReturnValue' and re.fullmatch(r'Argument\[(this|[0-9]+)\]',row[6]):
                roles.add('taint-propagator');used.append(fact)
        if len(roles)!=1:return None
        role=next(iter(roles))
        return {**identity,'type':role,'sink_args':sorted(slots) if role=='sink' else [],
                'specification_origin':'CODEQL_LIBRARY_MODEL','model_facts':used,'library_models_hash':self.hash}
