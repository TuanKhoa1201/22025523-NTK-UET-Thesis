"""NTK-generated-pack extension: stock CodeQL security models + IRIS specs.

Pinned upstream files stay untouched. Exact generated diffs and hashes are
retained with the run. The independent stock-flow CSV authorizes contextual
proof; a role prediction alone never authorizes REPORT or SUPPRESS.
"""
from pathlib import Path
import re

VERSION='NTK_IRIS_STOCK_SECURITY_MODEL_UNION_V1'
MODELS={
    22:('TaintedPathQuery','TaintedPathSink','TaintedPathConfig','TaintedPathFlow','MyTaintedPathQuery.qll'),
    78:('CommandLineQuery','CommandInjectionSink','InputToArgumentToExecFlowConfig','InputToArgumentToExecFlow','MyCommandInjectionRuntimeExec.qll'),
    79:('XssQuery','XssSink','XssConfig','XssFlow','MyXssQuery.qll'),
    89:('SqlInjectionQuery','QueryInjectionSink','QueryInjectionFlowConfig','QueryInjectionFlow','MySqlInjectionQuery.qll'),
}


def extend_generated_pack(pipeline,cwe,upstream):
    module,sink,config,flow,config_file=MODELS[cwe]
    folder=Path(pipeline.source_qll_path).parent
    # Copy exactly the files the upstream find_vulnerability() would copy.
    # That method is still executed and sees these versioned NTK extensions.
    import src.queries as queries
    for relative in queries.QUERIES[pipeline.query]['queries']:
        target=folder/Path(relative).name
        if not target.exists():target.write_bytes((Path(upstream)/'src'/relative).read_bytes())
    standard=f'''import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.{module} as Stock
predicate isNTKStandardSource(DataFlow::Node n) {{ n instanceof ActiveThreatModelSource }}
predicate isNTKStandardSink(DataFlow::Node n) {{ n instanceof Stock::{sink} }}
predicate isNTKStandardStep(DataFlow::Node a, DataFlow::Node b) {{ Stock::{config}::isAdditionalFlowStep(a,b) }}
predicate isNTKStandardBarrier(DataFlow::Node n) {{ Stock::{config}::isBarrier(n) }}
predicate isNTKStandardFlow(DataFlow::Node a, DataFlow::Node b) {{ Stock::{flow}::flow(a,b) }}
'''
    if cwe==79:standard+='predicate isNTKStandardBarrierOut(DataFlow::Node n) { Stock::XssConfig::isBarrierOut(n) }\n'
    (folder/'NTKStandardModel.qll').write_text(standard)
    for path,name,var,body in [
        (Path(pipeline.source_qll_path),'Source','src','isNTKStandardSource(src)'),
        (Path(pipeline.sink_qll_path),'Sink','snk','isNTKStandardSink(snk)'),
        (Path(pipeline.summary_qll_path),'Step','prev, DataFlow::Node next','isNTKStandardStep(prev,next)')]:
        text=path.read_text();old='predicate isGPTDetected'+name+'('
        if text.count(old)!=1:raise ValueError('PINNED_IRIS_PREDICATE_TEMPLATE_CHANGED')
        text=text.replace(old,'predicate isNTKLLMMined'+name+'(',1)
        arguments='prev,next' if name=='Step' else var
        text+='\nimport NTKStandardModel\npredicate isGPTDetected'+name+'(DataFlow::Node '+var+') {\n'
        text+='isNTKLLMMined'+name+'('+arguments+') or '+body+'\n}\n'
        path.write_text(text)
    path=folder/config_file;text=path.read_text()
    text='import NTKStandardModel\n'+text
    text=re.sub(r'(predicate isBarrier\(DataFlow::Node (\w+)\)\s*\{)',
        lambda m:m[1]+'\n isNTKStandardBarrier('+m[2]+') or ',text)
    if cwe==79:
        text=re.sub(r'(predicate isBarrierOut\(DataFlow::Node (\w+)\)\s*\{)',
            lambda m:m[1]+'\n isNTKStandardBarrierOut('+m[2]+') or ',text)
    path.write_text(text)
    proof=folder/'NTKStandardProof.ql'
    proof.write_text('''import java
import NTKStandardModel
from DataFlow::Node source, DataFlow::Node sink
where isNTKStandardFlow(source,sink)
select source.getLocation().getFile().getAbsolutePath() as source_file,
 source.getLocation().getStartLine() as source_line, source.getLocation().getStartColumn() as source_column,
 sink.getLocation().getFile().getAbsolutePath() as sink_file,
 sink.getLocation().getStartLine() as sink_line, sink.getLocation().getStartColumn() as sink_column
''')
    return proof
