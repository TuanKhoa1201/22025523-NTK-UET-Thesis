"""Bounded local EO06 generation with canonical prompts by default.

Identity is input metadata, not a prediction. Only sink_args/type are generated.
Both the exact prefill and generated suffix are retained, so no synthetic role
or repaired model response can be mistaken for a generation.
"""
import hashlib
import json
import time

from ntk_local_gpu_lock import gpu_inference_lock

PROMPT_VERSION='EO06_INPUT_BOUND_IDENTITY_PREFILL_V1'


def identity_prefill(identity):
    fields=['package','class','method','signature']
    if any(not isinstance(identity.get(key),str) for key in fields):
        raise ValueError('API_IDENTITY_FIELDS_REQUIRED')
    return json.dumps({key:identity[key] for key in fields},separators=(',',':'),ensure_ascii=True)[:-1]+',"sink_args":'


def generate(requests, config, batch_size=4, identity_prefilled=False,messages_override=None,prefixes_override=None):
    if not requests:return [],{'generation_batches':0,'input_tokens':0,'output_tokens':0,'records':[]}
    if not 1<=batch_size<=4:raise ValueError('GPU_BATCH_LIMIT_1_TO_4')
    import torch
    import ntk_web_backend_service as service
    import ntk_iris_shared as shared
    outputs=[];records=[];batches=0;input_tokens=output_tokens=0;load_ms=0
    torch.set_num_threads(2)
    with service._MODEL_INFERENCE_LOCK,gpu_inference_lock():
        load_started=time.monotonic()
        tokenizer,model,device=service._get_or_load_model_bundle(config)
        load_ms=(time.monotonic()-load_started)*1000
        previous_padding=tokenizer.padding_side;tokenizer.padding_side='left'
        try:
            for offset in range(0,len(requests),batch_size):
                batch=requests[offset:offset+batch_size];texts=[];prefixes=[]
                for local_index,(cwe,identity) in enumerate(batch):
                    absolute_index=offset+local_index
                    prefix=(prefixes_override[absolute_index] if prefixes_override is not None else
                            identity_prefill(identity) if identity_prefilled else '')
                    prefixes.append(prefix)
                    messages=(messages_override[absolute_index] if messages_override is not None else
                              shared.build_canonical_iris_prompt_messages(cwe,identity))
                    texts.append(tokenizer.apply_chat_template(messages,tokenize=False,add_generation_prompt=True)+prefix)
                enc=tokenizer(texts,return_tensors='pt',padding=True).to(device)
                if enc['input_ids'].shape[1]>2048:raise ValueError('API_ROLE_INPUT_TOKEN_LIMIT')
                started=time.monotonic()
                with torch.inference_mode():
                    generated=model.generate(**enc,max_new_tokens=72 if identity_prefilled else 160,do_sample=False,pad_token_id=tokenizer.eos_token_id)
                duration_ms=(time.monotonic()-started)*1000;batches+=1
                if str(enc['input_ids'].device)!='cuda:0' or str(generated.device)!='cuda:0':
                    raise RuntimeError('LOCAL_ROLE_BATCH_REQUIRES_ACTUAL_CUDA')
                width=enc['input_ids'].shape[1]
                for index,(cwe,identity) in enumerate(batch):
                    suffix_ids=generated[index,width:];suffix=tokenizer.decode(suffix_ids,skip_special_tokens=True).strip()
                    raw=prefixes[index]+suffix
                    used_ids=suffix_ids.tolist()
                    try:used_ids=used_ids[:used_ids.index(tokenizer.eos_token_id)+1]
                    except ValueError:pass
                    in_count=int(enc['attention_mask'][index].sum());out_count=len(used_ids)
                    input_tokens+=in_count;output_tokens+=out_count
                    outputs.append((raw,duration_ms/len(batch)))
                    records.append({'cwe':cwe,'identity':identity,'prefill':prefixes[index],
                        'generated_suffix':suffix,'raw_output':raw,'identity_is_input_not_prediction':bool(prefixes[index]),
                        'prompt_version':('EXPLICIT_PROMPT_PREFIX_V1' if messages_override is not None else PROMPT_VERSION) if prefixes[index] else 'CANONICAL_IRIS_2MSG_PROMPT_V1_BATCHED',
                        'prompt_sha256':hashlib.sha256(texts[index].encode()).hexdigest(),
                        'input_tokens':in_count,'generated_tokens':out_count,'batch_index':batches,
                        'batch_size':len(batch),'batch_wallclock_ms':duration_ms,
                        'input_device':str(enc['input_ids'].device),'output_device':str(generated.device)})
                service._LAST_INFERENCE_TELEMETRY.update(input_tensor_device=str(enc['input_ids'].device),
                    output_tensor_device=str(generated.device),prefill_prompt_version=records[-1]['prompt_version'])
        finally:tokenizer.padding_side=previous_padding
    return outputs,{'generation_batches':batches,'api_requests':len(requests),'input_tokens':input_tokens,
        'output_tokens':output_tokens,'model_load_or_lookup_ms':load_ms,'records':records,
        'cuda_peak_allocated_bytes':torch.cuda.max_memory_allocated(),'cloud_calls_enabled':False}
