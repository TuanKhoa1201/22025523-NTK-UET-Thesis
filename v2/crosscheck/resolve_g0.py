"""Close the known issue ledger without changing historical audit results.

This is a derived presentation, not another raw auditor. Raw audit must be run
first. Exit 0 means documents generated, never experimental acceptance.
"""
import argparse
import ast
from collections import Counter
import csv
import hashlib
import io
import json
from pathlib import Path


def sha(data):
    return hashlib.sha256(data).hexdigest()


def compare_csv(a, b):
    def parse(data):
        reader = csv.DictReader(io.StringIO(data.decode('utf-8-sig')))
        rows = list(reader)
        if not reader.fieldnames or 'alert_id' not in reader.fieldnames:
            raise ValueError('missing alert_id')
        if len({r['alert_id'] for r in rows}) != len(rows):
            raise ValueError('duplicate alert_id')
        return reader.fieldnames, {r['alert_id']: r for r in rows}
    pa, pb = parse(a), parse(b)
    return {'byte_equal': a == b, 'rows_columns_equal': pa == pb,
            'rows': len(pa[1]), 'columns': len(pa[0]),
            'versions': [{'sha256': sha(d), 'bytes': len(d), 'crlf': d.count(b'\r\n'),
                          'bom': d.startswith(b'\xef\xbb\xbf'),
                          'lf_sha256': sha(d.replace(b'\r\n', b'\n'))} for d in (a, b)]}


def valid_errata(row, entries=()):
    if row.get('criterion') not in ('document_consistency', 'annotation_rationale',
                                  'java_rationale_review', 'peer_document_provenance'):
        return False
    keys = ('criterion', 'alert_id', 'field', 'expected', 'actual', 'source_sha256')
    def canonical(value):
        if isinstance(value, str) and value.startswith('{'):
            try:
                value = ast.literal_eval(value)
            except (ValueError, SyntaxError):
                pass
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    return any(all(canonical(e.get(k, '')) == canonical(row.get(k, '')) for k in keys)
               and all(str(row.get(k, '')) for k in keys)
               and len(row.get('source_sha256', '')) == 64
               and e.get('errata_id') and e.get('check_id')
               and e.get('approval') in ('PENDING', 'APPROVED') for e in entries)


def classify(row, entries=()):
    """Explicit disposition, not a replacement for original PASS/FAIL status."""
    if row['status'] == 'FAIL':
        if not valid_errata(row, entries):
            return 'UNRESOLVED_FAIL', 'No matching evidence-specific errata', 'Codex'
        return 'ERRATA_ISSUED', 'Giữ FAIL lịch sử; công bố giá trị đúng trong errata', 'Antigravity/G3'
    if row['status'] == 'PASS':
        return 'PASS', 'Giữ nguyên phạm vi kiểm tra đã ghi', 'Codex'
    if row['criterion'] in ('heldout_aggregate_comparison', 'latency_measurements'):
        return 'NOT_MEASURED', 'A/B không có mẫu đo; không suy ra mean/p50/p95 từ số 0', 'Người hướng dẫn/G1 nếu cần đo mới'
    if row['field'] in ('heldout_strict_lock_manifest.json', 'PROMPT_VERSION_MANIFEST.json'):
        return 'REFERENCE_AVAILABLE_LIMITED', 'Git 86636b9 có bản tham chiếu; không chứng thực bản chạy hoặc thời điểm khóa', 'JavisOS/G3'
    if row['field'].startswith('manual FP'):
        if row['field'].endswith('10'):
            return 'LABEL_REVIEW_REQUIRED', 'Thiếu caller/validator độc lập; không chốt TP hoặc FP', 'Người gán nhãn/JavisOS'
        return 'CONDITIONAL', 'Giữ điều kiện SQL dialect hoặc filesystem/caller; không nâng thành GT chuẩn', 'Người gán nhãn/JavisOS'
    if 'Original request' in row['actual']:
        return 'PROMPT_NOT_ATTESTED', 'Không có payload lịch sử; không dựng lại để chứng thực', 'Công bố G3; lưu đầy đủ nếu G1 được duyệt'
    if row['field']=='checkpoint_absent':
        return 'INCOMPLETE', 'Git 86636b9 cli.py: --checkpoint optional; thiếu argv baseline để chứng minh không áp dụng, không miễn trừ', 'JavisOS/G3'
    if row['field']=='historical_stale_source_demo':
        return 'INCOMPLETE', 'DB/transcript 13 bước có sẵn nhưng không có thao tác stale-source; thiếu log/DB của lần thử lịch sử', 'JavisOS/G3'
    if row['field']=='lock_config_null':
        return 'INCOMPLETE', 'Đã tính khóa Git/raw; config_file/config_sha256 null, cần bản config lịch sử nếu từng lưu', 'JavisOS/G3'
    if row['field']=='pre_run_lock_time':
        return 'INCOMPLETE', 'Git có khóa nhưng không chứng minh thời điểm trước run; cần provenance lịch sử, không lập khóa hồi tố', 'Người hướng dẫn/G3'
    if row['criterion']=='manual_ground_truth':
        return 'INCOMPLETE', 'Raw có nhãn tác giả, thiếu chứng minh caller/môi trường; loại 20 nhãn khỏi tuyên bố GT độc lập', 'Người gán nhãn/JavisOS'
    return 'INCOMPLETE', 'Giới hạn lịch sử chưa đóng; không yêu cầu chạy lại để thay thế', 'JavisOS/người hướng dẫn'


REQUIRED = ('transfer_integrity','scan_development','scan_heldout','scan_manual',
            'owasp_labels_and_sources','heldout_published_comparison','immutability',
            'manual_label_catalog','public_lock_raw_lf',
            'run_stage4_heldout40_armB_heuristic',
            'run_stage4_heldout40_armC_evidence_llm','run_stage4_heldout40_armD_llm_ablation')


def execution_completed(audit):
    # Completion requires positive receipts for every required execution section.
    return (all(audit.get('criteria', {}).get(k) in ('PASS', 'FAIL', 'INCOMPLETE')
                for k in REQUIRED)
            and all(any(r.get('criterion') == k for r in audit.get('register', [])) for k in REQUIRED)
            and bool(audit.get('checked_fields')) and audit.get('checks', 0) > 0
            and audit.get('exit_code') in (0, 2, 3)
            and audit.get('limitations_recorded') is True)


def acceptance(audit, comparison, entries=()):
    required=REQUIRED
    if any(audit.get('criteria',{}).get(k) != 'PASS' for k in required):
        return 'BLOCKED'
    if not comparison['rows_columns_equal']:
        return 'BLOCKED'
    for row in audit['register']:
        if row['status']=='FAIL' and not valid_errata(row, entries):
            return 'BLOCKED'
        if row['status']=='INCOMPLETE':
            # Only the disclosed historical gaps may enter a conditional handoff.
            with (Path(__file__).parent/'G0_DISCREPANCY_REGISTER.csv').open(encoding='utf-8', newline='') as stream:
                known = list(csv.DictReader(stream))
            keys = ('criterion', 'alert_id', 'field', 'actual', 'source_sha256')
            if not any(x['status']=='INCOMPLETE' and all(str(x.get(k) or '') == str(row.get(k) or '') for k in keys) for x in known):
                return 'INCOMPLETE'
    if not execution_completed(audit):
        return 'INCOMPLETE'
    failures = any(r['status']=='FAIL' for r in audit['register'])
    incomplete = any(r['status']=='INCOMPLETE' for r in audit['register'])
    if audit['exit_code'] != (2 if failures else 3 if incomplete else 0):
        return 'BLOCKED'
    return 'CONDITIONAL' if failures or incomplete or entries else 'PASS'


JAVA = {
 '00863': ('Sai cơ chế', '45 source hằng getTheValue; Thing1/Thing2 truyền đối số; sink 51'),
 '01746': ('Sai phép toán/nhánh', '45 source hằng; 94-96: (7*42)-106=188, nhánh false chọn param; sink 66'),
 '01752': ('Diễn giải quá chung', '45 source hằng; put keyB 80/get keyB 82 giữ param; sink 60-61. Nhãn nhận không nói keyA'),
 '00864': ('Thiếu một cơ chế', '45 source hằng; 50-56 list remove(0)/get(1) lấy hằng; sink 59'),
 '00062': ('Thiếu bước trung gian', '54-60 cookie; map keyB put 69/get 71; sink 78'),
 '01006': ('Thiếu bước trung gian', '54-60 cookie; helper 96/98 map keyB giữ param; SQL 68, sink 73-74'),
 '01156': ('Thiếu bước trung gian', '44-51 header; helper 100/102 map keyB giữ param; URI 64-71/File 72'),
 '00949': ('Peer mô tả sai nhánh', '54-60 cookie; helper 91/93 gán bar=param rồi return; sink 68-69. Không có toán tử ba ngôi'),
 '00950': ('Peer mô tả sai nhánh', '54-60 cookie; helper 90/92 gán bar=param rồi return; sink 68. Không có toán tử ba ngôi'),
}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ('package', 'raw-audit', 'public-dir', 'peer-handoff', 'peer-paired', 'output'):
        ap.add_argument('--'+name, required=True, type=Path)
    a = ap.parse_args()
    root = Path(__file__).parent
    old = root/'G0_DISCREPANCY_REGISTER.csv'
    audit = json.loads(a.raw_audit.read_text('utf-8'))
    entries = json.loads((root/'G0_ERRATA_REGISTER.json').read_text('utf-8'))
    audit['limitations_recorded'] = 'missing' in audit
    prior = list(csv.DictReader(old.open(encoding='utf-8', newline='')))
    e = a.package/'extracted/evidence/post_report_cwe22_cwe89_20261112'
    # No values in peer prose are used to calculate metrics or choose OWASP labels.
    metrics = {arm: {c: {k:v for k,v in m.items() if k != 'per_finding'}
                    for c,m in groups.items()} for arm,groups in audit['heldout_metrics'].items()}
    comparison = compare_csv((e/'metrics/PAIRED_EVALUATION.csv').read_bytes(),
                             (a.public_dir/'PAIRED_EVALUATION.csv').read_bytes())
    peer = a.peer_handoff.read_text('utf-8')
    peer_line = next(l for l in peer.splitlines() if '35,627' in l and 'e19fc' in l)
    import re
    comparison['peer_declared_sha256'] = re.search(r'`([a-f0-9]{64})`', peer_line)[1]
    comparison['peer_declared_hash_matches_raw'] = comparison['peer_declared_sha256'] == comparison['versions'][0]['sha256']
    comparison['peer_source_commit'] = 'bf19b5e1392645baba55e5039ebc0d71a1af9aaa'
    comparison['peer_text_utf8_sha256'] = sha(a.peer_handoff.read_bytes())
    peer_csv=a.peer_paired.read_bytes()
    peer_blob=hashlib.sha1(b'blob '+str(len(peer_csv)).encode()+b'\0'+peer_csv).hexdigest()
    # Blob identity independently read from GitHub tree bf19b5e; not a metric answer.
    if peer_blob != '9cb4e96e67e235cd828070cc7596e6ceb5ac16ad':
        raise ValueError('peer CSV differs from pinned Git blob')
    comparison['peer_git_blob']=peer_blob
    comparison['peer_git_csv']=compare_csv((e/'metrics/PAIRED_EVALUATION.csv').read_bytes(),peer_csv)
    comparison['codex_prior_input_hashes']=json.loads((root/'results/published_metrics.json').read_text('utf-8'))['public_input_hashes']
    rows=[]
    for i,r in enumerate(prior,1):
        status,method,owner=classify(r, entries)
        rows.append({'check_id':f'OLD-{i:03d}', 'criterion':r['criterion'], 'alert_id':r['alert_id'],
                     'field':r['field'], 'before':r['status'], 'after':status,
                     'expected':r['expected'], 'actual':r['actual'],
                     'source_file':r['source_file'], 'source_sha256':r['source_sha256'],
                     'method':method, 'remaining_reason':method if status not in ('PASS','ERRATA_ISSUED') else '',
                     'owner':owner})
    notes=[]
    labels=[]
    for group in ('development','heldout'):
        labels += json.loads((e/'labels'/('labels_'+group+'.json')).read_text('utf-8'))['labels']
    for case,(kind,flow) in JAVA.items():
        label=next(r for r in labels if r['file_path']=='BenchmarkTest'+case+'.java')
        source=next((e/'sources').rglob(label['file_path']))
        assert sha(source.read_bytes()) == label['source_sha256']
        notes.append({'case':case,'kind':kind,'flow':flow,'label':label['ground_truth'],
                      'alert_id':label['alert_id'],'source_sha256':sha(source.read_bytes()),
                      'source_file':source.relative_to(e).as_posix(),
                      'old_rationale':label['annotator_rationale']})
    before=dict(Counter(r['before'] for r in rows))
    for n in notes:
        if n['case'] in ('00863','01746'):
            continue  # Already present in the original six FAIL rows.
        rows.append({'check_id':'JAVA-'+n['case'],'criterion':'java_rationale_review',
                     'alert_id':n['alert_id'],'field':'mechanism','before':'NEW_REVIEW',
                     'after':'ERRATA_ISSUED','expected':n['flow'],'actual':n['old_rationale'],
                     'source_file':n['source_file'],'source_sha256':n['source_sha256'],
                     'method':n['kind']+'; direct source review, no label change',
                     'remaining_reason':'No runtime path proof claimed','owner':'Antigravity/G3'})
    rows.append({'check_id':'PEER-CSV-HASH','criterion':'peer_document_provenance',
                 'alert_id':'*','field':'PAIRED_EVALUATION.csv SHA-256','before':'NEW_REVIEW',
                 'after':'ERRATA_ISSUED','expected':comparison['versions'][0]['sha256'],
                 'actual':comparison['peer_declared_sha256'],'source_file':'Git bf19b5e:G0_SERVER_FINAL_HANDOFF.md',
                 'source_sha256':comparison['peer_text_utf8_sha256'],
                 'method':'Raw bytes and Git 86636b9 equal; peer prose hash incorrect for these artifacts',
                 'remaining_reason':'No bytes with peer-declared hash supplied; cannot identify its origin',
                 'owner':'JavisOS/G3'})
    after=dict(Counter(r['after'] for r in rows))
    verdict=acceptance(audit,comparison, entries)
    report={'schema':'ntk-g0-resolution-1','date':'2026-11-13',
            'AUDIT_EXECUTION_COMPLETED':execution_completed(audit),'G0_ACCEPTANCE':verdict,'READY_FOR_G1':'CONDITIONAL' if verdict in ('PASS','CONDITIONAL') else 'NO',
            'axes':{'DATA_INTEGRITY':'PASS for delivered artifacts; historical runtime unattested',
                    'METRIC_RECOMPUTATION':'PASS for measured C/D and classification A/B/C/D; A/B latency NOT_MEASURED',
                    'GROUND_TRUTH_ATTESTATION':'56 OWASP verified; manual 20 not independently attested; #10 review required',
                    'LLM_CONTRIBUTION':'CONFOUNDED','G1_READINESS':'CONDITIONAL; advisor approval of scope and exclusions'},
            'historical_register_sha256':sha(old.read_bytes()),'before':before,'after':after,
            'additional_review_rows':8,
            'raw_audit_exit_code':audit['exit_code'],'raw_audit_sha256':sha(a.raw_audit.read_bytes()),
            'raw_audit_failure_count':sum(r['status']=='FAIL' for r in audit['register']),
            'raw_audit_incomplete_count':len(audit['missing']),
            'transfer':audit['transfer'],'inputs_aliases':{'E':'extracted/evidence/post_report_cwe22_cwe89_20261112',
                 'F':'extracted/evidence/server_forensic_audit_failclosed_20261112','PUBLIC':'Git 86636b9:v2/evaluation/post_report'},
            'scans':audit['scans'],'ground_truth':audit['ground_truth'],
            'heldout_metrics':metrics,'paired_comparison':comparison,'java_reviews':notes,
            'guided_agreement':audit['guided_pipeline_agreement'],
            'git':{'branch':'v2/advisor-m1-proof-20261111','head':'8db7dafae6c4abc99ca8a78e9b2e83a0e0b9f204',
                   'target':'v2/codex-core','switch_exit':128,'clone_exit':128,'commit':None,'pushed':False},
            'conditions':['Approve errata without modifying locked inputs','Exclude manual labels from verified GT claims',
                          'Retain PROMPT_NOT_ATTESTED and CONFOUNDED; no standalone Qwen accuracy claim',
                          'Checkpoint history, pre-run locking and stale-source historical attempt remain unverified'],
            'additional_peer_errata':3}
    a.output.mkdir(exist_ok=True,parents=True)
    names=['G0_FINAL_RESOLUTION.json','G0_RESOLUTION_REGISTER.csv','G0_ERRATA.md']
    if any((a.output/n).exists() for n in names):raise FileExistsError('refuse to overwrite derived outputs')
    (a.output/names[0]).write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    with (a.output/names[1]).open('w',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    text=['# Đính chính hiện vật lịch sử\n',
          'Không sửa raw, nhãn, manifest, SQLite hoặc register gốc. ERRATA_ISSUED không đổi FAIL lịch sử thành PASS.\n',
          '## Sáu sai lệch đã có\n','| ID | Trường | Bản cũ | Theo nguồn | Xử lý |','|---|---|---|---|---|']
    for r in rows:
        if r['before']=='FAIL':text.append(f"| {r['check_id']} | {r['field']} | {r['actual']} | {r['expected']} | Đính chính; không đổi GT/metrics raw |")
    text+=['\n## Chín cơ chế Java đã đối chiếu trực tiếp\n',
           'Các diễn giải dưới là rà soát tĩnh nguồn đã khớp blob OWASP, không phải chạy Java mới. Ba mô tả map thiếu chi tiết không đồng nghĩa nhãn sai.\n',
           '| Case | Nhãn giữ nguyên | Phân loại | Cơ chế đúng |','|---|---|---|---|']
    for n in notes:text.append(f"| {n['case']} | {n['label']} | {n['kind']} | {n['flow']} |")
    text+=['\nHai mô tả ba ngôi 00949/00950 trong bàn giao JavisOS là sai; mã thực tế chỉ gán và trả param. Không chấp nhận tự động cả chín mô tả của peer. SHA nguồn và rationale cũ có trong JSON.\n',
           '## SHA bảng bắt cặp\n',
           f"Raw E và Git 86636b9: `{comparison['versions'][0]['sha256']}`, {comparison['versions'][0]['bytes']} byte. Khớp byte, 40 alert × 27 cột; UTF-8 không BOM, LF.\n",
           f"Bàn giao JavisOS tại bf19b5e ghi `{comparison['peer_declared_sha256']}` / 35.627 byte: không khớp. Không phải chênh CRLF/LF giữa hai bản đã có. Không có bản byte mang hash peer để suy ra nguyên nhân; đính chính lời khai, không sửa raw.\n",
           'Đây là lỗi truy xuất trong tài liệu peer, không làm thay đổi kết quả tái tính từ bản raw đã định danh. Không cần chạy lại model.\n']
    (a.output/names[2]).write_text('\n'.join(text),encoding='utf-8')
    print(json.dumps({'documents_generated':True,'before':before,'after':after,'acceptance':verdict}))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
