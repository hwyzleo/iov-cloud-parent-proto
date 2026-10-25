"""Executable specification only. Not a production implementation or test adapter."""
import json,hashlib,pathlib,sys
D=pathlib.Path(__file__).parent

def decide(x):
 o=x['operation']
 if o=='issue':
  if not x.get('safety_valid_through_E',True):return dict(action='SECURITY_BLOCKED',provider_calls=0,item_changes=0)
  E=min(x['now']+60000,x['B']-30000)
  if E-x['now']<20000:return dict(action='EXPIRED_NO_ITEMS',provider_calls=0,item_changes=0)
  return dict(action='FRESH_RESPONSE',E=E,provider_calls=0,item_changes=0)
 if o=='accept':
  a='LATE_RESPONSE' if x.get('terminalized') else 'RESPONSE_EXPIRED' if x['U']>=x['E'] else 'LEASE_TOO_SHORT' if x['E']-x['U']<15000 else 'IMPORT'
  return dict(action=a,import_calls=int(a=='IMPORT'))
 if o=='ack':
  if x['state']=='ACTIVE':return dict(action='ACTIVE' if x['valid_dual_proof'] else 'REJECT_ACK',active_purposes=2,new_events=0)
  if x['state']=='FAILED' or x['now']>=x['B']:return dict(action='FAILED_ACK_TIMEOUT',active_purposes=0,new_events=0)
  if not x['valid_dual_proof']:return dict(action='REJECT_ACK',active_purposes=0,new_events=0)
  return dict(action='ACTIVE',active_purposes=2,new_events=1)
 if o=='dedupe':return dict(action='SAME_BATCH_FRESH_LEASE' if x['same_business_digest'] else 'CONFLICT_806095',new_material_versions=0,provider_calls=0)
 if o=='budget':
  n,t=(8,120000) if x['phase']=='REQUEST' else (3,10**18) if x['phase']=='ACK' else (12,300000)
  exhausted=x['count']>=n or x['elapsed']>=t or (x['phase']=='ACK' and not x.get('before_D',False))
  return dict(action=('READONLY' if x['phase'] in ['REQUEST','ACK'] else 'BLOCKED') if exhausted else 'SEND',new_sends=0 if exhausted else 1)
 if o=='reconcile':
  a='READONLY'
  if x['sec']=='COMMITTED':
   if x['cloud']=='FAILED':a='BLOCKED_REMOTE_REPAIR'
   elif x['cloud']=='ACK_PENDING' and x.get('ack_budget') and x.get('before_D'):a='RESTORE_ORIGINAL_ACK'
  return dict(action=a,import_calls=0,new_ids=0,nf_increment=0)
 if o=='stabilize':
  run=[];epoch=None
  for obs in x['observations']:
   if obs['kind']!='NOT_FOUND':run=[];epoch=None;continue
   if obs['epoch']!=epoch:run=[];epoch=obs['epoch']
   run.append(obs['t'])
  proven=len(run)>=3 and run[-1]-run[0]>=12000
  remote_releasable=x['cloud']=='FAILED' or (x['cloud']=='UNSPECIFIED' and x.get('error_code')==806099 and x.get('retryable') is False and x.get('error_action')=='DO_NOT_RETRY')
  eligible=proven and remote_releasable
  if eligible and x.get('successor'):a='RESTORE_SUCCESSOR'
  elif eligible and x['chain_ids']<3 and x['chain_elapsed']<600000:a='SUPERSEDE_ONCE'
  else:a='READONLY'
  return dict(action=a,proven=proven,new_ids=int(a=='SUPERSEDE_ONCE'))
 if o=='expired':
  fresh=x['proven'] and x['cloud']=='ACK_PENDING' and x['freshen_used']==0 and x['request_budget'] and x['deliverable']
  return dict(action='FRESHEN_SAME_ID' if fresh else 'READONLY',new_requests=int(fresh))
 if o=='transport':
  ok=x['envelope_fresh'] and x['payload_fresh']
  return dict(action='ADMIT' if ok else 'REJECT',import_calls=int(ok))
 if o=='new_attempt':
  ok=x['old_terminal'] and x['proven'] and x['same_material'] and not x['same_rid']
  return dict(action='NEW_WRAP_SAME_MATERIAL' if ok else 'BLOCKED',new_material_versions=0,new_wrap_operations=int(ok),new_rid_bound_aad=ok)
 if o=='time':
  bad=x.get('uncertainty',0)>1000 or x.get('sample_age',0)>300000 or x.get('rollback',False) or abs(x.get('skew',0))>2000
  return dict(action='TIME_UNTRUSTED' if bad else 'TIME_READY',import_calls=0,new_leases=0)
 if o=='chain':return dict(action='BLOCKED' if x['chain_ids']>=3 or x['elapsed']>=600000 else 'ALLOW_SUCCESSOR',new_ids=0 if x['chain_ids']>=3 or x['elapsed']>=600000 else 1)
 if o=='sec_contract':
  ok=x['version_known'] and x['state_consistent']
  return dict(action='READY' if ok else 'CONTRACT_UNKNOWN',proven=False)
 if o=='store':
  ok=all(x.get(k,True) for k in ['digest_valid','codec_known','profile_known'])
  return dict(action='REPLAY' if ok else 'STORE_QUARANTINE',provider_calls=0)
 raise ValueError(o)

def main():
 v=json.loads((D/'lifecycle-vectors.json').read_text()); rows=[]
 for c in v['cases']:
  actual=decide(c['input']);rows.append(dict(case_id=c['case_id'],input_hash=c['input_hash'],expected_hash=c['expected_hash'],actual=actual,passed=actual==c['expected']))
 out=dict(scope='REFERENCE_ORACLE_ONLY_NOT_PRODUCTION_CI',profile=v['profile'],total=len(rows),passed=sum(r['passed'] for r in rows),results=rows)
 (D/'reference-report.json').write_text(json.dumps(out,indent=2)+'\n')
 print(json.dumps({k:out[k] for k in ['scope','total','passed']}));return 0 if out['passed']==out['total'] else 1
if __name__=='__main__':sys.exit(main())
