'use strict';
const $ = id => document.getElementById(id);
let report = null;
const decisions = new Map();
$('ai').disabled = document.querySelector('meta[name="ai-available"]').content !== 'true';
async function request(path, body) {
  const response = await fetch(path, {method:'POST', headers:{'Content-Type':'application/json', 'X-Sentinel-Token':document.querySelector('meta[name="sentinel-token"]').content}, body:JSON.stringify(body)});
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'Request failed');
  return result;
}
function element(tag, text, cls) {
  const node = document.createElement(tag); node.textContent = text;
  if (cls) node.className = cls;
  return node;
}
function render(result) {
  report = result; decisions.clear(); $('results').hidden = false;
  $('summary').textContent = `${result.status.toUpperCase()} · ${result.tools.length} tools · ${result.findings.length} findings`;
  $('limitations').textContent = result.limitations;
  $('trace').textContent = result.trace.join(' → ') + (result.status === 'awaiting_review' ? ' → human_review (paused)' : '');
  $('errors').replaceChildren(...result.errors.map(e => element('p',e,'notice')));
  $('inventory').replaceChildren(...result.tools.map(t => element('p',`${t.name} — ${t.description || '(no description)'}`)));
  $('findings').replaceChildren();
  if (!result.findings.length) $('findings').append(element('p','No heuristic findings. This does not establish safety.'));
  for (const f of result.findings) {
    const card = element('article','');
    card.append(element('p',`${f.severity.toUpperCase()} · ${f.kind} · ${f.tool}`,'eyebrow'),element('h4',f.summary),element('p',`Confidence: ${f.confidence}. Runtime behavior unverified.`));
    for (const e of f.evidence) card.append(element('p',e.path,'mono'),element('pre',e.quote));
    card.append(element('p',f.mitigation));
    for (const c of result.critiques.filter(c => c.target_id === f.id)) card.append(element('p',`Critic: ${c.verdict} — ${c.explanation} ${c.suggested_correction}`,'notice'));
    for (const d of result.decisions.filter(d => d.finding_id === f.id)) card.append(element('p',`Human review: ${d.disposition} — ${d.rationale}`));
    if (result.status === 'awaiting_review') {
      const label = element('label','Human disposition'); const select = document.createElement('select');
      for (const v of ['needs_investigation','confirmed','dismissed']) {const o=element('option',v); o.value=v; select.append(o);}
      label.append(select); const rationaleLabel=element('label','Review rationale (required)'); const rationale=document.createElement('input'); rationale.type='text'; rationale.maxLength=2000; rationaleLabel.append(rationale);
      card.append(label,rationaleLabel); decisions.set(f.id,{select,rationale});
    }
    $('findings').append(card);
  }
  $('resume').hidden = result.status !== 'awaiting_review';
  $('changes').replaceChildren(...result.changes.map(c => element('p',`${c.status}: ${c.tool}${c.fields.length ? ' · '+c.fields.join(', ') : ''}`)));
  if (!result.changes.length) $('changes').append(element('p', result.baseline_compared ? 'No metadata changes.' : 'No valid baseline supplied.'));
}
$('scan').addEventListener('click',async () => {
  $('scan').disabled=true; $('message').textContent='Running inspection…';
  try { render(await request('/api/scan',{payload:JSON.parse($('payload').value),baseline:$('baseline').value.trim() ? JSON.parse($('baseline').value) : null,ai:$('ai').checked,review:$('review').checked})); $('message').textContent='Inspection ready.'; }
  catch(e) {$('message').textContent=e.message;} finally {$('scan').disabled=false;}
});
$('resume').addEventListener('click',async () => {
  $('resume').disabled=true;
  try {
    const rows=Array.from(decisions,([finding_id,{select,rationale}])=>({finding_id,disposition:select.value,rationale:rationale.value.trim()}));
    if (rows.some(d=>!d.rationale)) throw new Error('Enter a rationale for every finding.');
    render(await request('/api/review',{scan_id:report.scan_id,decisions:rows}));
    $('message').textContent='Human review recorded. Evidence preserved.';
  } catch(e) {$('message').textContent=e.message;} finally {$('resume').disabled=false;}
});
$('download').addEventListener('click',() => {
  const url=URL.createObjectURL(new Blob([JSON.stringify(report,null,2)],{type:'application/json'}));
  const a=document.createElement('a'); a.href=url; a.download='sentinel-report.json'; a.click(); setTimeout(()=>URL.revokeObjectURL(url),1000);
});
