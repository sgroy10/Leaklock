const e="da5e4cafd7abd6acf76b5e064aef4e93",t="vx_cOV1UNMbmJcxZd-TbruXANYeXbsh_l1yCrKYwU5y",n="https://demoprojectref1234.supabase.co",o="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRlbW9wcm9qZWN0cmVmMTIzNCIsInJvbGUiOiJhbm9uIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjIwMDAwMDAwMDB9.d3moSignatureNotReal_simFG5VvDLcXVXBo5l_haZMTE58";
async function r(a){const s=await fetch("https://api.imagegen-demo.ai/v1/generate",{method:"POST",headers:{Authorization:`Bearer ${e}`,"Content-Type":"application/json"},body:JSON.stringify({prompt:a})});return s.json()}
async function i(a){return fetch("https://api.voicecloner-demo.io/tts",{method:"POST",headers:{"x-api-key":t},body:a})}
function c(){return createClient(n,o)}
export{r as generate,i as speak,c as db};
