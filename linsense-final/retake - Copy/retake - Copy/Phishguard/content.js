(() => {
	let threatPrompt;

	const removeThreatPrompt = () => {
		threatPrompt?.remove();
		threatPrompt = null;
	};

	const showThreatPrompt = (analysis) => {
		removeThreatPrompt();
		const isMalicious = analysis.verdict === "malicious";
		const host = (() => {
			try { return new URL(analysis.url).hostname; } catch { return "this website"; }
		})();
		const root = document.createElement("div");
		root.style.cssText = "all:initial; position:fixed; z-index:2147483647; right:20px; bottom:20px; width:min(380px, calc(100vw - 40px)); font-family:Segoe UI, Arial, sans-serif; color:#202124;";
		const shadow = root.attachShadow({ mode: "closed" });
		shadow.innerHTML = `
			<style>
				.panel { background:#fff; border:1px solid #c8c8c8; border-radius:3px; box-shadow:0 8px 28px rgba(0,0,0,.28); overflow:hidden; }
				.header { display:flex; gap:12px; align-items:flex-start; padding:16px 18px 12px; background:#f7f7f7; border-bottom:1px solid #e1e1e1; }
				.shield { flex:0 0 30px; height:30px; border-radius:50%; display:grid; place-items:center; color:#fff; background:${isMalicious ? "#c43131" : "#b36b00"}; font:bold 18px Segoe UI; }
				.title { margin:0; font-size:16px; line-height:1.25; font-weight:600; }
				.subtitle { margin:4px 0 0; color:#5f6368; font-size:12px; line-height:1.35; overflow-wrap:anywhere; }
				.body { padding:14px 18px 16px; }
				.message { margin:0 0 8px; font-size:13px; line-height:1.45; }
				.signals { margin:0 0 14px; padding-left:18px; color:#5f6368; font-size:12px; line-height:1.45; }
				.actions { display:flex; justify-content:flex-end; gap:8px; }
				button { border:1px solid #8a8a8a; border-radius:2px; padding:8px 12px; cursor:pointer; font:600 12px Segoe UI, Arial, sans-serif; }
				.continue { background:#fff; color:#333; }
				.block { background:#c43131; border-color:#a92727; color:#fff; }
				button:hover { filter:brightness(.95); }
				button:focus-visible { outline:2px solid #1261a0; outline-offset:2px; }
			</style>
			<section class="panel" role="alertdialog" aria-labelledby="linksense-title" aria-describedby="linksense-message">
				<div class="header"><div class="shield" aria-hidden="true">!</div><div><h2 class="title" id="linksense-title">${isMalicious ? "Malicious website detected" : "Suspicious website detected"}</h2><p class="subtitle">LinkSense security alert | ${host}</p></div></div>
				<div class="body"><p class="message" id="linksense-message">LinkSense detected signals that may put your passwords or personal information at risk. Do you want to block this website?</p>
					<ul class="signals">${(analysis.signals || []).slice(0, 3).map(signal => `<li>${String(signal).replace(/[&<>"']/g, character => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[character]))}</li>`).join("")}</ul>
					<div class="actions"><button class="continue" type="button">Continue anyway</button><button class="block" type="button">Block website</button></div>
				</div>
			</section>`;
		document.documentElement.appendChild(root);
		threatPrompt = root;
		shadow.querySelector(".block").addEventListener("click", () => {
			chrome.runtime.sendMessage({ type: "THREAT_DECISION", decision: "block", url: analysis.url, verdict: analysis.verdict });
			removeThreatPrompt();
		});
		shadow.querySelector(".continue").addEventListener("click", () => {
			chrome.runtime.sendMessage({ type: "THREAT_DECISION", decision: "continue", url: analysis.url, verdict: analysis.verdict });
			removeThreatPrompt();
		});
	};

	chrome.runtime.onMessage.addListener((message) => {
		if (message.type === "THREAT_DETECTED" && message.analysis?.url === location.href) showThreatPrompt(message.analysis);
	});

	const signals = [];
	let score = 0;
	const addSignal = (points, label) => {
		score += points;
		signals.push(label);
	};

	const forms = [...document.forms];
	const passwordForms = forms.filter(form => form.querySelector('input[type="password"]'));
	if (passwordForms.length) addSignal(12, "Credential form");
	const sensitiveInputs = [...document.querySelectorAll('input[type="password"], input[autocomplete*="cc-"], input[name*="card" i]')];
	if (sensitiveInputs.some(input => !input.form)) addSignal(18, "Sensitive field outside form");
	if (location.protocol === "http:" && sensitiveInputs.length) addSignal(25, "Unencrypted credential capture");

	const externalSubmit = passwordForms.some(form => {
		try { return new URL(form.action || location.href).origin !== location.origin; } catch { return false; }
	});
	if (externalSubmit) addSignal(25, "External form destination");

	chrome.runtime.sendMessage({
		type: "PAGE_SIGNALS",
		url: location.href,
		score: Math.min(100, score),
		signals
	});
})();
