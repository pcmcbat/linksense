document.addEventListener("DOMContentLoaded", () => {
  const params = new URLSearchParams(window.location.search);
  const targetUrl = params.get('url');

  const severity = params.get('severity') || 'suspicious';

  const severityConfig = {
    malicious: {
      title: "CRITICAL THREAT DETECTED",
      message: "Immediate termination of connection recommended",
      color: "var(--danger)",
      animation: "pulse 1.5s ease infinite"
    },
    suspicious: {
      title: "SUSPICIOUS ACTIVITY IDENTIFIED",
      message: "Proceed with extreme caution",
      color: "var(--warning)",
      animation: "pulse 2s ease infinite"
    },
    safe: {
      title: "SECURITY SCAN COMPLETE",
      message: "No immediate threats detected",
      color: "var(--safe)",
      animation: "pulse 3s ease infinite"
    }
  };

  const config = severityConfig[severity] || severityConfig.suspicious;
  const indicator = document.getElementById('warning-indicator');

  indicator.style.background = `conic-gradient(${config.color} 0%, transparent 100%)`;
  indicator.querySelector('.glow-pulse').style.background = config.color;
  
  document.getElementById('warning-title').textContent = config.title;
  document.getElementById('warning-message').textContent = config.message;

  const handleContinue = async () => {
    if (!targetUrl) return;

    if (severity === 'safe') {
      window.location.href = targetUrl;
      return;
    }

    const confirmation = confirm(
      `SECURITY WARNING:\n\n` +
      `You are attempting to access a potentially risky website.\n` +
      `Threat Level: ${severity.toUpperCase()}\n\n` +
      `Are you absolutely sure you want to proceed?`
    );
    if (!confirmation) return;

    try {
      const result = await chrome.runtime.sendMessage({
        type: 'THREAT_DECISION',
        decision: 'continue',
        url: targetUrl,
        verdict: severity
      });
      if (result?.error) throw new Error(result.error);
    } catch (error) {
      console.error('[LinkSense] Could not continue to the website:', error);
      alert('LinkSense could not apply the one-time exception. Please try again.');
    }
  };

  const handleBlock = () => {
    if (!targetUrl) return;

    chrome.runtime.sendMessage({
      type: 'THREAT_DECISION',
      decision: 'block',
      url: targetUrl,
      verdict: severity
    });

    window.location.href = 'about:blank';
  };

  document.querySelectorAll('.action-button').forEach(button => {
    button.addEventListener('click', function() {
      this.style.transform = 'scale(0.98)';
      setTimeout(() => { this.style.transform = '' }, 100);
    });
  });

  document.getElementById('go-back-button').addEventListener('click', () => window.history.back());
  document.getElementById('block-site-button').addEventListener('click', handleBlock);
  document.getElementById('report-phish-button').addEventListener('click', () => {
    alert(`Threat reported to security team\nCase ID: ${Date.now().toString(16)}`);
  });
  document.getElementById('continue-button').addEventListener('click', handleContinue);

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.style.opacity = 1;
        entry.target.style.transform = 'translateY(0)';
      }
    });
  });

  document.querySelectorAll('[data-aos]').forEach(el => {
    el.style.opacity = 0;
    el.style.transform = 'translateY(20px)';
    el.style.transition = 'all 0.6s cubic-bezier(0.4, 0, 0.2, 1)';
    observer.observe(el);
  });
});