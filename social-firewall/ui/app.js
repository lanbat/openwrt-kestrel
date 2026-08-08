(() => {
  const views = {
    dashboard: {
      eyebrow: 'router control plane',
      title: 'One surface for the local network.',
      text: 'The static application shell is now served by uhttpd. Existing CGI views remain the trusted data and mutation boundary during the API migration.',
      cards: [['Router dashboard', 'Live devices, networks, traffic, and peers.', '/cgi-bin/status'], ['Social groups', 'Review replicated groups and shared fingerprints.', '/cgi-bin/sf-groups'], ['Partyline', 'Coordinate decisions with the group.', '/cgi-bin/sf-partyline']]
    },
    groups: { title: 'Groups', text: 'Group state is currently rendered by the social-firewall CGI surface.', cards: [['Open groups', 'Browse groups and shared identity context.', '/cgi-bin/sf-groups']] },
    policies: { title: 'Policies', text: 'Review and vote on shared policy proposals.', cards: [['Shared policies', 'Open the current policy review interface.', '/cgi-bin/sf-policies'], ['Fingerprints', 'Inspect shared identity evidence.', '/cgi-bin/sf-fingerprint'], ['Profiles', 'Review reusable policy profiles.', '/cgi-bin/sf-profiles']] },
    partyline: { iframe: true }
  };
  const app = document.querySelector('#app');
  function render() {
    const key = (location.hash.slice(2) || 'dashboard').split('/')[0];
    const view = views[key] || views.dashboard;
    document.body.classList.toggle('partyline-view', Boolean(view.iframe));
    app.innerHTML = view.iframe
      ? '<iframe class="partyline-frame" src="/cgi-bin/sf-partyline" title="partyline chat"></iframe>'
      : `<p class="eyebrow">${view.eyebrow || 'kestrel'}</p><h1>${view.title}</h1><p class="lede">${view.text}</p><section class="grid">${view.cards.map(([title, text, href]) => `<article class="card"><h2>${title}</h2><p>${text}</p><a href="${href}">Open view &rarr;</a></article>`).join('')}</section><p class="notice">SPA shell only: server-side authorization and all mutations still terminate in the existing CGI endpoints.</p>`;
    app.focus();
  }
  addEventListener('hashchange', render);
  render();
})();
