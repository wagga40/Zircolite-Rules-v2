// Docsify configuration for the documentation site (index.html). It lives in its own
// file so the Content-Security-Policy can refuse every inline script and handler.

// Pages live where they do in the repository, so links written for GitHub work here too.
function repoPaths(hook, vm) {
  var blob = 'https://github.com/wagga40/Zircolite-Rules-v2/blob/main/';
  hook.afterEach(function (html, next) {
    var file = vm.route.file || 'README.md';
    var dir = file.slice(0, file.lastIndexOf('/') + 1);
    // Raw-HTML figures (<picture>) are relative to the page's folder, not the site root.
    html = html.replace(/\b(src|srcset)="(?![a-z]+:|\/|#)([^"]+)"/g, function (_, attr, path) {
      return attr + '="' + dir + path + '"';
    });
    // relativePath compiles ../rules_linux.json to #/rules_linux.json; only .md files are pages.
    html = html.replace(/href="#\/([^"?#]+\.(?!md")[a-z0-9]+)"/gi, function (_, path) {
      return 'href="' + blob + path + '" target="_blank" rel="noopener"';
    });
    next(html);
  });
}

function renderMermaid(hook) {
  var dark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  mermaid.initialize({ startOnLoad: false, theme: dark ? 'dark' : 'default' });
  hook.doneEach(function () {
    mermaid.run({ querySelector: '.mermaid' });
  });
}

function escapeHtml(text) {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

window.$docsify = {
  name: 'Zircolite rules',
  repo: 'wagga40/Zircolite-Rules-v2',
  loadSidebar: true,
  alias: { '/.*/_sidebar.md': '/_sidebar.md' },  // one sidebar, no 404 per folder
  relativePath: true,                             // links resolve from the page, as on GitHub
  subMaxLevel: 2,
  auto2top: true,
  // The Zircolite docs share the wagga40.github.io origin; a namespace keeps the indexes apart.
  search: { placeholder: 'Search', noData: 'No results', depth: 3, namespace: 'zircolite-rules' },
  markdown: {
    renderer: {
      code: function (token) {
        if (token.lang === 'mermaid') {
          return '<div class="mermaid">' + escapeHtml(token.text) + '</div>';
        }
        return this.origin.code.apply(this, arguments);
      }
    }
  },
  plugins: [repoPaths, renderMermaid]
};
