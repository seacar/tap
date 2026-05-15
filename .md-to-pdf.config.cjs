module.exports = {
  pdf_options: {
    format: 'Letter',
    margin: { top: '20mm', right: '18mm', bottom: '20mm', left: '18mm' },
    printBackground: true,
  },
  stylesheet: [
    'https://cdnjs.cloudflare.com/ajax/libs/github-markdown-css/5.5.1/github-markdown.min.css',
  ],
  css: `
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; }
    .markdown-body { box-sizing: border-box; max-width: 980px; margin: 0 auto; padding: 32px 40px; font-size: 11pt; line-height: 1.55; }
    .markdown-body h1 { font-size: 22pt; border-bottom: 1px solid #eaecef; padding-bottom: 0.3em; }
    .markdown-body h2 { font-size: 16pt; margin-top: 1.4em; border-bottom: 1px solid #eaecef; padding-bottom: 0.25em; }
    .markdown-body h3 { font-size: 13pt; }
    .markdown-body pre { font-size: 9pt; }
    .markdown-body table { font-size: 10pt; }
    .mermaid { text-align: center; margin: 1.5em 0; }
    .mermaid svg { max-width: 100% !important; height: auto !important; }
  `,
  body_class: 'markdown-body',
  script: [
    { url: 'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js' },
    {
      content: `
        mermaid.initialize({ startOnLoad: false, theme: 'neutral', securityLevel: 'loose' });
        document.querySelectorAll('code.language-mermaid').forEach((el) => {
          const pre = el.parentElement;
          const div = document.createElement('div');
          div.className = 'mermaid';
          div.textContent = el.textContent;
          pre.replaceWith(div);
        });
        await mermaid.run({ querySelector: '.mermaid' });
      `,
    },
  ],
};
