/* The dashboard's one script (docs/dashboard-design.md). Every page works without it: a form is
   still sent by the browser, to the same address and with the same fields, and the answer is a
   page as before. This file sends no request and reads none, but for the update check (below).
   It does these things:
   - an update check is confirmed in a dialog, and a running one shows its progress in place;
   - the button of a request that takes time says so while it runs (data-busy-label);
   - a second such request is not sent meanwhile: the server runs one at a time, and its refusal
     would replace the answer of the first;
   - while such a request runs, the rail's theme form is not sent from this page either: leaving
     would lose the answer of the request, such as the result of an apply;
   - a project of the rail that takes the focus is brought wholly into view;
   - Escape puts the bubble of the rail's question mark away.
   Block comments only: the tests refuse two slashes in a row anywhere in static/. */
(() => {
  'use strict';

  const live = document.getElementById('live');
  let running = null; /* the button whose request is on its way */

  /* For a screen reader. Emptied first, so that the same words are read again. */
  const say = (text) => {
    if (!live) return;
    live.textContent = '';
    setTimeout(() => { live.textContent = text; }, 50);
  };

  const buttons = () => document.querySelectorAll('[data-busy-label], form.theme button');

  const start = (button) => {
    running = button;
    button.dataset.idleLabel = button.textContent;
    button.textContent = button.dataset.busyLabel;
    /* A name given apart from the text would keep saying the idle one. */
    if (button.hasAttribute('aria-label')) {
      button.dataset.idleName = button.getAttribute('aria-label');
      button.removeAttribute('aria-label');
    }
    button.setAttribute('aria-busy', 'true');
    /* Not disabled: a disabled button drops out of the form being sent and loses the focus. */
    buttons().forEach((other) => other.setAttribute('aria-disabled', 'true'));
    say(button.dataset.busyLabel);
  };

  const stop = () => {
    const button = running;
    running = null;
    if (!button) return;
    button.textContent = button.dataset.idleLabel;
    if (button.dataset.idleName !== undefined) {
      button.setAttribute('aria-label', button.dataset.idleName);
    }
    button.removeAttribute('aria-busy');
    buttons().forEach((other) => other.removeAttribute('aria-disabled'));
  };

  document.addEventListener('submit', (event) => {
    if (event.target.classList.contains('theme')) { /* at once, unless a request runs here */
      if (running) event.preventDefault();
      return;
    }
    const button = event.submitter || event.target.querySelector('[data-busy-label]');
    if (!button || !button.dataset.busyLabel) return; /* a search: at once */
    if (running) event.preventDefault();
    else start(button);
  });

  /* Between 46rem and 80rem the rail is a row that scrolls sideways. A browser counts a link
     whose edge shows as in view and does not scroll to it, which leaves the focus on a name that
     cannot be seen. The row's scroll-padding keeps the focus ring inside it too. */
  const rail = document.querySelector('.tabs ul');
  if (rail) {
    rail.addEventListener('focusin', (event) => {
      event.target.scrollIntoView({ block: 'nearest', inline: 'nearest' });
    });
  }

  /* The rail's question mark shows its bubble while the pointer or the focus is on it
     (style.css .rail-help). Escape puts the bubble away without moving either; it shows again
     when the pointer or the focus next comes to the question mark. */
  const help = document.querySelector('.rail-help');
  if (help) {
    const open = () => help.classList.remove('shut');
    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape' && help.matches(':hover, :focus-within')) {
        help.classList.add('shut');
      }
    });
    help.addEventListener('pointerenter', open);
    help.addEventListener('focusin', open);
  }

  /* The update check (templates/confirm.html, check.html). These are the two places where this
     file reads the dashboard's own pages; it still sends nothing a form of the page would not
     send, and both work without it.

     A form that asks for a check only asks for its confirmation, which runs nothing. Its answer
     is read here and the confirmation shown in a dialog over this page, so that cancelling
     leaves the page as it was. The dialog's own form, the confirmed check, is the browser's to
     send: it opens the check's page. Whatever else the answer is (a refusal, an error page) is
     left to the browser too: the same form is sent again as a page would send it. */
  const asksCheck = (form) => /\/projects\/[0-9]+\/previews$/.test(new URL(form.action).pathname)
    && !form.elements.confirm;
  let asking = false;

  document.addEventListener('submit', (event) => {
    const form = event.target;
    if (event.defaultPrevented || form.dataset.plain || !asksCheck(form)) return;
    if (typeof HTMLDialogElement !== 'function') return;
    event.preventDefault();
    if (asking) return;
    asking = true;
    const opener = event.submitter;
    const plain = () => { form.dataset.plain = '1'; form.requestSubmit(opener); };
    let body;
    try {
      body = new URLSearchParams(new FormData(form, opener)); /* the button's own name and value */
    } catch (error) {
      asking = false;
      plain();
      return;
    }
    fetch(form.action, { method: 'POST', body })
      .then((response) => response.text())
      .then((html) => {
        const answer = new DOMParser().parseFromString(html, 'text/html');
        const sheet = answer.getElementById('confirm-check');
        if (!sheet) { plain(); return; }
        const dialog = document.createElement('dialog');
        dialog.className = 'confirm-modal';
        dialog.setAttribute('aria-labelledby', 'confirm-title');
        dialog.append(document.adoptNode(sheet));
        dialog.addEventListener('click', (click) => {
          if (click.target.closest('[data-cancel]')) { click.preventDefault(); dialog.close(); }
        });
        /* Esc closes it as the cancel link does; the focus goes back to the button. */
        dialog.addEventListener('close', () => { dialog.remove(); if (opener) opener.focus(); });
        document.body.append(dialog);
        dialog.showModal();
        /* On the question, not on a button: Enter pressed twice must not start the check. */
        dialog.querySelector('#confirm-title').focus();
      })
      .catch(plain)
      .finally(() => { asking = false; });
  });

  /* A running check's page: this address is read again and what it says now replaces what the
     page shows, with nothing made up in between. A page without the progress is a check that
     ended, and the browser loads it. The words for a screen reader are said when they change. */
  const watch = () => {
    const shown = document.getElementById('check-progress');
    if (!shown) return;
    const lost = document.getElementById('check-lost');
    const wait = () => setTimeout(watch, 1000 * (Number(shown.dataset.refresh) || 3));
    fetch(location.href)
      .then((response) => response.text())
      .then((html) => {
        const answer = new DOMParser().parseFromString(html, 'text/html');
        const next = answer.getElementById('check-progress');
        if (!next) { location.reload(); return; }
        const said = next.querySelector('#check-said').textContent;
        if (said !== shown.querySelector('#check-said').textContent) say(said);
        shown.replaceWith(document.adoptNode(next));
        if (lost) lost.hidden = true;
        wait();
      })
      .catch(() => { if (lost) lost.hidden = false; wait(); });
  };
  const progress = document.getElementById('check-progress');
  if (progress) setTimeout(watch, 1000 * (Number(progress.dataset.refresh) || 3));

  /* A page the browser's back button brings back as it was left: nothing runs any more. */
  window.addEventListener('pageshow', (event) => { if (event.persisted) stop(); });
})();
