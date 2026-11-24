/* The dashboard's one script (docs/dashboard-design.md). Every page works without it: a form is
   still sent by the browser, to the same address and with the same fields, and the answer is a
   page as before. This file sends no request and reads none. It does these things:
   - the button of a request that takes time says so while it runs (data-busy-label);
   - a second such request is not sent meanwhile: the server runs one at a time, and its refusal
     would replace the answer of the first;
   - after an update check from the packages view, the focus goes to the first candidate that
     check returned, or to the line that says it returned none (data-landing);
   - while such a request runs, the rail's theme form is not sent from this page either: leaving
     would lose the answer of the request, such as the result of an apply;
   - a project of the rail that takes the focus is brought wholly into view.
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
    if (!button || !button.dataset.busyLabel) return; /* a search or a typed path: at once */
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

  /* A page the browser's back button brings back as it was left: nothing runs any more. */
  window.addEventListener('pageshow', (event) => { if (event.persisted) stop(); });

  const status = document.getElementById('check-status');
  if (status && status.dataset.landing) {
    /* The place the fragment of the address names: the candidate the check opened, or the
       line that says it opened none. The browser scrolls to it by itself, as it does without
       this script: a scroll made from here ended at another place in WebKit at times. */
    const picked = status.dataset.landing === 'picked' && document.getElementById('picked');
    (picked || status).focus({ preventScroll: true });
    say(status.textContent.replace(/\s+/g, ' ').trim());
    /* Once: the address without the check and without that fragment, so that a reload or a
       way back moves no focus and says nothing again. It still names what is open (item).
       Not before the browser has gone to the fragment, which can be just after the load. */
    window.addEventListener('load', () => setTimeout(() => {
      const url = new URL(location.href);
      url.searchParams.delete('checked');
      url.hash = '';
      history.replaceState(null, '', url);
    }));
  }
})();
