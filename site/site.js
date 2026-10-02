/* global document, window */
// attestium.com: theme, menus, copy buttons, tooltips, table of contents.
(() => {
  const root = document.documentElement;
  root.classList.add('js');
  const byId = id => document.querySelector(`[id="${id}"]`);

  const live = document.createElement('div');
  live.className = 'sr-only';
  live.setAttribute('aria-live', 'polite');
  document.body.append(live);

  // Theme: system, light or dark; the choice is kept in localStorage.
  const toggle = document.querySelector('.theme-toggle');
  const choices = ['system', 'light', 'dark'];
  let choice = root.dataset.theme || 'system';
  const applyTheme = () => {
    if (choice === 'system') {
      delete root.dataset.theme;
    } else {
      root.dataset.theme = choice;
    }

    if (toggle) {
      toggle.dataset.choice = choice;
      toggle.title = `Theme: ${choice}`;
      toggle.setAttribute('aria-label', `Theme: ${choice}. Change theme`);
    }
  };

  applyTheme();
  if (toggle) {
    toggle.addEventListener('click', () => {
      choice = choices[(choices.indexOf(choice) + 1) % choices.length];
      try {
        if (choice === 'system') {
          localStorage.removeItem('theme');
        } else {
          localStorage.setItem('theme', choice);
        }
      } catch {}

      applyTheme();
      live.textContent = `Theme: ${choice}`;
    });
  }

  // Disclosure menus: the header navigation and the docs sidebar on small screens.
  const menus = [...document.querySelectorAll('.menu-toggle, .side-toggle')];
  const setMenu = (button, open) => {
    button.setAttribute('aria-expanded', String(open));
    byId(button.getAttribute('aria-controls')).classList.toggle('open', open);
  };

  for (const button of menus) {
    button.addEventListener('click', () => setMenu(button, button.getAttribute('aria-expanded') !== 'true'));
  }

  document.addEventListener('click', event => {
    for (const button of menus) {
      const panel = byId(button.getAttribute('aria-controls'));
      if (button.getAttribute('aria-expanded') === 'true' && !button.contains(event.target) && !panel.contains(event.target)) {
        setMenu(button, false);
      }
    }
  });

  // Copy buttons: a data-copy value, or the code block they sit in.
  const copyText = async text => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const area = document.createElement('textarea');
      area.value = text;
      area.setAttribute('readonly', '');
      area.style.position = 'fixed';
      area.style.opacity = '0';
      document.body.append(area);
      area.select();
      document.execCommand('copy');
      area.remove();
    }
  };

  for (const button of document.querySelectorAll('.copy')) {
    let timer;
    button.addEventListener('click', async () => {
      const block = button.closest('.code');
      const text = button.dataset.copy || (block ? block.querySelector('pre').textContent : '');
      await copyText(text);
      button.textContent = 'Copied';
      button.classList.add('done');
      live.textContent = 'Copied to clipboard';
      clearTimeout(timer);
      timer = setTimeout(() => {
        button.textContent = 'Copy';
        button.classList.remove('done');
      }, 1600);
    });
  }

  // Tooltips: on hover and keyboard focus, on tap for touch; Escape closes.
  let open = null;
  let pointer = 'mouse';
  let wasOpen = false;
  const place = (trigger, tip) => {
    tip.style.position = 'fixed';
    tip.style.left = '0px';
    tip.style.top = '0px';
    const box = trigger.getClientRects()[0] || trigger.getBoundingClientRect();
    const size = tip.getBoundingClientRect();
    const width = root.clientWidth;
    const left = Math.max(8, Math.min(box.left + (box.width / 2) - (size.width / 2), width - size.width - 8));
    let top = box.bottom + 8;
    if (top + size.height > window.innerHeight - 8 && box.top - size.height - 8 > 8) {
      top = box.top - size.height - 8;
    }

    tip.style.left = `${Math.round(left)}px`;
    tip.style.top = `${Math.round(top)}px`;
  };

  const hide = () => {
    if (open) {
      open.tip.classList.remove('open');
      open.trigger.classList.remove('active');
      open = null;
    }
  };

  const show = (trigger, tip) => {
    if (open && open.tip !== tip) {
      hide();
    }

    tip.classList.add('open');
    trigger.classList.add('active');
    place(trigger, tip);
    open = {trigger, tip};
  };

  for (const trigger of document.querySelectorAll('[aria-describedby]')) {
    const tip = byId(trigger.getAttribute('aria-describedby'));
    if (!tip || !tip.classList.contains('tip')) {
      continue;
    }

    trigger.addEventListener('pointerenter', event => {
      if (event.pointerType === 'mouse') {
        show(trigger, tip);
      }
    });
    trigger.addEventListener('pointerleave', event => {
      if (event.pointerType === 'mouse' && document.activeElement !== trigger) {
        hide();
      }
    });
    trigger.addEventListener('focus', () => show(trigger, tip));
    trigger.addEventListener('blur', () => {
      if (open && open.trigger === trigger) {
        hide();
      }
    });
    trigger.addEventListener('click', event => {
      // On touch, the first tap shows the tooltip; a second tap follows the link.
      if (pointer !== 'mouse' && !(wasOpen && trigger.tagName === 'A')) {
        event.preventDefault();
        show(trigger, tip);
      }
    });
  }

  document.addEventListener('pointerdown', event => {
    pointer = event.pointerType || 'mouse';
    wasOpen = Boolean(open && open.trigger.contains(event.target));
    if (open && !open.trigger.contains(event.target)) {
      hide();
    }
  }, true);
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape') {
      hide();
      for (const button of menus) {
        if (button.getAttribute('aria-expanded') === 'true') {
          setMenu(button, false);
          button.focus();
        }
      }
    }
  });

  // Table of contents: highlight the section being read.
  const header = document.querySelector('.site-header');
  const tocLinks = [...document.querySelectorAll('.toc a')];
  const sections = tocLinks.map(link => byId(decodeURIComponent(link.hash.slice(1))));
  let frame = 0;
  const spy = () => {
    frame = 0;
    const offset = (header ? header.offsetHeight : 0) + 32;
    let index = 0;
    for (const [i, section] of sections.entries()) {
      if (section && section.getBoundingClientRect().top - offset <= 0) {
        index = i;
      }
    }

    if (window.innerHeight + window.scrollY >= document.body.scrollHeight - 4) {
      index = sections.length - 1;
    }

    for (const [i, link] of tocLinks.entries()) {
      link.classList.toggle('active', i === index);
    }
  };

  const onScroll = () => {
    if (open) {
      place(open.trigger, open.tip);
    }

    if (tocLinks.length > 0 && !frame) {
      frame = globalThis.requestAnimationFrame(spy);
    }
  };

  window.addEventListener('scroll', onScroll, {passive: true});
  window.addEventListener('resize', onScroll, {passive: true});
  if (tocLinks.length > 0) {
    spy();
  }

  // Keep the current page visible in a long sidebar.
  const nav = document.querySelector('.sidebar');
  const current = nav && nav.querySelector('[aria-current="page"]');
  if (current && nav.scrollHeight > nav.clientHeight && current.offsetTop > nav.clientHeight * 0.6) {
    nav.scrollTop = current.offsetTop - (nav.clientHeight / 3);
  }
})();
