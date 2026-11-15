# Multi-context UI: design

Approved in chat on 2026-11-15. It follows the "Product focus" section of `2026-11-13-kubedelos-design.md`: kubedelos
is UI-first, and the laptop UI should switch between kube-contexts and scan any of them.

## Intent

People who run kubedelos usually have several clusters. Today `kubedelos ui` shows one context, fixed at startup, and
switching means restarting the UI. After this change, a single UI shows every cluster: you pick one in the sidebar,
look at its results, and scan it.

- **Goals:**
  - view any context's runs without a restart;
  - start a scan of any context that is in the kubeconfig;
  - keep two tabs on two clusters independent of each other.
- **Non-goals:**
  - identifying clusters by their own UID. That follows as its own PR, because it touches every history query.
  - more than one scan at a time.
  - in-cluster mode, which Phase 3 adds and which serves a single cluster.
- **Anti-goals:**
  - a scan of a cluster other than the one the page names;
  - a context switch that silently keeps showing the old cluster's data;
  - any JavaScript beyond the htmx already on the Scans page;
  - any change to the CSP.

## Approaches considered

1. **The context travels in the URL, as `?context=` (chosen).** Links can be bookmarked, and two tabs can show two
   clusters. Every link the UI builds has to carry the context. Most links go through one helper, so that is
   mechanical work.
2. **The selected context is kept per session, server side.** Links would need no change, but every tab of a session
   would switch together, and a reload of another tab would quietly show the other cluster. That is the second
   anti-goal.
3. **The context goes in a path prefix, `/c/<context>/findings`.** It is clean for short names. Context names are often
   ARNs or contain `/` and `:` (`arn:aws:eks:…:cluster/x`), so the prefix would need its own encoding scheme for no gain
   over a query parameter.

## Design

- **Known contexts:** the contexts in the kubeconfig, plus the contexts that have runs in the database. A context that
  exists only in the database can be viewed but not scanned.
  - The kubeconfig is re-read on every page, so a context added while the UI runs shows up.
  - Reading the kubeconfig never runs a context's login plugin.
  - The app takes the listing function as a parameter, so tests can inject one.
- **The shown context:** the `context` query parameter, or by default the context the UI started with. An unknown
  value gets the 404 error page "unknown context". Every page reads the shown context from `request.state.context`;
  `app.state.context` stays the default.
- **Links:** every link and form target the UI builds carries `context=` when the shown context isn't the default.
  This covers the nav, the wordmark, findings, the dashboard and scans links, the findings filter form, and the "Scans
  page" link. Links for the default context stay as they are now.
- **The switcher:** the sidebar context card becomes a `<details>` element.
  - The summary is the shown context with its freshness dot.
  - The open list links every known context to the same page, without the other query parameters, because run IDs
    and filters belong to one cluster.
  - Each entry shows when its newest result run finished ("2 h ago", "never").
  - When there is only one known context, the card stays as it is today.
- **Scans:**
  - The form posts a hidden `context` field, and the button reads "Scan <context>".
  - `POST /scans` accepts only a context that is in the kubeconfig at the moment of the click. Otherwise it answers
    400 "<context> is not in your kubeconfig".
  - `ScanRunner.start(overrides, context)` takes the context per call, and it is applied last, as it is today.
  - Still one scan at a time across all contexts.
  - `JobView` gains the scan's context. The readout names it ("Scanning prod-eu"), and when it isn't the shown context
    it links to that context's Scans page.
  - Cancel and progress stay global, because there is only one job.
- **History and run lookups:** these are unchanged. They stay keyed by the context name, and they use the shown
  context instead of the startup one.
- **Docs:** the README explains the switcher. It also explains that a scan runs the context's kubeconfig login, as
  kubectl does. A login that needs a browser or a device code happens in the terminal running `kubedelos ui`, and the
  scan fails with an error if nobody completes it.

## Left to the builder

- The CSS for the open list.
- The exact copy, which follows the existing tone.
- How the listing function caches, if at all.
