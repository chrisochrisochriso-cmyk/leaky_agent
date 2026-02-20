// leaky_agent — configuration
// Update all values marked REPLACE_ME before deploying.

const CONFIG = {
  // GitHub repo that hosts this page (owner/repo)
  GITHUB_REPO: 'chrisochrisochriso-cmyk/leaky_agent',

  // Issue number of the manually-created pinned "Breach Log" issue.
  // Create it at: https://github.com/[repo]/issues/new
  // Title: "📊 Breach Event Log (Do Not Close)"
  // Leave body blank — comments are the data.
  BREACH_LOG_ISSUE: 1,

  // GitHub personal access token with ONLY 'public_repo' + 'issues:write' scope.
  // Generate at: https://github.com/settings/tokens/new
  // This token is public (client-side). Scope-restrict it so the worst
  // a bad actor can do is spam comments on your one public issue.
  PUBLIC_TOKEN: 'github_pat_REPLACE_ME',

  // Prefix for canary tokens shown in breach reports
  CANARY_PREFIX: 'BREACH',

  // One GitHub comment per browser per this many ms (default: 1 hour).
  // Prevents a single visitor from burning through the ~500/hr secondary cap.
  POST_COOLDOWN_MS: 60 * 60 * 1000,

  // Max events kept in localStorage for local stats display
  MAX_LOCAL_EVENTS: 100,
};
