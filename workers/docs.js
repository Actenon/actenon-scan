/**
 * Cloudflare Worker — redirects to the actenon-scan GitHub repo.
 *
 * This Worker exists so the Cloudflare Workers and Pages GitHub App
 * (installed at the org level) can build successfully on every push.
 * Without a Worker entry point, the "Workers Builds" check fails on
 * every commit.
 *
 * The Worker is a 301 redirect to the GitHub repo. Useful for anyone
 * who hits the Workers URL (e.g. actenon-scan.workers.dev).
 */

export default {
  async fetch(request, env) {
    const githubUrl = env.GITHUB_URL || "https://github.com/Actenon/actenon-scan";
    return Response.redirect(githubUrl, 301);
  },
};
