/** Site footer: brand, one-liner, and the GitHub link. */

import { Link } from "../router";

const GITHUB_URL = "https://github.com/SuperstrongBE/signbox";

export function Footer() {
  return (
    <footer className="sitefoot">
      <div className="footinner">
        <Link to="/" className="footbrand">
          <span className="brandmark" aria-hidden="true" />
          SignBox
        </Link>
        <span className="footmut">controlled signing for autonomous agents · on XPR Network</span>
        <nav className="footnav">
          <Link to="/getting-started">Getting started</Link>
          <Link to="/my-agents">My agents</Link>
          <a href={GITHUB_URL} target="_blank" rel="noreferrer">GitHub ↗</a>
        </nav>
      </div>
    </footer>
  );
}
