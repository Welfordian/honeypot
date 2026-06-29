export interface Decoy {
  trap: string;
  status: number;
  contentType: string;
  body: string;
  tags: string[];
}

function html(title: string, body: string): string {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="robots" content="noindex"><title>${title}</title><style>body{font-family:Arial,sans-serif;margin:2rem;background:#f6f8fb;color:#17202a}main{max-width:460px}input{display:block;margin:.5rem 0;padding:.55rem;width:100%;box-sizing:border-box}button{padding:.55rem .8rem}</style></head><body><main>${body}</main></body></html>`;
}

function decoySite(title = "DesktopC", active = "home"): string {
  const nav = ["home", "services", "support", "contact"]
    .map((item) => `<a class="${item === active ? "active" : ""}" href="${item === "home" ? "/" : `/${item}`}">${item}</a>`)
    .join("");
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${title}</title>
  <style>
    :root{font-family:Inter,Arial,sans-serif;color:#1e2a30;background:#f5f7f8;letter-spacing:0}
    body{margin:0}
    header{border-bottom:1px solid #dfe6e8;background:#fff}
    .bar{max-width:1040px;margin:auto;display:flex;align-items:center;justify-content:space-between;padding:18px 22px}
    .brand{font-weight:800;font-size:22px;color:#18333c}
    nav{display:flex;gap:18px}
    nav a{color:#52646b;text-decoration:none;text-transform:capitalize}
    nav a.active{color:#146c7c;font-weight:700}
    main{max-width:1040px;margin:auto;padding:48px 22px 72px}
    .hero{display:grid;grid-template-columns:minmax(0,1.2fr) minmax(260px,.8fr);gap:34px;align-items:center}
    h1{font-size:44px;line-height:1.05;margin:0 0 16px;color:#12252c}
    p{line-height:1.65;color:#52646b}
    .panel{background:#fff;border:1px solid #dfe6e8;border-radius:8px;padding:22px}
    .grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px;margin-top:30px}
    .card{background:#fff;border:1px solid #dfe6e8;border-radius:8px;padding:18px}
    .status{display:flex;justify-content:space-between;border-bottom:1px solid #edf1f2;padding:10px 0;color:#52646b}
    .status:last-child{border-bottom:0}
    form{display:grid;gap:10px}
    input,textarea{font:inherit;border:1px solid #cad5d8;border-radius:6px;padding:10px}
    button{font:inherit;border:0;border-radius:6px;background:#146c7c;color:#fff;padding:10px 14px}
    @media(max-width:760px){.hero,.grid{grid-template-columns:1fr}nav{gap:10px}h1{font-size:34px}}
  </style>
</head>
<body>
  <header><div class="bar"><div class="brand">DesktopC</div><nav>${nav}</nav></div></header>
  <main>
    <section class="hero">
      <div>
        <h1>Managed desktop support for small teams.</h1>
        <p>DesktopC helps independent offices keep workstations, printers, updates, backups, and everyday support requests moving without an in-house IT department.</p>
      </div>
      <div class="panel">
        <strong>Service status</strong>
        <div class="status"><span>Remote support</span><span>online</span></div>
        <div class="status"><span>Backup monitoring</span><span>normal</span></div>
        <div class="status"><span>Patch window</span><span>Sunday 02:00 UTC</span></div>
      </div>
    </section>
    <section class="grid">
      <div class="card"><strong>Endpoint care</strong><p>Routine checks for desktop health, patch status, and storage issues.</p></div>
      <div class="card"><strong>Help desk</strong><p>Simple support intake for common device and account problems.</p></div>
      <div class="card"><strong>Recovery planning</strong><p>Lightweight backup reviews and restore-readiness tracking.</p></div>
    </section>
  </main>
</body>
</html>`;
}

export function classifyPath(pathname: string): Decoy {
  const path = pathname.toLowerCase();

  if (path === "/" || path === "/home" || path === "/index.html") {
    return {
      trap: "desktopc-homepage",
      status: 200,
      contentType: "text/html",
      body: decoySite("DesktopC - Managed Desktop Support", "home"),
      tags: ["decoy-site", "browser"]
    };
  }

  if (path === "/services" || path === "/support") {
    return {
      trap: "desktopc-content",
      status: 200,
      contentType: "text/html",
      body: decoySite("DesktopC Services", path.slice(1)),
      tags: ["decoy-site", "browser"]
    };
  }

  if (path === "/contact") {
    return {
      trap: "desktopc-contact",
      status: 200,
      contentType: "text/html",
      body: `${decoySite("DesktopC Contact", "contact").replace("</main>", `<section class="panel" style="margin-top:24px"><form method="post" action="/contact"><input name="name" placeholder="Name"><input name="email" placeholder="Email"><textarea name="message" placeholder="How can we help?"></textarea><button>Send</button></form></section></main>`)}`,
      tags: ["decoy-site", "contact-form"]
    };
  }

  if (path === "/.env" || path.endsWith("/.env")) {
    return {
      trap: "env-file",
      status: 200,
      contentType: "text/plain",
      body: "APP_ENV=production\nAPP_DEBUG=false\nDB_HOST=127.0.0.1\nDB_PASSWORD=redacted\n",
      tags: ["config-leak", "env"]
    };
  }

  if (path.startsWith("/.git")) {
    return {
      trap: "git-leak",
      status: 200,
      contentType: "text/plain",
      body: "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n[remote \"origin\"]\n\turl = git@example.invalid:app/site.git\n",
      tags: ["config-leak", "git"]
    };
  }

  if (path.includes("wp-login") || path.includes("wordpress") || path.includes("wp-admin")) {
    return {
      trap: "wordpress-login",
      status: 200,
      contentType: "text/html",
      body: html("WordPress Login", "<h1>WordPress</h1><form method=\"post\"><input name=\"log\" autocomplete=\"off\"><input name=\"pwd\" type=\"password\"><button>Log In</button></form>"),
      tags: ["cms", "login"]
    };
  }

  if (path.includes("phpmyadmin") || path.includes("pma")) {
    return {
      trap: "phpmyadmin",
      status: 200,
      contentType: "text/html",
      body: html("phpMyAdmin", "<h1>phpMyAdmin</h1><form method=\"post\"><input name=\"pma_username\"><input name=\"pma_password\" type=\"password\"><button>Go</button></form>"),
      tags: ["database", "login"]
    };
  }

  if (path.includes("jenkins")) {
    return {
      trap: "jenkins",
      status: 403,
      contentType: "text/html",
      body: html("Jenkins", "<h1>Jenkins</h1><p>Authentication required</p>"),
      tags: ["ci", "admin"]
    };
  }

  if (path.includes("grafana")) {
    return {
      trap: "grafana",
      status: 200,
      contentType: "text/html",
      body: html("Grafana", "<h1>Grafana</h1><form method=\"post\"><input name=\"user\"><input name=\"password\" type=\"password\"><button>Sign in</button></form>"),
      tags: ["monitoring", "login"]
    };
  }

  if (path.includes("kubernetes") || path.includes("/api/v1/namespaces") || path.includes("/apis/")) {
    return {
      trap: "kubernetes-api",
      status: 401,
      contentType: "application/json",
      body: JSON.stringify({ kind: "Status", apiVersion: "v1", status: "Failure", reason: "Unauthorized", code: 401 }),
      tags: ["kubernetes", "api"]
    };
  }

  if (path.includes("docker") || path === "/containers/json" || path === "/version") {
    return {
      trap: "docker-api",
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ Version: "24.0.7", ApiVersion: "1.43", GitCommit: "decoy", Os: "linux", Arch: "amd64" }),
      tags: ["docker", "api"]
    };
  }

  if (path.includes("latest/meta-data") || path.includes("metadata/instance")) {
    return {
      trap: "cloud-metadata",
      status: 200,
      contentType: "text/plain",
      body: "ami-id\nhostname\niam/security-credentials/\nlocal-ipv4\n",
      tags: ["cloud", "metadata"]
    };
  }

  if (path.includes("actuator") || path.includes("laravel") || path.includes("_ignition")) {
    return {
      trap: "framework-probe",
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ status: "UP", components: { db: { status: "UP" } } }),
      tags: ["framework", "api"]
    };
  }

  if (path.startsWith("/api/")) {
    return {
      trap: "generic-api",
      status: 401,
      contentType: "application/json",
      body: JSON.stringify({ error: "unauthorized", message: "missing bearer token" }),
      tags: ["api"]
    };
  }

  if (path.includes("admin") || path.includes("login")) {
    return {
      trap: "admin-login",
      status: 200,
      contentType: "text/html",
      body: html("Admin Console", "<h1>Admin Console</h1><form method=\"post\"><input name=\"username\" autocomplete=\"off\"><input name=\"password\" type=\"password\"><button>Sign in</button></form>"),
      tags: ["admin", "login"]
    };
  }

  return {
    trap: "generic-web-probe",
    status: 404,
    contentType: "text/html",
    body: html("Not Found", "<h1>404</h1><p>The requested resource was not found.</p>"),
    tags: ["web"]
  };
}
