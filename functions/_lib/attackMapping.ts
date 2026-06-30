export interface AttackTechnique {
  id: string;
  name: string;
  tactic: string;
  url: string;
}

export interface AttackEventInput {
  protocol: string;
  trap: string;
  http_path?: string | null;
  has_credentials?: boolean;
  confidence_reasons?: string[];
}

type TechniqueDef = Omit<AttackTechnique, "url">;

const CATALOG: Record<string, TechniqueDef> = {
  "T1595.002": {
    id: "T1595.002",
    name: "Active Scanning: Vulnerability Scanning",
    tactic: "reconnaissance"
  },
  "T1110": {
    id: "T1110",
    name: "Brute Force",
    tactic: "credential-access"
  },
  "T1110.001": {
    id: "T1110.001",
    name: "Brute Force: Password Guessing",
    tactic: "credential-access"
  },
  "T1190": {
    id: "T1190",
    name: "Exploit Public-Facing Application",
    tactic: "initial-access"
  },
  "T1059": {
    id: "T1059",
    name: "Command and Scripting Interpreter",
    tactic: "execution"
  },
  "T1078": {
    id: "T1078",
    name: "Valid Accounts",
    tactic: "persistence"
  }
};

const CONFIDENCE_REASON_MAP: Record<string, string[]> = {
  scanner_user_agent: ["T1595.002"],
  credential_attempt: ["T1110"],
  exploit_path: ["T1190"],
  sensitive_path: ["T1110"]
};

const CREDENTIAL_PATH_PATTERN =
  /(wp-login|wp-admin|phpmyadmin|\.env|\.git|admin|login|auth|signin|passwd|credential)/i;
const PATH_TRAVERSAL_PATTERN = /(\.\.\/|%2e%2e)/i;
const SQL_INJECTION_PATTERN = /(select.+from|union.+select)/i;
const SHELL_CMD_PATTERN = /(cmd=|exec=|shell)/i;

function techniqueUrl(id: string): string {
  const [base, sub] = id.split(".");
  return sub
    ? `https://attack.mitre.org/techniques/${base}/${sub}/`
    : `https://attack.mitre.org/techniques/${base}/`;
}

export function techniqueById(id: string): AttackTechnique | null {
  const entry = CATALOG[id];
  if (!entry) return null;
  return { ...entry, url: techniqueUrl(id) };
}

function addTechniques(ids: Set<string>, techniqueIds: string[]): void {
  for (const id of techniqueIds) {
    if (CATALOG[id]) ids.add(id);
  }
}

export function mapConfidenceReasonToTechniques(reason: string): AttackTechnique[] {
  return (CONFIDENCE_REASON_MAP[reason] ?? [])
    .map((id) => techniqueById(id))
    .filter((technique): technique is AttackTechnique => technique !== null);
}

export function mapEventToTechniques(event: AttackEventInput): AttackTechnique[] {
  const ids = new Set<string>();

  for (const reason of event.confidence_reasons ?? []) {
    addTechniques(ids, CONFIDENCE_REASON_MAP[reason] ?? []);
  }

  const path = event.http_path ?? "";
  if (path) {
    if (CREDENTIAL_PATH_PATTERN.test(path)) ids.add("T1110");
    if (PATH_TRAVERSAL_PATTERN.test(path)) ids.add("T1190");
    if (SQL_INJECTION_PATTERN.test(path)) ids.add("T1190");
    if (SHELL_CMD_PATTERN.test(path)) ids.add("T1059");
  }

  if (event.has_credentials) {
    ids.add("T1110.001");
  }

  const protocol = event.protocol.toLowerCase();
  const trap = event.trap.toLowerCase();
  const isFtpSmtpLogin =
    protocol === "ftp" ||
    protocol === "smtp" ||
    trap.includes("ftp-login") ||
    trap.includes("smtp") ||
    (trap.includes("login") && (protocol === "ftp" || protocol === "smtp"));

  if (isFtpSmtpLogin && (event.has_credentials || trap.includes("login") || trap.includes("relay"))) {
    ids.add("T1078");
  }

  return [...ids]
    .sort()
    .map((id) => techniqueById(id))
    .filter((technique): technique is AttackTechnique => technique !== null);
}

export function attackTechniqueIds(event: AttackEventInput): string[] {
  return mapEventToTechniques(event).map((technique) => technique.id);
}
