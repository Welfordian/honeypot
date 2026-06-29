export interface TcpTrapDefinition {
  protocol: string;
  trap: string;
  listenPort: number;
  publicPort: number;
  banner?: string | Buffer;
  response?: string | Buffer;
  closeAfterMs: number;
  tags: string[];
}

export interface UdpTrapDefinition {
  protocol: string;
  trap: string;
  listenPort: number;
  publicPort: number;
  response?: string | Buffer;
  tags: string[];
}

export const TCP_TRAPS: TcpTrapDefinition[] = [
  {
    protocol: "ftp",
    trap: "ftp-login",
    listenPort: 2121,
    publicPort: 21,
    banner: "220 File service ready\r\n",
    response: "530 Authentication failed\r\n",
    closeAfterMs: 8000,
    tags: ["ftp", "login"]
  },
  {
    protocol: "smtp",
    trap: "smtp-relay",
    listenPort: 2525,
    publicPort: 25,
    banner: "220 mail.honeypot.invalid ESMTP Postfix\r\n",
    response: "554 5.7.1 Relay access denied\r\n",
    closeAfterMs: 8000,
    tags: ["smtp", "relay"]
  },
  {
    protocol: "http-proxy",
    trap: "http-proxy",
    listenPort: 18080,
    publicPort: 8080,
    banner: "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\n\r\n",
    closeAfterMs: 6000,
    tags: ["proxy"]
  },
  {
    protocol: "mysql",
    trap: "mysql-login",
    listenPort: 3306,
    publicPort: 3306,
    banner: Buffer.from("4a0000000a382e302e3332001a0000003f2d4a424c6f435600ffff210200ff8115000000000000000000006545626a6f5d636545645f3e006d7973716c5f6e61746976655f70617373776f726400", "hex"),
    response: Buffer.from("ff15042332383030304163636573732064656e69656400", "hex"),
    closeAfterMs: 5000,
    tags: ["database", "mysql"]
  },
  {
    protocol: "mssql",
    trap: "mssql-login",
    listenPort: 1433,
    publicPort: 1433,
    response: Buffer.from("0401002500000100000000150006010025000102", "hex"),
    closeAfterMs: 5000,
    tags: ["database", "mssql"]
  },
  {
    protocol: "redis",
    trap: "redis",
    listenPort: 6379,
    publicPort: 6379,
    response: "-NOAUTH Authentication required.\r\n",
    closeAfterMs: 5000,
    tags: ["database", "redis"]
  },
  {
    protocol: "rdp",
    trap: "rdp",
    listenPort: 3389,
    publicPort: 3389,
    response: Buffer.from("030000130ed0000012340002000800000000", "hex"),
    closeAfterMs: 5000,
    tags: ["rdp"]
  },
  {
    protocol: "smb",
    trap: "smb",
    listenPort: 4445,
    publicPort: 445,
    response: Buffer.from("00000055ff534d427200000000800000000000000000000000000000000000000000000000", "hex"),
    closeAfterMs: 5000,
    tags: ["smb"]
  },
  {
    protocol: "vnc",
    trap: "vnc",
    listenPort: 5900,
    publicPort: 5900,
    banner: "RFB 003.008\n",
    response: Buffer.from([0x00, 0x00, 0x00, 0x01, 0x02]),
    closeAfterMs: 5000,
    tags: ["vnc"]
  }
];

export const UDP_TRAPS: UdpTrapDefinition[] = [
  {
    protocol: "snmp",
    trap: "snmp",
    listenPort: 1161,
    publicPort: 161,
    tags: ["snmp", "udp"]
  },
  {
    protocol: "tftp",
    trap: "tftp",
    listenPort: 6969,
    publicPort: 69,
    response: Buffer.from([0x00, 0x05, 0x00, 0x02, ...Buffer.from("Access denied"), 0x00]),
    tags: ["tftp", "udp"]
  }
];
