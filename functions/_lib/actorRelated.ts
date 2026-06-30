/** Related IPs among the current page only — avoids scanning the full events window. */
export function relatedIpsAmongActors(
  ips: string[],
  trapSeqByIp: Map<string, string[]>,
  uaByIp: Map<string, string>,
  minSharedTraps = 2
): Map<string, Set<string>> {
  const siblingsByIp = new Map<string, Set<string>>();
  const trapSets = new Map(ips.map((ip) => [ip, new Set(trapSeqByIp.get(ip) ?? [])]));

  for (let i = 0; i < ips.length; i += 1) {
    for (let j = i + 1; j < ips.length; j += 1) {
      const ipA = ips[i] as string;
      const ipB = ips[j] as string;
      const uaA = uaByIp.get(ipA);
      const uaB = uaByIp.get(ipB);
      if (!uaA || !uaB || uaA !== uaB) continue;

      const trapsA = trapSets.get(ipA)!;
      const trapsB = trapSets.get(ipB)!;
      let shared = 0;
      for (const trap of trapsA) {
        if (trapsB.has(trap)) shared += 1;
      }
      if (shared < minSharedTraps) continue;

      const setA = siblingsByIp.get(ipA) ?? new Set<string>();
      setA.add(ipB);
      siblingsByIp.set(ipA, setA);

      const setB = siblingsByIp.get(ipB) ?? new Set<string>();
      setB.add(ipA);
      siblingsByIp.set(ipB, setB);
    }
  }

  return siblingsByIp;
}
