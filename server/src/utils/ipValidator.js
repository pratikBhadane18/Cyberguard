const dns = require('dns').promises;
const ipaddr = require('ipaddr.js');
const { SsrfError } = require('../errors/SsrfError');

/**
 * Named ranges that ipaddr.js identifies and that we consider private/internal.
 *
 * ipaddr.js addr.range() returns one of these strings for well-known CIDR blocks.
 * Any range NOT listed as 'unicast' is considered unsafe for outbound scanning.
 *
 * IPv4 ranges blocked:
 *   loopback        127.0.0.0/8
 *   private         10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
 *   linkLocal       169.254.0.0/16  (APIPA / AWS metadata endpoint)
 *   multicast       224.0.0.0/4
 *   broadcast       255.255.255.255
 *   unspecified     0.0.0.0
 *   carrierGradeNat 100.64.0.0/10   (RFC 6598 shared address space)
 *   reserved        various IANA reserved ranges
 *
 * IPv6 ranges blocked:
 *   loopback        ::1
 *   uniqueLocal     fc00::/7         (ULA — analogous to IPv4 private)
 *   linkLocal       fe80::/10
 *   multicast       ff00::/8
 *   unspecified     ::
 */
const BLOCKED_RANGES = new Set([
  'loopback',
  'private',
  'linkLocal',
  'multicast',
  'broadcast',
  'unspecified',
  'carrierGradeNat',
  'reserved',
  'uniqueLocal', // IPv6 ULA
]);

/**
 * Returns true if the given IP string resolves to a private, loopback,
 * link-local, multicast, or otherwise internal address.
 *
 * Accepts both IPv4 and IPv6 strings, and handles IPv4-mapped IPv6
 * addresses (e.g. ::ffff:127.0.0.1) by extracting the embedded IPv4 part.
 *
 * @param {string} ip
 * @returns {boolean}
 */
function isPrivateIp(ip) {
  try {
    let addr = ipaddr.parse(ip);

    // Unwrap IPv4-mapped IPv6 addresses (::ffff:192.168.x.x, etc.)
    if (addr.kind() === 'ipv6' && addr.isIPv4MappedAddress()) {
      addr = addr.toIPv4Address();
    }

    const range = addr.range();
    return BLOCKED_RANGES.has(range);
  } catch {
    // Unparseable IP strings are considered unsafe
    return true;
  }
}

/**
 * Resolves a hostname to its IP address(es) via the OS resolver and
 * verifies that none of them fall into a private/internal range.
 *
 * Throws SsrfError if any resolved address is blocked.
 *
 * ⚠️  DNS-rebinding limitation:
 * This check resolves the hostname once using dns.lookup (OS-level).
 * A malicious DNS server can return a safe public IP here, then serve
 * a private IP on the second lookup made inside the TCP stack during
 * the actual HTTP connection. Fully mitigating DNS rebinding requires a
 * custom HTTP agent that inspects the socket address after connect(), which
 * is out of scope for this implementation. This pre-resolution check
 * significantly raises the bar but should not be relied upon as the sole
 * control in high-risk environments.
 *
 * @param {string} hostname
 * @returns {Promise<void>}
 */
async function resolveAndValidate(hostname) {
  let addresses;

  try {
    // dns.lookup returns a single record; use dns.resolve4/6 for all addresses.
    // We use both to cover dual-stack hosts where possible.
    const [v4Results, v6Results] = await Promise.allSettled([
      dns.resolve4(hostname),
      dns.resolve6(hostname),
    ]);

    addresses = [
      ...(v4Results.status === 'fulfilled' ? v4Results.value : []),
      ...(v6Results.status === 'fulfilled' ? v6Results.value : []),
    ];
  } catch {
    // If all resolution attempts fail, fall back to dns.lookup so we can
    // still check numeric IPs or single-record hostnames.
    try {
      const result = await dns.lookup(hostname);
      addresses = [result.address];
    } catch {
      throw new SsrfError(`Could not resolve hostname: ${hostname}`);
    }
  }

  if (addresses.length === 0) {
    throw new SsrfError(`Could not resolve hostname: ${hostname}`);
  }

  for (const ip of addresses) {
    if (isPrivateIp(ip)) {
      throw new SsrfError(
        `Scanning private or internal addresses is not permitted.`
      );
    }
  }
}

module.exports = { isPrivateIp, resolveAndValidate };
