/*!
 * cookie
 * Copyright(c) 2012-2014 Roman Shtylman
 * Copyright(c) 2015 Douglas Christopher Wilson
 * MIT Licensed
 */

'use strict';

/**
 * Module exports.
 * @public
 */

const cookie = {
    "parse" : parse,
    "serialize" : serialize,
}
/**
 * Module variables.
 * @private
 */

var __toString = Object.prototype.toString

/**
 * RegExp to match field-content in RFC 7230 sec 3.2
 *
 * field-content = field-vchar [ 1*( SP / HTAB ) field-vchar ]
 * field-vchar   = VCHAR / obs-text
 * obs-text      = %x80-FF
 */

var fieldContentRegExp = /^[\u0009\u0020-\u007e\u0080-\u00ff]+$/;

/**
 * Parse a cookie header.
 *
 * Parse the given cookie header string into an object
 * The object has the various cookies as keys(names) => values
 *
 * @param {string} str
 * @param {object} [options]
 * @return {object}
 * @public
 */

function parse(str, options) {
  if (typeof str !== 'string') {
    throw new TypeError('argument str must be a string');
  }

  var obj = {}
  var opt = options || {};
  var dec = opt.decode || decode;

  var index = 0
  while (index < str.length) {
    var eqIdx = str.indexOf('=', index)

    // no more cookie pairs
    if (eqIdx === -1) {
      break
    }

    var endIdx = str.indexOf(';', index)

    if (endIdx === -1) {
      endIdx = str.length
    } else if (endIdx < eqIdx) {
      // backtrack on prior semicolon
      index = str.lastIndexOf(';', eqIdx - 1) + 1
      continue
    }

    var key = str.slice(index, eqIdx).trim()

    // only assign once
    if (undefined === obj[key]) {
      var val = str.slice(eqIdx + 1, endIdx).trim()

      // quoted values
      if (val.charCodeAt(0) === 0x22) {
        val = val.slice(1, -1)
      }

      obj[key] = tryDecode(val, dec);
    }

    index = endIdx + 1
  }

  return obj;
}

/**
 * Serialize data into a cookie header.
 *
 * Serialize the a name value pair into a cookie string suitable for
 * http headers. An optional options object specified cookie parameters.
 *
 * serialize('foo', 'bar', { httpOnly: true })
 *   => "foo=bar; httpOnly"
 *
 * @param {string} name
 * @param {string} val
 * @param {object} [options]
 * @return {string}
 * @public
 */

function serialize(name, val, options) {
  var opt = options || {};
  var enc = opt.encode || encode;

  if (typeof enc !== 'function') {
    throw new TypeError('option encode is invalid');
  }

  if (!fieldContentRegExp.test(name)) {
    throw new TypeError('argument name is invalid');
  }

  var value = enc(val);

  if (value && !fieldContentRegExp.test(value)) {
    throw new TypeError('argument val is invalid');
  }

  var str = name + '=' + value;

  if (null != opt.maxAge) {
    var maxAge = opt.maxAge - 0;

    if (isNaN(maxAge) || !isFinite(maxAge)) {
      throw new TypeError('option maxAge is invalid')
    }

    str += '; Max-Age=' + Math.floor(maxAge);
  }

  if (opt.domain) {
    if (!fieldContentRegExp.test(opt.domain)) {
      throw new TypeError('option domain is invalid');
    }

    str += '; Domain=' + opt.domain;
  }

  if (opt.path) {
    if (!fieldContentRegExp.test(opt.path)) {
      throw new TypeError('option path is invalid');
    }

    str += '; Path=' + opt.path;
  }

  if (opt.expires) {
    var expires = opt.expires

    if (!isDate(expires) || isNaN(expires.valueOf())) {
      throw new TypeError('option expires is invalid');
    }

    str += '; Expires=' + expires.toUTCString()
  }

  if (opt.httpOnly) {
    str += '; HttpOnly';
  }

  if (opt.secure) {
    str += '; Secure';
  }

  if (opt.priority) {
    var priority = typeof opt.priority === 'string'
      ? opt.priority.toLowerCase()
      : opt.priority

    switch (priority) {
      case 'low':
        str += '; Priority=Low'
        break
      case 'medium':
        str += '; Priority=Medium'
        break
      case 'high':
        str += '; Priority=High'
        break
      default:
        throw new TypeError('option priority is invalid')
    }
  }

  if (opt.sameSite) {
    var sameSite = typeof opt.sameSite === 'string'
      ? opt.sameSite.toLowerCase() : opt.sameSite;

    switch (sameSite) {
      case true:
        str += '; SameSite=Strict';
        break;
      case 'lax':
        str += '; SameSite=Lax';
        break;
      case 'strict':
        str += '; SameSite=Strict';
        break;
      case 'none':
        str += '; SameSite=None';
        break;
      default:
        throw new TypeError('option sameSite is invalid');
    }
  }

  return str;
}

/**
 * URL-decode string value. Optimized to skip native call when no %.
 *
 * @param {string} str
 * @returns {string}
 */

function decode (str) {
  return str.indexOf('%') !== -1
    ? decodeURIComponent(str)
    : str
}

/**
 * URL-encode value.
 *
 * @param {string} str
 * @returns {string}
 */

function encode (val) {
  return encodeURIComponent(val)
}

/**
 * Determine if value is a Date.
 *
 * @param {*} val
 * @private
 */

function isDate (val) {
  return __toString.call(val) === '[object Date]' ||
    val instanceof Date
}

/**
 * Try decoding a string using a decoding function.
 *
 * @param {string} str
 * @param {function} decode
 * @private
 */

function tryDecode(str, decode) {
  try {
    return decode(str);
  } catch (e) {
    return str;
  }
}var ipaddr = (function (root) {
    'use strict';
    // A list of regular expressions that match arbitrary IPv4 addresses,
    // for which a number of weird notations exist.
    // Note that an address like 0010.0xa5.1.1 is considered legal.
    const ipv4Part = '(0?\\d+|0x[a-f0-9]+)';
    const ipv4Regexes = {
        fourOctet: new RegExp(`^${ipv4Part}\\.${ipv4Part}\\.${ipv4Part}\\.${ipv4Part}$`, 'i'),
        threeOctet: new RegExp(`^${ipv4Part}\\.${ipv4Part}\\.${ipv4Part}$`, 'i'),
        twoOctet: new RegExp(`^${ipv4Part}\\.${ipv4Part}$`, 'i'),
        longValue: new RegExp(`^${ipv4Part}$`, 'i')
    };

    // Regular Expression for checking Octal numbers
    const octalRegex = new RegExp(`^0[0-7]+$`, 'i');
    const hexRegex = new RegExp(`^0x[a-f0-9]+$`, 'i');

    const zoneIndex = '%[0-9a-z]{1,}';

    // IPv6-matching regular expressions.
    // For IPv6, the task is simpler: it is enough to match the colon-delimited
    // hexadecimal IPv6 and a transitional variant with dotted-decimal IPv4 at
    // the end.
    const ipv6Part = '(?:[0-9a-f]+::?)+';
    const ipv6Regexes = {
        zoneIndex: new RegExp(zoneIndex, 'i'),
        'native': new RegExp(`^(::)?(${ipv6Part})?([0-9a-f]+)?(::)?(${zoneIndex})?$`, 'i'),
        deprecatedTransitional: new RegExp(`^(?:::)(${ipv4Part}\\.${ipv4Part}\\.${ipv4Part}\\.${ipv4Part}(${zoneIndex})?)$`, 'i'),
        transitional: new RegExp(`^((?:${ipv6Part})|(?:::)(?:${ipv6Part})?)${ipv4Part}\\.${ipv4Part}\\.${ipv4Part}\\.${ipv4Part}(${zoneIndex})?$`, 'i')
    };

    // Expand :: in an IPv6 address or address part consisting of `parts` groups.
    function expandIPv6 (string, parts) {
        // More than one '::' means invalid adddress
        if (string.indexOf('::') !== string.lastIndexOf('::')) {
            return null;
        }

        let colonCount = 0;
        let lastColon = -1;
        let zoneId = (string.match(ipv6Regexes.zoneIndex) || [])[0];
        let replacement, replacementCount;

        // Remove zone index and save it for later
        if (zoneId) {
            zoneId = zoneId.substring(1);
            string = string.replace(/%.+$/, '');
        }

        // How many parts do we already have?
        while ((lastColon = string.indexOf(':', lastColon + 1)) >= 0) {
            colonCount++;
        }

        // 0::0 is two parts more than ::
        if (string.substr(0, 2) === '::') {
            colonCount--;
        }

        if (string.substr(-2, 2) === '::') {
            colonCount--;
        }

        // The following loop would hang if colonCount > parts
        if (colonCount > parts) {
            return null;
        }

        // replacement = ':' + '0:' * (parts - colonCount)
        replacementCount = parts - colonCount;
        replacement = ':';
        while (replacementCount--) {
            replacement += '0:';
        }

        // Insert the missing zeroes
        string = string.replace('::', replacement);

        // Trim any garbage which may be hanging around if :: was at the edge in
        // the source strin
        if (string[0] === ':') {
            string = string.slice(1);
        }

        if (string[string.length - 1] === ':') {
            string = string.slice(0, -1);
        }

        parts = (function () {
            const ref = string.split(':');
            const results = [];

            for (let i = 0; i < ref.length; i++) {
                results.push(parseInt(ref[i], 16));
            }

            return results;
        })();

        return {
            parts: parts,
            zoneId: zoneId
        };
    }

    // A generic CIDR (Classless Inter-Domain Routing) RFC1518 range matcher.
    function matchCIDR (first, second, partSize, cidrBits) {
        if (first.length !== second.length) {
            throw new Error('ipaddr: cannot match CIDR for objects with different lengths');
        }

        let part = 0;
        let shift;

        while (cidrBits > 0) {
            shift = partSize - cidrBits;
            if (shift < 0) {
                shift = 0;
            }

            if (first[part] >> shift !== second[part] >> shift) {
                return false;
            }

            cidrBits -= partSize;
            part += 1;
        }

        return true;
    }

    function parseIntAuto (string) {
        // Hexadedimal base 16 (0x#)
        if (hexRegex.test(string)) {
            return parseInt(string, 16);
        }
        // While octal representation is discouraged by ECMAScript 3
        // and forbidden by ECMAScript 5, we silently allow it to
        // work only if the rest of the string has numbers less than 8.
        if (string[0] === '0' && !isNaN(parseInt(string[1], 10))) {
        if (octalRegex.test(string)) {
            return parseInt(string, 8);
        }
            throw new Error(`ipaddr: cannot parse ${string} as octal`);
        }
        // Always include the base 10 radix!
        return parseInt(string, 10);
    }

    function padPart (part, length) {
        while (part.length < length) {
            part = `0${part}`;
        }

        return part;
    }

    const ipaddr = {};

    // An IPv4 address (RFC791).
    ipaddr.IPv4 = (function () {
        // Constructs a new IPv4 address from an array of four octets
        // in network order (MSB first)
        // Verifies the input.
        function IPv4 (octets) {
            if (octets.length !== 4) {
                throw new Error('ipaddr: ipv4 octet count should be 4');
            }

            let i, octet;

            for (i = 0; i < octets.length; i++) {
                octet = octets[i];
                if (!((0 <= octet && octet <= 255))) {
                    throw new Error('ipaddr: ipv4 octet should fit in 8 bits');
                }
            }

            this.octets = octets;
        }

        // Special IPv4 address ranges.
        // See also https://en.wikipedia.org/wiki/Reserved_IP_addresses
        IPv4.prototype.SpecialRanges = {
            unspecified: [[new IPv4([0, 0, 0, 0]), 8]],
            broadcast: [[new IPv4([255, 255, 255, 255]), 32]],
            // RFC3171
            multicast: [[new IPv4([224, 0, 0, 0]), 4]],
            // RFC3927
            linkLocal: [[new IPv4([169, 254, 0, 0]), 16]],
            // RFC5735
            loopback: [[new IPv4([127, 0, 0, 0]), 8]],
            // RFC6598
            carrierGradeNat: [[new IPv4([100, 64, 0, 0]), 10]],
            // RFC1918
            'private': [
                [new IPv4([10, 0, 0, 0]), 8],
                [new IPv4([172, 16, 0, 0]), 12],
                [new IPv4([192, 168, 0, 0]), 16]
            ],
            // Reserved and testing-only ranges; RFCs 5735, 5737, 2544, 1700
            reserved: [
                [new IPv4([192, 0, 0, 0]), 24],
                [new IPv4([192, 0, 2, 0]), 24],
                [new IPv4([192, 88, 99, 0]), 24],
                [new IPv4([198, 18, 0, 0]), 15],
                [new IPv4([198, 51, 100, 0]), 24],
                [new IPv4([203, 0, 113, 0]), 24],
                [new IPv4([240, 0, 0, 0]), 4]
            ]
        };

        // The 'kind' method exists on both IPv4 and IPv6 classes.
        IPv4.prototype.kind = function () {
            return 'ipv4';
        };

        // Checks if this address matches other one within given CIDR range.
        IPv4.prototype.match = function (other, cidrRange) {
            let ref;
            if (cidrRange === undefined) {
                ref = other;
                other = ref[0];
                cidrRange = ref[1];
            }

            if (other.kind() !== 'ipv4') {
                throw new Error('ipaddr: cannot match ipv4 address with non-ipv4 one');
            }

            return matchCIDR(this.octets, other.octets, 8, cidrRange);
        };

        // returns a number of leading ones in IPv4 address, making sure that
        // the rest is a solid sequence of 0's (valid netmask)
        // returns either the CIDR length or null if mask is not valid
        IPv4.prototype.prefixLengthFromSubnetMask = function () {
            let cidr = 0;
            // non-zero encountered stop scanning for zeroes
            let stop = false;
            // number of zeroes in octet
            const zerotable = {
                0: 8,
                128: 7,
                192: 6,
                224: 5,
                240: 4,
                248: 3,
                252: 2,
                254: 1,
                255: 0
            };
            let i, octet, zeros;

            for (i = 3; i >= 0; i -= 1) {
                octet = this.octets[i];
                if (octet in zerotable) {
                    zeros = zerotable[octet];
                    if (stop && zeros !== 0) {
                        return null;
                    }

                    if (zeros !== 8) {
                        stop = true;
                    }

                    cidr += zeros;
                } else {
                    return null;
                }
            }

            return 32 - cidr;
        };

        // Checks if the address corresponds to one of the special ranges.
        IPv4.prototype.range = function () {
            return ipaddr.subnetMatch(this, this.SpecialRanges);
        };

        // Returns an array of byte-sized values in network order (MSB first)
        IPv4.prototype.toByteArray = function () {
            return this.octets.slice(0);
        };

        // Converts this IPv4 address to an IPv4-mapped IPv6 address.
        IPv4.prototype.toIPv4MappedAddress = function () {
            return ipaddr.IPv6.parse(`::ffff:${this.toString()}`);
        };

        // Symmetrical method strictly for aligning with the IPv6 methods.
        IPv4.prototype.toNormalizedString = function () {
            return this.toString();
        };

        // Returns the address in convenient, decimal-dotted format.
        IPv4.prototype.toString = function () {
            return this.octets.join('.');
        };

        return IPv4;
    })();

    // A utility function to return broadcast address given the IPv4 interface and prefix length in CIDR notation
    ipaddr.IPv4.broadcastAddressFromCIDR = function (string) {

        try {
            const cidr = this.parseCIDR(string);
            const ipInterfaceOctets = cidr[0].toByteArray();
            const subnetMaskOctets = this.subnetMaskFromPrefixLength(cidr[1]).toByteArray();
            const octets = [];
            let i = 0;
            while (i < 4) {
                // Broadcast address is bitwise OR between ip interface and inverted mask
                octets.push(parseInt(ipInterfaceOctets[i], 10) | parseInt(subnetMaskOctets[i], 10) ^ 255);
                i++;
            }

            return new this(octets);
        } catch (e) {
            throw new Error('ipaddr: the address does not have IPv4 CIDR format');
        }
    };

    // Checks if a given string is formatted like IPv4 address.
    ipaddr.IPv4.isIPv4 = function (string) {
        return this.parser(string) !== null;
    };

    // Checks if a given string is a valid IPv4 address.
    ipaddr.IPv4.isValid = function (string) {
        try {
            new this(this.parser(string));
            return true;
        } catch (e) {
            return false;
        }
    };

    // Checks if a given string is a full four-part IPv4 Address.
    ipaddr.IPv4.isValidFourPartDecimal = function (string) {
        if (ipaddr.IPv4.isValid(string) && string.match(/^(0|[1-9]\d*)(\.(0|[1-9]\d*)){3}$/)) {
            return true;
        } else {
            return false;
        }
    };

    // A utility function to return network address given the IPv4 interface and prefix length in CIDR notation
    ipaddr.IPv4.networkAddressFromCIDR = function (string) {
        let cidr, i, ipInterfaceOctets, octets, subnetMaskOctets;

        try {
            cidr = this.parseCIDR(string);
            ipInterfaceOctets = cidr[0].toByteArray();
            subnetMaskOctets = this.subnetMaskFromPrefixLength(cidr[1]).toByteArray();
            octets = [];
            i = 0;
            while (i < 4) {
                // Network address is bitwise AND between ip interface and mask
                octets.push(parseInt(ipInterfaceOctets[i], 10) & parseInt(subnetMaskOctets[i], 10));
                i++;
            }

            return new this(octets);
        } catch (e) {
            throw new Error('ipaddr: the address does not have IPv4 CIDR format');
        }
    };

    // Tries to parse and validate a string with IPv4 address.
    // Throws an error if it fails.
    ipaddr.IPv4.parse = function (string) {
        const parts = this.parser(string);

        if (parts === null) {
            throw new Error('ipaddr: string is not formatted like an IPv4 Address');
        }

        return new this(parts);
    };

    // Parses the string as an IPv4 Address with CIDR Notation.
    ipaddr.IPv4.parseCIDR = function (string) {
        let match;

        if ((match = string.match(/^(.+)\/(\d+)$/))) {
            const maskLength = parseInt(match[2]);
            if (maskLength >= 0 && maskLength <= 32) {
                const parsed = [this.parse(match[1]), maskLength];
                Object.defineProperty(parsed, 'toString', {
                    value: function () {
                        return this.join('/');
                    }
                });
                return parsed;
            }
        }

        throw new Error('ipaddr: string is not formatted like an IPv4 CIDR range');
    };

    // Classful variants (like a.b, where a is an octet, and b is a 24-bit
    // value representing last three octets; this corresponds to a class C
    // address) are omitted due to classless nature of modern Internet.
    ipaddr.IPv4.parser = function (string) {
        let match, part, value;

        // parseInt recognizes all that octal & hexadecimal weirdness for us
        if ((match = string.match(ipv4Regexes.fourOctet))) {
            return (function () {
                const ref = match.slice(1, 6);
                const results = [];

                for (let i = 0; i < ref.length; i++) {
                    part = ref[i];
                    results.push(parseIntAuto(part));
                }

                return results;
            })();
        } else if ((match = string.match(ipv4Regexes.longValue))) {
            value = parseIntAuto(match[1]);
            if (value > 0xffffffff || value < 0) {
                throw new Error('ipaddr: address outside defined range');
            }

            return ((function () {
                const results = [];
                let shift;

                for (shift = 0; shift <= 24; shift += 8) {
                    results.push((value >> shift) & 0xff);
                }

                return results;
            })()).reverse();
        } else if ((match = string.match(ipv4Regexes.twoOctet))) {
            return (function () {
                const ref = match.slice(1, 4);
                const results = [];

                value = parseIntAuto(ref[1]);
                if (value > 0xffffff || value < 0) {
                    throw new Error('ipaddr: address outside defined range');
                }

                results.push(parseIntAuto(ref[0]));
                results.push((value >> 16) & 0xff);
                results.push((value >>  8) & 0xff);
                results.push( value        & 0xff);

                return results;
            })();
        } else if ((match = string.match(ipv4Regexes.threeOctet))) {
            return (function () {
                const ref = match.slice(1, 5);
                const results = [];

                value = parseIntAuto(ref[2]);
                if (value > 0xffff || value < 0) {
                    throw new Error('ipaddr: address outside defined range');
                }

                results.push(parseIntAuto(ref[0]));
                results.push(parseIntAuto(ref[1]));
                results.push((value >> 8) & 0xff);
                results.push( value       & 0xff);

                return results;
            })();
        } else {
            return null;
        }
    };

    // A utility function to return subnet mask in IPv4 format given the prefix length
    ipaddr.IPv4.subnetMaskFromPrefixLength = function (prefix) {
        prefix = parseInt(prefix);
        if (prefix < 0 || prefix > 32) {
            throw new Error('ipaddr: invalid IPv4 prefix length');
        }

        const octets = [0, 0, 0, 0];
        let j = 0;
        const filledOctetCount = Math.floor(prefix / 8);

        while (j < filledOctetCount) {
            octets[j] = 255;
            j++;
        }

        if (filledOctetCount < 4) {
            octets[filledOctetCount] = Math.pow(2, prefix % 8) - 1 << 8 - (prefix % 8);
        }

        return new this(octets);
    };

    // An IPv6 address (RFC2460)
    ipaddr.IPv6 = (function () {
        // Constructs an IPv6 address from an array of eight 16 - bit parts
        // or sixteen 8 - bit parts in network order(MSB first).
        // Throws an error if the input is invalid.
        function IPv6 (parts, zoneId) {
            let i, part;

            if (parts.length === 16) {
                this.parts = [];
                for (i = 0; i <= 14; i += 2) {
                    this.parts.push((parts[i] << 8) | parts[i + 1]);
                }
            } else if (parts.length === 8) {
                this.parts = parts;
            } else {
                throw new Error('ipaddr: ipv6 part count should be 8 or 16');
            }

            for (i = 0; i < this.parts.length; i++) {
                part = this.parts[i];
                if (!((0 <= part && part <= 0xffff))) {
                    throw new Error('ipaddr: ipv6 part should fit in 16 bits');
                }
            }

            if (zoneId) {
                this.zoneId = zoneId;
            }
        }

        // Special IPv6 ranges
        IPv6.prototype.SpecialRanges = {
            // RFC4291, here and after
            unspecified: [new IPv6([0, 0, 0, 0, 0, 0, 0, 0]), 128],
            linkLocal: [new IPv6([0xfe80, 0, 0, 0, 0, 0, 0, 0]), 10],
            multicast: [new IPv6([0xff00, 0, 0, 0, 0, 0, 0, 0]), 8],
            loopback: [new IPv6([0, 0, 0, 0, 0, 0, 0, 1]), 128],
            uniqueLocal: [new IPv6([0xfc00, 0, 0, 0, 0, 0, 0, 0]), 7],
            ipv4Mapped: [new IPv6([0, 0, 0, 0, 0, 0xffff, 0, 0]), 96],
            // RFC6145
            rfc6145: [new IPv6([0, 0, 0, 0, 0xffff, 0, 0, 0]), 96],
            // RFC6052
            rfc6052: [new IPv6([0x64, 0xff9b, 0, 0, 0, 0, 0, 0]), 96],
            // RFC3056
            '6to4': [new IPv6([0x2002, 0, 0, 0, 0, 0, 0, 0]), 16],
            // RFC6052, RFC6146
            teredo: [new IPv6([0x2001, 0, 0, 0, 0, 0, 0, 0]), 32],
            // RFC4291
            reserved: [[new IPv6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0]), 32]],
            benchmarking: [new IPv6([0x2001, 0x2, 0, 0, 0, 0, 0, 0]), 48],
            amt: [new IPv6([0x2001, 0x3, 0, 0, 0, 0, 0, 0]), 32],
            as112v6: [new IPv6([0x2001, 0x4, 0x112, 0, 0, 0, 0, 0]), 48],
            deprecated: [new IPv6([0x2001, 0x10, 0, 0, 0, 0, 0, 0]), 28],
            orchid2: [new IPv6([0x2001, 0x20, 0, 0, 0, 0, 0, 0]), 28]
        };

        // Checks if this address is an IPv4-mapped IPv6 address.
        IPv6.prototype.isIPv4MappedAddress = function () {
            return this.range() === 'ipv4Mapped';
        };

        // The 'kind' method exists on both IPv4 and IPv6 classes.
        IPv6.prototype.kind = function () {
            return 'ipv6';
        };

        // Checks if this address matches other one within given CIDR range.
        IPv6.prototype.match = function (other, cidrRange) {
            let ref;

            if (cidrRange === undefined) {
                ref = other;
                other = ref[0];
                cidrRange = ref[1];
            }

            if (other.kind() !== 'ipv6') {
                throw new Error('ipaddr: cannot match ipv6 address with non-ipv6 one');
            }

            return matchCIDR(this.parts, other.parts, 16, cidrRange);
        };

        // returns a number of leading ones in IPv6 address, making sure that
        // the rest is a solid sequence of 0's (valid netmask)
        // returns either the CIDR length or null if mask is not valid
        IPv6.prototype.prefixLengthFromSubnetMask = function () {
            let cidr = 0;
            // non-zero encountered stop scanning for zeroes
            let stop = false;
            // number of zeroes in octet
            const zerotable = {
                0: 16,
                32768: 15,
                49152: 14,
                57344: 13,
                61440: 12,
                63488: 11,
                64512: 10,
                65024: 9,
                65280: 8,
                65408: 7,
                65472: 6,
                65504: 5,
                65520: 4,
                65528: 3,
                65532: 2,
                65534: 1,
                65535: 0
            };
            let part, zeros;

            for (let i = 7; i >= 0; i -= 1) {
                part = this.parts[i];
                if (part in zerotable) {
                    zeros = zerotable[part];
                    if (stop && zeros !== 0) {
                        return null;
                    }

                    if (zeros !== 16) {
                        stop = true;
                    }

                    cidr += zeros;
                } else {
                    return null;
                }
            }

            return 128 - cidr;
        };


        // Checks if the address corresponds to one of the special ranges.
        IPv6.prototype.range = function () {
            return ipaddr.subnetMatch(this, this.SpecialRanges);
        };

        // Returns an array of byte-sized values in network order (MSB first)
        IPv6.prototype.toByteArray = function () {
            let part;
            const bytes = [];
            const ref = this.parts;
            for (let i = 0; i < ref.length; i++) {
                part = ref[i];
                bytes.push(part >> 8);
                bytes.push(part & 0xff);
            }

            return bytes;
        };

        // Returns the address in expanded format with all zeroes included, like
        // 2001:0db8:0008:0066:0000:0000:0000:0001
        IPv6.prototype.toFixedLengthString = function () {
            const addr = ((function () {
                const results = [];
                for (let i = 0; i < this.parts.length; i++) {
                    results.push(padPart(this.parts[i].toString(16), 4));
                }

                return results;
            }).call(this)).join(':');

            let suffix = '';

            if (this.zoneId) {
                suffix = `%${this.zoneId}`;
            }

            return addr + suffix;
        };

        // Converts this address to IPv4 address if it is an IPv4-mapped IPv6 address.
        // Throws an error otherwise.
        IPv6.prototype.toIPv4Address = function () {
            if (!this.isIPv4MappedAddress()) {
                throw new Error('ipaddr: trying to convert a generic ipv6 address to ipv4');
            }

            const ref = this.parts.slice(-2);
            const high = ref[0];
            const low = ref[1];

            return new ipaddr.IPv4([high >> 8, high & 0xff, low >> 8, low & 0xff]);
        };

        // Returns the address in expanded format with all zeroes included, like
        // 2001:db8:8:66:0:0:0:1
        //
        // Deprecated: use toFixedLengthString() instead.
        IPv6.prototype.toNormalizedString = function () {
            const addr = ((function () {
                const results = [];

                for (let i = 0; i < this.parts.length; i++) {
                    results.push(this.parts[i].toString(16));
                }

                return results;
            }).call(this)).join(':');

            let suffix = '';

            if (this.zoneId) {
                suffix = `%${this.zoneId}`;
            }

            return addr + suffix;
        };

        // Returns the address in compact, human-readable format like
        // 2001:db8:8:66::1
        // in line with RFC 5952 (see https://tools.ietf.org/html/rfc5952#section-4)
        IPv6.prototype.toRFC5952String = function () {
            const regex = /((^|:)(0(:|$)){2,})/g;
            const string = this.toNormalizedString();
            let bestMatchIndex = 0;
            let bestMatchLength = -1;
            let match;

            while ((match = regex.exec(string))) {
                if (match[0].length > bestMatchLength) {
                    bestMatchIndex = match.index;
                    bestMatchLength = match[0].length;
                }
            }

            if (bestMatchLength < 0) {
                return string;
            }

            return `${string.substring(0, bestMatchIndex)}::${string.substring(bestMatchIndex + bestMatchLength)}`;
        };

        // Returns the address in compact, human-readable format like
        // 2001:db8:8:66::1
        // Calls toRFC5952String under the hood.
        IPv6.prototype.toString = function () {
            return this.toRFC5952String();
        };

        return IPv6;

    })();

    // A utility function to return broadcast address given the IPv6 interface and prefix length in CIDR notation
    ipaddr.IPv6.broadcastAddressFromCIDR = function (string) {
        try {
            const cidr = this.parseCIDR(string);
            const ipInterfaceOctets = cidr[0].toByteArray();
            const subnetMaskOctets = this.subnetMaskFromPrefixLength(cidr[1]).toByteArray();
            const octets = [];
            let i = 0;
            while (i < 16) {
                // Broadcast address is bitwise OR between ip interface and inverted mask
                octets.push(parseInt(ipInterfaceOctets[i], 10) | parseInt(subnetMaskOctets[i], 10) ^ 255);
                i++;
            }

            return new this(octets);
        } catch (e) {
            throw new Error(`ipaddr: the address does not have IPv6 CIDR format (${e})`);
        }
    };

    // Checks if a given string is formatted like IPv6 address.
    ipaddr.IPv6.isIPv6 = function (string) {
        return this.parser(string) !== null;
    };

    // Checks to see if string is a valid IPv6 Address
    ipaddr.IPv6.isValid = function (string) {

        // Since IPv6.isValid is always called first, this shortcut
        // provides a substantial performance gain.
        if (typeof string === 'string' && string.indexOf(':') === -1) {
            return false;
        }

        try {
            const addr = this.parser(string);
            new this(addr.parts, addr.zoneId);
            return true;
        } catch (e) {
            return false;
        }
    };

    // A utility function to return network address given the IPv6 interface and prefix length in CIDR notation
    ipaddr.IPv6.networkAddressFromCIDR = function (string) {
        let cidr, i, ipInterfaceOctets, octets, subnetMaskOctets;

        try {
            cidr = this.parseCIDR(string);
            ipInterfaceOctets = cidr[0].toByteArray();
            subnetMaskOctets = this.subnetMaskFromPrefixLength(cidr[1]).toByteArray();
            octets = [];
            i = 0;
            while (i < 16) {
                // Network address is bitwise AND between ip interface and mask
                octets.push(parseInt(ipInterfaceOctets[i], 10) & parseInt(subnetMaskOctets[i], 10));
                i++;
            }

            return new this(octets);
        } catch (e) {
            throw new Error(`ipaddr: the address does not have IPv6 CIDR format (${e})`);
        }
    };

    // Tries to parse and validate a string with IPv6 address.
    // Throws an error if it fails.
    ipaddr.IPv6.parse = function (string) {
        const addr = this.parser(string);

        if (addr.parts === null) {
            throw new Error('ipaddr: string is not formatted like an IPv6 Address');
        }

        return new this(addr.parts, addr.zoneId);
    };

    ipaddr.IPv6.parseCIDR = function (string) {
        let maskLength, match, parsed;

        if ((match = string.match(/^(.+)\/(\d+)$/))) {
            maskLength = parseInt(match[2]);
            if (maskLength >= 0 && maskLength <= 128) {
                parsed = [this.parse(match[1]), maskLength];
                Object.defineProperty(parsed, 'toString', {
                    value: function () {
                        return this.join('/');
                    }
                });
                return parsed;
            }
        }

        throw new Error('ipaddr: string is not formatted like an IPv6 CIDR range');
    };

    // Parse an IPv6 address.
    ipaddr.IPv6.parser = function (string) {
        let addr, i, match, octet, octets, zoneId;

        if ((match = string.match(ipv6Regexes.deprecatedTransitional))) {
            return this.parser(`::ffff:${match[1]}`);
        }
        if (ipv6Regexes.native.test(string)) {
            return expandIPv6(string, 8);
        }
        if ((match = string.match(ipv6Regexes.transitional))) {
            zoneId = match[6] || '';
            addr = expandIPv6(match[1].slice(0, -1) + zoneId, 6);
            if (addr.parts) {
                octets = [
                    parseInt(match[2]),
                    parseInt(match[3]),
                    parseInt(match[4]),
                    parseInt(match[5])
                ];
                for (i = 0; i < octets.length; i++) {
                    octet = octets[i];
                    if (!((0 <= octet && octet <= 255))) {
                        return null;
                    }
                }

                addr.parts.push(octets[0] << 8 | octets[1]);
                addr.parts.push(octets[2] << 8 | octets[3]);
                return {
                    parts: addr.parts,
                    zoneId: addr.zoneId
                };
            }
        }

        return null;
    };

    // A utility function to return subnet mask in IPv6 format given the prefix length
    ipaddr.IPv6.subnetMaskFromPrefixLength = function (prefix) {
        prefix = parseInt(prefix);
        if (prefix < 0 || prefix > 128) {
            throw new Error('ipaddr: invalid IPv6 prefix length');
        }

        const octets = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let j = 0;
        const filledOctetCount = Math.floor(prefix / 8);

        while (j < filledOctetCount) {
            octets[j] = 255;
            j++;
        }

        if (filledOctetCount < 16) {
            octets[filledOctetCount] = Math.pow(2, prefix % 8) - 1 << 8 - (prefix % 8);
        }

        return new this(octets);
    };

    // Try to parse an array in network order (MSB first) for IPv4 and IPv6
    ipaddr.fromByteArray = function (bytes) {
        const length = bytes.length;

        if (length === 4) {
            return new ipaddr.IPv4(bytes);
        } else if (length === 16) {
            return new ipaddr.IPv6(bytes);
        } else {
            throw new Error('ipaddr: the binary input is neither an IPv6 nor IPv4 address');
        }
    };

    // Checks if the address is valid IP address
    ipaddr.isValid = function (string) {
        return ipaddr.IPv6.isValid(string) || ipaddr.IPv4.isValid(string);
    };


    // Attempts to parse an IP Address, first through IPv6 then IPv4.
    // Throws an error if it could not be parsed.
    ipaddr.parse = function (string) {
        if (ipaddr.IPv6.isValid(string)) {
            return ipaddr.IPv6.parse(string);
        } else if (ipaddr.IPv4.isValid(string)) {
            return ipaddr.IPv4.parse(string);
        } else {
            throw new Error('ipaddr: the address has neither IPv6 nor IPv4 format');
        }
    };

    // Attempt to parse CIDR notation, first through IPv6 then IPv4.
    // Throws an error if it could not be parsed.
    ipaddr.parseCIDR = function (string) {
        try {
            return ipaddr.IPv6.parseCIDR(string);
        } catch (e) {
            try {
                return ipaddr.IPv4.parseCIDR(string);
            } catch (e2) {
                throw new Error('ipaddr: the address has neither IPv6 nor IPv4 CIDR format');
            }
        }
    };

    // Parse an address and return plain IPv4 address if it is an IPv4-mapped address
    ipaddr.process = function (string) {
        const addr = this.parse(string);

        if (addr.kind() === 'ipv6' && addr.isIPv4MappedAddress()) {
            return addr.toIPv4Address();
        } else {
            return addr;
        }
    };

    // An utility function to ease named range matching. See examples below.
    // rangeList can contain both IPv4 and IPv6 subnet entries and will not throw errors
    // on matching IPv4 addresses to IPv6 ranges or vice versa.
    ipaddr.subnetMatch = function (address, rangeList, defaultName) {
        let i, rangeName, rangeSubnets, subnet;

        if (defaultName === undefined || defaultName === null) {
            defaultName = 'unicast';
        }

        for (rangeName in rangeList) {
            if (Object.prototype.hasOwnProperty.call(rangeList, rangeName)) {
                rangeSubnets = rangeList[rangeName];
                // ECMA5 Array.isArray isn't available everywhere
                if (rangeSubnets[0] && !(rangeSubnets[0] instanceof Array)) {
                    rangeSubnets = [rangeSubnets];
                }

                for (i = 0; i < rangeSubnets.length; i++) {
                    subnet = rangeSubnets[i];
                    if (address.kind() === subnet[0].kind() && address.match.apply(address, subnet)) {
                        return rangeName;
                    }
                }
            }
        }

        return defaultName;
    };

    return ipaddr

}(this));/*
 * jwt-simple
 *
 * JSON Web Token encode and decode module for node.js
 *
 * Copyright(c) 2011 Kazuhito Hokamura
 * MIT Licensed
 */

/**
 * module dependencies
 */
var crypto = require('crypto');


/**
 * support algorithm mapping
 */
var algorithmMap = {
  HS256: 'sha256',
  HS384: 'sha384',
  HS512: 'sha512',
  RS256: 'RSA-SHA256'
};

/**
 * Map algorithm to hmac or sign type, to determine which crypto function to use
 */
var typeMap = {
  HS256: 'hmac',
  HS384: 'hmac',
  HS512: 'hmac',
  RS256: 'sign'
};


/**
 * expose object
 */
var jwt = {};


/**
 * version
 */
jwt.version = '0.5.6';

/**
 * Decode jwt
 *
 * @param {Object} token
 * @param {String} key
 * @param {Boolean} [noVerify]
 * @param {String} [algorithm]
 * @return {Object} payload
 * @api public
 */
jwt.decode = function jwt_decode(token, key, noVerify, algorithm) {
  // check token
  if (!token) {
    throw new Error('No token supplied');
  }
  // check segments
  var segments = token.split('.');
  if (segments.length !== 3) {
    throw new Error('Not enough or too many segments');
  }

  // All segment should be base64
  var headerSeg = segments[0];
  var payloadSeg = segments[1];
  var signatureSeg = segments[2];

  // base64 decode and parse JSON
  var header = JSON.parse(base64urlDecode(headerSeg));
  var payload = JSON.parse(base64urlDecode(payloadSeg));

  if (!noVerify) {
    if (!algorithm && /BEGIN( RSA)? PUBLIC KEY/.test(key.toString())) {
      algorithm = 'RS256';
    }

    var signingMethod = algorithmMap[algorithm || header.alg];
    var signingType = typeMap[algorithm || header.alg];
    if (!signingMethod || !signingType) {
      throw new Error('Algorithm not supported');
    }

    // verify signature. `sign` will return base64 string.
    var signingInput = [headerSeg, payloadSeg].join('.');
    if (!verify(signingInput, key, signingMethod, signingType, signatureSeg)) {
      throw new Error('Signature verification failed');
    }

    // Support for nbf and exp claims.
    // According to the RFC, they should be in seconds.
    if (payload.nbf && Date.now() < payload.nbf*1000) {
      throw new Error('Token not yet active');
    }

    if (payload.exp && Date.now() > payload.exp*1000) {
      throw new Error('Token expired');
    }
  }

  return payload;
};


/**
 * Encode jwt
 *
 * @param {Object} payload
 * @param {String} key
 * @param {String} algorithm
 * @param {Object} options
 * @return {String} token
 * @api public
 */
jwt.encode = function jwt_encode(payload, key, algorithm, options) {
  // Check key
  if (!key) {
    throw new Error('Require key');
  }

  // Check algorithm, default is HS256
  if (!algorithm) {
    algorithm = 'HS256';
  }

  var signingMethod = algorithmMap[algorithm];
  var signingType = typeMap[algorithm];
  if (!signingMethod || !signingType) {
    throw new Error('Algorithm not supported');
  }

  // header, typ is fixed value.
  var header = { typ: 'JWT', alg: algorithm };
  if (options && options.header) {
    assignProperties(header, options.header);
  }

  // create segments, all segments should be base64 string
  var segments = [];
  segments.push(base64urlEncode(JSON.stringify(header)));
  segments.push(base64urlEncode(JSON.stringify(payload)));
  segments.push(sign(segments.join('.'), key, signingMethod, signingType));

  return segments.join('.');
};

/**
 * private util functions
 */

function assignProperties(dest, source) {
  for (var attr in source) {
    if (source.hasOwnProperty(attr)) {
      dest[attr] = source[attr];
    }
  }
}

function verify(input, key, method, type, signature) {
  if(type === "hmac") {
    return (signature === sign(input, key, method, type));
  }
  else if(type == "sign") {
    return crypto.createVerify(method)
                 .update(input)
                 .verify(key, base64urlUnescape(signature), 'base64');
  }
  else {
    throw new Error('Algorithm type not recognized');
  }
}

function sign(input, key, method, type) {
  var base64str;
  if(type === "hmac") {
    base64str = crypto.createHmac(method, key).update(input).digest('base64');
  }
  else if(type == "sign") {
    base64str = crypto.createSign(method).update(input).sign(key, 'base64');
  }
  else {
    throw new Error('Algorithm type not recognized');
  }

  return base64urlEscape(base64str);
}

function base64urlDecode(str) {
  return Buffer.from(base64urlUnescape(str), 'base64').toString();
}

function base64urlUnescape(str) {
  str += new Array(5 - str.length % 4).join('=');
  return str.replace(/\-/g, '+').replace(/_/g, '/');
}

function base64urlEncode(str) {
  return base64urlEscape(Buffer.from(str).toString('base64'));
}

function base64urlEscape(str) {
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}/* global */
/* eslint curly: 0, max-len: [1, 150], no-underscore-dangle: 0, no-param-reassign: 0,
  no-plusplus: 0, no-bitwise: 0, vars-on-top: 0, dot-notation: 0, quote-props: 0,
  no-mixed-operators: 0, key-spacing: 0, no-else-return: 0, consistent-return: 0,
  no-return-assign: 0, semi-style: 0, no-multi-spaces: 0, nonblock-statement-body-position: 0,
  no-buffer-constructor: 0,
  no-var: 0, object-shorthand: 0, prefer-destructuring: 0, one-var: 0,
  prefer-template: 0, prefer-arrow-callback: 0
  */

  'use strict';

  // -- Node modules
  var fs = require('fs')
    ;
  
  // -- Local modules
  
  // -- Local constants
  
  // -- Local variables
  
  /**
   * LRU cache Library
   *
   * This library stores key/value pair in cache. It implements the LRU algoritmn
   * (Least Recently Used). It is freely inspired from
   * https://github.com/isaacs/node-lru-cache.
   *
   * @author   jclo
   * @since    0.0.1
   */
  /* istanbul ignore next */
  var _cache = function() {};
  
  /* istanbul ignore next */
  _cache = {
  
    init: function(_this) {
      _this._cache = {};      // contains keys, values,
      _this._list = {};       // contains time stamp and associated key,
      _this._lru = 0;         // the least recently used time stamp,
      _this._mru = 0;         // the most recently used time stamp,
      _this._items = 0;       // the number of key/value pairs stored in the cache,
      _this._maxItems = 1000; // the cache capacity in term of key/value pairs,
    },
  
    reset: function(_this) {
      _cache.init(_this);
    },
  
    // Add this key and its value to the cache.
    // If the key is already in the cache, retag it as the most recently
    // used. If the cache overflows, delete the least recently used.
    set: function(_this, key, value) {
      var oldStamp
        ;
  
      // Is this key already in cache?
      if (_this._cache[key] === undefined) {
        // No! Store it in cache and list, update _mru and _items.
        _this._cache[key] = {
          'key': key,
          'value': value,
          'stamp': _this._mru++,
        };
        _this._list[_this._cache[key].stamp] = _this._cache[key];
        _this._items++;
  
        // Overflow?
        if (_this._items > _this._maxItems)
          _cache._overflow(_this);
      } else {
        // Yes! Make it as the most recently used.
        oldStamp = _this._cache[key].stamp;
  
        delete _this._list[_this._cache[key].stamp];
        _this._cache[key].stamp = _this._mru++;
        _this._list[_this._cache[key].stamp] = _this._cache[key];
  
        // If this key was the least recently used, find the new one.
        if (oldStamp === _this._lru)
          _cache._findLRU(_this);
      }
    },
  
    // Return the associated record or undefined.
    get: function(_this, key) {
      if (_this._cache[key])
        return _this._cache[key].value;
      else
        return undefined;
    },
  
    // As the cache overflows, delete the least recently used key
    // and find the new least recently used.
    _overflow: function(_this) {
      // Find the the least recently used key and delete it.
      var key = _this._list[_this._lru].key;
      delete _this._list[_this._cache[key].stamp];
      delete _this._cache[key];
      _this._items--;
      // Find the new LRU
      _cache._findLRU(_this);
    },
  
    // Find the new least recently used key.
    _findLRU: function(_this) {
      while (_this._lru < _this._mru && _this._list[_this._lru] === undefined) {
        _this._lru++;
      }
    },
  
    // For debugging purpose.
    _dumpCache: function(_this) {
      return _this._cache;
    },
  
    // For debugging purpose.
    _dumpList: function(_this) {
      return _this._list;
    },
  
    // For debugging purpose.
    _dumpParams: function(_this) {
      return {
        '_lru':      _this._lru,
        '_mru':      _this._mru,
        '_items':    _this._items,
        '_maxItems': _this._maxItems,
      };
    },
  };
  
  
  /**
   * This library helps developpers to read the content of MaxMind Database. It
   * implements two methods. The first one retrieves information on the database
   * structure. The second one returns the stored record for a given IP address.
  
   * The structure of the database is detailed here:
   *   - http://maxmind.github.io/MaxMind-DB.
   *
   * In brief, it is organized in three sections:
   *
   *  . the Binary Search Section that contains the list of recognized IP addresses
   *    in an encoded format.
   *
   *  . the Output Data Section that contains records relative to these IP
   *    addresses.
   *
   *  . and finally the Metadata section that contains parameters on the database.
   *    These parameters allow to parse the database.
   *
   *         ___________________
   *        |                   |
   *        |   Binary Search   |
   *        |   Tree Section    |
   *        |___________________|
   *        |                   |
   *        |    Output Data    |
   *        |     Section       |
   *        |                   |
   *        |___________________|
   *        |                   |
   *        | Metadata Section  |
   *        |___________________|
   *
   *
   * When the constructor is called, it builds the following Javascript object by
   * extracting the metadata information:
   *
   *  this.metadata = {
   *    binary_format_major_version:    // release number,
   *    binary_format_minor_version:    // release number,
   *    build_epoch: 1396538608         //
   *    database_type:                  // name of the database,
   *    description:                    // a description of the database,
   *    ip_version:                     // IP addresses organization (IPV4 or IPV4 encapsulated into IPV6 format),
   *    languages:                      // languages supported in the record,
   *    node_count:                     // number of nodes,
   *    record_size:                    // node bit size,
   *    nodeByteSize:                   // node byte size,
   *    searchTreeSection:              // size of the search tree section,
   *    pointerBase:                    // beginning of the Output Data Section,
   *  }
   *
   * @author   jclo
   * @since    0.0.1
   */
  
  // -- Private functions
  
  /**
   * Finds where the Metadata section starts.
   *
   * @function (db)
   * @private
   * @param {Buffer}    The database contents,
   * @returns {Number}  Returns where the Metadata section starts or false,
   * @throws {Objet}    Throws an error message if the metadata pattern is not found,
   */
  function _findWhereMetadataStart(db) {
    var METADATA_START_MARKER
      , metadataPointer
      , dbPointer
      , match
      ;
  
    // Metadata pattern to find: '\xab\xcd\xefMaxMind.com'
    METADATA_START_MARKER = Buffer.from('abcdef4d61784d696e642e636f6d', 'hex');
    metadataPointer = METADATA_START_MARKER.length - 1;
    dbPointer = db.length - 1;
    match = 0;
  
    // Start parsing 'db' from the end as the metadata section is the last section
    // of the 'database'. More details here: http://maxmind.github.io/MaxMind-DB.
    while (match <= metadataPointer && dbPointer--) {
      match = (db[dbPointer] === METADATA_START_MARKER[metadataPointer - match]) ? match + 1 : 0;
    }
  
    // Check if this pattern is found.
    if (match !== METADATA_START_MARKER.length)
      /* istanbul ignore next */
      throw new Error('The metadata pattern "0xab0xcd0xefMaxMind.com" was not found! Are you sure that you provided a MaxMind database file?');
  
    // Return the start position of the metadata section.
    return dbPointer + match;
  }
  
  /**
   * Finds the type and its payload.
   *
   * @function (db, offset)
   * @private
   * @param {Buffer}    The database contents,
   * @param {Number}    The pointer position,
   * @returns {Object}  Returns type, payload size and new pointer position,
   * @throws {Objet}    Throws an error if type unknown,
   */
  function _findTypeAndPayloadSize(db, offset) {
    // The type is coded in the tree MSB bytes (000X XXXX).
    // The payload is coded in the five LSB bytes (XXX0 0000).
    var type
      , payload
      ;
  
    type = db[offset] >> 5;
    payload = db[offset++] & 0x1f;
  
    // Extended type?
    if (type === 0) {
      type = db[offset++] + 7;
      if (typeof type !== 'number' || type > 15)
        /* istanbul ignore next */
        throw new Error('The Type "' + type + '" is unknown!');
    }
  
    // For payload < 29
    // Be aware! For pointer (type 1) payload gives pointer size.
    if (payload < 29)
      return { type: type, 'size': payload, 'offset': offset };
  
    // If the value is 29, then the size is 29 + the next byte after
    // the type specifying bytes as an unsigned integer.
    if (payload === 29)
      return { type: type, 'size': 29 + db.readUInt8(offset++), 'offset': offset };
  
    // If the value is 30, then the size is 285 + the next two bytes
    // after the type specifying bytes as a single unsigned integer.
    if (payload === 30)
      return { type: type, 'size': 285 + ((db[offset++] << 8) | db[offset++]), 'offset': offset };
  
    // If the value is 31, then the size is 65,821 + the next three
    // bytes after the type specifying bytes as a single unsigned integer.
    if (payload === 31)
      return { type: type, 'size': 65821 + ((db[offset++] << 16) | (db[offset++] << 8) | db[offset++]), 'offset': offset };
  
    // This case should never occur because of 0x1f!
    /* istanbul ignore next */
    throw new Error('Payload size ' + payload + ' should never occur!');
  }
  
  /**
   * Returns the pointer value.
   *
   * @function (db, offset, pointerBase, payload)
   * @private
   * @param {Buffer}    The database contents,
   * @param {Number}    The pointer position,
   * @param {Number}    The data section position,
   * @returns {Object}  Returns pointer address and new pointer position,
   */
  function _getPointer(db, offset, pointerBase, payload) {
    // Pointers use the last five bits in the control byte to calculate
    // the pointer value.
    // payload: 001S SVVV
    // 001 type pointer, SS pointer size, VVV pointer value
    var value = 0x7 & payload
      , size = 0x3 & (payload >> 3)
      , p
      ;
  
    // SS = 0 => p = vvv:byte(n+1)
    if (size === 0) {
      p = (value << 8) | db[offset++];
      return { 'pointer': pointerBase + p, 'offset': offset };
    }
  
    // SS = 1 => p = vvv:byte(n+1):byte(n+2) + 2048
    if (size === 1) {
      p = (value << 16) | (db[offset++] << 8) | db[offset++];
      return { 'pointer': pointerBase + p + 2048, 'offset': offset };
    }
  
    // SS = 2 => p = vvv:byte(n+1):byte(n+2):byte(n+3) + 526336
    if (size === 2) {
      p = (value << 24) | (db[offset++] << 16) | (db[offset++] << 8) | db[offset++];
      return { 'pointer': pointerBase + p + 526336, 'offset': offset };
    }
  
    // SS = 3 => p = byte(n+1):..:byte(n+4)
    if (size === 3) {
      p = (db[offset++] << 24) | (db[offset++] << 16) | (db[offset++] << 8) | db[offset++];
      return { 'pointer': pointerBase + p + 0, 'offset': offset };
    }
  }
  
  /**
   * Decode the type.
   *
   * @function (db, offset, pointerBase)
   * @private
   * @param {Buffer}    The database contents,
   * @param {Number}    The position of the type into the Buffer,
   * @param {Number}    The beginning of the data section,
   * @returns {Object}  Returns an object with the 'type', it's 'value' and the
   *                    position of the next 'element' in the database,
   * @throws {Object}   Throws an error if a not yet supported type has to be decoded,
   * @throws {Object}   Throws an error if the type is unknown,
   */
  function _decode(db, offset, pointerBase) {
    var types
      , type
      , payloadSize
      , data
      , i
      ;
  
    // Associated type to data field.
    // More details here: http://maxmind.github.io/MaxMind-DB
    // (chapter: 'Output Data Section')
    types = [
      'extended',         //  0
      'pointer',          //  1
      'utf8_string',      //  2
      'double',           //  3
      'bytes',            //  4
      'uint16',           //  5
      'uint32',           //  6
      'map',              //  7
      'int32',            //  8
      'uint64',           //  9
      'uint128',          // 10
      'array',            // 11
      'container',        // 12
      'end_marker',       // 13
      'boolean',          // 14
      'float',            // 15
    ];
  
    // Retrieve type and payload.
    data = _findTypeAndPayloadSize(db, offset);
    type = types[data.type];
    offset = data.offset;
    payloadSize = data.size;
  
  
    // Decode the type.
    switch (type) {
      case 'pointer':
        var pData = _getPointer(db, offset, pointerBase, payloadSize);
        var pType = _decode(db, pData.pointer, pointerBase);
        return {
          'type': pType.type,
          'value': pType.value,
          'offset': pData.offset,
        };
  
      case 'utf8_string':
        return {
          'type': type,
          'value': db.toString('utf8', offset, offset + payloadSize),
          'offset': offset += payloadSize,
        };
  
      case 'double':
        return {
          'type': type,
          'value': db.readDoubleBE(offset),
          'offset': offset += payloadSize,
        };
  
      case 'bytes':
        return {
          'type': type,
          'value': db.slice(offset, offset + payloadSize),
          'offset': offset += payloadSize,
        };
  
      case 'uint16':
        if (payloadSize === 0) {
          data = 0;
        } else if (payloadSize === 1) {
          data = db[offset++];
        } else {
          data = (db[offset++] << 8) | db[offset++];
        }
        return {
          'type': type,
          'value': data,
          'offset': offset,
        };
  
      case 'uint32':
  
        if (payloadSize === 0) {
          data = 0;
        } else if (payloadSize === 1) {
          data = db[offset++];
        } else if (payloadSize === 2) {
          data = (db[offset++] << 8) | db[offset++];
        } else if (payloadSize === 3) {
          data = (db[offset++] << 16) | (db[offset++]) << 8 | db[offset++];
        } else {
          data = (db[offset++] << 24) | (db[offset++]) << 16 | (db[offset++] << 8) | db[offset++];
        }
        return {
          'type': type,
          'value': data,
          'offset': offset,
        };
  
      case 'map':
        // Compute number of keys/values pairs contained in the map.
        // Extract the map.
        var mapTypeKey = {};
        var mapTypeValue = {};
        var mapObj = {};
        var mapOffset = offset;
  
        for (i = 0; i < payloadSize; i++) {
          // Extract the key.
          mapTypeKey = _decode(db, mapOffset, pointerBase);
          mapOffset = mapTypeKey.offset;
          // Extract the key value.
          mapTypeValue = _decode(db, mapOffset, pointerBase);
          mapObj[mapTypeKey.value] = mapTypeValue.value;
          mapOffset = mapTypeValue.offset;
        }
        return {
          'type': type,
          'value': mapObj,
          'offset': mapOffset,
        };
  
      case 'int32':
        data = 0;
        for (i = 0; i < payloadSize; i++)
          data = (data << 8) | db[offset++];
        return {
          'type': type,
          'value': data,
          'offset': offset,
        };
  
      case 'uint64':
        data = 0;
        for (i = 0; i < payloadSize; i++)
          data = (data << 8) | db[offset++];
  
        return {
          'type': type,
          'value': data,
          'offset': offset,
        };
  
      case 'uint128':
        throw new Error('This Type "' + type + '" is not decoded yet!');
  
      case 'array':
        // Extract the array
        var arrayType = {};
        var arrayObj = [];
        var arrayOffset = offset;
  
        for (i = 0; i < payloadSize; i++) {
          arrayType = _decode(db, arrayOffset, pointerBase);
          arrayObj.push(arrayType.value);
          arrayOffset = arrayType.offset;
        }
        return {
          'type': type,
          'value': arrayObj,
          'offset': arrayOffset,
        };
  
      /* istanbul ignore next */
      case 'container':
        // Nothing in the database will ever contain a pointer to the this field
        // itself. This is in case of it changes in the future.
        throw new Error('This Type "' + type + '" is not decoded yet!');
  
      case 'end_marker':
        return {
          'type': type,
          'value': 0,
          'offset': offset,
        };
  
      case 'boolean':
        return {
          'type': type,
          'value': payloadSize & 0x01,
          'offset': offset,
        };
  
      case 'float':
        return {
          'type': type,
          'value': db.readFloatBE(offset),
          'offset': offset += 4,
        };
  
      /* istanbul ignore next */
      default:
        throw new Error('This Type "' + type + '" is totally unknown!');
    }
  }
  
  /**
   * Returns the IP address converted to an array.
   *
   * @function (arg)
   * @param {String}    The IP address,
   * @returns {Array}   The pointer associated to this IP Address.
   * @throws {Object}   Throws an error if the IP address is malformed,
   */
  function _expandIP(ip) {
    //  https://en.wikipedia.org/wiki/IPv6#Software, IPv4-mapped IPv6 addresses, "::ffff:192.168.13.13"
    var regexIPv4 = /^(::ffff:){0,1}(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/
      // Standard IPv6 only.
      // regexIPv6 = /^(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$/
      // Compacted IPv6 form too.
      , regexIPv6c = /^((([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){6}:[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){5}:([0-9A-Fa-f]{1,4}:)?[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){4}:([0-9A-Fa-f]{1,4}:){0,2}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){3}:([0-9A-Fa-f]{1,4}:){0,3}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){2}:([0-9A-Fa-f]{1,4}:){0,4}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){6}((b((25[0-5])|(1d{2})|(2[0-4]d)|(d{1,2}))b).){3}(b((25[0-5])|(1d{2})|(2[0-4]d)|(d{1,2}))b))|(([0-9A-Fa-f]{1,4}:){0,5}:((b((25[0-5])|(1d{2})|(2[0-4]d)|(d{1,2}))b).){3}(b((25[0-5])|(1d{2})|(2[0-4]d)|(d{1,2}))b))|(::([0-9A-Fa-f]{1,4}:){0,5}((b((25[0-5])|(1d{2})|(2[0-4]d)|(d{1,2}))b).){3}(b((25[0-5])|(1d{2})|(2[0-4]d)|(d{1,2}))b))|([0-9A-Fa-f]{1,4}::([0-9A-Fa-f]{1,4}:){0,5}[0-9A-Fa-f]{1,4})|(::([0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){1,7}:))$/
      , bits
      ;
  
    // Test if it is a correct IPv4 or IPv6 address. Otherwise throw an error.
    if (regexIPv4.test(ip)) {
      if (ip.slice(0, 7) === '::ffff:') {
        //  6-mapped-4
        ip = ip.slice(7);
      }
      // Ok. It's an IPv4 address.
      // Convert the string to an array and convert the strings
      // elements to numbers.
      // Then, expand it to match IPv6 output form
      // From: '8.8.4.4'
      // To: [0, 0, 0, 0, 0, 0, 8 * 256 + 8, 4 * 256 + 4]
      // return ip.split('.').map(function(i) { return parseInt(i, 10); });
      ip = ip.split('.').map(function(i) {
        var partI = parseInt(i, 10);
        if (partI > 255) {
          throw new Error('This IP ' + ip + ' is not a valid IPv4 address!');
        } else {
          return partI;
        }
      });
      return [0, 0, 0, 0, 0, 0, ip[0] * 256 + ip[1], ip[2] * 256 + ip[3]];
    } else if (regexIPv6c.test(ip)) {
      // Ok. It's an IPv6 address.
      // Expand it if it's a compressed address and convert the
      // string elements to numbers.
      // Input form: '2001:4860:4860::8888'
      // return: [ 8193, 18528, 18528, 0, 0, 0, 0, 34952 ]
      bits = ip.split(':');
  
      if (bits.length < 8)
        // Expand it.
        ip = ip.replace('::', Array(11 - bits.length).join(':'));
  
      return ip.split(':').map(function(i) { return i === '' ? 0 : parseInt(i, 16); });
    } else
      // It's not an IPv4 nor an IPv6 address!
      throw new Error('This IP ' + ip + ' is not a valid IPv4 or IPv6 address!');
  }
  
  /**
   * Returns the node pointer for the given node and index.
   * section tree.
   *
   * @function (arg, arg, arg, arg4)
   * @private
   * @param {Number}    The current node number,
   * @param {Number}    The bit index,
   * @param {Object}    The database,
   * @param {Object}    The database metadata,
   * @returns {Number}  Returns he new pointer,
   * @throws {Object}   Throws an error if the record size is not supported,
   */
  
  // Returns the 'pointer' for the given node and index.
  function _returnNodePointer(nodeNumber, index, db, metadata) {
    var baseOffset = nodeNumber * metadata.nodeByteSize
      , bytes
      , middle
      ;
  
    switch (metadata.record_size) {
      // Node layout is 24 bits (6 bytes)
      // => each pointer is 3 bytes
      case 24:
        bytes = baseOffset + index * 3;
        // pointer = db(n) : db(n+1) : db(n+2)
        return ((db[bytes] << 16) | (db[bytes + 1] << 8) | db[bytes + 2]);
  
      // Node layout is 28 bits (7 bytes)
      // => each pointer is 14 bits (1 byte and half)
      // The middle byte is the MSB for each pointer
      case 28:
        // Extract middle byte
        middle = db.readUInt8(baseOffset + 3, true);
        middle = (index === 0) ? (0xF0 & middle) >> 4 : 0x0F & middle;
        bytes = baseOffset + index * 4;
        // pointer = middle : db(n) : db(n+1) : db(n+2)
        return ((middle << 24) | (db[bytes] << 16) | (db[bytes + 1] << 8) | db[bytes + 2]);
  
      // Node layout is 32 bits (8 bytes)
      // => each pointer is 4 bytes
      case 32:
        return bytes.readUInt32BE(baseOffset + index * 4, true);
  
      default:
        throw new Error('This record size: "' + metadata.record_size + '" is not supported!');
    }
  }
  
  /**
   * Searchs if the IP address has a corresponding pointer in the search
   * section tree.
   *
   * @function (ip, db, metadata)
   * @private
   * @param {String}    The IP address,
   * @param {Buffer}    The database,
   * @param {Object}    The database metadata,
   * @returns {Number}  The pointer associated to this IP Address.
   */
  function _findAddressInTree(ip, db, metadata) {
    var nodeNumber = 0
      , record = 0
      , rawAddress = _expandIP(ip)
      ;
  
    // Parse the whole bits of this IP address.
    for (var i = 0; i < 128; i++) {
      var bit = 0
        , ipW
        ;
  
      // Start scanning bits from MSB to LSB.
      ipW = 0xFFFF & rawAddress[parseInt((i / 16), 10)];
      bit = 1 & (ipW >> 15 - (i % 16));
  
      // Find pointer for this node (depending on bit value).
      record = _returnNodePointer(nodeNumber, bit, db, metadata);
  
      if (record === metadata.node_count) {
        // If the record value is equal to the number of nodes, that means
        // that we do not have any data for the IP address, and the search
        // ends here.
        return 0;
      } else if (record > metadata.node_count) {
        // If the record value is greater than the number of nodes in the
        // search tree, then it is an actual pointer value pointing into
        // the data section.
        // The value of the pointer is calculated from the start of the
        // data section, not from the start of the file. To get the abs
        // value, the formula is:
        // $offsetinfile = ( $recordvalue - $nodecount ) + $searchtreesizeinbytes
        return record - metadata.node_count + metadata.searchTreeSection;
      } else {
        // If the record value is a number that is less than the number of nodes
        // (not in bytes, but the actual node count) in the search tree (this is
        // stored in the database metadata), then the value is a node number.
        // In this case, we find that node in the search tree and repeat the
        // lookup algorithm from there.
        nodeNumber = record;
      }
    }
  }
  
  // -- Public
  
  /**
   * Reads the database, extracts the metadata and puts it in memory.
   *
   * @constructor (dbfile)
   * @param {String}  The database file,
   * @throws          Throws an error if the database doesn't not exist
   *                  or can't be read,
   * since 0.0.1,
   */
  var GeoIP2 = function(dbfile) {
    var DATA_SECTION_SEPARATOR_SIZE = 16    // Bytes of NULLs in between the search tree and the data section.
      , metadataStart
      ;
  
    if (dbfile === undefined)
      throw new Error('You need to provide a database!');
  
    // Check that a file exist and can be read. Otherwise throw an
    // explicit message!
    try {
      fs.accessSync(dbfile, fs.R_OK);
    } catch (e) {
      throw new Error(e.message);
    }
  
    // Ok there is a file. We are going to store all the contents in memory.
    this.db = fs.readFileSync(dbfile);
    this.metadata = {};
  
    // Find where the Metadata section starts.
    metadataStart = _findWhereMetadataStart(this.db);
    // Extract the Metadata structure.
    this.metadata = _decode(this.db, metadataStart, this.metadata.pointerBase).value;
    // Add further details
    this.metadata['nodeByteSize'] = this.metadata.record_size / 4;
    this.metadata['searchTreeSection'] = this.metadata.record_size * 2 / 8 * this.metadata.node_count;
    // Compute where the Data section starts.
    this.metadata['pointerBase'] = this.metadata.searchTreeSection + DATA_SECTION_SEPARATOR_SIZE;
  
    // Initialize the cache that stores the latest IP records.
    _cache.init(this);
  };
  
  // -- Public Methods.
  GeoIP2.prototype = {
  
    /**
     * Returns the database's metadata.
     *
     * @method ()
     * @public
     * @returns {Object}  Returns the metadata structure,
     * since 0.0.1,
     */
    getMetadata: function() {
      return this.metadata;
    },
  
    /**
     * Returns Maxmind's database record for this given IP address.
     *
     * @method (arg)
     * @public
     * @param {String}    The IPV4 or IPV6 address,
     * @returns {Objet}   The associated IP record or null,
     * since 0.0.1,
     */
    getRecord: function(ip) {
      var cache
        , pointer
        , value
        ;
  
      if (ip === undefined || ip === null)
        return null;
  
      /*
      pointer = _findAddressInTree(ip, this.db, this.metadata);
      return (pointer === 0) ? null : _decode(this.db, pointer, this.metadata.pointerBase).value;
      */
  
      // Retrieve the pointer associated to this IP.
      pointer = _findAddressInTree(ip, this.db, this.metadata);
      if (pointer === 0)
        return null;
  
      // IP already in cache?
      cache = _cache.get(this, pointer);
      if (cache)
        return cache;
  
      // Not! Extract the value from the db and save it to cache.
      value = _decode(this.db, pointer, this.metadata.pointerBase).value;
      _cache.set(this, pointer, value);
      return value;
    },
  };/// <reference path="./types/ngx_http_js_module.d.ts" />
export default { lapiPoller, getDecisionForRequest, serveBanTemplate, serveCaptchaTemplate, serveCaptchaSubmissionHandler };
var fs = require("fs");
const querystring = require('querystring');
// @ts-ignore
const config = crowdsec_config;
// @ts-ignore
const ip2CountryCache = ngx.shared.ip_to_country_cache;
// @ts-ignore
const ip2asCache = ngx.shared.ip_to_as_cache;
function getASForIP(ip) {
    const cacheResult = ip2asCache.get(ip);
    if (typeof cacheResult == "string" && cacheResult != "") {
        return cacheResult;
    }
    // @ts-ignore
    const reader = new GeoIP2(config.as_remediations.ip_to_as_mmdb_path);
    const result = reader.getRecord(ip).autonomous_system_number;
    ip2asCache.set(ip, result.toString().toLowerCase());
    return result;
}
function getCountryForIP(ip) {
    const cacheResult = ip2CountryCache.get(ip);
    if (typeof cacheResult == "string" && cacheResult != "") {
        return cacheResult;
    }
    // @ts-ignore
    const reader = new GeoIP2(config.country_remediations.ip_to_country_mmdb_path);
    const result = reader.getRecord(ip).country.iso_code;
    ip2CountryCache.set(ip, result.toLowerCase());
    return result;
}
function prepareRequest(config) {
    let lapiURL = config.crowdsec_config.lapi_url;
    if (!config.crowdsec_config.lapi_url.endsWith("/")) {
        lapiURL += "/";
    }
    const startup = "true" ? ngx.shared.crowdsec_decision_store.size() == 0 : "false";
    lapiURL += "v1/decisions/stream?startup=" + startup;
    if (config.crowdsec_config.exclude_scenarios_containing.length) {
        lapiURL += "&scenarios_not_containing=" + config.crowdsec_config.exclude_scenarios_containing.join(",");
    }
    if (config.crowdsec_config.include_scenarios_containing.length) {
        lapiURL += "&scenarios_containing=" + config.crowdsec_config.include_scenarios_containing.join(",");
    }
    if (config.crowdsec_config.only_include_decisions_from.length) {
        lapiURL += "&origins=" + config.crowdsec_config.only_include_decisions_from.join(",");
    }
    lapiURL += "&scopes=ip,range";
    if (config.as_remediations.enabled) {
        lapiURL += ",as";
    }
    if (config.country_remediations.enabled) {
        lapiURL += ",country";
    }
    ngx.log(ngx.INFO, "LAPI URL: " + lapiURL);
    return new Request(lapiURL, { headers: { "x-api-key": config.crowdsec_config.lapi_key } });
}
async function lapiPoller() {
    if (ngx.worker_id != 0) {
        return;
    }
    const lapiReq = prepareRequest(config);
    const resp = await ngx.fetch(lapiReq);
    const respText = await resp.text();
    ngx.log(ngx.INFO, "Got response: " + JSON.stringify(respText));
    const respJSON = JSON.parse(respText);
    ngx.shared.crowdsec_decision_store.add("IP_RANGES", "{}");
    // @ts-ignore
    const currentIPRanges = JSON.parse(ngx.shared.crowdsec_decision_store.get("IP_RANGES"));
    let ipRangesChanged = false;
    if ("deleted" in respJSON && Array.isArray(respJSON["deleted"])) {
        respJSON["deleted"].forEach((decision) => {
            decision = normalizeDecision(decision);
            if (decision.scope == "range") {
                delete currentIPRanges[decision.value];
                ipRangesChanged = true;
            }
            else {
                ngx.shared.crowdsec_decision_store.delete(decision.value);
            }
        });
    }
    if ("new" in respJSON && Array.isArray(respJSON["new"])) {
        respJSON["new"].forEach((decision) => {
            decision = normalizeDecision(decision);
            if (decision.scope == "range") {
                currentIPRanges[decision.value] = decision.type;
                ipRangesChanged = true;
            }
            else {
                ngx.log(ngx.INFO, "Setting decision for " + decision.value + " to " + decision.type);
                ngx.shared.crowdsec_decision_store.set(decision.value, decision.type.toString());
            }
        });
    }
    if (ipRangesChanged) {
        ngx.shared.crowdsec_decision_store.set("IP_RANGES", JSON.stringify(currentIPRanges));
    }
}
function normalizeDecision(decision) {
    decision.value = decision.value.toLowerCase();
    decision.type = decision.type.toLowerCase();
    decision.scope = decision.scope.toLowerCase();
    decision.origin = decision.origin.toLowerCase();
    return decision;
}
function serveBanTemplate(r) {
    r.headersOut["Content-Type"] = "text/html";
    if ("ban_template_path" in r) {
        return fs.readFileSync(r.ban_template_path);
    }
    return fs.readFileSync(config.ban.template_path);
}
function isCaptchaSubmission(r) {
    return "captcha_token" in r.args;
}
async function captchaSubmissionIsCorrect(r) {
    let siteVerifyURL;
    if (config.captcha.provider == "google_recaptcha_v2") {
        siteVerifyURL = "https://www.google.com/recaptcha/api/siteverify";
    }
    else if (config.captcha.provider == "hcaptcha") {
        siteVerifyURL = "https://hcaptcha.com/siteverify";
    }
    else {
        siteVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
    }
    const captchaToken = r.args["captcha_token"];
    const body = querystring.stringify({
        secret: config.captcha.secret_key,
        response: captchaToken,
        remoteip: r.remoteAddress
    });
    const result = await ngx.fetch(siteVerifyURL, {
        body: body,
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
    });
    const outcome = await result.json();
    return outcome["success"] === true;
}
async function serveCaptchaSubmissionHandler(r) {
    if (await captchaSubmissionIsCorrect(r) == true) {
        // @ts-ignore
        const cookie = jwt.encode({ "exp": Date.now() / 1000 + 1800 }, config.captcha.secret_key + r.remoteAddress);
        r.headersOut["Set-Cookie"] = ["crowdsec_captcha=" + cookie + "; Path=/; HttpOnly; SameSite=Strict"];
        r.return(200, "OK");
    }
    else {
        r.return(401, "Unauthorized");
    }
}
function serveCaptchaTemplate(r) {
    r.headersOut["Content-Type"] = "text/html";
    if ("captcha_template_path" in r) {
        return fs.readFileSync(r.captcha_template_path);
    }
    let captchaTemplate = fs.readFileSync(config.captcha.template_path).toString();
    captchaTemplate = captchaTemplate.replaceAll("{{captcha_site_key}}", config.captcha.site_key);
    captchaTemplate = captchaTemplate.replaceAll("{{captcha_frontend_js}}", jsForCaptchaProvider(config.captcha.provider));
    return captchaTemplate.replaceAll("{{captcha_frontend_css_class}}", cssClassForCaptchaProvider(config.captcha.provider));
}
const jsForCaptchaProvider = (provider) => {
    return {
        "turnstile": "https://challenges.cloudflare.com/turnstile/v0/api.js",
        "google_recaptcha_v2": "https://www.google.com/recaptcha/api.js",
        "hcaptcha": "https://hcaptcha.com/1/api.js"
    }[provider];
};
const cssClassForCaptchaProvider = (provider) => {
    return {
        "turnstile": "cf-turnstile",
        "google_recaptcha_v2": "g-recaptcha",
        "hcaptcha": "h-captcha"
    }[provider];
};
function alignDecisionWithConfig(decision, r) {
    const ret = _alignDecisionWithConfig(decision, r);
    if (ret == "captcha" && isCaptchaSubmission(r)) {
        return "captcha_submission";
    }
    return ret;
}
function _alignDecisionWithConfig(decision, r) {
    if (decision == "ban") {
        if ("disable_ban" in r) {
            if (r.disable_ban == "true" || r.disable_ban == "1") {
                return "pass";
            }
            else {
                return "ban";
            }
        }
        else if (!config.ban.enabled) {
            return "pass";
        }
        return "ban";
    }
    else if (decision == "captcha") {
        if ("disable_captcha" in r) {
            if (r.disable_captcha == "true" || r.disable_captcha == "1") {
                return "pass";
            }
            else {
                return hasValidCaptchaCookie(r) ? "pass" : "captcha";
            }
        }
        else if (!config.captcha.enabled) {
            return "pass";
        }
        return hasValidCaptchaCookie(r) ? "pass" : "captcha";
    }
    return config.fallback_decision;
}
function hasValidCaptchaCookie(r) {
    // @ts-ignore
    const captchaCookie = cookie.parse(r.headersIn.Cookie || "");
    if ("crowdsec_captcha" in captchaCookie) {
        try {
            // @ts-ignore
            jwt.decode(captchaCookie["crowdsec_captcha"], config.captcha.secret_key + r.remoteAddress, false);
        }
        catch (e) {
            return false;
        }
        return true;
    }
    return false;
}
function getDecisionForRequest(r) {
    // TODO: handle cases where there could be multiple decisions of diffetent type for the same IP
    // For that we'll need to map ip to an stringified array of decisions
    const ipDecision = ngx.shared.crowdsec_decision_store.get(r.remoteAddress);
    if (typeof (ipDecision) == "string" && ipDecision != "") {
        return alignDecisionWithConfig(ipDecision, r);
    }
    if (config.country_remediations.enabled) {
        const country = getCountryForIP(r.remoteAddress);
        const countryDecision = ngx.shared.crowdsec_decision_store.get(country);
        if (typeof (countryDecision) == "string" && countryDecision != "") {
            return alignDecisionWithConfig(countryDecision, r);
        }
    }
    if (config.as_remediations.enabled) {
        const as = getASForIP(r.remoteAddress);
        const asDecision = ngx.shared.crowdsec_decision_store.get(as);
        if (typeof (asDecision) == "string" && asDecision != "") {
            return alignDecisionWithConfig(asDecision, r);
        }
    }
    // @ts-ignore
    const actionByIPRange = JSON.parse(ngx.shared.crowdsec_decision_store.get("IP_RANGES"));
    // @ts-ignore
    const clientIPAddr = ipaddr.parse(r.remoteAddress);
    const entries = Object.entries(actionByIPRange);
    for (let i = 0; i < entries.length; i++) {
        const entry = entries[i];
        const range = entry[0];
        const action = entry[1];
        // @ts-ignore
        if (clientIPAddr.match(ipaddr.parseCIDR(range))) {
            return alignDecisionWithConfig(action, r);
        }
    }
    return "pass";
}
