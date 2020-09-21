# Changelog

`libjwt-typed` uses [PVP Versioning][1].
The changelog is available [on GitHub][2].

## 0.2

New features

* Ability to **use public keys only if you do not intend to sign tokens**. This feature is backwards incompatible:
  * Function `signJwt` has been removed in favor of `sign` and `sign'`
  * Signing and decoding functions now depend on the new `Algorithm k` type and their contexts have been extended to accomodate new key classes (`SigningKey` and `DecodingKey` respectively)
  * JWT header `alg` is now an enumeration, handling of all key data has been moved to `Algorithm`


## 0.1

* Initially created.

[1]: https://pvp.haskell.org
[2]: https://github.com/marcin-rzeznicki/libjwt-typed/releases
