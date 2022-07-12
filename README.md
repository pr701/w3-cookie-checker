# W3 Cookie Checker
HWID and Offline License Checker for [WarCraft III: Refunded](https://eu.shop.battle.net/en-us/family/warcraft-iii) and [StarCraft: Remastered](https://eu.shop.battle.net/en-us/family/starcraft-remastered)

## License

The license file (`cookie.bin`) is an encrypted [protobuf](https://github.com/protocolbuffers/protobuf) payload, located at `%LocalAppData%\Blizzard Entertainment\ClientSdk`.

## HWID

HWID aka Hardware ID is a hash that depends on the parameters in the *registry* and the *logical drive*, is the key to the cookie.

## Usage

A list of available options can be retrieved using:

```shell
w3_cookie_checker --help
```

### Arguments

| Option        | Default | Description                                                  |
| ------------- | ------- | ------------------------------------------------------------ |
| `-h/--help`   |         | A list of available command options                          |
| `-k/--key`    |         | Set HWID, if this parameter is not set, the HWID will be generated |
| `-d/--drive`  |         | Set a logical drive to generate HWID (format: `X:\`)         |
| `-c/--cookie` |         | Cookie filename                                              |

### Sample

Just sample with my license

```shell
w3_cookie_checker -c cookie.bin -d F:\

Offline cookie checker v1.0

Generate HWID (drive: F:\)...
HWID = 45xxxxxxxxxxxxxxxxxxLOfEffI=
Reading Cookies...
[#0]
Game ID = 22323 (Warcraft III: Refunded)
Verified signature = true
Entitlements = [w3-standard,hd,w3-presale]
Game ID = 22323
Account ID = xxxxxxxxx
ID = xxxxxxxxx
Locale = RUS
Expiration Timestamp = 1658196783
```

Generate HWID only

```shell
w3_cookie_checker -d F:\

Offline cookie checker v1.0

Generate HWID (drive: F:\)...
HWID = 45xxxxxxxxxxxxxxxxxxLOfEffI=
```

## Dependencies

[Botan (crypto)](https://github.com/randombit/botan)

[Google protobuf](https://github.com/protocolbuffers/protobuf)

[cxxopts](https://github.com/jarro2783/cxxopts)

