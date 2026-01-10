# VFDecrypt

[VFDecrypt](https://www.theiphonewiki.com/wiki/VFDecrypt) is used to decrypt Apple iOS root filesystem images.
Root filesystem images inside IPSW files are encrypted for iOS >= 9.
Since iOS 10, root filesystem images are not encrypted and VFDecrypt is no longer required.

Decrypting root filesystem images requires the decryption key.
This is provided for most root filesystem images version by the community at [The iPhone Wiki](https://www.theiphonewiki.com/wiki/Firmware_Keys).

There are several VFDecrypt builds available on the internet.
We've used and updated the implementation [here](https://github.com/trailofbits/iverify-oss/tree/master/vendor/vfdecrypt).
We've updated `vfdecrypt.c` to support OpenSSL >= 1.1.0 and the `Makefile` to be OS-dependent.

### Dependencies

To build and run vfdecrypt locally, you need to install the following dependencies:

* macOS

```console
brew install openssl make
```

* Ubuntu/Debian

```console
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev coreutils
```

* Fedora/RHEL/CentOS

```console
sudo dnf install -y gcc gcc-c++ make openssl-devel coreutils
```

* Arch Linux

```console
sudo pacman -S base-devel openssl coreutils
```

You build `vfdecrypt` using

```console
make
```

You run `vfdecrypt` by passing it the root filesystem key, the root filesystem image and the output (decrypted) file:

```console
./vfdecrypt -i ~/Projects/store/out/iPhone5,1_9.3_13E237/058-25512-331.dmg -k 2a66fd6377af8f60d5e300ac3aa8d9c44a1c0dee94579ad3f8a26515debbf381bb971ae8 -o decrypted.dmg
```

iExtractor runs `vfdecrypt` as part of the `bin/decrypt_fs` and `scripts/decrypt_fs` scripts.

The usage inside iExtractor:

```console
docker run -v "<input_absolute_path>":/in -v "<output_absolute_path>":/out -t ghcr.io/malus-security/vfdecrypt:latest -k<rootfs_key> /in /out > /dev/null 2>&1
```