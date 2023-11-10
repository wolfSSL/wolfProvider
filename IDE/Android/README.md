Installing WolfProvider on Android

# Prerequisites
You'll need to get the [Android NDK](https://developer.android.com/ndk/downloads/). I used [this one](https://dl.google.com/android/repository/android-ndk-r26b-linux.zip). Extract it into the folder that contains all the other files.

You will also need Android Studio to run an emulator. Though having an Android device plugged in via USB and able to connect via ADB should also work.

This example works with an x86_64 version of Android, but it should be relatively simple to change and use ARM or ARM64. You would need to modify `build.sh`.

# Usage
Have your Android device up and running. You can confirm it is reachable with `adb devices`.

Run the `build.sh` command which will compile OpenSSL as well as WolfProvider. Once the libraries are built, it will remove the symbolic links from the folders (because `adb push` is unable to deal with them). Lastly it will upload the files to `/data/local/tmp` on your Android device. It will also copy `run.sh` and execute it.

`run.sh` is a script that will attempt to run OpenSSL with wolfProvider and should output something like:
```
Providers:
  libwolfprov
    name: wolfSSL Provider
    version: 0.0.1
    status: active
    build info: wolfSSL 5.6.4
    gettable provider parameters:
      name: pointer to a UTF8 encoded string (arbitrary size)
      version: pointer to a UTF8 encoded string (arbitrary size)
      buildinfo: pointer to a UTF8 encoded string (arbitrary size)
      status: integer (arbitrary size)
		evpciph_aes_wrap.txt ... PASS
		evpencod.txt ... PASS
		evpkdf_hkdf.txt ... PASS
		evpkdf_pbkdf2.txt ... PASS
		evpkdf_tls11_prf.txt ... PASS
		evpkdf_tls12_prf.txt ... PASS
		evpkdf_tls13_kdf.txt ... PASS
		evpmd_md.txt ... PASS
		evpmd_sha.txt ... PASS
		evppbe_pbkdf2.txt ... PASS
		evppbe_pkcs12.txt ... PASS
		evppkey_kdf_hkdf.txt ... PASS
		evppkey_kdf_tls1_prf.txt ... PASS
```

An alternate way of running `build.sh` is within a Docker environment. This can avoid unwanted local changes to your system by wrapping the environment in a container. Simply launch Docker with `docker run --rm -it -v $(pwd)/../../:/ws -w /ws/IDE/Android ubuntu:22.04 ./build.sh`. This should start the script and build everything in the local folder. Then you can take the `run.sh` script and run it from your host environment.
