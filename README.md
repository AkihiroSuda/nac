# NAC is Not A Container for macOS

NAC provides a lightweight virtual environment for macOS with container-like user experience.

NAC does not need the root privilege and does not conflict with System Integrity Protection (SIP).

Note that NAC is _Not A Container_; NAC does not provide a secure isolation in any way.
In this sense, NAC is akin to Python's `venv` rather than Docker.

## Installation

```bash
make
sudo make install
```

## Usage

The command below virtually mounts `$HOME/usr_local` into `/usr/local`:
```bash
nac run -it --rm -v $HOME/usr_local:/usr/local host bash
```

The syntax of `nac run` is similar to `docker run`, but `nac run` does not support "images" yet.

> [!WARNING]
>
> Some applications (such as Homebrew) may not recognize the virtual mounts.
>
> Be cautious, especially when removing or overwriting a file on a virtual mount.
> It may potentially result in removing or or overwriting a file on the real filesystem.

> [!NOTE]
>
> GUI applications do not work (yet).

## How it works
NAC copies a command binary into a temporary directory and attaches
the `com.apple.security.cs.allow-dyld-environment-variables` entitlement to it
so that dylib calls for libc can be intercepted with `DYLD_INSERT_LIBRARIES`.

Non-dylib calls, such as a direct invocation of the `svc` (ARM) / `syscall` (Intel) instructions, are not intercepted.

## Future work
- Support running multiple Homebrew instances with isolated `/opt/homebrew`
- Build a fork of `/usr/lib/system/libsystem_kernel.dylib`, and inject it via `DYLD_LIBRARY_PATH`.
  This is expected to be more robust and will need less amount of hooks.
  However, it seems very hard to compile `libsystem_kernel.dylib` from
  the [source](https://github.com/apple-oss-distributions/xnu/tree/main/libsyscall).
