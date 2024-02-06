# Installation

## RustUp

> RustUp is this installation tool of Rust

RustUp: https://www.rust-lang.org/tools/install\

 - Quick install via the Visual Studio Community installer 
> This will install Visual Studio Code, install it and close it.
 - Proceed with installation (default)

### Version check

```bash
$ rustup --version
1.26.0

$ rustc --version
1.75.0

$ cargo --version
1.75.0
```

## Npcap

> Npcap is the packet capture library used in this project

### Npcap Installer

https://npcap.com/dist/npcap-1.79.exe

 - Default installation

### Npcap SDK

https://npcap.com/dist/npcap-sdk-1.13.zip

 - Unzip
 - Copy Lib/x64 path (C:\Npcap\Lib\x64 for me)
 - Add the path to the "LIB" environement variable

## Git

https://git-scm.com/

 - Default installation

# Run the script

In a new cmd

```bash
$ cd C:/path/to/folder
$ git clone https://github.com/zalo-alex/net-cap
$ cd net-cap
$ cargo run
```