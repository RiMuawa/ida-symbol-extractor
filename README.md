# IDA Symbol Extractor

A lightweight IDA Pro script for extracting function symbol names and addresses from a custom data section — typically found in embedded MIPS ELF binaries with dispatch tables.


## Features

- Recognize `[string_ptr, function_ptr]` pairs from specified memory range
- Renames functions in IDA Pro automatically
- Simple, minimal dependency (IDAPython only)


## Use Case

This tool is especially useful when:

- You're analyzing binaries with hardcoded dispatch tables
- Function names are stored as C strings followed by pointers in a known format (e.g., `.word "name" + .word address`)

>example use case:
![image](/images/image.png)

## Getting Started

- Download File or clone this repo
- run the scripts via `File → Script file...` in IDA.

## Configuration

In both scripts, edit the following values at the top to match your binary:
```python
start_addr = 0x00 #Add your own address here
end_addr   = 0x00 #Add your own address here
```

