# PE Dumper
Simple PE Format Parser written in C/C++ using Win32API

## Features
* Reads passed path and scans recursively the folder
* Dumps in an output-file the whole information about PE Format for each found file: 
    1. DOS Header
    2. NT Headers
    3. Section Headers
    4. Exports Table
    5. Imports Table

## Buit with
* C/C++
* Win32API
* Microsoft Visual Studio

## Usage
1. Compile project for `x86` platform
2. Run the created `.exe` from `cmd` and give as parameter a valid Windows path (e.g. `pedumper.exe "C:"`) 

## Resources
- http://www.delphibasics.info/home/delphibasicsarticles/anin-depthlookintothewin32portableexecutablefileformat-part1
- http://www.delphibasics.info/home/delphibasicsarticles/anin-depthlookintothewin32portableexecutablefileformat-part2