# ghidra_psx_ldr
Sony Playstation PSX executables loader for GHIDRA

Video tutorial on how to deal with overlays: https://youtu.be/DuQQfjTkkQc

# Building
* Install `GhidraDev` plugin into Eclipse
* Add your Ghidra installation dir
* Import this repository into Eclipse
* Do GhidraDev -> Link Ghidra...
* Press GhidraDev -> Export -> Ghidra module extension...
    
# Installation
* Open Ghidra, go to File -> Install Extensions... and select the .zip file generated by the previous step

# Analysing PSYQ LIBs and OBJs
* In case you have a directory with OBJ-files extracted from a LIB-file, create an empty `PSYQ_LIBNAME_XXX` file, where `LIBNAME` is your LIB-file name (for ex. `LIBSND`) and `XXX` is PSYQ version number according to [this list](https://github.com/lab313ru/psx_psyq_signatures).
* In case you want to batch-import all OBJ-files for a LIB-file or import a standalone OBJ-file (like `8MBYTE.OBJ`), create an empty `PSYQ_XXX` file, where `XXX` is PSYQ version number according to [this list](https://github.com/lab313ru/psx_psyq_signatures).

# Patches format ([example here](https://github.com/lab313ru/psx_psyq_signatures/blob/main/patches.json))

* `~` - is for replacing some pattern in a signature. check field is the original bytes in the signature to compare with
* `+` - is for adding some pattern in a signature
* `-` - is for removing some pattern from a signature

! `pos` fields are for the original signature. you should not add appended or removed sizes to them

# Screenshots

![Screen1](/imgs/screen1.png?raw=true)
![Screen7](/imgs/screen7.png?raw=true)
![Screen4](/imgs/screen4.png?raw=true)
![Screen5](/imgs/screen5.png?raw=true)
![Screen6](/imgs/screen6.png?raw=true)

