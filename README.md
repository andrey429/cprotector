cprotector
==========

**cprotector** is a result of research on PE EXE format (Windows executable) 
It is <em>not</em> intended for a real use and was intended to be used as a proof of concept in educational purposes

Nonetheless, it contains some very-hard-to-find tricks on PE-EXE.
One (and foremost) of such implemented tricks is merging ASM-compiled section into PE EXE file and changing original file entry point to this ASM section. 
In order to execute and get some info from original PE EXE file (for example, calculate checksum of a section or unpack it), ASM-section uses relative addressing.

Source file information:
-------------------------

* cprotector.cpp - a <em>VERY</em> simple GUI app that allows to choose a file in which to install the "protector" section
* protector_core.cpp - core logics for cprotector.cpp
* pe_commons.cpp - parser logics for PE EXE format (headers extractor, etc)
* protector.asm - MASM32 source of "protector" section. Used to check a set of file attributes and then delegate control to original EXE entry point

