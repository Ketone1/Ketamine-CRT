# Ketamine-CRT
Ketamine is a 64x architecture no CRT (C Runtime Library Files) base which you can use in your dynamic link library. The base itself comes with four functions including GetModuleBase, GetModuleExport, strcmp and strlen.

Before use you must set the project properties:

Project Properties -> C/C++ -> Precompiled Headers = Not Using Precompiled Headers                                   
Project Properties -> Linker -> Input -> Ignore All Default Libraries = Yes (/NODEFAULTLIB)

Next to make the asm file show in the linker you must enable masm:

Right click your project, hover above "Build Dependencies" then select "Build Customizations". Once you are on the Build Customizations window, select "masm(.targets, •props)"
Now you can input the asm file. 

Even after doing this, if you build and you get the linker error "unresolved external symbol GetProcessEnvironment" then do this:
delete the memory.asm file and re-add it back into the project.

