A simple AMD64 Modern POSIX Operating System.
My plan is to use as my primary one (or secondary on my laptop).

it's not that complete neither that good but i am trying my best,
but hey it's good for me.

so let's install it.

Steps to install this thing: (please use a linux distro because of tools)

Step1: Clone this repository
```
git clone https://github.com/VOXIDEVOSTRO/AxeialOS.git
```

Note on Step1:
if you want early acsess to some stuff use this
```
git clone -b pre-main https://github.com/VOXIDEVOSTRO/AxeialOS.git
```

Step2: Go into the repository
```
cd AxeialOS
```

Step3: Init the submodules
```
git submodule update --init --recursive
```

Step4: Make the bootable image (.img) (Note: Make sure you have GCC)
```
./Build.sh
```

Step5: Hopefully if no errors making it, run it (Note: You must have QEMU, or specifically the x86_64 one, also you must have OVMF for the UEFI Firmware on QEMU)
```
./Run.sh
```

Note for Step5:
You can use args such as 'img' OR 'iso' for the run script like:

for .img
```
./Run.sh img
```

for .iso
```
./Run.sh iso
```

Another note: also incase using the './' prefix does not work when using the the script use 'sh' cmdlet for example:

```
sh Build.sh
```

and for run script

```
sh Run.sh <your choice>
```

Yay you have installed AxeialOS (or just tested it).
Once it boots, you should just see some testing and logging code of the EarlyBootConsole (as it doesn't have any kind of shell or terminal yet).

Extras:

1: If you want to see more output (Debugging Output) on the console, just head to 'Kernel/KrnlLibs/Includes/KrnPrintf.h' and uncomment this statement
```c 
// #define DEBUG /*UNCOMMENT THIS*/
```
and rebuild.

2: If you want to do more with it and want to test on some spare and real machine, just burn the '.img' given from the build onto a USB Thumbdrive or some other USB mass storage device, and boot it from your UEFI Firmware.

3: If you want to see the complete mirror log of the console, inspect the 'debug.log' file in the project root

4: For a optional splash screen uncomment this statement in the file 'Kernel/Entry.c'
```c
// #define EarlySplash
```

anyway thanks for actually trying it out.

You are free to experiment on this operating system as much as you want

join my community! 
https://discord.gg/dEPMKfktBt
