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
You can use args such as 'img' OR 'iso' followed by 'CPU Cores' and 'Mem(G/M/K)' for the run script like:

for .img
```
./Run.sh img 8 2G
```

for .iso
```
./Run.sh iso 4 512M
```

Another note: also incase using the './' prefix does not work when using the the script use 'sh' cmdlet for example:

```
sh Build.sh
```

and for run script

```
sh Run.sh <your choice (iso/img)> <CPU Cores> <Memory(G/M/K)>
```

Yay you have installed AxeialOS (or just tested it).
Once it boots, you should just see some testing and logging code of the EarlyBootConsole (as it doesn't have any kind of shell or terminal yet).

Extras:

1: If you want to do more with it and want to test on some spare and real machine, just burn the '.img' given from the build onto a USB Thumbdrive or some other USB mass storage device, and boot it from your UEFI Firmware.

2: If you want to see the complete mirror log of the console, inspect the 'debug.log' file in the project root

3: Now the kernel has configuration header namely AXEKCONF located in ```./Kernel/KrnlLibs/Includes/__AXEKCONF__.c```

anyway thanks for actually trying it out.

You are free to experiment on this operating system as much as you want

join my community! 
https://discord.gg/dEPMKfktBt
