HashTap 0.1
===========

Tool for running LLMNR/NBNS spoofing on a Windows TAP interface.


Usage
-----

Tap.exe <device guid> <ip of responder server>

Finding the device guid is difficult as a low-priv user, there are some registry branches that can be manually read and you can make an educated guess about which GUID represents the TAP interface based on IP/subnet added to it.

Once this starts it'll poison any requests it gets, its usually much faster than responses from legit sources too. Its known to work well with WPAD spoofing.
Low priv users appear to be able to use this without problems

Tested on:
* OpenVPN TAP adapter
* NordVPN TAP adapter


