# Introduction
This is a proof-of-concept to show how a stack-based buffer overflow vulnerability can be exploited for remote code execution in the Steam version of BlazBlue: Central Fiction (game by Arc System Works/Arc Sys).
I've decided on public disclosure to make sure that Arc Sys fixes this sooner than later, knowing their history of sitting on known reported problems for too long and never fixing them in some cases.
In the meantime, or if Arc Sys decides this isn't worthy of a quick fix, this should help the community create their own fix, as this is a rather simple thing to prevent. I don't recommend playing the game online without a fix, even if it's private lobbies.

# Vulnerability
![function](https://user-images.githubusercontent.com/109482766/179424981-c4315311-6f09-42dc-b0d6-38a35108c714.png)

The image above shows the decompiled & labeled vulnerable code in BBCF.exe. It's part of the SteamUdp class, I don't know the actual function name.
It uses the IsP2PPacketAvailable & ReadP2PPacket functions of ISteamNetworking from Steamworks SDK, creating the core of a P2P recv loop.
From my testing, this function only gets called once the actual ingame match starts (after character selection).
The size of the buffer on the stack doesn't get checked against the actual packet size before the packet is written into it, making it possible to overwrite the return address, which will change the flow of execution once the function returns.
BBCF.exe has no ASLR enabled and appears to be compiled without stack canaries, which means that currently any stack-based buffer overflow of similiar quality in the netcode can lead to RCE.
Finding this took me only 5 minutes after I started looking for it, which is worrisome considering how long this must have been in the game. It's likely that this is the exact vulnerability that stirred up the community recently, but for the reasons above it's not unlikely that there are more.
This probably also affects other Arc Sys games if they use the same code and also have these security features disabled.

# PoC
The PoC uses the overflow to jump into a ROP chain, which allocates executable memory and stores some shellcode to start calc.exe.
Since this is only for demonstration, the ROP chain is not optimized and returning to regular execution is not in scope (Process will crash after payload execution).
To test it yourself, make sure to compile as x86 and load the dll into your BBCF.exe process at runtime.
You can then call the exported function "RunPoCOnSteamID", which takes the target Steam ID as a C-style wide string in decimal (for reliable timing, call right after character selection).


https://user-images.githubusercontent.com/109482766/179426816-7507a75e-4554-4f99-91e0-e6ef89ddde73.mp4


# Fix
Simply make sure the queued packet is not larger than the intended 4096 bytes before ReadP2PPacket copies the memory.
For Arc Sys, your mistake was re-using the cubDest param as the target buffer size and somehow expecting the packet can't be larger. Enabling the mentioned security features would also help.
For the community, I suggest either a byte patch, or hooking one of the ISteamNetworking functions like so:
```cpp
bool __fastcall hReadP2PPacket(void* _this, void* edx, void* pubDest, uint32 cubDest, uint32* pcubMsgSize, CSteamID* psteamIDRemote, int iVirtualPort)
{
    if (cubDest > 4096 && iVirtualPort == 3)
    {
        // Overflow prevented
        return false;
    }

    return oReadP2PPacket(_this, edx, pubDest, cubDest, pcubMsgSize, psteamIDRemote, iVirtualPort);
}
```

# To Arc Sys
It would be great if you could provide something like a clear vulnerability disclosure policy in the future, to make this easier for all of us.

# External
https://github.com/SteamRE/open-steamworks
