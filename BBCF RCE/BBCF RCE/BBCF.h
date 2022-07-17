#pragma once

namespace BBCF
{
	struct SteamInterfaces
	{
		std::uintptr_t steamClient017;
		std::uintptr_t steamUser019;
		std::uintptr_t steamFriends015;
		std::uintptr_t steamUtils008;
		std::uintptr_t steamMatchmaking009;
		std::uintptr_t steamUserStats011;
		std::uintptr_t steamApps008;
		std::uintptr_t steamMatchMakingServer002;
		ISteamNetworking005* steamNetworking005;
		std::uintptr_t steamRemoteStorage014;
		std::uintptr_t steamScreenshots003;
		std::uintptr_t steamHttp002;
		std::uintptr_t steamUnifiedMessages001;
		std::uintptr_t steamController004;
		std::uintptr_t steamUGC009;
		std::uintptr_t steamApplist001;
		std::uintptr_t steamMusic001;
		std::uintptr_t steamMusicRemote001;
		std::uintptr_t steamHtmlSurface003;
		std::uintptr_t steamInventory001;
		std::uintptr_t steamVideo001;
	};

	typedef bool(__cdecl* tGetSteamInterfaces)(SteamInterfaces* value);
	inline bool GetSteamInterfaces(SteamInterfaces* value)
	{
		return ((tGetSteamInterfaces)0x407D80)(value);
	}
}