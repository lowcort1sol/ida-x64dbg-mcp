#include <windows.h>
#include <winhttp.h>

#include <atomic>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <mutex>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "../../pluginsdk/_plugins.h"

#pragma comment(lib, "winhttp.lib")

namespace
{
constexpr wchar_t kBridgeHost[] = L"127.0.0.1";
constexpr INTERNET_PORT kBridgePort = 8765;
constexpr wchar_t kBridgePath[] = L"/";
constexpr char kPluginName[] = "IX64MCP";
constexpr char kProtocolVersion[] = "0.1";
constexpr char kBridgeVersion[] = "0.1.0";

int g_pluginHandle = 0;
std::atomic_bool g_running = false;
std::thread g_bridgeThread;
std::mutex g_socketMutex;
std::mutex g_stateMutex;
HINTERNET g_ws = nullptr;
std::deque<std::string> g_exceptions;
std::map<std::string, std::vector<std::string>> g_recipeApis;

void Log(const char* message)
{
    _plugin_logputs(message);
}

std::string Hex(duint value)
{
    char buffer[32] = {};
#ifdef _WIN64
    sprintf_s(buffer, "0x%llx", static_cast<unsigned long long>(value));
#else
    sprintf_s(buffer, "0x%lx", static_cast<unsigned long>(value));
#endif
    return buffer;
}

std::string JsonEscape(const std::string& value)
{
    std::string out;
    out.reserve(value.size() + 8);
    for(char ch : value)
    {
        switch(ch)
        {
        case '\\':
            out += "\\\\";
            break;
        case '"':
            out += "\\\"";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            if(static_cast<unsigned char>(ch) < 0x20)
                out += ' ';
            else
                out += ch;
            break;
        }
    }
    return out;
}

std::string JsonString(const std::string& value)
{
    return "\"" + JsonEscape(value) + "\"";
}

std::string EnvString(const char* name)
{
    char buffer[512] = {};
    const DWORD copied = GetEnvironmentVariableA(name, buffer, static_cast<DWORD>(sizeof(buffer)));
    if(copied == 0 || copied >= sizeof(buffer))
        return {};
    return buffer;
}

bool SendText(const std::string& message)
{
    std::lock_guard<std::mutex> lock(g_socketMutex);
    if(!g_ws)
        return false;
    auto status = WinHttpWebSocketSend(
        g_ws,
        WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE,
        const_cast<char*>(message.data()),
        static_cast<DWORD>(message.size()));
    return status == NO_ERROR;
}

void CloseSocket()
{
    std::lock_guard<std::mutex> lock(g_socketMutex);
    if(g_ws)
    {
        WinHttpWebSocketClose(g_ws, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, nullptr, 0);
        WinHttpCloseHandle(g_ws);
        g_ws = nullptr;
    }
}

std::string ExtractJsonString(const std::string& json, const std::string& key)
{
    const std::string needle = "\"" + key + "\"";
    auto pos = json.find(needle);
    if(pos == std::string::npos)
        return {};
    pos = json.find(':', pos + needle.size());
    if(pos == std::string::npos)
        return {};
    pos = json.find('"', pos + 1);
    if(pos == std::string::npos)
        return {};
    std::string out;
    bool escape = false;
    for(++pos; pos < json.size(); ++pos)
    {
        char ch = json[pos];
        if(escape)
        {
            out += ch;
            escape = false;
            continue;
        }
        if(ch == '\\')
        {
            escape = true;
            continue;
        }
        if(ch == '"')
            break;
        out += ch;
    }
    return out;
}

int ExtractJsonInt(const std::string& json, const std::string& key, int fallback = 0)
{
    const std::string needle = "\"" + key + "\"";
    auto pos = json.find(needle);
    if(pos == std::string::npos)
        return fallback;
    pos = json.find(':', pos + needle.size());
    if(pos == std::string::npos)
        return fallback;
    ++pos;
    while(pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos])))
        ++pos;
    try
    {
        return std::stoi(json.substr(pos));
    }
    catch(...)
    {
        return fallback;
    }
}

std::string ExtractJsonValue(const std::string& json, const std::string& key)
{
    const std::string needle = "\"" + key + "\"";
    auto pos = json.find(needle);
    if(pos == std::string::npos)
        return {};
    pos = json.find(':', pos + needle.size());
    if(pos == std::string::npos)
        return {};
    ++pos;
    while(pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos])))
        ++pos;
    const auto start = pos;
    int depth = 0;
    bool inString = false;
    bool escape = false;
    for(; pos < json.size(); ++pos)
    {
        const char ch = json[pos];
        if(escape)
        {
            escape = false;
            continue;
        }
        if(ch == '\\' && inString)
        {
            escape = true;
            continue;
        }
        if(ch == '"')
        {
            inString = !inString;
            continue;
        }
        if(inString)
            continue;
        if(ch == '{' || ch == '[')
            ++depth;
        if(ch == '}' || ch == ']')
        {
            if(depth == 0)
                break;
            --depth;
        }
        if(depth == 0 && ch == ',')
            break;
    }
    return json.substr(start, pos - start);
}

duint ParseAddress(const std::string& text)
{
    if(text.empty())
        return 0;
    return DbgValFromString(text.c_str());
}

std::string BytesToHex(const std::vector<uint8_t>& bytes)
{
    static constexpr char alphabet[] = "0123456789abcdef";
    std::string out;
    out.resize(bytes.size() * 2);
    for(size_t i = 0; i < bytes.size(); ++i)
    {
        out[i * 2] = alphabet[(bytes[i] >> 4) & 0xf];
        out[i * 2 + 1] = alphabet[bytes[i] & 0xf];
    }
    return out;
}

duint PeImageSizeFromMemory(duint base)
{
    std::vector<uint8_t> header(0x1000);
    if(!base || !DbgMemRead(base, header.data(), static_cast<duint>(header.size())))
        return 0;
    if(header[0] != 'M' || header[1] != 'Z')
        return 0;
    const uint32_t peOffset = *reinterpret_cast<const uint32_t*>(&header[0x3c]);
    if(peOffset + 0x100 > header.size())
        return 0;
    if(header[peOffset] != 'P' || header[peOffset + 1] != 'E' || header[peOffset + 2] != 0 || header[peOffset + 3] != 0)
        return 0;
    const uint32_t optionalOffset = peOffset + 4 + 20;
    if(optionalOffset + 0x40 > header.size())
        return 0;
    const uint32_t sizeOfImageOffset = optionalOffset + 56;
    return static_cast<duint>(*reinterpret_cast<const uint32_t*>(&header[sizeOfImageOffset]));
}

std::string BuildModulesJson(bool emitEvents);
std::string BuildMemoryMapJson(int limit, int offset);
std::string BuildThreadsJson();
std::string BuildCallStackJson(int limit);
std::string BuildExceptionsJson(int limit, int offset);
std::string BuildBreakpointSnapshotJson(const std::string& addressText);
std::string BuildDumpMetadataJson(const std::string& addressText, int requestedSize);

std::string BuildRegistersJson()
{
    REGDUMP_AVX512 dump = {};
    const bool hasDump = DbgGetRegDumpEx(&dump, sizeof(dump));

    std::ostringstream out;
    out << "{";
    out << "\"cip\":" << JsonString(Hex(DbgValFromString("cip")));
    out << ",\"csp\":" << JsonString(Hex(DbgValFromString("csp")));
    out << ",\"cax\":" << JsonString(Hex(DbgValFromString("cax")));
    out << ",\"cbx\":" << JsonString(Hex(DbgValFromString("cbx")));
    out << ",\"ccx\":" << JsonString(Hex(DbgValFromString("ccx")));
    out << ",\"cdx\":" << JsonString(Hex(DbgValFromString("cdx")));
    out << ",\"csi\":" << JsonString(Hex(DbgValFromString("csi")));
    out << ",\"cdi\":" << JsonString(Hex(DbgValFromString("cdi")));
#ifdef _WIN64
    out << ",\"r8\":" << JsonString(Hex(DbgValFromString("r8")));
    out << ",\"r9\":" << JsonString(Hex(DbgValFromString("r9")));
    out << ",\"r10\":" << JsonString(Hex(DbgValFromString("r10")));
    out << ",\"r11\":" << JsonString(Hex(DbgValFromString("r11")));
    out << ",\"r12\":" << JsonString(Hex(DbgValFromString("r12")));
    out << ",\"r13\":" << JsonString(Hex(DbgValFromString("r13")));
    out << ",\"r14\":" << JsonString(Hex(DbgValFromString("r14")));
    out << ",\"r15\":" << JsonString(Hex(DbgValFromString("r15")));
#endif
    out << ",\"available\":" << (hasDump ? "true" : "false");
    out << "}";
    return out.str();
}

std::string ReadPointerArrayJson(duint start, int count)
{
    std::ostringstream out;
    out << "[";
    bool first = true;
    for(int i = 0; i < count; ++i)
    {
        duint value = 0;
        const duint address = start + static_cast<duint>(i * sizeof(duint));
        if(!DbgMemRead(address, &value, sizeof(value)))
            break;
        if(!first)
            out << ",";
        first = false;
        out << "{\"address\":" << JsonString(Hex(address)) << ",\"value\":" << JsonString(Hex(value)) << "}";
    }
    out << "]";
    return out.str();
}

std::string BuildBreakpointSnapshotJson(const std::string& addressText)
{
    duint address = addressText.empty() ? DbgValFromString("cip") : ParseAddress(addressText);
    if(!address)
        address = DbgValFromString("cip");
    const duint stack = DbgValFromString("csp");
    std::ostringstream out;
    out << "{";
    out << "\"ok\":true";
    out << ",\"address\":" << JsonString(Hex(address));
    out << ",\"registers\":" << BuildRegistersJson();
    out << ",\"stack\":" << ReadPointerArrayJson(stack, 8);
    out << "}";
    return out.str();
}

std::string BuildMemoryMapJson(int limit, int offset)
{
    limit = limit <= 0 ? 256 : (limit > 2048 ? 2048 : limit);
    offset = offset < 0 ? 0 : offset;
    MEMMAP memmap = {};
    std::ostringstream out;
    out << "{\"ok\":true,\"limit\":" << limit << ",\"offset\":" << offset << ",\"regions\":[";
    bool first = true;
    int emitted = 0;
    if(DbgMemMap(&memmap))
    {
        for(int i = offset; i < memmap.count && emitted < limit; ++i)
        {
            const auto& page = memmap.page[i];
            const auto& mbi = page.mbi;
            const duint base = reinterpret_cast<duint>(mbi.BaseAddress);
            const duint allocationBase = reinterpret_cast<duint>(mbi.AllocationBase);
            char moduleName[MAX_MODULE_SIZE] = {};
            DbgGetModuleAt(base, moduleName);
            if(!first)
                out << ",";
            first = false;
            ++emitted;
            out << "{";
            out << "\"base\":" << JsonString(Hex(base));
            out << ",\"allocation_base\":" << JsonString(Hex(allocationBase));
            out << ",\"size\":" << JsonString(Hex(static_cast<duint>(mbi.RegionSize)));
            out << ",\"protect\":" << JsonString(Hex(static_cast<duint>(mbi.Protect)));
            out << ",\"state\":" << JsonString(Hex(static_cast<duint>(mbi.State)));
            out << ",\"type\":" << JsonString(Hex(static_cast<duint>(mbi.Type)));
            out << ",\"module\":" << JsonString(moduleName);
            out << ",\"info\":" << JsonString(page.info);
            out << "}";
        }
        out << "],\"total\":" << memmap.count << "}";
        BridgeFree(memmap.page);
        return out.str();
    }
    out << "],\"total\":0}";
    return out.str();
}

std::string BuildThreadsJson()
{
    THREADLIST list = {};
    DbgGetThreadList(&list);
    std::ostringstream out;
    out << "{\"ok\":true,\"current\":" << list.CurrentThread << ",\"threads\":[";
    bool first = true;
    const auto* funcs = DbgFunctions();
    for(int i = 0; i < list.count; ++i)
    {
        const auto& thread = list.list[i];
        char name[MAX_THREAD_NAME_SIZE] = {};
        if(funcs && funcs->ThreadGetName)
            funcs->ThreadGetName(thread.BasicInfo.ThreadId, name);
        if(!name[0])
            strcpy_s(name, thread.BasicInfo.threadName);
        if(!first)
            out << ",";
        first = false;
        out << "{";
        out << "\"number\":" << thread.BasicInfo.ThreadNumber;
        out << ",\"id\":" << JsonString(Hex(static_cast<duint>(thread.BasicInfo.ThreadId)));
        out << ",\"cip\":" << JsonString(Hex(thread.ThreadCip));
        out << ",\"start\":" << JsonString(Hex(thread.BasicInfo.ThreadStartAddress));
        out << ",\"teb\":" << JsonString(Hex(thread.BasicInfo.ThreadLocalBase));
        out << ",\"suspend_count\":" << thread.SuspendCount;
        out << ",\"last_error\":" << JsonString(Hex(static_cast<duint>(thread.LastError)));
        out << ",\"name\":" << JsonString(name);
        out << "}";
    }
    out << "]}";
    if(list.list)
        BridgeFree(list.list);
    return out.str();
}

std::string BuildCallStackJson(int limit)
{
    limit = limit <= 0 ? 64 : (limit > 256 ? 256 : limit);
    DBGCALLSTACK stack = {};
    const auto* funcs = DbgFunctions();
    if(funcs && funcs->GetCallStackEx)
        funcs->GetCallStackEx(&stack, true);
    else if(funcs && funcs->GetCallStack)
        funcs->GetCallStack(&stack);
    std::ostringstream out;
    out << "{\"ok\":true,\"limit\":" << limit << ",\"frames\":[";
    bool first = true;
    for(int i = 0; i < stack.total && i < limit; ++i)
    {
        const auto& entry = stack.entries[i];
        if(!first)
            out << ",";
        first = false;
        out << "{";
        out << "\"addr\":" << JsonString(Hex(entry.addr));
        out << ",\"from\":" << JsonString(Hex(entry.from));
        out << ",\"to\":" << JsonString(Hex(entry.to));
        out << ",\"comment\":" << JsonString(entry.comment);
        out << "}";
    }
    out << "],\"total\":" << stack.total << "}";
    if(stack.entries)
        BridgeFree(stack.entries);
    return out.str();
}

std::string BuildExceptionsJson(int limit, int offset)
{
    limit = limit <= 0 ? 100 : (limit > 500 ? 500 : limit);
    offset = offset < 0 ? 0 : offset;
    std::lock_guard<std::mutex> lock(g_stateMutex);
    std::ostringstream out;
    out << "{\"ok\":true,\"limit\":" << limit << ",\"offset\":" << offset << ",\"exceptions\":[";
    bool first = true;
    for(size_t i = static_cast<size_t>(offset); i < g_exceptions.size() && limit > 0; ++i, --limit)
    {
        if(!first)
            out << ",";
        first = false;
        out << g_exceptions[i];
    }
    out << "],\"total\":" << g_exceptions.size() << "}";
    return out.str();
}

double ByteEntropy(const std::vector<uint8_t>& bytes)
{
    if(bytes.empty())
        return 0.0;
    double counts[256] = {};
    for(uint8_t byte : bytes)
        counts[byte] += 1.0;
    double entropy = 0.0;
    for(double count : counts)
    {
        if(count <= 0.0)
            continue;
        const double p = count / static_cast<double>(bytes.size());
        entropy -= p * (std::log(p) / std::log(2.0));
    }
    return entropy;
}

std::string BuildDumpMetadataJson(const std::string& addressText, int requestedSize)
{
    const duint address = ParseAddress(addressText);
    if(!address || requestedSize <= 0)
        return "{\"ok\":false,\"error\":\"invalid address or size\"}";
    duint regionSize = 0;
    const duint regionBase = DbgMemFindBaseAddr(address, &regionSize);
    char moduleName[MAX_MODULE_SIZE] = {};
    DbgGetModuleAt(regionBase ? regionBase : address, moduleName);
    const int sampleSize = requestedSize > 4096 ? 4096 : requestedSize;
    std::vector<uint8_t> sample(static_cast<size_t>(sampleSize));
    const bool sampled = DbgMemRead(address, sample.data(), static_cast<duint>(sample.size()));
    char entropyBuffer[64] = {};
    sprintf_s(entropyBuffer, "%.4f", sampled ? ByteEntropy(sample) : 0.0);
    std::ostringstream out;
    out << "{";
    out << "\"ok\":true";
    out << ",\"address\":" << JsonString(Hex(address));
    out << ",\"requested_size\":" << JsonString(Hex(static_cast<duint>(requestedSize)));
    out << ",\"region_base\":" << JsonString(Hex(regionBase));
    out << ",\"region_size\":" << JsonString(Hex(regionSize));
    out << ",\"module\":" << JsonString(moduleName);
    out << ",\"sampled_bytes\":" << sampleSize;
    out << ",\"entropy\":" << entropyBuffer;
    out << ",\"raw_bytes_returned\":false";
    out << "}";
    return out.str();
}

std::string HandleMethod(const std::string& method, const std::string& request)
{
    if(method == "x64dbg.goto")
    {
        const auto address = ExtractJsonString(request, "address");
        DbgCmdExecDirect(("disasm " + address).c_str());
        return "{\"ok\":true,\"address\":" + JsonString(address) + "}";
    }
    if(method == "x64dbg.set_breakpoint")
    {
        const auto address = ExtractJsonString(request, "address");
        DbgCmdExecDirect(("bp " + address).c_str());
        return "{\"ok\":true,\"address\":" + JsonString(address) + "}";
    }
    if(method == "x64dbg.remove_breakpoint")
    {
        const auto address = ExtractJsonString(request, "address");
        DbgCmdExecDirect(("bc " + address).c_str());
        return "{\"ok\":true,\"address\":" + JsonString(address) + "}";
    }
    if(method == "x64dbg.run")
    {
        DbgCmdExecDirect("run");
        return "{\"ok\":true}";
    }
    if(method == "x64dbg.pause")
    {
        DbgCmdExecDirect("pause");
        return "{\"ok\":true}";
    }
    if(method == "x64dbg.step_into")
    {
        DbgCmdExecDirect("sti");
        return "{\"ok\":true}";
    }
    if(method == "x64dbg.step_over")
    {
        DbgCmdExecDirect("sto");
        return "{\"ok\":true}";
    }
    if(method == "x64dbg.read_registers")
    {
        return BuildRegistersJson();
    }
    if(method == "x64dbg.read_memory")
    {
        const auto addressText = ExtractJsonString(request, "address");
        const int size = ExtractJsonInt(request, "size", 0);
        const duint address = ParseAddress(addressText);
        if(!address || size <= 0 || size > 0x10000)
            return "{\"ok\":false,\"error\":\"invalid address or size\"}";
        std::vector<uint8_t> bytes(static_cast<size_t>(size));
        if(!DbgMemRead(address, bytes.data(), static_cast<duint>(bytes.size())))
            return "{\"ok\":false,\"error\":\"DbgMemRead failed\"}";
        return "{\"ok\":true,\"address\":" + JsonString(Hex(address)) + ",\"bytes\":" + JsonString(BytesToHex(bytes)) + "}";
    }
    if(method == "x64dbg.list_modules")
    {
        return "{\"ok\":true,\"modules\":" + BuildModulesJson(false) + "}";
    }
    if(method == "x64dbg.memory_map")
    {
        return BuildMemoryMapJson(ExtractJsonInt(request, "limit", 256), ExtractJsonInt(request, "offset", 0));
    }
    if(method == "x64dbg.call_stack")
    {
        return BuildCallStackJson(ExtractJsonInt(request, "limit", 64));
    }
    if(method == "x64dbg.threads")
    {
        return BuildThreadsJson();
    }
    if(method == "x64dbg.exceptions")
    {
        return BuildExceptionsJson(ExtractJsonInt(request, "limit", 100), ExtractJsonInt(request, "offset", 0));
    }
    if(method == "x64dbg.breakpoint_snapshot")
    {
        return BuildBreakpointSnapshotJson(ExtractJsonString(request, "address"));
    }
    if(method == "x64dbg.dump_metadata")
    {
        return BuildDumpMetadataJson(ExtractJsonString(request, "address"), ExtractJsonInt(request, "size", 0));
    }
    if(method == "x64dbg.set_hardware_breakpoint")
    {
        const auto address = ExtractJsonString(request, "address");
        const auto access = ExtractJsonString(request, "access").empty() ? "x" : ExtractJsonString(request, "access");
        const int size = ExtractJsonInt(request, "size", sizeof(duint));
        const std::string command = "bphws " + address + ", " + access + ", " + std::to_string(size);
        const bool ok = DbgCmdExecDirect(command.c_str());
        return "{\"ok\":" + std::string(ok ? "true" : "false") + ",\"address\":" + JsonString(address) + ",\"command\":" + JsonString(command) + "}";
    }
    if(method == "x64dbg.remove_hardware_breakpoint")
    {
        const auto address = ExtractJsonString(request, "address");
        const std::string command = "bphwc " + address;
        const bool ok = DbgCmdExecDirect(command.c_str());
        return "{\"ok\":" + std::string(ok ? "true" : "false") + ",\"address\":" + JsonString(address) + ",\"command\":" + JsonString(command) + "}";
    }
    if(method == "x64dbg.set_memory_breakpoint")
    {
        const auto address = ExtractJsonString(request, "address");
        const int size = ExtractJsonInt(request, "size", 1);
        const auto access = ExtractJsonString(request, "access");
        const std::string command = "membp " + address + ", " + std::to_string(size) + (access.empty() ? "" : ", " + access);
        const bool ok = DbgCmdExecDirect(command.c_str());
        return "{\"ok\":" + std::string(ok ? "true" : "false") + ",\"address\":" + JsonString(address) + ",\"command\":" + JsonString(command) + "}";
    }
    if(method == "x64dbg.remove_memory_breakpoint")
    {
        const auto address = ExtractJsonString(request, "address");
        const std::string command = "membpc " + address;
        const bool ok = DbgCmdExecDirect(command.c_str());
        return "{\"ok\":" + std::string(ok ? "true" : "false") + ",\"address\":" + JsonString(address) + ",\"command\":" + JsonString(command) + "}";
    }
    if(method == "x64dbg.set_conditional_breakpoint")
    {
        const auto address = ExtractJsonString(request, "address");
        const auto condition = ExtractJsonString(request, "condition");
        const auto logText = ExtractJsonString(request, "log_text");
        const bool bpOk = DbgCmdExecDirect(("bp " + address).c_str());
        bool condOk = true;
        bool logOk = true;
        if(!condition.empty())
            condOk = DbgCmdExecDirect(("SetBreakpointCondition " + address + ", " + condition).c_str());
        if(!logText.empty())
            logOk = DbgCmdExecDirect(("SetBreakpointLog " + address + ", \"" + JsonEscape(logText) + "\"").c_str());
        return "{\"ok\":" + std::string((bpOk && condOk && logOk) ? "true" : "false") + ",\"address\":" + JsonString(address) + "}";
    }
    if(method == "x64dbg.trace_recipe_enable")
    {
        const auto name = ExtractJsonString(request, "name");
        std::vector<std::string> apis;
        if(name == "LoadLibrary")
            apis = {"LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW"};
        else if(name == "GetProcAddress")
            apis = {"GetProcAddress"};
        else if(name == "CreateFile")
            apis = {"CreateFileA", "CreateFileW"};
        else if(name == "ReadFile")
            apis = {"ReadFile"};
        else if(name == "WriteFile")
            apis = {"WriteFile"};
        else if(name == "RegOpenKey")
            apis = {"RegOpenKeyA", "RegOpenKeyW", "RegOpenKeyExA", "RegOpenKeyExW"};
        else if(name == "Internet")
            apis = {"InternetOpenA", "InternetOpenW", "InternetConnectA", "InternetConnectW", "InternetOpenUrlA", "InternetOpenUrlW"};
        else if(name == "WinHttp")
            apis = {"WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest", "WinHttpSendRequest", "WinHttpReceiveResponse"};
        else if(name == "WSA")
            apis = {"WSAStartup", "socket", "connect", "send", "recv"};
        else
            apis = {name};
        for(const auto& api : apis)
            DbgCmdExecDirect(("bp " + api).c_str());
        {
            std::lock_guard<std::mutex> lock(g_stateMutex);
            g_recipeApis[name] = apis;
        }
        std::ostringstream out;
        out << "{\"ok\":true,\"name\":" << JsonString(name) << ",\"apis\":[";
        for(size_t i = 0; i < apis.size(); ++i)
            out << (i ? "," : "") << JsonString(apis[i]);
        out << "]}";
        return out.str();
    }
    if(method == "x64dbg.trace_recipe_disable")
    {
        const auto name = ExtractJsonString(request, "name");
        std::vector<std::string> apis;
        {
            std::lock_guard<std::mutex> lock(g_stateMutex);
            auto it = g_recipeApis.find(name);
            if(it != g_recipeApis.end())
            {
                apis = it->second;
                g_recipeApis.erase(it);
            }
        }
        for(const auto& api : apis)
            DbgCmdExecDirect(("bc " + api).c_str());
        return "{\"ok\":true,\"name\":" + JsonString(name) + "}";
    }
    return "{\"ok\":false,\"error\":\"unknown method\"}";
}

void SendResponse(const std::string& id, const std::string& resultJson)
{
    SendText("{\"jsonrpc\":\"2.0\",\"id\":" + JsonString(id) + ",\"result\":" + resultJson + "}");
}

void SendError(const std::string& id, const std::string& message)
{
    SendText("{\"jsonrpc\":\"2.0\",\"id\":" + JsonString(id) + ",\"error\":{\"message\":" + JsonString(message) + "}}");
}

void SendEvent(const std::string& type, const std::string& payloadJson)
{
    SendText("{\"jsonrpc\":\"2.0\",\"method\":\"event\",\"params\":{\"type\":" + JsonString(type) + ",\"payload\":" + payloadJson + "}}");
}

void SendAddressEvent(const std::string& type)
{
    const auto address = DbgValFromString("cip");
    BuildModulesJson(true);
    SendEvent(type, "{\"address\":" + JsonString(Hex(address)) + "}");
}

std::string Basename(const char* path)
{
    if(!path || !*path)
        return {};
    std::string text(path);
    const auto slash = text.find_last_of("\\/");
    if(slash == std::string::npos)
        return text;
    return text.substr(slash + 1);
}

void SendModuleLoadedEvent(const char* name, DWORD64 base, DWORD size, bool mainModule)
{
    if(!base)
        return;
    duint regionSize = 0;
    const duint normalizedBase = DbgMemFindBaseAddr(static_cast<duint>(base), &regionSize);
    const duint imageSize = PeImageSizeFromMemory(normalizedBase ? normalizedBase : static_cast<duint>(base));
    if(imageSize != 0)
        size = static_cast<DWORD>(imageSize);
    if(size == 0 && regionSize != 0)
        size = static_cast<DWORD>(regionSize);
    const std::string moduleName = name && *name ? Basename(name) : "module";
    std::ostringstream payload;
    payload << "{";
    payload << "\"name\":" << JsonString(moduleName);
    payload << ",\"runtime_base\":" << JsonString(Hex(normalizedBase ? normalizedBase : static_cast<duint>(base)));
    payload << ",\"size\":" << JsonString(Hex(static_cast<duint>(size)));
    payload << ",\"main\":" << (mainModule ? "true" : "false");
    payload << "}";
    SendEvent("module.loaded", payload.str());
    SendEvent("memory_map.changed", "{\"reason\":\"module.loaded\",\"module\":" + JsonString(moduleName) + "}");
}

std::string BuildModulesJson(bool emitEvents)
{
    MEMMAP memmap = {};
    std::ostringstream out;
    out << "[";
    bool first = true;
    std::set<std::string> seenModules;
    if(DbgMemMap(&memmap))
    {
        for(int i = 0; i < memmap.count; ++i)
        {
            const auto address = reinterpret_cast<duint>(memmap.page[i].mbi.BaseAddress);
            duint size = 0;
            const duint base = DbgMemFindBaseAddr(address, &size);
            if(!base)
                continue;
            char moduleName[MAX_MODULE_SIZE] = {};
            if(!DbgGetModuleAt(base, moduleName) || !moduleName[0])
                continue;
            const std::string moduleKey = moduleName;
            if(seenModules.count(moduleKey))
                continue;
            seenModules.insert(moduleKey);
            const duint moduleBase = DbgModBaseFromName(moduleName);
            if(!moduleBase)
                continue;
            duint moduleSize = 0;
            DbgMemFindBaseAddr(moduleBase, &moduleSize);
            const duint imageSize = PeImageSizeFromMemory(moduleBase);
            if(imageSize != 0)
                moduleSize = imageSize;
            if(!first)
                out << ",";
            first = false;
            out << "{";
            out << "\"name\":" << JsonString(moduleName);
            out << ",\"runtime_base\":" << JsonString(Hex(moduleBase));
            out << ",\"size\":" << JsonString(Hex(moduleSize));
            out << "}";
            if(emitEvents)
                SendModuleLoadedEvent(moduleName, moduleBase, static_cast<DWORD>(moduleSize), false);
        }
        BridgeFree(memmap.page);
    }
    out << "]";
    return out.str();
}

std::string BuildHello()
{
    std::ostringstream out;
    out << "{\"jsonrpc\":\"2.0\",\"id\":\"hello\",\"method\":\"hello\",\"params\":{";
    out << "\"role\":\"x64dbg\"";
    out << ",\"protocol_version\":" << JsonString(kProtocolVersion);
    out << ",\"bridge_version\":" << JsonString(kBridgeVersion);
    out << ",\"capabilities\":[";
    out << "\"debug.paused\",\"step\",\"breakpoint.hit\",\"module.loaded\",\"module.unloaded\",";
    out << "\"thread.created\",\"thread.exited\",\"exception.hit\",\"memory_map.changed\",\"breakpoint.hit.snapshot\",";
    out << "\"x64dbg.goto\",\"x64dbg.set_breakpoint\",\"x64dbg.remove_breakpoint\",";
    out << "\"x64dbg.run\",\"x64dbg.pause\",\"x64dbg.step_into\",\"x64dbg.step_over\",";
    out << "\"x64dbg.read_memory\",\"x64dbg.read_registers\",\"x64dbg.list_modules\",";
    out << "\"x64dbg.memory_map\",\"x64dbg.call_stack\",\"x64dbg.threads\",\"x64dbg.exceptions\",";
    out << "\"x64dbg.set_hardware_breakpoint\",\"x64dbg.remove_hardware_breakpoint\",";
    out << "\"x64dbg.set_memory_breakpoint\",\"x64dbg.remove_memory_breakpoint\",";
    out << "\"x64dbg.set_conditional_breakpoint\",\"x64dbg.breakpoint_snapshot\",\"x64dbg.dump_metadata\",";
    out << "\"x64dbg.trace_recipe_enable\",\"x64dbg.trace_recipe_disable\"";
    out << "]";
    out << ",\"token\":" << JsonString(EnvString("IX64MCP_TOKEN"));
    out << ",\"session\":{\"architecture\":\"x64\"}";
    out << "}}";
    return out.str();
}

bool ConnectOnce()
{
    HINTERNET session = WinHttpOpen(
        L"IX64MCP x64dbg bridge/0.1",
        WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);
    if(!session)
        return false;

    HINTERNET connect = WinHttpConnect(session, kBridgeHost, kBridgePort, 0);
    if(!connect)
    {
        WinHttpCloseHandle(session);
        return false;
    }

    HINTERNET request = WinHttpOpenRequest(
        connect,
        L"GET",
        kBridgePath,
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        0);
    if(!request)
    {
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return false;
    }

    WinHttpSetOption(request, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, nullptr, 0);
    const BOOL sent = WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, nullptr, 0, 0, 0);
    const BOOL received = sent ? WinHttpReceiveResponse(request, nullptr) : FALSE;
    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(statusCode);
    if(received)
    {
        WinHttpQueryHeaders(
            request,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX,
            &statusCode,
            &statusCodeSize,
            WINHTTP_NO_HEADER_INDEX);
    }
    HINTERNET ws = received && statusCode == HTTP_STATUS_SWITCH_PROTOCOLS ? WinHttpWebSocketCompleteUpgrade(request, 0) : nullptr;
    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);

    if(!ws)
        return false;

    {
        std::lock_guard<std::mutex> lock(g_socketMutex);
        g_ws = ws;
    }

    Log("[IX64MCP] connected to MCP bridge hub");
    SendText(BuildHello());
    Sleep(100);
    BuildModulesJson(true);
    return true;
}

void ReceiveLoop()
{
    std::vector<char> buffer(64 * 1024);
    while(g_running && g_ws)
    {
        DWORD bytesRead = 0;
        WINHTTP_WEB_SOCKET_BUFFER_TYPE type = WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE;
        const DWORD status = WinHttpWebSocketReceive(g_ws, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, &type);
        if(status != NO_ERROR || type == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE)
            break;
        if(type != WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE && type != WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE)
            continue;

        std::string request(buffer.data(), buffer.data() + bytesRead);
        const auto id = ExtractJsonString(request, "id");
        const auto method = ExtractJsonString(request, "method");
        if(id.empty() || method.empty())
            continue;
        try
        {
            SendResponse(id, HandleMethod(method, request));
        }
        catch(const std::exception& exc)
        {
            SendError(id, exc.what());
        }
    }
}

void BridgeThreadMain()
{
    while(g_running)
    {
        if(ConnectOnce())
        {
            ReceiveLoop();
            CloseSocket();
            Log("[IX64MCP] disconnected from MCP bridge hub");
        }
        for(int i = 0; g_running && i < 20; ++i)
            Sleep(100);
    }
}

bool CommandSetBreakpoint(int argc, char* argv[])
{
    if(argc < 2)
    {
        Log("[IX64MCP] usage: ix64mcp_bp <address>");
        return false;
    }
    DbgCmdExecDirect((std::string("bp ") + argv[1]).c_str());
    SendEvent("breakpoint.added", "{\"address\":" + JsonString(argv[1]) + "}");
    return true;
}

bool CommandRemoveBreakpoint(int argc, char* argv[])
{
    if(argc < 2)
    {
        Log("[IX64MCP] usage: ix64mcp_bc <address>");
        return false;
    }
    DbgCmdExecDirect((std::string("bc ") + argv[1]).c_str());
    SendEvent("breakpoint.removed", "{\"address\":" + JsonString(argv[1]) + "}");
    return true;
}

bool CommandGoto(int argc, char* argv[])
{
    if(argc < 2)
    {
        Log("[IX64MCP] usage: ix64mcp_goto <address>");
        return false;
    }
    DbgCmdExecDirect((std::string("disasm ") + argv[1]).c_str());
    SendEvent("cursor.changed", "{\"address\":" + JsonString(argv[1]) + "}");
    return true;
}

void OnPause(CBTYPE, void*)
{
    SendAddressEvent("debug.paused");
}

void OnStep(CBTYPE, void*)
{
    SendAddressEvent("step");
}

void OnBreakpoint(CBTYPE, void*)
{
    const auto address = DbgValFromString("cip");
    BuildModulesJson(true);
    SendEvent("breakpoint.hit", "{\"address\":" + JsonString(Hex(address)) + "}");
    SendEvent("breakpoint.hit.snapshot", BuildBreakpointSnapshotJson(Hex(address)));
}

void OnCreateProcess(CBTYPE, void* callbackInfo)
{
    auto* info = static_cast<PLUG_CB_CREATEPROCESS*>(callbackInfo);
    if(!info || !info->modInfo)
        return;
    SendModuleLoadedEvent(
        info->DebugFileName,
        info->modInfo->BaseOfImage,
        info->modInfo->ImageSize,
        true);
}

void OnLoadDll(CBTYPE, void* callbackInfo)
{
    auto* info = static_cast<PLUG_CB_LOADDLL*>(callbackInfo);
    if(!info || !info->modInfo)
        return;
    SendModuleLoadedEvent(
        info->modname,
        info->modInfo->BaseOfImage,
        info->modInfo->ImageSize,
        false);
}

void OnUnloadDll(CBTYPE, void* callbackInfo)
{
    auto* info = static_cast<PLUG_CB_UNLOADDLL*>(callbackInfo);
    if(!info || !info->UnloadDll)
        return;
    SendEvent(
        "module.unloaded",
        "{\"runtime_base\":" + JsonString(Hex(reinterpret_cast<duint>(info->UnloadDll->lpBaseOfDll))) + "}");
    SendEvent("memory_map.changed", "{\"reason\":\"module.unloaded\"}");
}

void OnCreateThread(CBTYPE, void* callbackInfo)
{
    auto* info = static_cast<PLUG_CB_CREATETHREAD*>(callbackInfo);
    if(!info || !info->CreateThread)
        return;
    std::ostringstream payload;
    payload << "{";
    payload << "\"thread_id\":" << JsonString(Hex(static_cast<duint>(info->dwThreadId)));
    payload << ",\"start\":" << JsonString(Hex(reinterpret_cast<duint>(info->CreateThread->lpStartAddress)));
    payload << ",\"teb\":" << JsonString(Hex(reinterpret_cast<duint>(info->CreateThread->lpThreadLocalBase)));
    payload << "}";
    SendEvent("thread.created", payload.str());
}

void OnExitThread(CBTYPE, void* callbackInfo)
{
    auto* info = static_cast<PLUG_CB_EXITTHREAD*>(callbackInfo);
    if(!info || !info->ExitThread)
        return;
    std::ostringstream payload;
    payload << "{";
    payload << "\"thread_id\":" << JsonString(Hex(static_cast<duint>(info->dwThreadId)));
    payload << ",\"exit_code\":" << JsonString(Hex(static_cast<duint>(info->ExitThread->dwExitCode)));
    payload << "}";
    SendEvent("thread.exited", payload.str());
}

void OnException(CBTYPE, void* callbackInfo)
{
    auto* info = static_cast<PLUG_CB_EXCEPTION*>(callbackInfo);
    if(!info || !info->Exception)
        return;
    const auto& record = info->Exception->ExceptionRecord;
    std::ostringstream payload;
    payload << "{";
    payload << "\"code\":" << JsonString(Hex(static_cast<duint>(record.ExceptionCode)));
    payload << ",\"address\":" << JsonString(Hex(reinterpret_cast<duint>(record.ExceptionAddress)));
    payload << ",\"first_chance\":" << (info->Exception->dwFirstChance ? "true" : "false");
    payload << "}";
    const auto text = payload.str();
    {
        std::lock_guard<std::mutex> lock(g_stateMutex);
        g_exceptions.push_back(text);
        while(g_exceptions.size() > 500)
            g_exceptions.pop_front();
    }
    SendEvent("exception.hit", text);
}

void StartBridge()
{
    if(g_running.exchange(true))
        return;
    g_bridgeThread = std::thread(BridgeThreadMain);
}

void StopBridge()
{
    if(!g_running.exchange(false))
        return;
    CloseSocket();
    if(g_bridgeThread.joinable())
        g_bridgeThread.join();
}
}

extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* initStruct)
{
    initStruct->pluginVersion = 1;
    initStruct->sdkVersion = PLUG_SDKVERSION;
    strcpy_s(initStruct->pluginName, kPluginName);
    g_pluginHandle = initStruct->pluginHandle;
    return true;
}

extern "C" __declspec(dllexport) bool plugstop()
{
    StopBridge();
    _plugin_unregistercallback(g_pluginHandle, CB_PAUSEDEBUG);
    _plugin_unregistercallback(g_pluginHandle, CB_STEPPED);
    _plugin_unregistercallback(g_pluginHandle, CB_BREAKPOINT);
    _plugin_unregistercallback(g_pluginHandle, CB_CREATEPROCESS);
    _plugin_unregistercallback(g_pluginHandle, CB_LOADDLL);
    _plugin_unregistercallback(g_pluginHandle, CB_UNLOADDLL);
    _plugin_unregistercallback(g_pluginHandle, CB_CREATETHREAD);
    _plugin_unregistercallback(g_pluginHandle, CB_EXITTHREAD);
    _plugin_unregistercallback(g_pluginHandle, CB_EXCEPTION);
    _plugin_unregistercommand(g_pluginHandle, "ix64mcp_bp");
    _plugin_unregistercommand(g_pluginHandle, "ix64mcp_bc");
    _plugin_unregistercommand(g_pluginHandle, "ix64mcp_goto");
    return true;
}

extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT*)
{
    _plugin_registercommand(g_pluginHandle, "ix64mcp_bp", CommandSetBreakpoint, true);
    _plugin_registercommand(g_pluginHandle, "ix64mcp_bc", CommandRemoveBreakpoint, true);
    _plugin_registercommand(g_pluginHandle, "ix64mcp_goto", CommandGoto, true);
    _plugin_registercallback(g_pluginHandle, CB_PAUSEDEBUG, OnPause);
    _plugin_registercallback(g_pluginHandle, CB_STEPPED, OnStep);
    _plugin_registercallback(g_pluginHandle, CB_BREAKPOINT, OnBreakpoint);
    _plugin_registercallback(g_pluginHandle, CB_CREATEPROCESS, OnCreateProcess);
    _plugin_registercallback(g_pluginHandle, CB_LOADDLL, OnLoadDll);
    _plugin_registercallback(g_pluginHandle, CB_UNLOADDLL, OnUnloadDll);
    _plugin_registercallback(g_pluginHandle, CB_CREATETHREAD, OnCreateThread);
    _plugin_registercallback(g_pluginHandle, CB_EXITTHREAD, OnExitThread);
    _plugin_registercallback(g_pluginHandle, CB_EXCEPTION, OnException);
    StartBridge();
    Log("[IX64MCP] x64dbg bridge loaded");
}
