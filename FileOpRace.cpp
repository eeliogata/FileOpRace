#include <windows.h>
#include <winioctl.h>
#include <wincrypt.h>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <cwchar>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace {

constexpr DWORD share_all = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

class Handle {
public:
    explicit Handle(HANDLE value = INVALID_HANDLE_VALUE) : value_(value) {}
    ~Handle() { reset(); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;

    HANDLE get() const { return value_; }
    bool valid() const { return value_ && value_ != INVALID_HANDLE_VALUE; }

    void reset(HANDLE next = INVALID_HANDLE_VALUE) {
        if (valid()) CloseHandle(value_);
        value_ = next;
    }

private:
    HANDLE value_;
};

HANDLE stop_event = nullptr;

BOOL WINAPI on_control(DWORD code) {
    if ((code == CTRL_C_EVENT || code == CTRL_BREAK_EVENT) && stop_event) {
        SetEvent(stop_event);
        return TRUE;
    }
    return FALSE;
}

class StopSignal {
public:
    StopSignal() : event_(CreateEventW(nullptr, TRUE, FALSE, nullptr)) {
        if (event_.valid()) {
            stop_event = event_.get();
            registered_ = SetConsoleCtrlHandler(on_control, TRUE) != 0;
            if (!registered_) stop_event = nullptr;
        }
    }

    ~StopSignal() {
        if (registered_) SetConsoleCtrlHandler(on_control, FALSE);
        stop_event = nullptr;
    }

    bool valid() const { return event_.valid() && registered_; }
    HANDLE get() const { return event_.get(); }

private:
    Handle event_;
    bool registered_ = false;
};

struct Stamp {
    FILE_ID_INFO id{};
    ULONGLONG size = 0;
    std::wstring hash;
};

struct MountPoint {
    DWORD tag;
    WORD length;
    WORD reserved;
    WORD substitute_offset;
    WORD substitute_length;
    WORD print_offset;
    WORD print_length;
    WCHAR path[1];
};

static_assert(offsetof(MountPoint, path) == 16);

std::wstring hex_bytes(const BYTE* bytes, size_t length) {
    std::wostringstream out;
    out << std::hex << std::setfill(L'0');
    for (size_t i = 0; i < length; ++i)
        out << std::setw(2) << static_cast<unsigned>(bytes[i]);
    return out.str();
}

std::wstring file_id(const FILE_ID_INFO& id) {
    std::wostringstream out;
    out << std::hex << std::setfill(L'0') << std::setw(16) << id.VolumeSerialNumber
        << L':' << hex_bytes(id.FileId.Identifier, sizeof(id.FileId.Identifier));
    return out.str();
}

bool same_file(const FILE_ID_INFO& left, const FILE_ID_INFO& right) {
    return left.VolumeSerialNumber == right.VolumeSerialNumber &&
           std::memcmp(left.FileId.Identifier, right.FileId.Identifier,
                       sizeof(left.FileId.Identifier)) == 0;
}

bool sha256(HANDLE file, std::wstring& digest, DWORD& error) {
    HCRYPTPROV provider = 0;
    HCRYPTHASH hash = 0;
    if (!CryptAcquireContextW(&provider, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        error = GetLastError();
        return false;
    }
    bool ok = false;
    if (!CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash)) {
        error = GetLastError();
    } else {
        std::array<BYTE, 65536> buffer{};
        while (true) {
            DWORD read = 0;
            if (!ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr)) {
                error = GetLastError();
                break;
            }
            if (!read) {
                std::array<BYTE, 32> result{};
                DWORD length = static_cast<DWORD>(result.size());
                if (CryptGetHashParam(hash, HP_HASHVAL, result.data(), &length, 0)) {
                    digest = hex_bytes(result.data(), length);
                    ok = true;
                } else {
                    error = GetLastError();
                }
                break;
            }
            if (!CryptHashData(hash, buffer.data(), read, 0)) {
                error = GetLastError();
                break;
            }
        }
    }
    if (hash) CryptDestroyHash(hash);
    CryptReleaseContext(provider, 0);
    return ok;
}

bool stamp(const std::wstring& path, Stamp& result, DWORD& error) {
    Handle file(CreateFileW(path.c_str(), FILE_READ_DATA | FILE_READ_ATTRIBUTES, share_all,
                            nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    if (!file.valid()) {
        error = GetLastError();
        return false;
    }
    if (!GetFileInformationByHandleEx(file.get(), FileIdInfo, &result.id, sizeof(result.id))) {
        error = GetLastError();
        return false;
    }
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file.get(), &size)) {
        error = GetLastError();
        return false;
    }
    result.size = static_cast<ULONGLONG>(size.QuadPart);
    return sha256(file.get(), result.hash, error);
}

void print_stamp(const wchar_t* label, const Stamp& value) {
    std::wcout << label << L" id=" << file_id(value.id) << L" size=" << value.size
               << L" sha256=" << value.hash << L'\n';
}

std::wstring full_path(const wchar_t* path) {
    std::vector<wchar_t> buffer(32768);
    DWORD length = GetFullPathNameW(path, static_cast<DWORD>(buffer.size()), buffer.data(), nullptr);
    if (!length || length >= buffer.size()) return {};
    std::wstring result(buffer.data(), length);
    if (result.size() < 3 || result[1] != L':' || result[2] != L'\\') return {};
    while (result.size() > 3 && result.back() == L'\\') result.pop_back();
    return result;
}

std::wstring parent_path(const std::wstring& path) {
    size_t slash = path.find_last_of(L'\\');
    if (slash == std::wstring::npos) return {};
    return path.substr(0, slash == 2 ? 3 : slash);
}

std::wstring leaf_name(const std::wstring& path) {
    size_t slash = path.find_last_of(L'\\');
    return slash == std::wstring::npos ? path : path.substr(slash + 1);
}

bool plain_file(const std::wstring& path) {
    DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES &&
           !(attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT));
}

bool directory(const std::wstring& path) {
    DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY);
}

bool set_junction(HANDLE handle, const std::wstring& target, DWORD& error) {
    const std::wstring substitute = L"\\??\\" + target;
    const size_t path_bytes = (substitute.size() + 1 + target.size() + 1) * sizeof(wchar_t);
    const size_t total = offsetof(MountPoint, path) + path_bytes;
    if (total > MAXIMUM_REPARSE_DATA_BUFFER_SIZE || total - 8 > 0xffff) {
        error = ERROR_BUFFER_OVERFLOW;
        return false;
    }
    std::vector<DWORD> buffer((total + sizeof(DWORD) - 1) / sizeof(DWORD));
    auto* point = reinterpret_cast<MountPoint*>(buffer.data());
    point->tag = IO_REPARSE_TAG_MOUNT_POINT;
    point->length = static_cast<WORD>(total - 8);
    point->substitute_offset = 0;
    point->substitute_length = static_cast<WORD>(substitute.size() * sizeof(wchar_t));
    point->print_offset = static_cast<WORD>((substitute.size() + 1) * sizeof(wchar_t));
    point->print_length = static_cast<WORD>(target.size() * sizeof(wchar_t));
    std::memcpy(point->path, substitute.c_str(), (substitute.size() + 1) * sizeof(wchar_t));
    std::memcpy(reinterpret_cast<BYTE*>(point->path) + point->print_offset,
                target.c_str(), (target.size() + 1) * sizeof(wchar_t));
    DWORD returned = 0;
    if (!DeviceIoControl(handle, FSCTL_SET_REPARSE_POINT, buffer.data(),
                         static_cast<DWORD>(total), nullptr, 0, &returned, nullptr)) {
        error = GetLastError();
        return false;
    }
    return true;
}

class Junction {
public:
    explicit Junction(std::wstring path) : path_(std::move(path)) {}
    ~Junction() {
        DWORD error = 0;
        if (!remove(error)) std::wcerr << L"junction removal failed error=" << error << L'\n';
    }

    bool create(const std::wstring& target, DWORD& error) {
        if (!CreateDirectoryW(path_.c_str(), nullptr)) {
            error = GetLastError();
            return false;
        }
        created_ = true;
        handle_.reset(CreateFileW(path_.c_str(), GENERIC_WRITE, share_all, nullptr,
                                  OPEN_EXISTING,
                                  FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                                  nullptr));
        if (!handle_.valid()) {
            error = GetLastError();
            return false;
        }
        return set_junction(handle_.get(), target, error);
    }

    bool retarget(const std::wstring& target, DWORD& error) {
        return set_junction(handle_.get(), target, error);
    }

    bool remove(DWORD& error) {
        handle_.reset();
        if (created_ && !RemoveDirectoryW(path_.c_str())) {
            error = GetLastError();
            return false;
        }
        created_ = false;
        return true;
    }

private:
    std::wstring path_;
    Handle handle_;
    bool created_ = false;
};

std::wstring utc_time() {
    SYSTEMTIME time{};
    GetSystemTime(&time);
    wchar_t text[32]{};
    std::swprintf(text, 32, L"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
                  time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute,
                  time.wSecond, time.wMilliseconds);
    return text;
}

struct Demo {
    std::wstring path;
    FILE_ID_INFO first{};
    FILE_ID_INFO second{};
    DWORD error = 0;
};

DWORD WINAPI demo_worker(void* opaque) {
    auto& demo = *static_cast<Demo*>(opaque);
    for (FILE_ID_INFO* id : {&demo.first, &demo.second}) {
        Handle file(CreateFileW(demo.path.c_str(), FILE_READ_DATA | FILE_READ_ATTRIBUTES,
                                share_all, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (!file.valid()) {
            demo.error = GetLastError();
            return 1;
        }
        if (!GetFileInformationByHandleEx(file.get(), FileIdInfo, id, sizeof(*id))) {
            demo.error = GetLastError();
            return 1;
        }
    }
    return 0;
}

bool parse_ms(const wchar_t* text, DWORD& value) {
    if (!text || !*text || *text == L'-') return false;
    wchar_t* end = nullptr;
    errno = 0;
    unsigned long parsed = std::wcstoul(text, &end, 10);
    if (errno == ERANGE || !end || *end || parsed > 300000) return false;
    value = static_cast<DWORD>(parsed);
    return true;
}

int trial(int argc, wchar_t** argv) {
    if (argc < 5) return 2;
    const std::wstring link = full_path(argv[2]);
    const std::wstring bait = full_path(argv[3]);
    const std::wstring canary = full_path(argv[4]);
    if (link.empty() || bait.empty() || canary.empty() ||
        leaf_name(bait).empty() || _wcsicmp(leaf_name(bait).c_str(), leaf_name(canary).c_str()) ||
        !plain_file(bait) || !plain_file(canary) || !directory(parent_path(link)) ||
        GetFileAttributesW(link.c_str()) != INVALID_FILE_ATTRIBUTES) {
        std::wcerr << L"need a new junction path and two plain files with the same name\n";
        return 2;
    }

    DWORD timeout = 30000;
    DWORD hold = 1000;
    bool demo_mode = false;
    for (int i = 5; i < argc; ++i) {
        const std::wstring option = argv[i];
        if (option == L"--demo") {
            demo_mode = true;
        } else if ((option == L"--timeout" || option == L"--hold") && i + 1 < argc) {
            DWORD value = 0;
            if (!parse_ms(argv[++i], value)) return 2;
            if (option == L"--timeout") timeout = value;
            else hold = value;
        } else {
            return 2;
        }
    }

    DWORD error = 0;
    Stamp bait_before;
    Stamp canary_before;
    if (!stamp(bait, bait_before, error) || !stamp(canary, canary_before, error)) {
        std::wcerr << L"initial stamp failed error=" << error << L'\n';
        return 1;
    }
    if (same_file(bait_before.id, canary_before.id)) {
        std::wcerr << L"bait and canary resolve to the same file\n";
        return 2;
    }
    print_stamp(L"bait_before", bait_before);
    print_stamp(L"canary_before", canary_before);

    StopSignal stop;
    if (!stop.valid()) {
        std::wcerr << L"console handler setup failed error=" << GetLastError() << L'\n';
        return 1;
    }

    Junction junction(link);
    if (!junction.create(parent_path(bait), error)) {
        std::wcerr << L"junction setup failed error=" << error << L'\n';
        return 1;
    }
    const std::wstring slot = link + L"\\" + leaf_name(bait);
    Stamp slot_before;
    if (!stamp(slot, slot_before, error) || !same_file(slot_before.id, bait_before.id)) {
        std::wcerr << L"junction does not resolve to bait error=" << error << L'\n';
        return 1;
    }

    Handle file(CreateFileW(bait.c_str(), GENERIC_READ, share_all, nullptr, OPEN_EXISTING,
                            FILE_FLAG_OVERLAPPED, nullptr));
    if (!file.valid()) {
        std::wcerr << L"oplock open failed error=" << GetLastError() << L'\n';
        return 1;
    }
    Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!event.valid()) {
        std::wcerr << L"event creation failed error=" << GetLastError() << L'\n';
        return 1;
    }
    OVERLAPPED overlapped{};
    overlapped.hEvent = event.get();
    DWORD returned = 0;
    BOOL request = DeviceIoControl(file.get(), FSCTL_REQUEST_OPLOCK_LEVEL_1,
                                   nullptr, 0, nullptr, 0, &returned, &overlapped);
    if (request || GetLastError() != ERROR_IO_PENDING) {
        std::wcerr << L"oplock request failed error=" << (request ? 0 : GetLastError()) << L'\n';
        return 1;
    }

    std::wcout << L"armed=" << utc_time() << L" path=\"" << slot << L"\" timeout_ms=" << timeout
               << std::endl;
    Demo demo{slot};
    Handle worker;
    if (demo_mode) {
        worker.reset(CreateThread(nullptr, 0, demo_worker, &demo, 0, nullptr));
        if (!worker.valid()) {
            std::wcerr << L"demo thread failed error=" << GetLastError() << L'\n';
            return 1;
        }
    }

    const ULONGLONG start = GetTickCount64();
    HANDLE signals[2] = {event.get(), stop.get()};
    DWORD wait = WaitForMultipleObjects(2, signals, FALSE, timeout ? timeout : INFINITE);
    if (wait != WAIT_OBJECT_0) {
        std::wcout << L"result=" << (wait == WAIT_TIMEOUT ? L"no_break" :
                                      wait == WAIT_OBJECT_0 + 1 ? L"interrupted" : L"wait_failed")
                   << L" elapsed_ms=" << GetTickCount64() - start << L'\n';
        file.reset();
        if (worker.valid()) WaitForSingleObject(worker.get(), INFINITE);
        return 1;
    }
    DWORD transferred = 0;
    if (!GetOverlappedResult(file.get(), &overlapped, &transferred, FALSE)) {
        std::wcerr << L"oplock completion failed error=" << GetLastError() << L'\n';
        file.reset();
        if (worker.valid()) WaitForSingleObject(worker.get(), INFINITE);
        return 1;
    }
    std::wcout << L"break=" << utc_time() << L" elapsed_ms=" << GetTickCount64() - start << L'\n';
    if (!junction.retarget(parent_path(canary), error)) {
        std::wcerr << L"junction switch failed error=" << error << L'\n';
        file.reset();
        if (worker.valid()) WaitForSingleObject(worker.get(), INFINITE);
        return 1;
    }
    std::wcout << L"switched=" << utc_time() << L" target=\"" << parent_path(canary)
               << L"\"\n";
    file.reset();
    bool demo_redirected = false;
    if (worker.valid()) {
        if (WaitForSingleObject(worker.get(), INFINITE) != WAIT_OBJECT_0) {
            std::wcerr << L"demo did not finish\n";
            return 1;
        }
        if (demo.error) {
            std::wcerr << L"demo open failed error=" << demo.error << L'\n';
            return 1;
        }
        demo_redirected = same_file(demo.first, bait_before.id) &&
                          same_file(demo.second, canary_before.id);
        std::wcout << L"demo_first=" << file_id(demo.first)
                   << L" demo_second=" << file_id(demo.second)
                   << L" redirected=" << (demo_redirected ? 1 : 0)
                   << L'\n';
    } else if (hold && WaitForSingleObject(stop.get(), hold) == WAIT_OBJECT_0) {
        std::wcout << L"result=interrupted\n";
        return 1;
    }

    Stamp bait_after;
    Stamp canary_after;
    Stamp slot_after;
    if (!stamp(bait, bait_after, error) || !stamp(canary, canary_after, error) ||
        !stamp(slot, slot_after, error)) {
        std::wcerr << L"final stamp failed error=" << error << L'\n';
        return 1;
    }
    print_stamp(L"bait_after", bait_after);
    print_stamp(L"canary_after", canary_after);
    print_stamp(L"slot_after", slot_after);
    bool success = same_file(slot_after.id, canary_after.id) &&
                   (!demo_mode || demo_redirected);
    std::wcout << L"result=" << (success ? (demo_mode ? L"redirected" : L"switched") : L"missed")
               << L" bait_changed=" << (bait_before.hash != bait_after.hash ? 1 : 0)
               << L" canary_changed=" << (canary_before.hash != canary_after.hash ? 1 : 0)
               << L'\n';
    if (!junction.remove(error)) {
        std::wcerr << L"junction removal failed error=" << error << L'\n';
        return 1;
    }
    return success ? 0 : 1;
}

void usage() {
    std::wcerr << L"FileOpRace.exe stamp <file>\n"
               << L"FileOpRace.exe trial <new-junction> <bait-file> <canary-file> "
                  L"[--timeout ms] [--hold ms] [--demo]\n";
}

}

int wmain(int argc, wchar_t** argv) {
    if (argc == 3 && std::wcscmp(argv[1], L"stamp") == 0) {
        std::wstring path = full_path(argv[2]);
        DWORD error = 0;
        Stamp value;
        if (!path.empty() && stamp(path, value, error)) {
            std::wcout << L"path=\"" << path << L"\" ";
            print_stamp(L"file", value);
            return 0;
        }
        std::wcerr << L"stamp failed error=" << error << L'\n';
        return 1;
    }
    if (argc >= 5 && std::wcscmp(argv[1], L"trial") == 0) {
        int result = trial(argc, argv);
        if (result != 2) return result;
    }
    usage();
    return 2;
}
