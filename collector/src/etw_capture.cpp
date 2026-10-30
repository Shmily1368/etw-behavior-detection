// SPDX-License-Identifier: AGPL-3.0-only
// Public standalone extraction of the kernel-session lifecycle from the
// author's ETWConfiguration. See docs/windows-collector.md for scope.
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <vector>

namespace {
const GUID kSystemTrace = {0x9e814aad,0x3204,0x11d2,{0x9a,0x82,0x00,0x60,0x08,0xa8,0x69,0x39}};
const GUID kProcess = {0x3d6fa8d0,0xfe05,0x11d0,{0x9d,0xda,0x00,0xc0,0x4f,0xd7,0xba,0x7c}};
const GUID kThread = {0x3d6fa8d1,0xfe05,0x11d0,{0x9d,0xda,0x00,0xc0,0x4f,0xd7,0xba,0x7c}};
const GUID kImage = {0x2cb15d1d,0x5fc1,0x11d2,{0xab,0xe1,0x00,0xa0,0xc9,0x11,0xf5,0x18}};
const GUID kStackWalk = {0xdef2fe46,0x7bd6,0x4b80,{0xbd,0x94,0xf5,0x7f,0xe2,0x0d,0x0c,0xe3}};
std::atomic<bool> cancelled{false};

BOOL WINAPI handle_ctrl(DWORD code) {
    if (code == CTRL_C_EVENT || code == CTRL_BREAK_EVENT) {
        cancelled.store(true);
        return TRUE;
    }
    return FALSE;
}
std::string guid_text(const GUID& g) {
    std::ostringstream s;
    s << std::hex << std::setfill('0') << std::setw(8) << g.Data1 << '-'
      << std::setw(4) << g.Data2 << '-' << std::setw(4) << g.Data3 << '-'
      << std::setw(2) << static_cast<unsigned>(g.Data4[0])
      << std::setw(2) << static_cast<unsigned>(g.Data4[1]) << '-';
    for (int i = 2; i < 8; ++i) s << std::setw(2) << static_cast<unsigned>(g.Data4[i]);
    return s.str();
}
template<typename T> T read_value(const BYTE* data) {
    T result{};
    std::memcpy(&result, data, sizeof(T));
    return result;
}

class Capture {
public:
    Capture(const std::filesystem::path& output, bool stackwalk) : stackwalk_(stackwalk) {
        if (std::filesystem::exists(output)) throw std::runtime_error("output already exists");
        stream_.open(output, std::ios::binary);
        if (!stream_) throw std::runtime_error("cannot open output");
        LARGE_INTEGER now{};
        QueryPerformanceCounter(&now);
        name_ = L"ETWBehavior-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(now.QuadPart);
        properties_.resize(sizeof(EVENT_TRACE_PROPERTIES) + (name_.size() + 1) * sizeof(wchar_t));
        auto* props = properties();
        props->Wnode.BufferSize = static_cast<ULONG>(properties_.size());
        props->Wnode.Guid = kSystemTrace;
        props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        props->Wnode.ClientContext = 1; // raw QPC timestamps
        props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
        props->EnableFlags = EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_THREAD | EVENT_TRACE_FLAG_IMAGE_LOAD;
        props->BufferSize = 128;
        props->MinimumBuffers = 8;
        props->MaximumBuffers = 128;
        props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        LARGE_INTEGER frequency{};
        QueryPerformanceFrequency(&frequency);
        qpc_frequency_ = frequency.QuadPart;
    }
    ~Capture() {
        if (session_) ControlTraceW(session_, name_.c_str(), properties(), EVENT_TRACE_CONTROL_STOP);
        if (consumer_ != INVALID_PROCESSTRACE_HANDLE) CloseTrace(consumer_);
        if (worker_.joinable()) worker_.join();
    }
    void run(unsigned seconds) {
        ULONG status = StartTraceW(&session_, name_.c_str(), properties());
        if (status != ERROR_SUCCESS) {
            session_ = 0;
            throw std::runtime_error("StartTrace failed, Windows error " + std::to_string(status) + "; run an elevated terminal");
        }
        if (stackwalk_) {
            CLASSIC_EVENT_ID ids[] = {{kProcess, 1, {}}, {kThread, 1, {}}, {kImage, 10, {}}};
            status = TraceSetInformation(session_, TraceStackTracingInfo, ids, sizeof(ids));
            if (status != ERROR_SUCCESS)
                throw std::runtime_error("TraceSetInformation failed, Windows error " + std::to_string(status));
        }
        EVENT_TRACE_LOGFILEW logfile{};
        logfile.LoggerName = name_.data();
        logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
        logfile.EventRecordCallback = &Capture::callback;
        logfile.Context = this;
        consumer_ = OpenTraceW(&logfile);
        if (consumer_ == INVALID_PROCESSTRACE_HANDLE)
            throw std::runtime_error("OpenTrace failed, Windows error " + std::to_string(GetLastError()));
        worker_ = std::thread([this] {
            TRACEHANDLE handle = consumer_;
            const ULONG result = ProcessTrace(&handle, 1, nullptr, nullptr);
            process_status_.store(result);
            consumer_done_.store(true);
        });
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
        while (std::chrono::steady_clock::now() < deadline && !cancelled.load() && !consumer_done_.load())
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        status = ControlTraceW(session_, name_.c_str(), properties(), EVENT_TRACE_CONTROL_STOP);
        if (status != ERROR_SUCCESS) {
            CloseTrace(consumer_);
            consumer_ = INVALID_PROCESSTRACE_HANDLE;
            worker_.join();
            throw std::runtime_error("failed to stop owned ETW session, Windows error " + std::to_string(status));
        }
        session_ = 0;
        worker_.join();
        CloseTrace(consumer_);
        consumer_ = INVALID_PROCESSTRACE_HANDLE;
        stream_.flush();
        if (!stream_ || write_failed_.load()) throw std::runtime_error("capture output failed");
        const ULONG result = process_status_.load();
        if (result != ERROR_SUCCESS && result != ERROR_CANCELLED)
            throw std::runtime_error("ProcessTrace failed, Windows error " + std::to_string(result));
        const auto* p = properties();
        std::cerr << "{\"events\":" << events_ << ",\"stackwalk_records\":" << stacks_
                  << ",\"events_lost\":" << p->EventsLost << ",\"realtime_buffers_lost\":" << p->RealTimeBuffersLost
                  << ",\"qpc_frequency\":" << qpc_frequency_ << "}\n";
    }
private:
    EVENT_TRACE_PROPERTIES* properties() { return reinterpret_cast<EVENT_TRACE_PROPERTIES*>(properties_.data()); }
    static void WINAPI callback(EVENT_RECORD* event) noexcept {
        auto* self = static_cast<Capture*>(event->UserContext);
        try { self->write(event); }
        catch (...) { self->write_failed_.store(true); cancelled.store(true); }
    }
    void write(EVENT_RECORD* event) {
        DWORD pid = event->EventHeader.ProcessId, tid = event->EventHeader.ThreadId;
        LONGLONG timestamp = event->EventHeader.TimeStamp.QuadPart;
        const BYTE* frames = nullptr;
        std::size_t count = 0, width = 0;
        if (IsEqualGUID(event->EventHeader.ProviderId, kStackWalk) && event->EventHeader.EventDescriptor.Opcode == 32) {
            if (event->UserDataLength < 16) return;
            const auto* data = static_cast<const BYTE*>(event->UserData);
            timestamp = read_value<LONGLONG>(data);
            pid = read_value<DWORD>(data + 8);
            tid = read_value<DWORD>(data + 12);
            width = event->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER ? 4 : 8;
            if ((event->UserDataLength - 16) % width != 0) return;
            frames = data + 16;
            count = (event->UserDataLength - 16) / width;
            ++stacks_;
        }
        stream_ << "{\"schema_version\":\"raw-etw-v1\",\"provider\":\"" << guid_text(event->EventHeader.ProviderId)
                << "\",\"opcode\":" << static_cast<unsigned>(event->EventHeader.EventDescriptor.Opcode)
                << ",\"pid\":" << pid << ",\"tid\":" << tid << ",\"timestamp_qpc\":" << timestamp
                << ",\"qpc_frequency\":" << qpc_frequency_ << ",\"stack_addresses\":[";
        for (std::size_t i = 0; i < count; ++i) {
            if (i) stream_ << ',';
            const std::uint64_t address = width == 4 ? read_value<DWORD>(frames + i * width) : read_value<ULONGLONG>(frames + i * width);
            stream_ << '"' << "0x" << std::hex << address << std::dec << '"';
        }
        stream_ << "]}\n";
        if (!stream_) { write_failed_.store(true); cancelled.store(true); }
        ++events_;
    }
    std::vector<BYTE> properties_;
    std::wstring name_;
    TRACEHANDLE session_ = 0;
    TRACEHANDLE consumer_ = INVALID_PROCESSTRACE_HANDLE;
    std::ofstream stream_;
    std::thread worker_;
    bool stackwalk_;
    LONGLONG qpc_frequency_ = 0;
    std::uint64_t events_ = 0, stacks_ = 0;
    std::atomic<ULONG> process_status_{ERROR_SUCCESS};
    std::atomic<bool> consumer_done_{false}, write_failed_{false};
};
}

int main(int argc, char** argv) {
    try {
        std::string output;
        unsigned seconds = 0;
        bool stackwalk = false;
        for (int i = 1; i < argc; ++i) {
            const std::string option = argv[i];
            if (option == "--help") {
                std::cout << "etw_capture --output captures/events.ndjson --seconds 10 [--stackwalk]\n"
                          << "Elevated Windows terminal required. Captures process/thread/image events;\n"
                          << "optional stackwalks retain raw addresses, not resolved model features.\n";
                return 0;
            }
            if (option == "--stackwalk") { stackwalk = true; continue; }
            if ((option == "--output" || option == "--seconds") && i + 1 < argc) {
                const std::string value = argv[++i];
                if (option == "--output") output = value;
                else {
                    if (value.empty() || value.find_first_not_of("0123456789") != std::string::npos)
                        throw std::invalid_argument("seconds must be an integer");
                    auto duration = std::stoul(value);
                    if (duration == 0 || duration > 3600) throw std::invalid_argument("seconds must be in 1..3600");
                    seconds = static_cast<unsigned>(duration);
                }
            } else throw std::invalid_argument("unknown or incomplete option");
        }
        if (output.empty() || !seconds) throw std::invalid_argument("--output and --seconds are required");
        SetConsoleCtrlHandler(handle_ctrl, TRUE);
        Capture capture(output, stackwalk);
        capture.run(seconds);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "etw_capture: " << error.what() << '\n';
        return 2;
    }
}
