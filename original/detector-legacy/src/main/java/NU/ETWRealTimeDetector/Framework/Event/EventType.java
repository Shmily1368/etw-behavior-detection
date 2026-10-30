package NU.ETWRealTimeDetector.Framework.Event;

public enum EventType {
    PROCESS_START,
    PROCESS_END,
    FILE_READ,
    FILE_WRITE,
    LOAD_OWN_EXE,
    Zone_Identifier,
    // 注入的判断条件包含线程检测
    INJECTION,
    // 注入的判断条件不包含线程检测
    INJECTION2,
    // Potential Harmful Function 恶意行为
    PHF,
    // 远程线程执行了PHF
    REMOTE_THREAD_PHF,
    IMAGE_LOAD,
    START_SCRIPT,
    FILE_RENAME,
    FILE_CREATE,
    NETWORK_SEND,
    NETWORK_RECV,
    FILE_DELETE,
    NOTHING;
}
