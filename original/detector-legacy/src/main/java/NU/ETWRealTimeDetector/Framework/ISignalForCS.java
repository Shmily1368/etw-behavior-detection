package NU.ETWRealTimeDetector.Framework;

public interface ISignalForCS {
    String getClientId();
    String getFileName();
    long getTimestamp();
    boolean isEvent();
}
