package NU.ETWRealTimeDetector.Signature;

public class SigKey {
    private int phfNo;
    private int sigNo;
    private String phfName;

    public SigKey(int phfNo, int sigNo, String phfName) {
        this.phfNo = phfNo;
        this.sigNo = sigNo;
        this.phfName = phfName;
    }

    public int getPhfNo() {
        return phfNo;
    }

    public int getSigNo() {
        return sigNo;
    }

    public String getPhfName() {
        return phfName;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        SigKey that = (SigKey) o;

        if (phfNo != that.phfNo) return false;
        return sigNo == that.sigNo;
    }

    @Override
    public int hashCode() {
        int result = phfNo;
        result = 31 * result + sigNo;
        return result;
    }

    @Override
    public String toString() {
        return String.format("phfNo_%d_sigNo_%d_%s", phfNo, sigNo, phfName);
    }
}
