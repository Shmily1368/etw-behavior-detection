/* this class is used to store one signature sequence and its coverage, falsePositive etc. */
package NU.ETWRealTimeDetector.Signature;

import java.util.List;
import java.util.Set;

public class SignatureUnit {
    public Set<String> traces;
    public List<String> sig;
    public List<Integer> sigInInt;
    public int windowSize;
    public double coverage;
    public double falsePositiveShare;

    public SignatureUnit(Set<String> traces, List<String> sig, int windowSize, double coverage, double falsePositiveShare) {
        this.traces = traces;
        this.sig = sig;
        this.sigInInt = ApiToInteger.stringListToIntegerList(sig);
        this.windowSize = windowSize;
        this.coverage = coverage;
        this.falsePositiveShare = falsePositiveShare;
    }

    public SignatureUnit(){}

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        SignatureUnit that = (SignatureUnit) o;

        if (windowSize != that.windowSize) return false;
        if (Double.compare(that.coverage, coverage) != 0) return false;
        if (Double.compare(that.falsePositiveShare, falsePositiveShare) != 0) return false;
        if (traces != null ? !traces.equals(that.traces) : that.traces != null) return false;
        return sig != null ? sig.equals(that.sig) : that.sig == null;
    }

    @Override
    public int hashCode() {
        int result;
        long temp;
        result = traces != null ? traces.hashCode() : 0;
        result = 31 * result + (sig != null ? sig.hashCode() : 0);
        result = 31 * result + windowSize;
        temp = Double.doubleToLongBits(coverage);
        result = 31 * result + (int) (temp ^ (temp >>> 32));
        temp = Double.doubleToLongBits(falsePositiveShare);
        result = 31 * result + (int) (temp ^ (temp >>> 32));
        return result;
    }

}
