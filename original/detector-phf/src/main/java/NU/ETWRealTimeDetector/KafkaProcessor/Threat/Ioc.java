package NU.ETWRealTimeDetector.KafkaProcessor.Threat;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Ioc {
    private String ioc;
    @JsonProperty("ioc_type")
    private Integer iocType;
    private Integer severity;
    private String label;
    @JsonProperty("threat_type")
    private Integer threatType;
    @JsonProperty("ioc_source")
    private Integer iocSource;
    private String iocCode;
    @JsonProperty("hash_type")
    private Integer hashType;

    public Integer getSeverity() {
        return severity;
    }

    public void setSeverity(Integer severity) {
        this.severity = severity;
    }

    public String getIoc() {
        return ioc;
    }

    public void setIoc(String ioc) {
        this.ioc = ioc;
    }

    public Integer getIocType() {
        return iocType;
    }

    public void setIocType(Integer iocType) {
        this.iocType = iocType;
    }

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public Integer getThreatType() {
        return threatType;
    }

    public void setThreatType(Integer threatType) {
        this.threatType = threatType;
    }

    public Integer getIocSource() {
        return iocSource;
    }

    public void setIocSource(Integer iocSource) {
        this.iocSource = iocSource;
    }

    public String getIocCode() {
        return iocCode;
    }

    public void setIocCode(String iocCode) {
        this.iocCode = iocCode;
    }

    public Integer getHashType() {
        return hashType;
    }

    public void setHashType(Integer hashType) {
        this.hashType = hashType;
    }
}
