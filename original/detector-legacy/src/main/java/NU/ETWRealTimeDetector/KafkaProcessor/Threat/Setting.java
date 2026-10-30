package NU.ETWRealTimeDetector.KafkaProcessor.Threat;

public class Setting {
    private Boolean local;
    private Boolean custom;
    private Boolean third_party;
    private Boolean threat_book;
    private String threat_book_url;
    private String threat_book_key;

    public Boolean getLocal() {
        return local;
    }

    public void setLocal(Boolean local) {
        this.local = local;
    }

    public Boolean getCustom() {
        return custom;
    }

    public void setCustom(Boolean custom) {
        this.custom = custom;
    }

    public static Setting defaultSetting() {
        Setting setting = new Setting();
        setting.setCustom(false);
        setting.setLocal(false);
        return setting;
    }

    public Boolean getThird_party() {
        return third_party;
    }

    public void setThird_party(Boolean third_party) {
        this.third_party = third_party;
    }

    public Boolean getThreat_book() {
        return threat_book;
    }

    public void setThreat_book(Boolean threat_book) {
        this.threat_book = threat_book;
    }

    public String getThreat_book_url() {
        return threat_book_url;
    }

    public void setThreat_book_url(String threat_book_url) {
        this.threat_book_url = threat_book_url;
    }

    public String getThreat_book_key() {
        return threat_book_key;
    }

    public void setThreat_book_key(String threat_book_key) {
        this.threat_book_key = threat_book_key;
    }
}
