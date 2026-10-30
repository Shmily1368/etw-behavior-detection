/* this class is used to store all signatures read from file */
package NU.ETWRealTimeDetector.Signature;

import NU.ETWRealTimeDetector.SysConfig;
import com.google.gson.Gson;
import com.google.gson.JsonIOException;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileReader;
import java.io.IOException;
import java.util.*;

public class Signature {

    private final Logger logger = LoggerFactory.getLogger(Signature.class);

    Map<SigKey, List<String>> signatureReadable = new HashMap<>();
    Map<SigKey, List<Integer>> signatures = new HashMap<>();
    Map<SigKey, Set<Integer>> signatureContainsApi = new HashMap<>();


    private String[] PHF_NAME = {
            "all_audiorecord",
            "all_download&exec",
            "all_keylogger",
            "all_remotedesktop",
            "all_remoteshell"
    };

    private String SIG_DIRECTORY = "signatures/api/";
    private String SIG_FILE_EXTENSION = ".APISigs";

    private boolean useEncryptedSignatures = SysConfig.getBoolean("UseEncryptedSignatures", true);

    private static Signature instance = new Signature("signatures/api/", ".APISigs");
    public static Signature getSignature() {
        return instance;
    }

    public Signature(String SIG_DIRECTORY, String SIG_FILE_EXTENSION) {
        this.SIG_DIRECTORY = SIG_DIRECTORY;
        this.SIG_FILE_EXTENSION = SIG_FILE_EXTENSION;
        this.PHF_NAME = SysConfig.getString("Phfs", "keylogger").split("@");
        if (useEncryptedSignatures) {
            loadEncryptedSignatures();
        } else {
            loadSignatures();
        }
        //loadHardCodedSignatures();
    }

    private void loadSignatures() {
        for (int phfNo = 0; phfNo < PHF_NAME.length; phfNo++) {
            try (FileReader fileReader = new FileReader(SIG_DIRECTORY + PHF_NAME[phfNo] + SIG_FILE_EXTENSION)) {
                // read signatures of one phf
                List<SignatureUnit> signatureUnits = new Gson().fromJson(
                        fileReader,
                        new TypeToken<List<SignatureUnit>>(){}.getType());
                // loop through all the signatures in it
                for (int sigNo = 0; sigNo < signatureUnits.size(); sigNo++) {
                    SigKey sigKey = new SigKey(phfNo, sigNo, PHF_NAME[phfNo]);
                    HashSet<Integer> containsApi = new HashSet<>();
                    List<String> signatureSequence = signatureUnits.get(sigNo).sig;
                    // add api to ApiToInteger Map
                    for (String api : signatureSequence) {
                        ApiToInteger.addAPI(api);
                        containsApi.add(ApiToInteger.stringToInteger(api));
                    }
                    signatureContainsApi.put(sigKey, containsApi);
                    List<Integer> signatureSequenceInInt = ApiToInteger.stringListToIntegerList(signatureSequence);
                    //this.signatures.put(sigKey, signatureSequence);     // add to map
                    this.signatures.put(sigKey, signatureSequenceInInt);
                    this.signatureReadable.put(sigKey, signatureSequence);
                }
            } catch (JsonIOException | JsonSyntaxException | IOException e) {
                logger.error("loading sigs error", e);
                System.exit(1);
            }
        }
    }

    private void loadEncryptedSignatures() {
        List<String> encryptedSigs = Encryption.loadAndDecrypt("signatures/api/", PHF_NAME,".APISigs");

        for (int phfNo = 0; phfNo < encryptedSigs.size(); phfNo++) {
            try {
                // read signatures of one phf
                List<SignatureUnit> signatureUnits = new Gson().fromJson(
                        encryptedSigs.get(phfNo),
                        new TypeToken<List<SignatureUnit>>(){}.getType());
                // loop through all the signatures in it
                for (int sigNo = 0; sigNo < signatureUnits.size(); sigNo++) {
                    SigKey sigKey = new SigKey(phfNo, sigNo, PHF_NAME[phfNo]);
                    HashSet<Integer> containsApi = new HashSet<>();
                    List<String> signatureSequence = signatureUnits.get(sigNo).sig;
                    // add api to ApiToInteger Map
                    for (String api : signatureSequence) {
                        ApiToInteger.addAPI(api);
                        containsApi.add(ApiToInteger.stringToInteger(api));
                    }
                    signatureContainsApi.put(sigKey, containsApi);
                    List<Integer> signatureSequenceInInt = ApiToInteger.stringListToIntegerList(signatureSequence);
                    this.signatures.put(sigKey, signatureSequenceInInt);
                }
            } catch (JsonIOException | JsonSyntaxException e) {
                logger.error("load sigs error", e);
                System.exit(1);
            }
        }
    }

    public List<Integer> getSignature(SigKey sigKey) {
        return signatures.get(sigKey);
    }

    public Map<SigKey, List<Integer>> getSignatures() {
        return signatures;
    }

    public Map<SigKey, Set<Integer>> getSignatureContainsApi() {
        return signatureContainsApi;
    }

    public Map<SigKey, List<String>> getSignatureReadable() {
        return signatureReadable;
    }


    public static void main(String[] args) {
        Signature sig = Signature.getSignature();
    }
}
