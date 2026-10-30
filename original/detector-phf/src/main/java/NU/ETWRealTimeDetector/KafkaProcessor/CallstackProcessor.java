package NU.ETWRealTimeDetector.KafkaProcessor;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.util.*;

import org.dmg.pmml.FieldName;
import org.jpmml.evaluator.*;


public class CallstackProcessor {

    private static Evaluator evaluator = null;

    private static final int featureNum = 2863;

    private static HashMap<String, String> phfTagMap = null;

    private static double p = 0.0;

    public static double getP(){return p;}

    public static int getFeatureNum() {
        return featureNum;
    }

    private static HashMap<String, String> getPhfTagMap() {
        if (phfTagMap == null) {
            phfTagMap = new HashMap<>();
            phfTagMap.put("B0", "B0");
            phfTagMap.put("B11", "B11");
            phfTagMap.put("B15", "B15");
            phfTagMap.put("B16", "B16");
            phfTagMap.put("B2", "B2");
            phfTagMap.put("B3", "B3");
            phfTagMap.put("B9", "B9");

            phfTagMap.put("M0", "RemoteShell");
            phfTagMap.put("M1", "Keylogger");
            phfTagMap.put("M2", "RemoteDesktop");
            phfTagMap.put("M6", "AudioRecord");
            phfTagMap.put("M7", "ReverseShell");
        }
        return phfTagMap;
    }

    private static Evaluator getEvaluator() {
        if (evaluator == null) {
            try {
                evaluator = new LoadingModelEvaluatorBuilder().load(new File("random_forest.pmml")).build();
                evaluator.verify();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return evaluator;
    }

    public static String preProcessCallstack(double[] weights) {

        Evaluator evaluator = getEvaluator();

        if (evaluator == null) {
            return "";
        }

        List<InputField> inputFields = evaluator.getInputFields();
        Map<FieldName, FieldValue> arguments = new LinkedHashMap<>();
        for (InputField inputField : inputFields) {
            FieldName fieldName = inputField.getFieldName();
            String fieldString = fieldName.getValue();
            fieldString = fieldString.substring(1);
            int field = -1;
            try {
                field = Integer.parseInt(fieldString);
            } catch (NumberFormatException e) {
                e.printStackTrace();
            }
            if (field <= 0 || field > featureNum) {
                return "";
            }
            Object value = weights[field-1];
            FieldValue fieldValue = inputField.prepare(value);
            arguments.put(fieldName, fieldValue);
        }

        Map<FieldName, ?> results = evaluator.evaluate(arguments);

        List<TargetField> targetFields = evaluator.getTargetFields();
        String tag = "";
        double tagValue = 0.0;
        for (TargetField targetField : targetFields) {
            FieldName targetFieldName = targetField.getName();
            ProbabilityDistribution targetFieldValue = (ProbabilityDistribution) results.get(targetFieldName);
            Object result = targetFieldValue.getResult();
            Double value1 = targetFieldValue.getValue(result);
            tag = result.toString();
            tagValue = value1;
            /*
            ValueMap<String,Double> values = targetFieldValue.getValues();
            for (String s : values.keySet()) {
                System.out.println(s+": "+values.get(s));
            }*/
        }
        //System.out.println("tag: " + tag + ", tagValue: " + tagValue);
        if (!tag.isEmpty()) {
            //System.out.println("===========================");
            HashMap<String, String> map = getPhfTagMap();
            String t = map.getOrDefault(tag, "Others");
            p = tagValue;
            //System.out.println("Final Result: "+t);
            //t = ", tag: "+ t +", p: "+ tagValue;
            return t;
        }

        return "";
    }

    private static void test() {
        System.out.println("----test----");
        final int feature_num = 1092;
        String callStackIndexStr = "249_0.5,611_0.5";
        double[] weights = new double[feature_num];

        String[] w = callStackIndexStr.split(",");
        for (String weight : w) {
            String[] info = weight.split("_");
            if (info.length == 2) {
                try {
                    int index = Integer.parseInt(info[0]);
                    double proportion = Double.parseDouble(info[1]);
                    if (index < feature_num && index >= 0 && proportion >= 0 && proportion <= 1) {
                        weights[index] = proportion;
                    }
                } catch (NumberFormatException e) {
                    e.printStackTrace();
                }
            }
        }

        try {

            String callStackStr = preProcessCallstack(weights);
            if(callStackStr.length() == 0){
                return ;
            }
            //over
            double p = CallstackProcessor.getP();

            try (BufferedWriter pw = new BufferedWriter(new FileWriter("phflogger", true))) {
                //pw.write("========> get the phf， time: " + timestamp + ", result: {pid: "+processId + ",tag: "+ callStackStr+", p: "+p+" }");
                pw.newLine();
            }catch (Exception e)
            {
                //logger.error("pw error", e);
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            System.out.println("----over----");
        }

    }

    public static void main(String[] args) {
        test();
    }
}