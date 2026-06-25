import java.util.*;
import java.util.stream.Collectors;

/**
 * Research-Grade Single File Framework
 * Explainable Fraud Detection and Protection Recommendation Framework
 * with Monte Carlo-Based Heuristic Evaluation and Ranking Analysis
 */
public class SanFraudDetectionSimulation {

    static final int MONTE_CARLO_RUNS = 1000;

    static class FraudCase {
        int id;
        String fraudType;
        boolean fraudKnown;
        int severity;
        int redFlags;
        double anomalyScore;
        boolean duplicate, documentMismatch, identityMismatch,
                timingMismatch, providerAbnormal, paymentIssue;

        FraudCase(int id,String fraudType,boolean fraudKnown,int severity,int redFlags,double anomalyScore,
                  boolean duplicate,boolean documentMismatch,boolean identityMismatch,
                  boolean timingMismatch,boolean providerAbnormal,boolean paymentIssue){
            this.id=id;
            this.fraudType=fraudType;
            this.fraudKnown=fraudKnown;
            this.severity=severity;
            this.redFlags=redFlags;
            this.anomalyScore=anomalyScore;
            this.duplicate=duplicate;
            this.documentMismatch=documentMismatch;
            this.identityMismatch=identityMismatch;
            this.timingMismatch=timingMismatch;
            this.providerAbnormal=providerAbnormal;
            this.paymentIssue=paymentIssue;
        }
    }

    static class AlgoResult {
        String name;
        List<Double> costs = new ArrayList<>();
        int tp,fp,fn;
        AlgoResult(String n){name=n;}
        double mean(){ return costs.stream().mapToDouble(Double::doubleValue).average().orElse(0);}
        double sd(){
            double m=mean(); double s=0;
            for(double d:costs) s+=(d-m)*(d-m);
            return costs.size()<2?0:Math.sqrt(s/(costs.size()-1));
        }
        double precision(){ return (tp+fp)==0?0:(double)tp/(tp+fp);}
        double recall(){ return (tp+fn)==0?0:(double)tp/(tp+fn);}
        double f1(){ double p=precision(),r=recall(); return p+r==0?0:2*p*r/(p+r);}
    }

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);

        System.out.println("=== Explainable Fraud Detection Framework ===");
        System.out.print("Enter number of fraud cases: ");
        int n = Integer.parseInt(sc.nextLine());

        List<FraudCase> cases = new ArrayList<>();

        for(int i=1;i<=n;i++){
            System.out.println("\nCase "+i);

            System.out.print("Fraud Type: ");
            String fraudType=sc.nextLine();

            System.out.print("Fraud Known (true/false): ");
            boolean fraud=Boolean.parseBoolean(sc.nextLine());

            System.out.print("Severity (0-100): ");
            int severity=Integer.parseInt(sc.nextLine());

            System.out.print("Red Flags: ");
            int redFlags=Integer.parseInt(sc.nextLine());

            System.out.print("Anomaly Score (0-1): ");
            double anomaly=Double.parseDouble(sc.nextLine());

            System.out.print("Duplicate Case (true/false): ");
            boolean duplicate=Boolean.parseBoolean(sc.nextLine());

            System.out.print("Document Mismatch (true/false): ");
            boolean documentMismatch=Boolean.parseBoolean(sc.nextLine());

            System.out.print("Identity Mismatch (true/false): ");
            boolean identityMismatch=Boolean.parseBoolean(sc.nextLine());

            System.out.print("Timing Mismatch (true/false): ");
            boolean timingMismatch=Boolean.parseBoolean(sc.nextLine());

            System.out.print("Provider Abnormal (true/false): ");
            boolean providerAbnormal=Boolean.parseBoolean(sc.nextLine());

            System.out.print("Payment Issue (true/false): ");
            boolean paymentIssue=Boolean.parseBoolean(sc.nextLine());

            cases.add(new FraudCase(i,fraudType,fraud,severity,redFlags,anomaly,
                    duplicate,documentMismatch,identityMismatch,
                    timingMismatch,providerAbnormal,paymentIssue));
        }

        for(FraudCase fc : cases){
            processCase(fc);
        }
    }

    static void processCase(FraudCase fc){
        System.out.println("\n================================================");
        System.out.println("CASE ID: "+fc.id);
        System.out.println("================================================");

        boolean fraudDetected = detectOverall(fc);

        if(!fraudDetected){
            System.out.println("STATUS: SAFE");
            System.out.println("No significant fraud indicators detected.");
            return;
        }

        System.out.println("STATUS: FRAUD DETECTED");
        System.out.println("TYPE: "+fc.fraudType);

        generateProtection(fc);
        explainReasoning(fc);

        Map<String,AlgoResult> results = runSimulation(fc);

        showStatistics(results);
        showRanking(results);
        showDifferenceAnalysis(results);
        showFinalRecommendation(results);
    }

    static boolean detectOverall(FraudCase fc){
        return fc.fraudKnown || fc.anomalyScore>0.7 || fc.redFlags>=7
                || fc.identityMismatch || fc.documentMismatch;
    }

    static void generateProtection(FraudCase fc){
        System.out.println("\nProtection Recommendations:");
        if(fc.identityMismatch){
            System.out.println("- Biometric Verification");
            System.out.println("- MFA Enforcement");
        }
        if(fc.documentMismatch){
            System.out.println("- OCR Validation");
            System.out.println("- Document Verification");
        }
        System.out.println("- Continuous Monitoring");
        System.out.println("- Manual Investigation");
    }

    static void explainReasoning(FraudCase fc){
        System.out.println("\nAlgorithm Reasoning:");
        System.out.println("CBR: Historical pattern match score based on duplicates.");
        System.out.println("Knowledge Graph: Entity relationship analysis.");
        System.out.println("Fuzzy Logic: Uncertainty reasoning using anomaly/red flags.");
        System.out.println("Forward Chaining: Rule-triggered fraud indicators.");
        System.out.println("Backward Chaining: Goal-driven fraud confirmation.");
    }

    static Map<String,AlgoResult> runSimulation(FraudCase fc){
        String[] algos = {
                "Case-Based Reasoning",
                "Knowledge Graph",
                "Fuzzy Logic",
                "Forward Chaining",
                "Backward Chaining"
        };

        Random r = new Random();
        Map<String,AlgoResult> map = new LinkedHashMap<>();
        for(String a:algos) map.put(a,new AlgoResult(a));

        for(int i=0;i<MONTE_CARLO_RUNS;i++){
            double severityFactor=0.9+r.nextDouble()*0.2;
            double remedyFactor=0.9+r.nextDouble()*0.2;
            double weightFactor=0.95+r.nextDouble()*0.1;

            for(String algo:algos){
                AlgoResult ar=map.get(algo);

                boolean detected=detectByAlgo(algo,fc);

                if(detected && fc.fraudKnown) ar.tp++;
                if(detected && !fc.fraudKnown) ar.fp++;
                if(!detected && fc.fraudKnown) ar.fn++;

                double cost=(fc.severity*100*severityFactor*remedyFactor*weightFactor)
                        + baseCost(algo);

                ar.costs.add(cost);
            }
        }
        return map;
    }

    static boolean detectByAlgo(String algo,FraudCase fc){
        switch(algo){
            case "Case-Based Reasoning":
                return fc.duplicate || fc.identityMismatch;
            case "Knowledge Graph":
                return fc.identityMismatch || fc.documentMismatch;
            case "Fuzzy Logic":
                return fc.anomalyScore>0.7 || fc.redFlags>=7;
            case "Forward Chaining":
                return fc.providerAbnormal || fc.paymentIssue;
            case "Backward Chaining":
                return fc.fraudKnown && fc.redFlags>=5;
            default:
                return false;
        }
    }

    static double baseCost(String algo){
        switch(algo){
            case "Case-Based Reasoning": return 600;
            case "Knowledge Graph": return 850;
            case "Fuzzy Logic": return 500;
            case "Forward Chaining": return 700;
            default: return 650;
        }
    }

    static void showStatistics(Map<String,AlgoResult> results){
        System.out.println("\nStatistical Analysis:");
        for(AlgoResult ar:results.values()){
            System.out.printf("%s | Mean=%.2f SD=%.2f Precision=%.3f Recall=%.3f F1=%.3f%n",
                    ar.name, ar.mean(), ar.sd(), ar.precision(), ar.recall(), ar.f1());
        }
    }

    static void showRanking(Map<String,AlgoResult> results){
        System.out.println("\nSimulation Ranking:");
        List<AlgoResult> ranked=results.values().stream()
                .sorted(Comparator.comparingDouble(AlgoResult::mean))
                .collect(Collectors.toList());

        for(int i=0;i<ranked.size();i++){
            System.out.println((i+1)+". "+ranked.get(i).name);
        }
    }

    static void showDifferenceAnalysis(Map<String,AlgoResult> results){
        System.out.println("\nActual Reasoning Ranking:");
        String[] actual={
                "Case-Based Reasoning",
                "Knowledge Graph",
                "Backward Chaining",
                "Fuzzy Logic",
                "Forward Chaining"
        };

        for(int i=0;i<actual.length;i++){
            System.out.println((i+1)+". "+actual[i]);
        }

        System.out.println("\nRanking Difference Analysis:");
        System.out.println("Compare simulation ranking against actual reasoning ranking.");
    }

    static void showFinalRecommendation(Map<String,AlgoResult> results){

    List<AlgoResult> ranked = results.values()
            .stream()
            .sorted(
                    Comparator.comparingDouble(AlgoResult::mean)
                            .thenComparing((AlgoResult a) -> -a.f1())
            )
            .collect(Collectors.toList());

    AlgoResult best = ranked.get(0);

    System.out.println("\n================================================");
    System.out.println("FINAL RECOMMENDATION");
    System.out.println("================================================");

    System.out.println("Recommended Algorithm : " + best.name);

    System.out.printf("Mean Cost : %.2f%n", best.mean());
    System.out.printf("Precision : %.4f%n", best.precision());
    System.out.printf("Recall    : %.4f%n", best.recall());
    System.out.printf("F1 Score  : %.4f%n", best.f1());

    String reason;

    switch(best.name){

        case "Case-Based Reasoning":
            reason =
                "Best match for historical fraud patterns and duplicate-case analysis.";
            break;

        case "Knowledge Graph":
            reason =
                "Best at discovering hidden relationships among entities.";
            break;

        case "Backward Chaining":
            reason =
                "Provides strong goal-driven fraud verification.";
            break;

        case "Fuzzy Logic":
            reason =
                "Handles uncertainty and incomplete information effectively.";
            break;

        case "Forward Chaining":
            reason =
                "Provides efficient rule-based fraud reasoning.";
            break;

        default:
            reason =
                "Selected because of superior simulation performance.";
    }

    System.out.println("Reason : " + reason);
}
}