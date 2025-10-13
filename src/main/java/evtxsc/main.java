package evtxsc;

import evtxsc.builder.*;
import evtxsc.output.ResultWriter;
import evtxsc.scanners.BruteForce.BruteForceScanner;
import evtxsc.scanners.Powershell.PowershellScanner;
import evtxsc.scanners.Privesc.PrivescScanner;
import evtxsc.scanners.Flag;
import evtxsc.scanners.ScanResult;

import java.util.*;
import java.io.*;

public class main {

    private static final Set<String> VALID_SCANS = Set.of("bruteforce", "powershell", "privesc");

    public static void main(String[] args) {
        if (args.length == 0) {
            printUsage();
            System.exit(1);
        }

        List<FileConfig> fileConfigs = buildFileConfigs(args);

        if (fileConfigs.isEmpty()) {
            System.err.println("Error: No files specified. Use -f <filepath>");
            System.exit(1);
        }

        // Process each file with its configuration
        for (FileConfig config : fileConfigs) {
            processFileConfig(config);
        }
    }

    /**
     * Bundles each config flag with the preceding file
     *
     * @param args Program input
     * @return a List of all FileConfig Objects for each file flag
     */
    private static List<FileConfig> buildFileConfigs(String[] args) {
        List<FileConfig> configs = new ArrayList<>();
        FileConfig currentConfig = null;

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];

            switch (arg) {
                case "-f" -> {
                    // Save previous config if exists
                    if (currentConfig != null) {
                        configs.add(currentConfig);
                    }

                    // Start new file config
                    if (i + 1 >= args.length) {
                        System.err.println("Error: -f requires a filepath");
                        System.exit(1);
                    }
                    currentConfig = new FileConfig(args[++i]);
                }
                case "--scan" -> {
                    if (currentConfig == null) {
                        System.err.println("Error: --scan must follow a -f flag");
                        System.exit(1);
                    }

                    // Collect all scan names until next flag
                    List<String> scans = new ArrayList<>();
                    while (i + 1 < args.length && !args[i + 1].startsWith("-")) {
                        String scan = args[++i];
                        if (!VALID_SCANS.contains(scan)) {
                            System.err.println("Error: Unknown scan type '" + scan + "'. Valid: " + VALID_SCANS);
                            System.exit(1);
                        }
                        scans.add(scan);
                    }

                    if (scans.isEmpty()) {
                        System.err.println("Error: --scan requires at least one scan name");
                        System.exit(1);
                    }

                    currentConfig.scans = scans;
                }
                case "--output" -> {
                    if (currentConfig == null) {
                        System.err.println("Error: --output must follow a -f flag");
                        System.exit(1);
                    }
                    if (i + 1 >= args.length) {
                        System.err.println("Error: --output requires a filepath");
                        System.exit(1);
                    }
                    currentConfig.outputFile = args[++i];
                }
                case "--append" -> {
                    if (currentConfig == null) {
                        System.err.println("Error: --append must follow a -f flag");
                        System.exit(1);
                    }
                    if (i + 1 >= args.length) {
                        System.err.println("Error: --append requires a filepath");
                        System.exit(1);
                    }
                    currentConfig.appendFile = args[++i];
                }
                case "--no-console" -> {
                    if (currentConfig == null) {
                        System.err.println("Error: --no-console must follow a -f flag");
                        System.exit(1);
                    }
                    currentConfig.noConsole = true;
                }
                default -> {
                    System.err.println("Error: Unknown argument '" + arg + "'");
                    printUsage();
                    System.exit(1);
                }
            }
        }

        // Add the last config
        if (currentConfig != null) {
            configs.add(currentConfig);
        }

        return configs;
    }

    /**
     * Load, scan, and output a given EVTX file with provided configs
     *
     * @param config FileConfig object for this file
     */
    private static void processFileConfig(FileConfig config) {
        // Validate file exists
        File file = new File(config.filepath);
        if (!file.exists() || !file.isFile()) {
            System.err.println("Error: Not a valid file: " + config.filepath);
            return;
        }

        // Avoid clobbering when output and append are same location
        if (config.outputFile != null && config.outputFile.equals(config.appendFile)) {
            System.err.println("Warning: --output and --append specify the same file (" + config.outputFile + ")");
        }


        EventLog log = Loader.parseFile(config.filepath);

        // Determine which scans to run (default to all if not specified)
        List<String> scansToRun = config.scans != null ? config.scans : new ArrayList<>(VALID_SCANS);

        // Run each scan
        for (String scanName : scansToRun) {
            ScanResult<? extends Flag> result = switch(scanName) {
                case "bruteforce"-> BruteForceScanner.runBruteForceScan(log);
                case "powershell"-> PowershellScanner.runPowershellScan(log);
                case "privesc"->PrivescScanner.runPrivescScan(log);
                default->ScanResult.empty();
            };

            // Write to console (unless --no-console)
            if (!config.noConsole) {
                ResultWriter.writeToConsole(result);
            }

            // Write to output file (overwrite)
            if (config.outputFile != null) {
                // Extract directory and filename from path
                File outputFile = new File(config.outputFile);
                String outputDir = outputFile.getParent() != null ? outputFile.getParent() : ".";
                String filename = outputFile.getName();
                if (!ResultWriter.writeToFile(result, outputDir, filename)) {
                    System.err.println("Warning: Failed to write output to " + config.outputFile);
                }

            }

            // Append to file
            if (config.appendFile != null) {
                // Extract directory and filename from path
                File appendFile = new File(config.appendFile);
                String appendDir = appendFile.getParent() != null ? appendFile.getParent() : ".";
                String filename = appendFile.getName();
                if (!ResultWriter.appendToFile(result, appendDir, filename)) {
                    System.err.println("Warning: Failed to append results to " + config.appendFile);
                }
            }
        }
    }

    /**
     * Help message if no args are specified
     */
    private static void printUsage() {
        System.out.println("Usage: [evtxsc] -f <file> [--scan <scans>] [--output <file>] [--append <file>] [--no-console] ...");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  -f <filepath>              Specify EVTX file to scan (required, repeatable)");
        System.out.println("  --scan <scan1> <scan2>...  Space-separated scan names (default: all)");
        System.out.println("                             Available: bruteforce, powershell, privesc");
        System.out.println("  --output <filepath>        Write results to file (overwrites)");
        System.out.println("  --append <filepath>        Append results to file");
        System.out.println("  --no-console               Suppress console output");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  [evtxsc] -f security.evtx");
        System.out.println("  [evtxsc] -f file.evtx --scan bruteforce powershell --output results.txt");
        System.out.println("  [evtxsc] -f file1.evtx --scan bruteforce --output bf.txt \\");
        System.out.println("           -f file2.evtx --append master.log --no-console");
    }

    // Inner class to hold configuration for each file
    private static class FileConfig {
        String filepath;
        List<String> scans = null; // null means run all scans
        String outputFile = null;
        String appendFile = null;
        boolean noConsole = false;

        FileConfig(String filepath) {
            this.filepath = filepath;
        }
    }
}

