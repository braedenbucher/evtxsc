package evtxsc.output;

import evtxsc.scanners.Flag;
import evtxsc.scanners.ScanResult;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class ResultWriter {
    private static final DateTimeFormatter TIMESTAMP_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd_HHmmss");

    // Private constructor for good practice
    private ResultWriter() {}

    /**
     * Ensures the output directory exists, creates it if necessary
     */
    private static void ensureDirectoryExists(Path directory) throws IOException {
        if (!Files.exists(directory)) {
            Files.createDirectories(directory);
        }
    }

    /**
     * Writes a Result object to a file with an auto-generated timestamped filename
     *
     * @param result The Result object to write
     * @param outputDir The directory to write to
     * @return true if write was successful, false otherwise
     */
    public static boolean writeToFile(ScanResult<? extends Flag> result, String outputDir) {
        String timestamp = LocalDateTime.now().format(TIMESTAMP_FORMAT);
        String filename = "scan_results_" + timestamp + ".txt";
        return writeToFile(result, outputDir, filename);
    }

    /**
     * Writes a Result object to a file
     *
     * @param result The Result object to write
     * @param outputDir The directory to write to
     * @param filename The name of the file (without path)
     * @return true if write was successful, false otherwise
     */
    public static boolean writeToFile(ScanResult<? extends Flag> result, String outputDir, String filename) {
        Path directory = Paths.get(outputDir);
        Path filePath = directory.resolve(filename);

        try {
            ensureDirectoryExists(directory);
            String content = result.toFormattedString();
            Files.writeString(filePath, content, StandardCharsets.UTF_8);
            System.out.println("Results written to: " + filePath.toAbsolutePath());
            return true;
        } catch (IOException e) {
            System.err.println("[ERROR] Unable to write to " + filePath.toAbsolutePath() + ": " + e.getMessage());
            return false;
        }
    }

    /**
     * Appends a Result object to an existing file
     *
     * @param result The Result object to append
     * @param outputDir The directory containing the file
     * @param filename The name of the file to append to
     * @return true if append was successful, false otherwise
     */
    public static boolean appendToFile(ScanResult<? extends Flag> result, String outputDir, String filename) {
        Path directory = Paths.get(outputDir);
        Path filePath = directory.resolve(filename);

        try {
            ensureDirectoryExists(directory);
            String content = result.toFormattedString();
            // Add separator between results
            String separator = "\n" + "=".repeat(80) + "\n\n";

            if (Files.exists(filePath)) {
                Files.writeString(filePath, separator + content, StandardCharsets.UTF_8,
                        StandardOpenOption.APPEND);
            } else {
                Files.writeString(filePath, content, StandardCharsets.UTF_8);
            }
            System.out.println("Results appended to: " + filePath.toAbsolutePath());
            return true;
        } catch (IOException e) {
            System.err.println("[ERROR] Unable to write to " + filePath.toAbsolutePath() + ": " + e.getMessage());
            return false;
        }
    }

    /**
     * Writes to console, technically redundant but here for extensibility
     *
     * @param result The Result object to print
     */
    public static void writeToConsole(ScanResult<? extends Flag> result) {
        System.out.println(result.toFormattedString());
    }
}