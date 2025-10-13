package evtxsc.builder;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;

/**
 * [UNUSED TEMP CLASS] Loads multiple EVTX XML files into a List. Uses an
 * ExecutorService to distribute file parsing across threads.
 */
public class LoaderOrchestrator {

    public static List<EventLog> parseMultipleFiles(List<String> paths) throws Exception {
        // ExecutorService for threads, CompletionService to pull returned Event Lists, Lists to store Event List returns
        ExecutorService executor = Executors.newFixedThreadPool(paths.size());
        CompletionService<EventLog> service = new ExecutorCompletionService<>(executor);
        List<EventLog> results = new ArrayList<>();

        for (String path : paths) {
            service.submit(() -> Loader.parseFile(path));
        }

        for (int i = 0; i < paths.size(); i++) {
            try {
                results.add(service.take().get());
            } catch (InterruptedException e) {
                throw new Exception("CompletionService taking interrupted while waiting: ", e);
            } catch (ExecutionException e) {
                throw new Exception("CompletionService getting failed: ", e);
            }
        }

        executor.shutdown();
        return results;
    }
}
