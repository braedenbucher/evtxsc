package evtxsc.builder;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import static javax.xml.stream.XMLStreamConstants.START_ELEMENT;
import static javax.xml.stream.XMLStreamConstants.CHARACTERS;
import static javax.xml.stream.XMLStreamConstants.END_ELEMENT;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.StringReader;
import java.util.*;
import java.util.concurrent.*;

/**
 * Loads components of a Windows EVTX XML file into a List of Events.
 * Uses a Producer thread to stream XML file input and Consumer threads to
 * assemble it into Event objects concurrently, compiled into a Synced List
 * which is sorted and bundled in an EventLog object.
 */
public class Loader {
    private static final XMLInputFactory factory = XMLInputFactory.newInstance();
    static { factory.setProperty(XMLInputFactory.IS_COALESCING, false); }
    private static final int NUM_CONSUMERS = Runtime.getRuntime().availableProcessors(); // Number of consumer threads (for poison pills)
    private static final int MAX_SNIPPET_SIZE = 2048;

    /**
     * Parses and XML file and returns an EventLog object.
     *
     * @param path the file path to the XML file
     * @return EventLog containing list of Events
     * @throws RuntimeException if parsing fails or is interrupted
     */
    public static EventLog parseFile(String path) throws RuntimeException {
        if (path == null || path.trim().isEmpty()) {
            throw new IllegalArgumentException("File path " + path + " cannot be null or empty");
        }

        // Queue for input stream, collection for output stream, latch for thread termination
        BlockingQueue<EventWorkItem> queue = new LinkedBlockingQueue<>();
        List<Event> results = Collections.synchronizedList(new ArrayList<>());
        CountDownLatch latch = new CountDownLatch(NUM_CONSUMERS);

        try {
            ExecutorService executor = Executors.newFixedThreadPool(NUM_CONSUMERS + 1);

            // Submit producer task
            executor.submit(() -> {
                try {
                    producerTask(path, queue);
                } catch (Exception e) {
                    throw new RuntimeException("Producer Error: ", e);
                }
            });

            // Submit consumer tasks
            for (int i = 0; i < NUM_CONSUMERS; i++) {
                executor.submit(() -> {
                    try {
                        consumerTask(queue, results);
                    } catch (Exception e) {
                        throw new RuntimeException("Consumer Error: ", e);
                    } finally {
                        latch.countDown();
                    }
                });
            }

            executor.shutdown();
            latch.await();

        } catch (InterruptedException e) {
            // Restore interrupted status
            Thread.currentThread().interrupt();
            throw new RuntimeException("Parsing interrupted", e);
        }

        // Sort by sequence to maintain log order
        results.sort(Comparator.comparingLong(Event::sequenceId));
        return new EventLog(results);
    }

    /**
     * Producer task which reads the XML file and queues work items for consumers.
     *
     * @param filePath path to the XML file
     * @param queue blocking queue to put work items
     * @throws Exception if file reading or XML parsing fails
     */
    private static void producerTask(String filePath, BlockingQueue<EventWorkItem> queue) throws Exception {
        XMLStreamReader reader = null; // Keep scope for exception handling
        long sequenceId = 0; // For sorting final Event list

        try {
            reader = factory.createXMLStreamReader(new FileInputStream(filePath));

            while (reader.hasNext()) {
                int element = reader.next();

                if (element == START_ELEMENT && reader.getLocalName().equals("Event")) {
                    String eventXml = fetchEventSnippet(reader);

                    EventWorkItem item = new EventWorkItem(++sequenceId, eventXml);

                    queue.put(item);
                }
            }

            // At EOF, push poison pill for each consumer
            for (int i = 0; i < NUM_CONSUMERS; i++) {
                queue.put(EventWorkItem.POISON_PILL);
            }
        } catch (FileNotFoundException e)  {
            throw new Exception("Producer could not find XML File: " + filePath, e);
        } catch (XMLStreamException e) {
            throw new Exception("Producer reader failed to parse XML at " + sequenceId, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt(); // Restore interrupted status
            throw new Exception("Producer was interrupted while queuing work", e);
        } finally {
            if (reader != null) {
                reader.close();
            }
        }
    }

    /**
     * Extracts a complete Event snippet from the stream reader.
     *
     * @param reader positioned at Event start element
     * @return complete Event XML as string
     * @throws XMLStreamException if XML parsing fails
     */
    private static String fetchEventSnippet(XMLStreamReader reader) throws XMLStreamException {
        StringBuilder eventSnippet = new StringBuilder(MAX_SNIPPET_SIZE);
        eventSnippet.append("<Event>");

        int depth = 1;

        while (depth > 0 && reader.hasNext()) {
            int element = reader.next();

            switch (element) {
                case START_ELEMENT:
                    eventSnippet.append("<").append(reader.getLocalName());

                    // attributes
                    int attrCount = reader.getAttributeCount();
                    for (int i = 0; i < attrCount; i++) {
                        String attrName = reader.getAttributeLocalName(i);
                        String attrValue = reader.getAttributeValue(i);
                        eventSnippet.append(" ").append(attrName).append("=\"").append(attrValue).append("\"");
                    }

                    eventSnippet.append(">");
                    depth++;
                    break;
                case CHARACTERS:
                    eventSnippet.append(reader.getText());
                    break;
                case END_ELEMENT:
                    eventSnippet.append("</").append(reader.getLocalName()).append(">");
                    depth--;
                    break;
            }
        }
        return eventSnippet.toString();
    }

    /**
     * Consumer task which processes work items from the queue.
     *
     * @param queue blocking queue to take work items from
     * @param results results collection to add parsed events to
     * @throws Exception if XML parsing fails or thread is interrupted
     */
    private static void consumerTask(BlockingQueue<EventWorkItem> queue, List<Event> results) throws Exception {
        try {
            while (true) {
                EventWorkItem item = queue.take();
                if (item.isPoisonPill()) {
                    break;
                }
                Event event = parseEventSnippet(item.xmlSegment(), item.sequenceId());
                results.add(event);
            }
        } catch (XMLStreamException e){
            throw new Exception("Consumer reader failed to parse XML", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new Exception("Consumer was interrupted while waiting for work", e);
        }
    }

    /**
     * Parses an Event XML snippet into an Event object.
     *
     * @param xml the Event XML snippet
     * @param sequenceId sequence identifier for sorting
     * @return parsed Event objects
     * @throws XMLStreamException if XML parsing fails
     */
    private static Event parseEventSnippet(String xml, long sequenceId) throws XMLStreamException {
        XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xml));
        EventSystem eventSystem = null;
        EventData eventData = null;

        while (reader.hasNext()) {
            int element = reader.next();

            if (element == START_ELEMENT && reader.getLocalName().equals("System")) {
                eventSystem = parseSystemElement(reader);
            } else if (element == START_ELEMENT && reader.getLocalName().equals("EventData")) {
                eventData = parseEventDataElement(reader);
            }
        }
        return new Event(sequenceId, eventSystem, eventData);
    }

    /**
     * Parses the System section of an Event.
     *
     * @param reader positioned at System start element
     * @return parsed EventSystem object
     */
    private static EventSystem parseSystemElement(XMLStreamReader reader) throws XMLStreamException {
        Map<String, String> fields = new HashMap<>();

        while (reader.hasNext()) {
            int element = reader.next();

            if (element == START_ELEMENT) {
                String elementName = reader.getLocalName();
                int attributeCount = reader.getAttributeCount();

                // Collect all attributes and their values into individual components
                for (int i = 0; i < attributeCount; i++) {
                    String attrName = reader.getAttributeLocalName(i);
                    String attrValue = reader.getAttributeValue(i);
                    fields.put(elementName + "." + attrName, attrValue);
                }

                // Collect content (getElementTest moves reader forward)
                String text = reader.getElementText();

                if (!text.isEmpty()) {
                    // Put text into element if present
                    fields.put(elementName, text);
                } else if (attributeCount == 0) {
                    // No attributes, no text, empty (avoids nulls)
                    fields.put(elementName, "");
                }
            } else if (element == END_ELEMENT && reader.getLocalName().equals("System")) {
                break;
            }
        }

        return new EventSystem(fields);
    }

    /**
     * Parses the EventData section of an Event.
     *
     * @param reader positioned at EventData start element
     * @return parsed EventData object
     */
    private static EventData parseEventDataElement(XMLStreamReader reader) throws XMLStreamException {
        Map<String, String> fields = new HashMap<>();

        while (reader.hasNext()) {
            int eventType = reader.next();

            if (eventType == START_ELEMENT && reader.getLocalName().equals("Data")) {
                String name = reader.getAttributeValue(null, "Name");
                String value = reader.getElementText();

                fields.put(name, value);
            } else if (eventType == END_ELEMENT && reader.getLocalName().equals("EventData")) {
                break;
            }
        }
        return new EventData(fields);
    }
}