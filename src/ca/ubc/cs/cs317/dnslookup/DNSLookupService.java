package ca.ubc.cs.cs317.dnslookup;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.TimeoutException;

public class DNSLookupService {

    public static final int DEFAULT_DNS_PORT = 53;
    private static final int MAX_INDIRECTION_LEVEL_NS = 10;
    private static final int MAX_QUERY_ATTEMPTS = 3;
    private static final int MAX_DNS_MESSAGE_LENGTH = 512;
    private static final int MAX_EDNS_MESSAGE_LENGTH = 1280;
    private static final int SO_TIMEOUT = 5000;

    private final DNSCache cache = DNSCache.getInstance();
    private final Random random = new Random();
    private final DNSVerbosePrinter verbose;
    private final DatagramSocket socket;

    /**
     * Creates a new lookup service. Also initializes the datagram socket object with a default timeout.
     *
     * @param verbose    A DNSVerbosePrinter listener object with methods to be called at key events in the query
     *                   processing.
     * @throws SocketException      If a DatagramSocket cannot be created.
     * @throws UnknownHostException If the nameserver is not a valid server.
     */
    public DNSLookupService(DNSVerbosePrinter verbose) throws SocketException, UnknownHostException {
        this.verbose = verbose;
        socket = new DatagramSocket();
        socket.setSoTimeout(SO_TIMEOUT);
    }

    /**
     * Closes the lookup service and related sockets and resources.
     */
    public void close() {
        socket.close();
    }

    /**
     * Examines a set of resource records to see if any of them are an answer to the given question.
     *
     * @param rrs       The set of resource records to be examined
     * @param question  The DNS question
     * @return          true if the collection of resource records contains an answer to the given question.
     */
    private boolean containsAnswer(Collection<CommonResourceRecord> rrs, DNSQuestion question) {
        for (CommonResourceRecord rr : rrs) {
            if (rr.getQuestion().equals(question) && rr.getRecordType() == question.getRecordType()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Finds all the results for a specific question. If there are valid (not expired) results in the cache, uses these
     * results, otherwise queries the nameserver for new records. If there are CNAME records associated to the question,
     * they are retrieved recursively for new records of the same type, and the returning set will contain both the
     * CNAME record and the resulting resource records of the indicated type.
     *
     * @param question             Host and record type to be used for search.
     * @param maxIndirectionLevels Number of CNAME indirection levels to support.
     * @return A set of resource records corresponding to the specific query requested.
     * @throws DNSErrorException If the number CNAME redirection levels exceeds the value set in
     *                           maxIndirectionLevels.
     */
    public Collection<CommonResourceRecord> getResultsFollowingCNames(DNSQuestion question, int maxIndirectionLevels)
            throws DNSErrorException {

        if (maxIndirectionLevels < 0) throw new DNSErrorException("CNAME indirection limit exceeded");

        Collection<CommonResourceRecord> directResults = iterativeQuery(question);
        if (containsAnswer(directResults, question)) {
            return directResults;
        }

        Set<CommonResourceRecord> newResults = new HashSet<>();
        for (CommonResourceRecord record : directResults) {
            newResults.add(record);
            if (record.getRecordType() == RecordType.CNAME) {
                newResults.addAll(getResultsFollowingCNames(
                        new DNSQuestion(record.getTextResult(), question.getRecordType(), question.getRecordClass()),
                        maxIndirectionLevels - 1));
            }
        }
        return newResults;
    }

    // /**
    //  * Answers one question.  If there are valid (not expired) results in the cache, returns these results.
    //  * Otherwise it chooses the best nameserver to query, retrieves results from that server
    //  * (using individualQueryProcess which adds all the results to the cache) and repeats until either:
    //  *   the cache contains an answer to the query, or
    //  *   the cache contains an answer to the query that is a CNAME record rather than the requested type, or
    //  *   every "best" nameserver in the cache has already been tried.
    //  *
    //  *  @param question Host name and record type/class to be used for the query.
    //  */
public Collection<CommonResourceRecord> iterativeQuery(DNSQuestion question) throws DNSErrorException {
    Collection<CommonResourceRecord> cacheResults;
    boolean foundRecord = false;
    for (int i = 0; i < MAX_INDIRECTION_LEVEL_NS; i++) {
        // Fetch cached results and search for relevant records
        cacheResults = cache.getCachedResults(question);
        for (CommonResourceRecord res : cacheResults) {
            if (res.getTextResult().equals(question.getHostName()) || res.getRecordType() == RecordType.CNAME) {
                foundRecord = true;
                break;
            }
        }
        // If record found, break out of outer loop
        if (foundRecord) {
            break;
        }
        // Fetch best name servers
        Collection<CommonResourceRecord> nameServers = cache.getBestNameservers(question);
        // Step 1: Resolve NS records to IP addresses if needed
        for (CommonResourceRecord nameServer : nameServers) {
            try {
                if (nameServer.getRecordType() == RecordType.NS) {
                    // Create a new DNS question for the NS record
                    DNSQuestion newAQuestion = cache.AQuestion(nameServer.getTextResult());
                    // Recursively resolve the name server's IP address
                    System.out.println("Attempting recursive call with: " + newAQuestion);
                    // iterativeQuery(newAQuestion);
                }
            } catch (Exception e) {
                System.err.println("Error resolving NS record: " + e.getMessage());
            }
        }
        // Step 2: Process known name servers
        Collection<CommonResourceRecord> knownNS = cache.filterByKnownIPAddress(nameServers);
        for (CommonResourceRecord knownServer: knownNS) {
            try {
                // Call individualQueryProcess to process DNS question with known name server
                individualQueryProcess(question, knownServer.getInetResult());
                foundRecord = true;
                break; // Exit the loop if successful
            } catch (DNSErrorException e) {
                System.err.println("Error processing known name server" + e.getMessage());
            }
        }
        // if processing successful, break out of the outer loop
        if (foundRecord) {
            break;
        }
    }
    // return final cached results
    return cache.getCachedResults(question);
}

    /**
     * Handles the process of sending an individual DNS query with a single question. Builds and sends the query (request)
     * message, then receives and parses the response. Received responses that do not match the requested transaction ID
     * are ignored. If no response is received after SO_TIMEOUT milliseconds, the request is sent again, with the same
     * transaction ID. The query should be sent at most MAX_QUERY_ATTEMPTS times, after which the function should return
     * without changing any values. If a response is received, all of its records are added to the cache.
     * <p>
     * If the reply contains a non-zero Rcode value, then throw a DNSErrorException.
     * <p>
     * The method verbose.printQueryToSend() must be called every time a new query message is about to be sent.
     *
     * @param question Host name and record type/class to be used for the query.
     * @param server   Address of the server to be used for the query.
     * @return If no response is received, returns null. Otherwise, returns a set of all resource records
     * received in the response.
     * @throws DNSErrorException if the Rcode in the response is non-zero
     */
    public Set<ResourceRecord> individualQueryProcess(DNSQuestion question, InetAddress server)
            throws DNSErrorException {
                DNSMessage query = buildQuery(question);
                byte[] queryData = query.getUsed();
                DatagramPacket packetToSend = new DatagramPacket(queryData, queryData.length, server, DEFAULT_DNS_PORT);
                for (int attempt = 0; attempt < MAX_QUERY_ATTEMPTS; attempt++) {
                    try {
                        verbose.printQueryToSend("udp", question, server, query.getID());
                        // send packet
                        socket.send(packetToSend);

                        // preprare buffer for response
                        byte[] responseBuffer = new byte[MAX_DNS_MESSAGE_LENGTH];
                        DatagramPacket responsePacket = new DatagramPacket(responseBuffer, responseBuffer.length);
                        // receive response
                        socket.receive(responsePacket);
                        // build message
                        DNSMessage responseMessage = new DNSMessage(responsePacket.getData(), responsePacket.getLength());
                        // check if received transaction ID matches the query transaction ID
                        if (responseMessage.getID() != query.getID()) {
                            continue; // ignore response
                        }
                        // check if response is a query
                        if (!responseMessage.getQR()) {
                            continue; // ignore response
                        }
                        if (responseMessage.getTC()) {
                            return tcpHelper(queryData, server);
                        }
                        // process response and return resource records
                        return processResponse(responseMessage);
                    } catch (IOException e) {
                        // Timeout: retry query
                        // e.printStackTrace(); 
                        // System.out.println(query.toString());
                        // throw new DNSErrorException("Timeout retry query");
                    }
                }
        return null;
    }
    
public Set<ResourceRecord> tcpHelper(byte[] queryData, InetAddress serverAddress) {
    try (Socket socket = new Socket(serverAddress, DEFAULT_DNS_PORT)) {
        // Output stream to send the DNS query
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        out.writeShort(queryData.length); // Write the length of the query
        out.write(queryData); // Write the query data
        // Input stream to receive the DNS response
        DataInputStream in = new DataInputStream(socket.getInputStream());
        int responseLength = in.readShort(); // Read the length of the response
        if (responseLength <= 0) {
            return Collections.emptySet(); // Return empty set if no data
        }
        byte[] responseData = new byte[responseLength];
        in.readFully(responseData); // Read the full response
        // Build and process the DNS message
        DNSMessage responseMessage = new DNSMessage(responseData, responseData.length);
        return processResponse(responseMessage);
    } catch (IOException | DNSErrorException e) {
        throw new RuntimeException("Error during TCP DNS query", e);
    }
}
     

    /**
     * Creates a DNSMessage containing a DNS query.
     * A random transaction ID must be generated and filled in the corresponding part of the query. The query
     * must be built as an iterative (non-recursive) request for a regular query with a single question. When the
     * function returns, the message's buffer's position (`message.buffer.position`) must be equivalent
     * to the size of the query data.
     *
     * @param question    Host name and record type/class to be used for the query.
     * @return The DNSMessage containing the query.
     */
    public DNSMessage buildQuery(DNSQuestion question) {
        // Generate a random transaction ID (16-bit)
        short transactionID = (short) (Math.random() * 0xFFFF);
        // Create a new DNSMessage with the generated ID
        DNSMessage message = new DNSMessage(transactionID);
        // Set the Recursion Desired (RD) flag to false for an iterative query
        message.setRD(false);
        // Set the Opcode to 0, indicating a standard query
        message.setOpcode(0);
        // Set the QR flag to false, indicating a query
        message.setQR(false);
        // Add the question to the message
        message.addQuestion(question);
        // Return the constructed DNSMessage
        return message;
    }

    /**
     * Parses and processes a response received by a nameserver.
     * If the reply contains a non-zero Rcode value, then throw a DNSErrorException.
     * Adds all resource records found in the response message to the cache.
     * Calls methods in the verbose object at appropriate points of the processing sequence. Must be able
     * to properly parse records of the types: A, AAAA, NS, CNAME and MX (the priority field for MX may be ignored). Any
     * other unsupported record type must create a record object with the data represented as a hex string (see method
     * byteArrayToHexString).
     *
     * @param message The DNSMessage received from the server.
     * @return A set of all resource records received in the response.
     * @throws DNSErrorException if the Rcode value in the reply header is non-zero
     */
    public Set<ResourceRecord> processResponse(DNSMessage message) throws DNSErrorException {
        // Check the Rcode in the response header
        if (message.getRcode() != 0) {
            throw new DNSErrorException("Non-zero Rcode received: " + message.getRcode());
        }
        // Create a set to store resource records
        Set<ResourceRecord> resourceRecords = new HashSet<>();
        // Get the count of Answer, Authority, and Additional records
        int answerCount = message.getANCount();
        int authorityCount = message.getNSCount();
        int additionalCount = message.getARCount();
        message.getQuestion();
        // Print response header info
        verbose.printResponseHeaderInfo(message.getID(), message.getAA(), message.getTC(), message.getRcode());
        // Process Answer Section
        verbose.printAnswersHeader(answerCount);
        for (int i = 0; i < answerCount; i++) {
            ResourceRecord rr = message.getRR();
            resourceRecords.add(rr);
            cache.addResult((CommonResourceRecord) rr);
            verbose.printIndividualResourceRecord(rr, rr.getRecordType().getCode(), rr.getRecordClassCode());
        }
        // Process Authority Section
        verbose.printNameserversHeader(authorityCount);
        for (int i = 0; i < authorityCount; i++) {
            ResourceRecord rr = message.getRR();
            resourceRecords.add(rr);
            cache.addResult((CommonResourceRecord) rr);
            verbose.printIndividualResourceRecord(rr, rr.getRecordType().getCode(), rr.getRecordClassCode());
        }
        // Process Additional Section
        verbose.printAdditionalInfoHeader(additionalCount);
        for (int i = 0; i < additionalCount; i++) {
            ResourceRecord rr = message.getRR();
            resourceRecords.add(rr);
            cache.addResult((CommonResourceRecord) rr);
            verbose.printIndividualResourceRecord(rr, rr.getRecordType().getCode(), rr.getRecordClassCode());
        }
        // Return the set of all resource records
        return resourceRecords; 
    }

    public static class DNSErrorException extends Exception {
        public DNSErrorException(String msg) {
            super(msg);
        }
    }
}
