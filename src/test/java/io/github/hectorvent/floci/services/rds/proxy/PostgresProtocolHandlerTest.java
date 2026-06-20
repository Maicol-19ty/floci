package io.github.hectorvent.floci.services.rds.proxy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PostgresProtocolHandlerTest {

    private static final int SSL_REQUEST_CODE = 80877103;
    private static final int STARTUP_PROTOCOL_VERSION = 196608; // PostgreSQL v3.0

    @Test
    void acceptsPostgresSslRequestAndUpgradesSocket() throws Exception {
        ArrayBlockingQueue<Integer> serverRead = new ArrayBlockingQueue<>(1);

        try (ServerSocket server = new ServerSocket(0)) {
            Thread.ofVirtual().start(() -> {
                try (Socket accepted = server.accept()) {
                    DataInputStream in = new DataInputStream(accepted.getInputStream());
                    DataOutputStream out = new DataOutputStream(accepted.getOutputStream());
                    assertEquals(8, in.readInt());
                    assertEquals(SSL_REQUEST_CODE, in.readInt());

                    out.writeByte('S');
                    out.flush();
                    Socket sslSocket = PostgresProtocolHandler.acceptSsl(accepted);
                    serverRead.add(sslSocket.getInputStream().read());
                    sslSocket.getOutputStream().write(99);
                    sslSocket.getOutputStream().flush();
                    sslSocket.close();
                } catch (Exception e) {
                    serverRead.add(-1);
                }
            });

            try (Socket rawClient = new Socket("localhost", server.getLocalPort())) {
                DataOutputStream out = new DataOutputStream(rawClient.getOutputStream());
                DataInputStream in = new DataInputStream(rawClient.getInputStream());
                out.writeInt(8);
                out.writeInt(SSL_REQUEST_CODE);
                out.flush();
                assertEquals('S', in.readUnsignedByte());

                SSLSocket sslClient = (SSLSocket) trustAllContext().getSocketFactory()
                        .createSocket(rawClient, "localhost", server.getLocalPort(), true);
                sslClient.setUseClientMode(true);
                sslClient.startHandshake();
                sslClient.getOutputStream().write(42);
                sslClient.getOutputStream().flush();
                assertEquals(99, sslClient.getInputStream().read());
                sslClient.close();
            }
        }

        assertEquals(42, serverRead.poll(5, TimeUnit.SECONDS));
    }

    private static SSLContext trustAllContext() throws Exception {
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, new TrustManager[] {new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) {}

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) {}

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        }}, new SecureRandom());
        return context;
    }

    // ── Startup parameter forwarding (rds-postgres-proxy spec) ────────────────

    @Test
    @DisplayName("Client database startup param is forwarded to the backend")
    void forwardsClientDatabaseStartupParam() throws Exception {
        String capturedDb = exerciseStartupForwarding("auth_db", "app");

        assertEquals("auth_db", capturedDb,
                "backend startup must carry the client-requested database, not the instance dbName");
    }

    @Test
    @DisplayName("Omitted database startup param falls back to instance dbName")
    void omittedDatabaseFallsBackToInstanceDbName() throws Exception {
        // Approval test: the current code already falls back to the instance dbName
        // when the client omits `database`. This pins the behavior so the fix does
        // not regress it.
        String capturedDb = exerciseStartupForwarding(null, "app");

        assertEquals("app", capturedDb,
                "omitted database must fall back to the instance create-time dbName");
    }

    @Test
    @DisplayName("Blank database startup param falls back to instance dbName")
    void blankDatabaseFallsBackToInstanceDbName() throws Exception {
        // Approval test: a blank `database` param must be treated as omitted.
        String capturedDb = exerciseStartupForwarding("", "app");

        assertEquals("app", capturedDb,
                "blank database must be treated as omitted and fall back to the instance dbName");
    }

    @Test
    @DisplayName("Backend ErrorResponse (3D000) is forwarded without a spurious AuthenticationOK")
    void nonExistentDatabaseErrorForwardedWithoutAuthOk() throws Exception {
        byte[] first = exerciseErrorPath("missing_db", "3D000",
                "database \"missing_db\" does not exist");

        assertEquals('E', first[0] & 0xFF,
                "client must receive ErrorResponse directly, not a spurious AuthenticationOK first");
        Map<Character, String> fields = parseErrorFields(Arrays.copyOfRange(first, 5, first.length));
        assertEquals("3D000", fields.get('C'),
                "forwarded error must carry the real backend SQLSTATE");
    }

    @Test
    @DisplayName("Backend ErrorResponse content is forwarded verbatim (SQLSTATE preserved)")
    void backendErrorContentForwardedVerbatim() throws Exception {
        // Triangulation: a different SQLSTATE/message must also be forwarded verbatim,
        // proving the guard forwards the real backend error rather than a synthetic one.
        byte[] first = exerciseErrorPath("missing_db", "42704",
                "type \"ghost\" does not exist");

        assertEquals('E', first[0] & 0xFF);
        Map<Character, String> fields = parseErrorFields(Arrays.copyOfRange(first, 5, first.length));
        assertEquals("42704", fields.get('C'));
        assertTrue(fields.get('M').contains("ghost"),
                "forwarded error message must be the backend's verbatim message");
    }

    // ── Harness ───────────────────────────────────────────────────────────────

    /**
     * Drives a full client→proxy→backend handshake and returns the {@code database}
     * value the proxy reconstructed into the backend startup message.
     *
     * @param clientDatabase the client's requested database, or {@code null} to omit
     *                       the param entirely, or {@code ""} to send it blank
     * @param instanceDbName the RDS instance create-time dbName (fallback source)
     */
    private static String exerciseStartupForwarding(String clientDatabase, String instanceDbName)
            throws Exception {
        Socket[] clientPair = newConnectedPair();
        Socket[] backendPair = newConnectedPair();
        Socket clientHandlerSocket = clientPair[0];
        Socket backendHandlerSocket = backendPair[0];
        Socket clientSide = clientPair[1];
        Socket backendSide = backendPair[1];

        DataOutputStream clientOut = new DataOutputStream(clientSide.getOutputStream());
        DataInputStream clientIn = new DataInputStream(clientSide.getInputStream());
        DataOutputStream backendOut = new DataOutputStream(backendSide.getOutputStream());
        DataInputStream backendIn = new DataInputStream(backendSide.getInputStream());

        Thread handler = Thread.ofVirtual().name("pg-handler-test").start(() -> {
            try {
                PostgresProtocolHandler.handleAuth(clientHandlerSocket, backendHandlerSocket,
                        "postgres", "any", instanceDbName, false, null, (u, p) -> true);
            } catch (IOException ignored) {
                // Expected when sockets close at end of test.
            }
        });

        try {
            // Client → proxy: startup message
            writeClientStartup(clientOut, "postgres", clientDatabase);
            // Proxy → client: AuthenticationCleartextPassword challenge
            readClientAuthRequest(clientIn);
            // Client → proxy: password
            writeClientPassword(clientOut, "anypassword");

            // Proxy → backend: reconstructed startup (capture the database param)
            Map<String, String> backendStartup = readBackendStartup(backendIn);
            // Backend → proxy: AuthOK (Trust) + ReadyForQuery
            writeBackendAuthOkTrust(backendOut);
            writeBackendReadyForQuery(backendOut);

            // Client drains AuthOK + ReadyForQuery forwarded by the proxy
            drainClientAuthOkAndReady(clientIn);

            return backendStartup.get("database");
        } finally {
            closeQuietly(clientSide);
            closeQuietly(backendSide);
            closeQuietly(clientHandlerSocket);
            closeQuietly(backendHandlerSocket);
            handler.join(TimeUnit.SECONDS.toMillis(10));
        }
    }

    /**
     * Drives the handshake with a backend that, after AuthOK, emits an
     * {@code ErrorResponse} instead of {@code ReadyForQuery}. Returns the first
     * complete message the proxy forwards to the client (type + length + payload).
     */
    private static byte[] exerciseErrorPath(String clientDatabase, String sqlState, String message)
            throws Exception {
        Socket[] clientPair = newConnectedPair();
        Socket[] backendPair = newConnectedPair();
        Socket clientHandlerSocket = clientPair[0];
        Socket backendHandlerSocket = backendPair[0];
        Socket clientSide = clientPair[1];
        Socket backendSide = backendPair[1];

        DataOutputStream clientOut = new DataOutputStream(clientSide.getOutputStream());
        DataInputStream clientIn = new DataInputStream(clientSide.getInputStream());
        DataOutputStream backendOut = new DataOutputStream(backendSide.getOutputStream());
        DataInputStream backendIn = new DataInputStream(backendSide.getInputStream());

        Thread handler = Thread.ofVirtual().name("pg-handler-test").start(() -> {
            try {
                PostgresProtocolHandler.handleAuth(clientHandlerSocket, backendHandlerSocket,
                        "postgres", "any", "app", false, null, (u, p) -> true);
            } catch (IOException ignored) {
                // Expected when sockets close at end of test.
            }
        });

        try {
            writeClientStartup(clientOut, "postgres", clientDatabase);
            readClientAuthRequest(clientIn);
            writeClientPassword(clientOut, "anypassword");

            readBackendStartup(backendIn);
            writeBackendAuthOkTrust(backendOut);
            // Backend emits an ErrorResponse instead of ReadyForQuery (non-existent DB)
            writeBackendError(backendOut, sqlState, message);

            return readFirstClientMessage(clientIn);
        } finally {
            closeQuietly(clientSide);
            closeQuietly(backendSide);
            closeQuietly(clientHandlerSocket);
            closeQuietly(backendHandlerSocket);
            handler.join(TimeUnit.SECONDS.toMillis(10));
        }
    }

    // ── Wire helpers ──────────────────────────────────────────────────────────

    private static Socket[] newConnectedPair() throws IOException {
        try (ServerSocket server = new ServerSocket(0)) {
            Socket a = new Socket("localhost", server.getLocalPort());
            Socket b = server.accept();
            a.setTcpNoDelay(true);
            b.setTcpNoDelay(true);
            return new Socket[] {a, b};
        }
    }

    private static void writeClientStartup(DataOutputStream out, String user, String database)
            throws IOException {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        DataOutputStream bodyOut = new DataOutputStream(body);
        bodyOut.writeInt(STARTUP_PROTOCOL_VERSION);
        writeNullTerminatedParam(bodyOut, "user", user);
        if (database != null) {
            writeNullTerminatedParam(bodyOut, "database", database);
        }
        bodyOut.writeByte(0); // final null terminator
        byte[] bodyBytes = body.toByteArray();
        out.writeInt(4 + bodyBytes.length);
        out.write(bodyBytes);
        out.flush();
    }

    private static void writeNullTerminatedParam(OutputStream out, String key, String value)
            throws IOException {
        out.write(key.getBytes(StandardCharsets.UTF_8));
        out.write(0);
        out.write(value.getBytes(StandardCharsets.UTF_8));
        out.write(0);
    }

    private static void readClientAuthRequest(DataInputStream in) throws IOException {
        assertEquals('R', in.readUnsignedByte(), "expected AuthenticationCleartextPassword");
        int length = in.readInt();
        int authType = in.readInt();
        assertEquals(3, authType, "expected AuthenticationCleartextPassword (type 3)");
        if (length > 8) {
            in.readFully(new byte[length - 8]);
        }
    }

    private static void writeClientPassword(DataOutputStream out, String password) throws IOException {
        byte[] pw = password.getBytes(StandardCharsets.UTF_8);
        out.writeByte('p');
        out.writeInt(4 + pw.length + 1);
        out.write(pw);
        out.writeByte(0);
        out.flush();
    }

    private static Map<String, String> readBackendStartup(DataInputStream in) throws IOException {
        int length = in.readInt();
        int proto = in.readInt();
        assertEquals(STARTUP_PROTOCOL_VERSION, proto, "backend startup must use protocol v3.0");
        byte[] payload = new byte[length - 8];
        in.readFully(payload);
        Map<String, String> params = new HashMap<>();
        int i = 0;
        while (i < payload.length) {
            int keyStart = i;
            while (i < payload.length && payload[i] != 0) {
                i++;
            }
            if (i >= payload.length) {
                break;
            }
            String key = new String(payload, keyStart, i - keyStart, StandardCharsets.UTF_8);
            i++; // skip null
            if (key.isEmpty()) {
                break; // final terminator
            }
            int valStart = i;
            while (i < payload.length && payload[i] != 0) {
                i++;
            }
            String value = new String(payload, valStart, i - valStart, StandardCharsets.UTF_8);
            i++; // skip null
            params.put(key, value);
        }
        return params;
    }

    private static void writeBackendAuthOkTrust(DataOutputStream out) throws IOException {
        out.writeByte('R');
        out.writeInt(8);
        out.writeInt(0); // authType 0 = AuthenticationOK / Trust
        out.flush();
    }

    private static void writeBackendReadyForQuery(DataOutputStream out) throws IOException {
        out.writeByte('Z');
        out.writeInt(5);
        out.writeByte('I'); // idle status
        out.flush();
    }

    private static void writeBackendError(DataOutputStream out, String sqlState, String message)
            throws IOException {
        ByteArrayOutputStream fields = new ByteArrayOutputStream();
        fields.write('S');
        fields.write("FATAL".getBytes(StandardCharsets.UTF_8));
        fields.write(0);
        fields.write('C');
        fields.write(sqlState.getBytes(StandardCharsets.UTF_8));
        fields.write(0);
        fields.write('M');
        fields.write(message.getBytes(StandardCharsets.UTF_8));
        fields.write(0);
        fields.write(0); // final null
        byte[] fieldBytes = fields.toByteArray();
        out.writeByte('E');
        out.writeInt(4 + fieldBytes.length);
        out.write(fieldBytes);
        out.flush();
    }

    private static void drainClientAuthOkAndReady(DataInputStream in) throws IOException {
        assertEquals('R', in.readUnsignedByte(), "expected proxy AuthenticationOK");
        int rLength = in.readInt();
        int authType = in.readInt();
        assertEquals(0, authType, "expected AuthenticationOK (type 0)");
        if (rLength > 8) {
            in.readFully(new byte[rLength - 8]);
        }
        assertEquals('Z', in.readUnsignedByte(), "expected ReadyForQuery");
        int zLength = in.readInt();
        in.readFully(new byte[zLength - 4]);
    }

    private static byte[] readFirstClientMessage(DataInputStream in) throws IOException {
        int type = in.readUnsignedByte();
        int length = in.readInt();
        byte[] payload = new byte[length - 4];
        in.readFully(payload);
        ByteArrayOutputStream full = new ByteArrayOutputStream();
        full.write(type);
        full.write((length >> 24) & 0xFF);
        full.write((length >> 16) & 0xFF);
        full.write((length >> 8) & 0xFF);
        full.write(length & 0xFF);
        full.write(payload);
        return full.toByteArray();
    }

    private static Map<Character, String> parseErrorFields(byte[] payload) {
        Map<Character, String> fields = new HashMap<>();
        int i = 0;
        while (i < payload.length && payload[i] != 0) {
            char field = (char) payload[i];
            i++;
            int start = i;
            while (i < payload.length && payload[i] != 0) {
                i++;
            }
            String value = new String(payload, start, i - start, StandardCharsets.UTF_8);
            i++; // skip null
            fields.put(field, value);
        }
        return fields;
    }

    private static void closeQuietly(Socket s) {
        try {
            s.close();
        } catch (IOException ignored) {
            // ignore
        }
    }
}
