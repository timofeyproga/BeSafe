package com.besafe.network;

import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

public class PeerConnection implements AutoCloseable {

    private final Socket socket;
    private final DataInputStream input;
    private final DataOutputStream output;

    private static final int MAX_MESSAGE_SIZE = 1_048_576;

    public PeerConnection(Socket socket) throws IOException {
        this.socket = socket;
        this.input = new DataInputStream(socket.getInputStream());
        this.output = new DataOutputStream(socket.getOutputStream());
    }

    public synchronized void sendBytes(byte[] data) throws IOException {
        if (data == null) {
            throw new NullPointerException("Data is null");
        }

        if (data.length > MAX_MESSAGE_SIZE) {
            throw new IOException("Data too large");
        }

        output.writeInt(data.length);
        output.write(data);
        output.flush();
    }

    public byte[] receiveBytes() throws IOException {
        int length = input.readInt();

        if (length < 0 || length > MAX_MESSAGE_SIZE) {
            throw new IOException("Invalid message length");
        }

        byte[] data = new byte[length];
        input.readFully(data);

        return data;
    }

    public void sendMessage(String message) throws IOException {
        if (message == null) {
            throw new NullPointerException("Message is null");
        }

        sendBytes(message.getBytes(StandardCharsets.UTF_8));
    }

    public String receiveMessage() throws IOException {
        return new String(receiveBytes(), StandardCharsets.UTF_8);
    }

    @Override
    public void close() throws IOException {
        this.socket.close();
    }

}
