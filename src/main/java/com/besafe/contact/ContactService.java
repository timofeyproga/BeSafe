package com.besafe.contact;

import com.besafe.network.PeerAddress;

import java.util.HashMap;
import java.util.Map;

public class ContactService {

    private final Map<String, Contact> contacts = new HashMap<>();
    private final Map<String, PeerAddress> addresses = new HashMap<>();

    public void addContact(Contact contact, PeerAddress address) {
        if (contact == null) {
            throw new IllegalArgumentException("Contact cannot be null");
        }

        if (address == null) {
            throw new IllegalArgumentException("Address cannot be null");
        }

        String userId = contact.getUserId();

        if (contacts.containsKey(userId)) {
            throw new IllegalArgumentException("Contact already exists");
        }

        contacts.put(userId, contact);
        addresses.put(userId, address);
    }

    public Contact getContact(String userId) {
        return contacts.get(userId);
    }

    public PeerAddress getPeerAddress(String userId) {
        return addresses.get(userId);
    }

    public void deleteContact(String userId) {
        contacts.remove(userId);
        addresses.remove(userId);
    }

}
