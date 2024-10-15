package com.p2pmessagingapp;

import java.io.Serializable;

public class User implements Serializable{
    private static final long serialVersionUID = 1L;

    private final String id;
    private final int port;

    public User(String id, int port) {
        this.id = id;
        this.port = port;
    }

    public String getId() {
        return id;
    }

    public int getPort() {
        return port;
    }
}
