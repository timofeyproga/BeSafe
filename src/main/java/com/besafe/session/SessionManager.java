package com.besafe.session;

import com.besafe.identity.UserIdentity;

public class SessionManager {

    private  UserIdentity user;

    public SessionManager() {
        user = null;
    }

    public void setUser(UserIdentity user) {
        this.user = user;
    }

    public UserIdentity getUser() {
        return user;
    }

    public void clearSession() {
        this.user = null;
    }

    public boolean hasUser() {
        return this.user != null;
    }

}
